#requires -Version 5.1


function Copy-KeeperFileAttachment {
    <#
	.Synopsis
	Download record attachments

    .Folder
    Keeper Folder

    .Record
    Keeper Record

	.Parameter Path
	Download folder path
#>

    [CmdletBinding()]
    Param (
        [Parameter(ParameterSetName = 'folder', Mandatory = $true)][string] $Folder,
        [Parameter(ParameterSetName = 'folder')][Switch] $Recursive,
        [Parameter(ParameterSetName = 'record', Mandatory = $true)][string] $Record,
        [Parameter()][string] $Name,
        [Parameter(Position = 0)][string] $Path
    )

    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault

        if (-not $Path) {
            $Path = '.'
        }
        $records = $null
        if ($Record) {
            $r = Get-KeeperRecord $record
            if ($r) {
                $records = @()
                $records += $r.Uid
            }

        } elseif ($Folder) {
            if ($Recursive.IsPresent) {
                $records = Get-KeeperChildItem $Folder -Recursive -SkipGrouping -ObjectType Record | Select-Object -ExpandProperty "Uid"
            } else {
                $records = Get-KeeperChildItem $Folder -SkipGrouping -ObjectType Record | Select-Object -ExpandProperty "Uid"
            }
        }
        if (-not $records) {
            Write-Error "No records were found" -ErrorAction Stop
        }
    }

    Process {
        if (-not (Test-Path $Path -PathType Container)) {
            New-Item -ItemType Directory -Path $Path | Out-Null
        }
        [KeeperSecurity.Vault.KeeperRecord]$keeperRecord
        [KeeperSecurity.Vault.IAttachment]$atta
        foreach($recordUid in $records) {
            $keeperRecord = Get-KeeperRecord $recordUid
            if (-not $keeperRecord) {
                continue
            }
            foreach ($atta in $vault.RecordAttachments($keeperRecord)) {
                if ($Name) {
                    if (-not (($atta.Name, $atta.Title) -contains $Name)) {
                        continue
                    }
                }
                $fileName = $atta.Id
                if ($atta.Title) {
                    $fileName = $atta.Title
                } elseif ($atta.Name) {
                    $fileName = $atta.Name
                }
                $filePath = Join-Path $path $fileName
                if (Test-Path $filePath -PathType Leaf) {
                    $filePath = Join-Path $path "$($atta.Id) - $fileName"
                    if (Test-Path $filePath -PathType Leaf) {
                        Write-Information -MessageData "File `"$filePath`" already exists"
                        continue
                    }
                }
                Write-Information -MessageData "Downloading `"$fileName`" into `"$filePath`""
                $newFile = New-Item -Name $filePath -ItemType File
                $fileStream = $newFile.OpenWrite()
                try {
                    $vault.DownloadAttachment($keeperRecord, $atta.Id, $fileStream).GetAwaiter().GetResult() | Out-Null
                }
                finally {
                    $fileStream.Dispose()
                }
            }
        }
    }
}
New-Alias -Name kda -Value Copy-KeeperFileAttachment

function Copy-KeeperFileAttachmentToStream {
    <#
    .Synopsis
    Downloads an attachment to a stream or file path.

    .Description
    Use -Path to download to a file (e.g. -Path "C:\Downloads\file.png").
    Use -Stream to write to an existing Stream object for advanced scenarios.

    .Parameter Record
    Keeper record UID or title.

    .Parameter Name
    Attachment file name or ID. Omit if the record has only one attachment.

    .Parameter Path
    File path to save the attachment. Creates the directory if needed.

    .Parameter Stream
    A System.IO.Stream to write the attachment data to.

    .Example
    Copy-KeeperFileAttachmentToStream -Record "ABxzAJFeEd_pRAFbcqGCJA" -Name "download.png" -Path "C:\Downloads\file.png"

    .Example
    $ms = [System.IO.MemoryStream]::new()                                       
    Copy-KeeperFileAttachmentToStream -Record <Record ID> -Stream $ms
    $ms.Position = 0
    $reader = [System.IO.StreamReader]::new($ms)
    $reader.ReadToEnd()
    $reader.Dispose()
    $ms.Dispose()
    #>

    [CmdletBinding(DefaultParameterSetName = 'Path')]
    Param (
        [Parameter(Mandatory = $true)][string] $Record,
        [Parameter()][string] $Name,
        [Parameter(ParameterSetName = 'Path', Mandatory = $true, Position = 0)][string] $Path,
        [Parameter(ParameterSetName = 'Stream', Mandatory = $true)][System.IO.Stream] $Stream
    )

    $keeperRecord = Get-KeeperRecord $Record
    if ($null -eq $keeperRecord -or (@($keeperRecord).Count -ne 1)) {
        Write-Error "Record `"$Record`" was not found" -ErrorAction Stop
    }
    $keeperRecord = @($keeperRecord)[0]

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $attachments = @($vault.RecordAttachments($keeperRecord))
    if ($attachments.Count -eq 0) {
        Write-Error "Record has no attachments" -ErrorAction Stop
    }

    [KeeperSecurity.Vault.IAttachment]$atta = $null
    if ($Name) {
        $atta = $attachments | Where-Object { $_.Name -eq $Name -or $_.Title -eq $Name -or $_.Id -eq $Name } | Select-Object -First 1
        if (-not $atta) {
            Write-Error "Attachment `"$Name`" not found on record" -ErrorAction Stop
        }
    } else {
        $atta = $attachments[0]
    }

    $streamToUse = $Stream
    $ownsStream = $false
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $dir = [System.IO.Path]::GetDirectoryName($fullPath)
        if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $streamToUse = [System.IO.File]::Create($fullPath)
        $ownsStream = $true
    }

    try {
        $vault.DownloadAttachment($keeperRecord, $atta.Id, $streamToUse).GetAwaiter().GetResult() | Out-Null
    }
    finally {
        if ($ownsStream) {
            $streamToUse.Dispose()
        }
    }
}

function Copy-FileToKeeperRecord {
    <#
    .Synopsis
    Upload file attachment to a record

    .Record
    Keeper Record Uid

    .Filename
    File path
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $Record,
        [Parameter(Position = 0, Mandatory = $true)][string] $Filename
    )

    $keeperRecord = Get-KeeperRecord $Record
    if ($null -eq $keeperRecord) {
        $keeperRecord = Get-KeeperRecord -Filter $Record
    }
    if ($null -eq $keeperRecord -or (@($keeperRecord).Count -ne 1)) {
        Write-Error "Record `"$Record`" was not found" -ErrorAction Stop
    }
    $keeperRecord = @($keeperRecord)[0]
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $path = Resolve-Path $Filename -ErrorAction Stop
    $uploadTask  = New-Object -TypeName KeeperSecurity.Vault.FileAttachmentUploadTask -ArgumentList $path.Path, $null

    $vault.UploadAttachment($keeperRecord, $uploadTask).GetAwaiter().GetResult() | Out-Null
}

function Remove-KeeperFileAttachment {
    <#
    .Synopsis
    Remove file attachments from a record

    .Parameter Record
    Keeper Record Uid or Name

    .Parameter FileName
    Attachment filename(s) to delete. Can be used multiple times to delete multiple filenames.

    .Example
    Remove-KeeperFileAttachment -Record "My Record" -FileName "document.pdf"

    .Example
    Remove-KeeperFileAttachment -Record "My Record" -FileName "document.pdf", "image.jpg", "report.docx"

    .Example
    Remove-KeeperFileAttachment -Record "record-uid" -FileName "attachment-id"
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Record,
        
        [Parameter(Mandatory = $true)]
        [Alias('f')]
        [string[]] $FileName
    )

    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }

    Process {
        $keeperRecord = Get-KeeperRecord $Record
        if (-not $keeperRecord) {
            Write-Error "Record `"$Record`" was not found" -ErrorAction Stop
        }

        $attachments = @($vault.RecordAttachments($keeperRecord))
        
        if ($attachments.Count -eq 0) {
            Write-Warning "Record `"$($keeperRecord.Title)`" has no attachments"
            return
        }

        $allAttachmentsToDelete = @()
        $notFoundFiles = @()

        foreach ($file in $FileName) {
            $matchingAttachments = $attachments | Where-Object {
                ($_.Id -eq $file) -or
                ($_.Title -eq $file) -or
                ($_.Name -eq $file) -or
                ($_.Title.ToLower().Trim() -eq $file.ToLower().Trim()) -or
                ($_.Name.ToLower().Trim() -eq $file.ToLower().Trim())
            }

            if (-not $matchingAttachments) {
                $notFoundFiles += $file
            }
            else {
                Write-Host "Found $($matchingAttachments.Count) attachment(s) matching '$file'"
                $allAttachmentsToDelete += $matchingAttachments
            }
        }

        if ($allAttachmentsToDelete.Count -eq 0) {
            Write-Warning "No matching attachments found to delete."
            if ($notFoundFiles.Count -gt 0) {
                Write-Host "Files not found: $($notFoundFiles -join ', ')" -ForegroundColor Yellow
                Write-Host "Available attachments:"
                foreach ($attachment in $attachments) {
                    $displayName = if ($attachment.Title) { $attachment.Title } elseif ($attachment.Name) { $attachment.Name } else { $attachment.Id }
                    Write-Host "  - $displayName (ID: $($attachment.Id))"
                }
            }
            return
        }

        $confirmMessage = "Delete $($allAttachmentsToDelete.Count) attachment(s) from record '$($keeperRecord.Title)'"
        
        if ($PSCmdlet.ShouldProcess($confirmMessage, "Remove Attachments")) {
            $deletedCount = 0
            $failedCount = 0

            foreach ($attachment in $allAttachmentsToDelete) {
                $displayName = if ($attachment.Title) { $attachment.Title } 
                              elseif ($attachment.Name) { $attachment.Name } 
                              else { $attachment.Id }

                try {
                    $success = $vault.DeleteAttachment($keeperRecord, $attachment.Id).GetAwaiter().GetResult()
                    
                    if ($success) {
                        Write-Host "Deleted '$displayName' (ID: $($attachment.Id))" -ForegroundColor Green
                        $deletedCount++
                    }
                    else {
                        Write-Host "Failed to delete '$displayName' (ID: $($attachment.Id))" -ForegroundColor Red
                        $failedCount++
                    }
                }
                catch {
                    Write-Host "Error deleting '$displayName': $($_.Exception.Message)" -ForegroundColor Red
                    $failedCount++
                }
            }

            Write-Host "Summary: $deletedCount deleted, $failedCount failed" -ForegroundColor Cyan
            
            if ($notFoundFiles.Count -gt 0) {
                Write-Host "Files not found: $($notFoundFiles -join ', ')" -ForegroundColor Yellow
                Write-Host "Available attachments:"
                foreach ($attachment in $attachments) {
                    $displayName = if ($attachment.Title) { $attachment.Title } elseif ($attachment.Name) { $attachment.Name } else { $attachment.Id }
                    Write-Host "  - $displayName (ID: $($att.Id))"
                }
            }
        }
    }
}
New-Alias -Name krfa -Value Remove-KeeperFileAttachment

function Get-KeeperFileReport {
    <#
    .SYNOPSIS
    List records with file attachments.

    .DESCRIPTION
    Generates a report of all records in the vault that have file attachments.
    Supports both legacy PasswordRecord (v2) and modern TypedRecord (v3) with fileRef fields.
    Optionally tests download accessibility for each attachment using HTTP Range requests.

    .PARAMETER TryDownload
    Try downloading every attachment you have access to. Tests accessibility by making
    an HTTP Range request (bytes=0-1) for each file and reports OK or the HTTP status code.

    .PARAMETER Format
    Output format: table (default), csv, json.

    .PARAMETER Output
    Export report results to a file path.

    .EXAMPLE
    Get-KeeperFileReport
    List all records with file attachments in table format.

    .EXAMPLE
    Get-KeeperFileReport -TryDownload
    List all file attachments and verify each one is downloadable.

    .EXAMPLE
    Get-KeeperFileReport -Format csv -Output "file_report.csv"
    Export the file attachment report to a CSV file.

    .EXAMPLE
    Get-KeeperFileReport -Format json
    Output the file attachment report as JSON.

    .EXAMPLE
    Get-KeeperFileReport -TryDownload -Format csv -Output "downloads.csv"
    Verify download accessibility and export results to CSV.
    #>
    [CmdletBinding()]
    Param (
        [Alias('dl')]
        [switch] $TryDownload,

        [ValidateSet('table', 'csv', 'json')]
        [string] $Format = 'table',

        [string] $Output
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Failed to connect to vault"
        return
    }

    $options = New-Object KeeperSecurity.Vault.FileReportOptions
    $options.TryDownload = $TryDownload.IsPresent

    if ($TryDownload.IsPresent) {
        Write-Host "Scanning vault for file attachments and verifying download accessibility..."
    }
    else {
        Write-Host "Scanning vault for file attachments..."
    }

    try {
        $report = [KeeperSecurity.Vault.KeeperFileReport]::GenerateFileReport($vault, $options, $null).GetAwaiter().GetResult()
    }
    catch {
        Write-Error "Failed to generate file report: $($_.Exception.Message)"
        return
    }

    if ($report.Count -eq 0) {
        Write-Host "No records with file attachments found."
        return
    }

    $result = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($item in $report) {
        $title = $item.RecordTitle; if ($null -eq $title) { $title = '' }
        $recUid = $item.RecordUid; if ($null -eq $recUid) { $recUid = '' }
        $recType = $item.RecordType; if ($null -eq $recType) { $recType = '' }
        $fileId = $item.FileId; if ($null -eq $fileId) { $fileId = '' }
        $fileName = $item.FileName; if ($null -eq $fileName) { $fileName = '' }
        $row = [ordered]@{
            'Title'       = $title
            'Record UID'  = $recUid
            'Record Type' = $recType
            'File ID'     = $fileId
            'File Name'   = $fileName
            'File Size'   = $item.FileSize
        }
        if ($TryDownload.IsPresent) {
            $dl = $item.Downloadable; if ($null -eq $dl) { $dl = '' }; $row['Downloadable'] = $dl
        }
        $result.Add([PSCustomObject]$row)
    }

    if ($Output) {
        switch ($Format) {
            'json' { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
            'csv'  { $result | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8 }
            default { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
        }
        Write-Host "Report exported to $Output ($($result.Count) file(s) found)"
    }
    else {
        switch ($Format) {
            'json' { $result | ConvertTo-Json -Depth 5 }
            'csv'  { $result | ConvertTo-Csv -NoTypeInformation }
            default {
                Write-Host ""
                $result | Format-Table -AutoSize
            }
        }
    }
}
New-Alias -Name file-report -Value Get-KeeperFileReport