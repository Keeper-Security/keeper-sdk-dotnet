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
    Get Attachment as stream

    .Record
    Keeper Record Uid

    .AttachmentName
    Attachment Name

    .Stream
    Attachment will be written to this stream
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $Record,
        [Parameter()][string] $AttachmentName,
        [Parameter(Position = 0, Mandatory = $true)][System.IO.Stream] $Stream
    )

    $keeperRecord = Get-KeeperRecord $Record
    if ($keeperRecord.Length -ne 1) {
        Write-Error "Record `"$Record`" was not found" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $vault.DownloadAttachment($keeperRecord, $AttachmentName, $Stream).GetAwaiter().GetResult() | Out-Null
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
    if ($keeperRecord.Length -ne 1) {
        Write-Error "Record `"$Record`" was not found" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $path = Resolve-Path $Filename -ErrorAction Stop
    $uploadTask  = New-Object -TypeName KeeperSecurity.Vault.FileAttachmentUploadTask -ArgumentList $path.Path, $null

    $vault.UploadAttachment($keeperRecord, $uploadTask).GetAwaiter().GetResult() | Out-Null
    Write-Host "Attachment uploaded successfully" -ForegroundColor Green
}

function Remove-KeeperFileAttachment {
    <#
    .Synopsis
    Remove file attachment from a record

    .Record
    Keeper Record Uid or Name

    .AttachmentName
    Attachment Name, Title, or ID to remove

    .Example
    Remove-KeeperFileAttachment -Record "My Record" -AttachmentName "document.pdf"

    .Example
    Remove-KeeperFileAttachment -Record "record-uid" -AttachmentName "attachment-id"
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true)][string] $Record,
        [Parameter(Mandatory = $true)][string] $AttachmentName
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

        $attachmentToDelete = $attachments | Where-Object {
            ($_.Id -eq $AttachmentName) -or
            ($_.Title -eq $AttachmentName) -or
            ($_.Name -eq $AttachmentName) -or
            ($_.Title.ToLower().Trim() -eq $AttachmentName.ToLower().Trim()) -or
            ($_.Name.ToLower().Trim() -eq $AttachmentName.ToLower().Trim())
        } | Select-Object -First 1

        if (-not $attachmentToDelete) {
            Write-Warning "Attachment `"$AttachmentName`" not found in record `"$($keeperRecord.Title)`""
            Write-Host "Available attachments:"
            foreach ($attachment in $attachments) {
                $displayName = if ($attachment.Title) { $attachment.Title } elseif ($attachment.Name) { $attachment.Name } else { $attachment.Id }
                Write-Host "  - $displayName (ID: $($attachment.Id))"
            }
            return
        }

        $displayName = if ($attachmentToDelete.Title) { $attachmentToDelete.Title } 
                      elseif ($attachmentToDelete.Name) { $attachmentToDelete.Name } 
                      else { $attachmentToDelete.Id }

        if ($PSCmdlet.ShouldProcess("$displayName from record '$($keeperRecord.Title)'", "Remove Attachment")) {
            try {
                $success = $vault.DeleteAttachment($keeperRecord, $attachmentToDelete.Id).GetAwaiter().GetResult()
                
                if ($success) {
                    Write-Host "Attachment '$displayName' has been deleted successfully from record '$($keeperRecord.Title)'" -ForegroundColor Green
                } else {
                    Write-Error "Failed to delete attachment '$displayName' from record '$($keeperRecord.Title)'"
                }
            }
            catch {
                Write-Error "Error deleting attachment '$displayName': $($_.Exception.Message)"
            }
        }
    }
}
New-Alias -Name krfa -Value Remove-KeeperFileAttachment