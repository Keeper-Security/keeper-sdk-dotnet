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

function Get-KeeperFileAttachmentToStream {
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


