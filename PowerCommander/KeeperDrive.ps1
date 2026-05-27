#requires -Version 5.1

function Get-KeeperDriveFolderList {
    <#
	.Synopsis
	Lists all Keeper Drive folders.

	.Description
	Displays all Keeper Drive folders synced to the vault, including UID, name, parent, and subfolder/record counts.
#>
    [CmdletBinding()]

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $folders = $vault.KeeperDriveFolderNodes
    if (-not $folders) {
        Write-Host "No Keeper Drive folders found."
        return
    }

    $result = @()
    foreach ($folder in $folders) {
        $result += [PSCustomObject]@{
            FolderUid   = $folder.FolderUid
            Name        = $folder.Name
            ParentUid   = if ($folder.ParentUid) { $folder.ParentUid } else { '(root)' }
            Subfolders  = $folder.Subfolders.Count
            Records     = $folder.Records.Count
        }
    }
    $result | Format-Table -AutoSize
}
New-Alias -Name kd-folders -Value Get-KeeperDriveFolderList

function Get-KeeperDriveRecordList {
    <#
	.Synopsis
	Lists all Keeper Drive records.

	.Description
	Displays all Keeper Drive records synced to the vault, including UID, revision, version, file size, and decrypted data.
#>
    [CmdletBinding()]

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $records = $vault.KeeperDriveRecordEntries
    if (-not $records) {
        Write-Host "No Keeper Drive records found."
        return
    }

    $result = @()
    foreach ($record in $records) {
        $result += [PSCustomObject]@{
            RecordUid    = $record.RecordUid
            Revision     = $record.Revision
            Version      = $record.Version
            Shared       = $record.Shared
            FileSize     = $record.FileSize
            ThumbnailSize = $record.ThumbnailSize
            Data         = if ($record.DecryptedData) { 
                               $record.DecryptedData.Substring(0, [Math]::Min(80, $record.DecryptedData.Length)) 
                           } else { '' }
        }
    }
    $result | Format-Table -AutoSize
}
New-Alias -Name kd-records -Value Get-KeeperDriveRecordList

function Get-KeeperDriveList {
    <#
	.Synopsis
	Lists all Keeper Drive folders and records (summary).

	.Description
	Displays a summary of Keeper Drive content: folder count, record count, and then lists both.
#>
    [CmdletBinding()]

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $folderCount = $vault.KeeperDriveFolderCount
    $recordCount = $vault.KeeperDriveRecordCount

    Write-Host ""
    Write-Host "=== Keeper Drive Summary ===" -ForegroundColor Cyan
    Write-Host "  Folders: $folderCount"
    Write-Host "  Records: $recordCount"
    Write-Host ""

    if ($folderCount -gt 0) {
        Write-Host "--- Folders ---" -ForegroundColor Yellow
        Get-KeeperDriveFolderList
    }

    if ($recordCount -gt 0) {
        Write-Host "--- Records ---" -ForegroundColor Yellow
        Get-KeeperDriveRecordList
    }

    if ($folderCount -eq 0 -and $recordCount -eq 0) {
        Write-Host "No Keeper Drive data found. Run Sync-Keeper to refresh." -ForegroundColor DarkYellow
    }
}
New-Alias -Name kd-list -Value Get-KeeperDriveList

function Get-KeeperDriveDiag {
    <#
	.Synopsis
	Diagnostic: checks raw KD storage tables for data.
#>
    [CmdletBinding()]

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $storage = $vault.Storage

    $kdFolders = @($storage.KdFolders.GetAll())
    $kdFolderKeys = @($storage.KdFolderKeys.GetAllLinks())
    $kdRecords = @($storage.KdRecords.GetAll())
    $kdRecordKeys = @($storage.KdRecordKeys.GetAllLinks())
    $kdFolderRecords = @($storage.KdFolderRecords.GetAllLinks())

    Write-Host ""
    Write-Host "=== KD Storage Diagnostic ===" -ForegroundColor Cyan
    Write-Host "  KdFolders (SQLite):       $($kdFolders.Count)"
    Write-Host "  KdFolderKeys (SQLite):    $($kdFolderKeys.Count)"
    Write-Host "  KdRecords (SQLite):       $($kdRecords.Count)"
    Write-Host "  KdRecordKeys (SQLite):    $($kdRecordKeys.Count)"
    Write-Host "  KdFolderRecords (SQLite): $($kdFolderRecords.Count)"
    Write-Host ""
    Write-Host "  In-memory KD Folders:     $($vault.KeeperDriveFolderCount)"
    Write-Host "  In-memory KD Records:     $($vault.KeeperDriveRecordCount)"
    Write-Host ""

    if ($kdFolders.Count -gt 0) {
        Write-Host "--- Raw KD Folders ---" -ForegroundColor Yellow
        foreach ($f in $kdFolders) {
            Write-Host "  UID=$($f.FolderUid)  Parent=$($f.ParentUid)  KeyType=$($f.KeyType)  FolderType=$($f.FolderType)"
        }
    }
    if ($kdRecords.Count -gt 0) {
        Write-Host "--- Raw KD Records ---" -ForegroundColor Yellow
        foreach ($r in $kdRecords) {
            Write-Host "  UID=$($r.RecordUid)  Rev=$($r.Revision)  Ver=$($r.Version)  FileSize=$($r.FileSize)"
        }
    }
}
New-Alias -Name kd-diag -Value Get-KeeperDriveDiag
