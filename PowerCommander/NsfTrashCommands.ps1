#requires -Version 5.1

function Get-KeeperNSFTrashList {
    <#
	.Synopsis
	Lists Keeper NSF records and folders currently in trash.

	.Description
	Displays all Keeper NSF records and folders in trash, including UID, title, record type, item type, and deletion date.

	.Parameter Reload
	Discard the cached trashcan snapshot and resync from the server.
#>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [switch] $Reload
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    try {
        $result = $vault.GetKeeperNSFTrash([bool]$Reload).GetAwaiter().GetResult()
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($result.Records.Count -eq 0 -and $result.Folders.Count -eq 0) {
        Write-Host "NSF trash is empty"
        return
    }

    $items = @($result.Records) + @($result.Folders) | Sort-Object -Property DateDeleted -Descending

    $items | ForEach-Object {
        $deletedAt = if ($_.DateDeleted -gt 0) {
            [DateTimeOffset]::FromUnixTimeMilliseconds($_.DateDeleted).LocalDateTime
        } else { '' }

        [PSCustomObject]@{
            Uid         = $_.Uid
            Title       = $_.Title
            RecordType  = $_.RecordType
            Type        = if ($_.IsFolder) { 'Folder' } else { 'Record' }
            DeletedAt   = $deletedAt
        }
    } | Format-Table -AutoSize
}
New-Alias -Name nsf-trash-list -Value Get-KeeperNSFTrashList

function Get-KeeperNSFTrashItem {
    <#
	.Synopsis
	Shows details for one Keeper NSF record or folder in trash.

	.Description
	Retrieves and displays the title, type, status, and deletion date for the specified trashed record or folder UID.

	.Parameter Uid
	The record or folder UID to look up.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Uid
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    try {
        $item = $vault.GetKeeperNSFTrashItem($Uid).GetAwaiter().GetResult()
    } catch {
        Write-Host "Failed to look up trash item: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $item) {
        Write-Host "`"$Uid`" was not found in trash."
        return
    }

    $deletedAt = if ($item.DateDeleted -gt 0) {
        [DateTimeOffset]::FromUnixTimeMilliseconds($item.DateDeleted).LocalDateTime
    } else { '' }

    Write-Host ("{0,-14}{1}" -f "UID:", $item.Uid)
    Write-Host ("{0,-14}{1}" -f "Title:", $item.Title)
    if (-not $item.IsFolder) {
        Write-Host ("{0,-14}{1}" -f "Type:", $item.RecordType)
    }
    Write-Host ("{0,-14}{1}" -f "Status:", $item.Status)
    Write-Host ("{0,-14}{1}" -f "Deleted At:", $deletedAt)
}
New-Alias -Name nsf-trash-get -Value Get-KeeperNSFTrashItem

function Restore-KeeperNSFTrash {
    <#
	.Synopsis
	Restores one or more Keeper NSF records and/or folders from trash.

	.Description
	Restores the specified trashed record and/or folder UIDs to their original location, or to -TargetFolder if specified.

	.Parameter Uids
	One or more record and/or folder UIDs to restore.

	.Parameter TargetFolder
	Folder UID to restore items into instead of their original location.

	.Parameter SourceFolder
	Folder UID (or "root"/"/" for the Drive root) a record is being restored out of. Only needed if the server rejects the restore with "source_folder_uid is required" (the record was trashed under more than one folder).

	.Parameter Force
	Skip confirmation.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
        [string[]] $Uids,

        [Parameter()]
        [string] $TargetFolder,

        [Parameter()]
        [string] $SourceFolder,

        [Parameter()]
        [switch] $Force
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $Uids -or $Uids.Count -eq 0) {
        Write-Host 'At least one record or folder UID is required.' -ForegroundColor Red
        return
    }

    if (-not $Force) {
        try {
            $preview = $vault.RestoreKeeperNSFTrash([string[]]$Uids, $TargetFolder, $SourceFolder, $true).GetAwaiter().GetResult()
        } catch {
            Write-Host "Failed to restore from trash: $($_.Exception.Message)" -ForegroundColor Red
            return
        }

        if ($preview.RestoredRecordUids.Count -eq 0 -and $preview.RestoredFolderUids.Count -eq 0) {
            foreach ($error_ in $preview.Errors) {
                Write-Host "Error: $error_" -ForegroundColor Red
            }
            if ($preview.Errors.Count -eq 0) {
                Write-Host "Nothing matched - nothing to restore."
            }
            return
        }

        $toDo = @()
        if ($preview.RestoredRecordUids.Count -gt 0) { $toDo += "$($preview.RestoredRecordUids.Count) record(s)" }
        if ($preview.RestoredFolderUids.Count -gt 0) { $toDo += "$($preview.RestoredFolderUids.Count) folder(s)" }
        $destination = if ($TargetFolder) { " into `"$TargetFolder`"" } else { "" }

        $confirmation = Read-Host "Do you want to restore $($toDo -join ' and ')$($destination)? (yes/No)"
        if ($confirmation -notmatch '^(?i)y(es)?$') {
            Write-Host "Restore cancelled."
            return
        }
    }

    try {
        $result = $vault.RestoreKeeperNSFTrash([string[]]$Uids, $TargetFolder, $SourceFolder).GetAwaiter().GetResult()
    } catch {
        Write-Host "Failed to restore from trash: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($result.RestoredRecordUids.Count -gt 0) {
        Write-Host "Restored $($result.RestoredRecordUids.Count) record(s): $($result.RestoredRecordUids -join ', ')"
    }

    if ($result.RestoredFolderUids.Count -gt 0) {
        Write-Host "Restored $($result.RestoredFolderUids.Count) folder(s): $($result.RestoredFolderUids -join ', ')"
    }

    foreach ($error_ in $result.Errors) {
        Write-Host "Error: $error_" -ForegroundColor Red
    }

    if (-not $result.Success -and $result.Errors.Count -eq 0) {
        Write-Host "Nothing was restored."
    }
}
New-Alias -Name nsf-trash-restore -Value Restore-KeeperNSFTrash
