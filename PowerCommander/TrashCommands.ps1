#requires -Version 5.1

function Get-KeeperTrashList {
    <#
    .SYNOPSIS
    Lists deleted records in trash

    .DESCRIPTION
    Lists all deleted records, orphaned records, and shared folders in the trash.
    Shows record details including UID, name, type, deletion date, and status.

    .PARAMETER Pattern
    Filter records by pattern (supports wildcards * and ?)

    .PARAMETER Verbose
    Show detailed information including folder details

    .EXAMPLE
    Get-KeeperTrashList
    Lists all items in trash

    .EXAMPLE
    Get-KeeperTrashList -Pattern "test*"
    Lists only records matching "test*" pattern

    .EXAMPLE
    Get-KeeperTrashList -Verbose
    Shows detailed information including folder details
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Pattern        
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    [KeeperSecurity.Vault.TrashManagement]::EnsureDeletedRecordsLoaded($vault).GetAwaiter().GetResult() | Out-Null

    $deletedRecords = [KeeperSecurity.Vault.TrashManagement]::GetDeletedRecords()
    $orphanedRecords = [KeeperSecurity.Vault.TrashManagement]::GetOrphanedRecords()
    $sharedFolders = [KeeperSecurity.Vault.TrashManagement]::GetSharedFolders()

    if ([KeeperSecurity.Vault.TrashManagement]::IsTrashEmpty()) {
        Write-Host "Trash is empty"
        return
    }

    $normalizedPattern = if ($Pattern -eq "*") { $null } else { if ($Pattern) { $Pattern.ToLower() } else { $null } }
    
    $titlePattern = $null
    if ($normalizedPattern) {
        try {
            $escapedPattern = [regex]::Escape($normalizedPattern)
            $regexPattern = $escapedPattern -replace "\\\*", ".*"
            $regexPattern = $regexPattern -replace "\\\?", "."
            $regexPattern = "^" + $regexPattern + "$"
            $titlePattern = [regex]::new($regexPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
        catch {
            Write-Warning "Invalid pattern: $($_.Exception.Message)"
            $titlePattern = $null
        }
    }

    $results = @()
    $results += Get-RecordTableData -Records $deletedRecords -IsShared $false -Pattern $normalizedPattern -TitlePattern $titlePattern
    $results += Get-RecordTableData -Records $orphanedRecords -IsShared $true -Pattern $normalizedPattern -TitlePattern $titlePattern
    $results += Get-FolderTableData -SharedFolders $sharedFolders -Pattern $normalizedPattern -TitlePattern $titlePattern -Verbose:($VerbosePreference -eq 'Continue')
    $results = $results | Sort-Object Name

    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host "No records found matching the specified criteria"
    }
}

function Get-RecordTableData {
    param(
        $Records,
        [bool]$IsShared,
        [string]$Pattern,
        [regex]$TitlePattern
    )

    $results = @()

    foreach ($record in $Records.Values) {
        $recordTitle = ""
        $recordType = ""
        
        if ($record.DataUnencrypted) {
            try {
                $jsonString = [System.Text.Encoding]::UTF8.GetString($record.DataUnencrypted)
                $jsonObject = $jsonString | ConvertFrom-Json
                $recordTitle = if ($jsonObject.title) { $jsonObject.title } else { "" }
                $recordType = if ($jsonObject.type) { $jsonObject.type } else { "" }
            }
            catch {
                $recordTitle = "Parse Error"
                $recordType = "Unknown"
            }
        }

        if ($Pattern -and $recordTitle -notmatch $TitlePattern) {
            continue
        }

        $status = if ($IsShared) { "Share" } else { "Record" }
        $dateDeleted = if (-not $IsShared) { Get-DeletedDate -Timestamp $record.DateDeleted } else { $null }

        $results += [PSCustomObject]@{
            'Folder UID' = ""
            'Record UID' = $record.RecordUid
            'Name' = $recordTitle
            'Record Type' = $recordType
            'Deleted At' = $dateDeleted
            'Status' = $status
        }
    }

    return $results
}

function Get-FolderTableData {
    param(
        $SharedFolders,
        [string]$Pattern,
        [regex]$TitlePattern,
        [switch]$Verbose
    )

    $results = @()

    if (-not $SharedFolders -or -not $SharedFolders.Folders -or -not $SharedFolders.Records) {
        return $results
    }

    if ($Verbose) {
        foreach ($folder in $SharedFolders.Folders.Values) {
            $folderName = Get-FolderName -Folder $folder -FolderUid $folder.FolderUidString
            $folderRecords = $SharedFolders.Records.Values | Where-Object { $_.FolderUid -eq $folder.FolderUidString }
            
            $folderNameMatches = -not $Pattern -or $folderName -match $TitlePattern
            
            $hasMatchingRecords = $false
            if ($Pattern) {
                foreach ($record in $folderRecords) {
                    $recordTitle = Get-RecordTitle -Record $record
                    if ($recordTitle -match $TitlePattern) {
                        $hasMatchingRecords = $true
                        break
                    }
                }
            }
            else {
                $hasMatchingRecords = $true 
            }
            
            $showFolder = $folderNameMatches -or $hasMatchingRecords
            
            if ($showFolder) {
                $results += [PSCustomObject]@{
                    'Folder UID' = $folder.FolderUidString
                    'Record UID' = ""
                    'Name' = $folderName
                    'Record Type' = "Shared Folder"
                    'Deleted At' = $null
                    'Status' = "Folder"
                }
            }

            foreach ($record in $folderRecords) {
                $recordTitle = Get-RecordTitle -Record $record
                $recordMatches = -not $Pattern -or $recordTitle -match $TitlePattern
                
                if ($recordMatches) {
                    $results += [PSCustomObject]@{
                        'Folder UID' = $folder.FolderUidString
                        'Record UID' = $record.RecordUid
                        'Name' = $recordTitle
                        'Record Type' = Get-RecordType -Record $record
                        'Deleted At' = Get-DeletedDate -Timestamp $record.DateDeleted
                        'Status' = "Share"
                    }
                }
            }
        }
    }
    else {
        foreach ($folder in $SharedFolders.Folders.Values) {
            $folderName = Get-FolderName -Folder $folder -FolderUid $folder.FolderUidString
            $folderRecords = $SharedFolders.Records.Values | Where-Object { $_.FolderUid -eq $folder.FolderUidString }
            $recordCount = $folderRecords.Count
            
            $folderNameMatches = -not $Pattern -or $folderName -match $TitlePattern
            
            $hasMatchingRecords = $false
            if ($Pattern) {
                foreach ($record in $folderRecords) {
                    $recordTitle = Get-RecordTitle -Record $record
                    if ($recordTitle -match $TitlePattern) {
                        $hasMatchingRecords = $true
                        break
                    }
                }
            }
            else {
                $hasMatchingRecords = $true 
            }
            
            $showFolder = $folderNameMatches -or $hasMatchingRecords
            
            if ($showFolder) {
                $results += [PSCustomObject]@{
                    'Folder UID' = $folder.FolderUidString
                    'Record UID' = ""
                    'Name' = "$folderName ($recordCount records)"
                    'Record Type' = "Shared Folder"
                    'Deleted At' = $null
                    'Status' = "Folder"
                }
            }
        }
    }

    return $results
}

function Get-RecordTitle {
    param($Record)
    
    if ($Record.DataUnencrypted) {
        try {
            $jsonString = [System.Text.Encoding]::UTF8.GetString($Record.DataUnencrypted)
            $jsonObject = $jsonString | ConvertFrom-Json
            return if ($jsonObject.title) { $jsonObject.title } else { "" }
        }
        catch {
            return "Parse Error"
        }
    }
    return ""
}

function Get-RecordType {
    param($Record)
    
    if ($Record.DataUnencrypted) {
        try {
            $jsonString = [System.Text.Encoding]::UTF8.GetString($Record.DataUnencrypted)
            $jsonObject = $jsonString | ConvertFrom-Json
            return if ($jsonObject.type) { $jsonObject.type } else { "" }
        }
        catch {
            return "Unknown"
        }
    }
    return ""
}

function Get-FolderName {
    param(
        $Folder,
        [string]$FolderUid
    )
    
    try {
        if ($Folder.DataUnEncrypted -and $Folder.DataUnEncrypted.Length -gt 0) {
            $jsonString = [System.Text.Encoding]::UTF8.GetString($Folder.DataUnEncrypted)
            $jsonObject = $jsonString | ConvertFrom-Json
            if ($jsonObject.name) { 
                return $jsonObject.name 
            } else { 
                return $FolderUid 
            }
        }
        return $FolderUid
    }
    catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Verbose "Error parsing folder data: $($_.Exception.Message)"
        }
        return $FolderUid
    }
}

function Get-DeletedDate {
    param([long]$Timestamp)
    
    if ($Timestamp -le 0) {
        return $null
    }
    
    try {
        $timestampSeconds = $Timestamp / 1000
        
        if ($timestampSeconds -lt 0 -or $timestampSeconds -gt 4102444800) {
            return $null
        }
        
        return [DateTimeOffset]::FromUnixTimeSeconds($timestampSeconds).DateTime
    }
    catch {
        return $null
    }
}


Set-Alias -Name ktrash -Value Get-KeeperTrashList
