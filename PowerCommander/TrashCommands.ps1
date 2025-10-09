#requires -Version 5.1

$script:MAX_TIMESTAMP = 4102444800  
$script:STRING_LENGTH_LIMIT = 100
$script:MAX_RECORDS_LIMIT = 10000

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
        [ValidateLength(0, 100)]
        [string]$Pattern        
    )

    Write-Verbose "Starting trash list operation with pattern: '$Pattern'"
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if (-not $vault) {
        Write-Error "Failed to get vault instance"
        return
    }

    try {
        $loadTask = [KeeperSecurity.Vault.TrashManagement]::EnsureDeletedRecordsLoaded($vault)
        $loadTask.Wait()
        if ($loadTask.Exception) {
            throw $loadTask.Exception
        }
    }
    catch {
        Write-Error "Failed to load deleted records: $($_.Exception.Message)"
        return
    }

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

    $recordResults = @(
        Get-RecordTableData -Records $deletedRecords -IsShared $false -Pattern $normalizedPattern -TitlePattern $titlePattern
        Get-RecordTableData -Records $orphanedRecords -IsShared $true -Pattern $normalizedPattern -TitlePattern $titlePattern
    )
    $folderResults = Get-FolderTableData -SharedFolders $sharedFolders -Pattern $normalizedPattern -TitlePattern $titlePattern
    
    $recordResults = $recordResults | Sort-Object @{Expression={if ($_.'Deleted At') { $_.'Deleted At' } else { [DateTime]::MinValue }}; Descending=$true}, Name
    $folderResults = $folderResults | Sort-Object @{Expression={if ($_.'Deleted At') { $_.'Deleted At' } else { [DateTime]::MinValue }}; Descending=$true}, Name
    
    $results = $recordResults + $folderResults

    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host "No records found matching the specified criteria"
    }
}

function Get-RecordTableData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Records,
        [Parameter(Mandatory = $true)]
        [bool]$IsShared,
        [string]$Pattern,
        [regex]$TitlePattern
    )

    if (-not $Records -or -not $Records.Values) {
        Write-Warning "No records provided or records collection is empty"
        return @()
    }

    $results = @()

    foreach ($record in $Records.Values) {
        if (-not $record) {
            Write-Warning "Null record found, skipping"
            continue
        }

        $recordTitle = ""
        $recordType = ""
        
        if ($record.DataUnencrypted) {
            try {
                $jsonString = [System.Text.Encoding]::UTF8.GetString($record.DataUnencrypted)
                $jsonObject = $jsonString | ConvertFrom-Json
                $recordTitle = if ($jsonObject.title) { $jsonObject.title } else { "" }
                $recordType = if ($jsonObject.type) { $jsonObject.type } else { "" }
            }
            catch [System.Text.DecoderFallbackException] {
                Write-Warning "Invalid encoding in record $($record.RecordUid): $($_.Exception.Message)"
                $recordTitle = "Parse Error"
                $recordType = "Unknown"
            }
            catch [System.ArgumentException] {
                Write-Warning "Invalid JSON data in record $($record.RecordUid): $($_.Exception.Message)"
                $recordTitle = "Parse Error"
                $recordType = "Unknown"
            }
            catch {
                Write-Warning "Unexpected error parsing record $($record.RecordUid): $($_.Exception.Message)"
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $SharedFolders,
        [string]$Pattern,
        [regex]$TitlePattern
    )

    $results = @()

    if (-not $SharedFolders -or -not $SharedFolders.Folders -or -not $SharedFolders.Records) {
        return $results
    }

    if ($VerbosePreference -eq 'Continue') {
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
    catch [System.Text.DecoderFallbackException] {
        if ($VerbosePreference -eq 'Continue') {
            Write-Verbose "Invalid encoding in folder $($FolderUid): $($_.Exception.Message)"
        }
        return $FolderUid
    }
    catch [System.ArgumentException] {
        if ($VerbosePreference -eq 'Continue') {
            Write-Verbose "Invalid JSON data in folder $($FolderUid): $($_.Exception.Message)"
        }
        return $FolderUid
    }
    catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Verbose "Unexpected error parsing folder data for $($FolderUid): $($_.Exception.Message)"
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
        
        if ($timestampSeconds -lt 0 -or $timestampSeconds -gt $script:MAX_TIMESTAMP) {
            return $null
        }
        
        return [DateTimeOffset]::FromUnixTimeSeconds($timestampSeconds).DateTime
    }
    catch {
        return $null
    }
}


function Restore-KeeperTrashRecords {
    <#
    .SYNOPSIS
    Restores deleted records from trash

    .DESCRIPTION
    Restores deleted records, orphaned records, and shared folders from the trash.
    Supports restoring by record UID or pattern matching.

    .PARAMETER Records
    Array of record UIDs or patterns to restore. Supports wildcards (* and ?).

    .PARAMETER Force
    Skip confirmation prompts and restore immediately.

    .EXAMPLE
    Restore-KeeperTrashRecords -Records "NyTgDxKnMRhcgpR_BGkFkw"
    Restores a specific record by UID

    .EXAMPLE
    Restore-KeeperTrashRecords -Records "test*", "MyRecord"
    Restores records matching "test*" pattern and a specific record

    .EXAMPLE
    Restore-KeeperTrashRecords -Records "test*" -Force
    Restores records matching "test*" pattern without confirmation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateCount(1, 10000)]
        [ValidateLength(1, 100)]
        [string[]]$Records,
        
        [Parameter()]
        [switch]$Force
    )

    Write-Verbose "Starting trash restore operation with $($Records.Count) record(s)"
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if (-not $vault) {
        Write-Error "Failed to get vault instance"
        return
    }

    $validationResult = Test-RecordParameters -Records $Records
    if (-not $validationResult.IsValid) {
        Write-Error $validationResult.ErrorMessage
        return
    }

    if ($validationResult.ValidRecords.Count -eq 0) {
        Write-Host "No valid records specified for restoration"
        return
    }

    try {
        $restoreTask = [KeeperSecurity.Vault.TrashManagement]::RestoreTrashRecords($vault, $validationResult.ValidRecords)
        $restoreTask.Wait()
        if ($restoreTask.Exception) {
            throw $restoreTask.Exception
        }
        Write-Host "Successfully initiated restoration of $($validationResult.ValidRecords.Count) record(s)"
        Write-Host "Use 'Get-KeeperTrashList' to verify the restoration"
    }
    catch {
        Write-Error "Failed to restore records: $($_.Exception.Message)"
    }
}

function Test-RecordParameters {
    <#
    .SYNOPSIS
    Validates record parameters for trash operations
    
    .PARAMETER Records
    Array of record identifiers to validate
    
    .OUTPUTS
    PSCustomObject with IsValid, ErrorMessage, and ValidRecords properties
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Records
    )
    
    $validatedRecords = @()
    $errors = @()
    
    if ($Records.Count -gt $script:MAX_RECORDS_LIMIT) {
        return [PSCustomObject]@{
            IsValid = $false
            ErrorMessage = "Too many records specified (max: $script:MAX_RECORDS_LIMIT)"
            ValidRecords = @()
        }
    }
    
    for ($i = 0; $i -lt $Records.Count; $i++) {
        $record = $Records[$i]
        
        if ([string]::IsNullOrWhiteSpace($record)) {
            $errors += "Record $($i + 1) must not be empty or whitespace"
            continue
        }
        
        if ($record.Length -gt $script:STRING_LENGTH_LIMIT) {
            $errors += "Record $($i + 1) exceeds maximum length ($script:STRING_LENGTH_LIMIT characters)"
            continue
        }
        
        $validatedRecords += $record.Trim()
    }
    
    return [PSCustomObject]@{
        IsValid = $validatedRecords.Count -gt 0
        ErrorMessage = if ($errors.Count -gt 0) { $errors -join "; " } else { $null }
        ValidRecords = $validatedRecords
    }
}

Set-Alias -Name ktrash -Value Get-KeeperTrashList
Set-Alias -Name ktrash-restore -Value Restore-KeeperTrashRecords
