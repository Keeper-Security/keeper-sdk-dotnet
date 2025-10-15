#requires -Version 5.1

$script:MAX_TIMESTAMP = 4102444800  
$script:STRING_LENGTH_LIMIT = 100
$script:MAX_RECORDS_LIMIT = 990
$script:FIELD_LABEL_WIDTH = 21
$script:STATUS_SUCCESS = "success"

$script:RECORD_VERSION_LEGACY_MIN = 0
$script:RECORD_VERSION_LEGACY_MAX = 2
$script:RECORD_VERSION_V3 = 3
$script:RECORD_VERSION_V4 = 4
$script:RECORD_VERSION_V5 = 5
$script:RECORD_VERSION_V6 = 6

function Get-VaultOrThrow {
    # Internal: Gets vault instance or throws error
    $vault = getVault
    if ($null -eq $vault) {
        throw "Failed to get vault instance"
    }
    return $vault
}

function Invoke-TaskAndWait {
    # Internal: Waits for task completion and properly unwraps exceptions
    param([System.Threading.Tasks.Task]$Task)
    
    $Task.Wait()
    if ($Task.IsFaulted) {
        if ($Task.Exception.InnerExceptions.Count -eq 1) {
            throw $Task.Exception.InnerException
        }
        throw $Task.Exception
    }
}

function Get-RecordMetadata {
    # Internal: Parses record title and type from decrypted data
    param([byte[]]$DataUnencrypted)
    
    if ($null -eq $DataUnencrypted -or $DataUnencrypted.Length -eq 0) {
        return @{ Title = ""; Type = "" }
    }
    
    try {
        $jsonString = [System.Text.Encoding]::UTF8.GetString($DataUnencrypted)
        $json = $jsonString | ConvertFrom-Json
        return @{
            Title = if ($json.title) { $json.title } else { "" }
            Type = if ($json.type) { $json.type } else { "" }
        }
    }
    catch {
        Write-Verbose "Failed to parse record metadata: $($_.Exception.Message)"
        return @{ Title = "Parse Error"; Type = "Unknown" }
    }
}

function New-WildcardRegex {
    # Internal: Creates regex from wildcard pattern with timeout protection
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        
        [int]$MaxLength = $script:STRING_LENGTH_LIMIT,
        
        [int]$TimeoutSeconds = 1
    )
    
    if ($Pattern.Length -gt $MaxLength) {
        Write-Warning "Pattern too long, truncated to $MaxLength characters"
        $Pattern = $Pattern.Substring(0, $MaxLength)
    }
    
    try {
        $escaped = [regex]::Escape($Pattern) -replace "\\\*", ".*" -replace "\\\?", "."
        $regexPattern = "^$escaped$"
        return [regex]::new(
            $regexPattern, 
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
            [TimeSpan]::FromSeconds($TimeoutSeconds)
        )
    }
    catch {
        Write-Warning "Invalid pattern '$Pattern': $($_.Exception.Message)"
        return $null
    }
}

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

    .OUTPUTS
    None. Displays formatted table output to console.

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
    [OutputType([void])]
    param(
        [Parameter(Position = 0)]
        [ValidateLength(0, 100)]
        [string]$Pattern        
    )

    Write-Verbose "Starting trash list operation with pattern: '$Pattern'"
    
    try {
        $vault = Get-VaultOrThrow
        $loadTask = [KeeperSecurity.Vault.TrashManagement]::EnsureDeletedRecordsLoaded($vault)
        Invoke-TaskAndWait -Task $loadTask
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

    $normalizedPattern = if ($Pattern -eq "*") { $null } elseif ($Pattern) { $Pattern.ToLower() } else { $null }
    $titlePattern = if ($normalizedPattern) { New-WildcardRegex -Pattern $normalizedPattern } else { $null }

    $recordResults = @(
        Get-RecordTableData -Records $deletedRecords -IsShared $false -Pattern $normalizedPattern -TitlePattern $titlePattern
        Get-RecordTableData -Records $orphanedRecords -IsShared $true -Pattern $normalizedPattern -TitlePattern $titlePattern
    )
    $folderResults = @(Get-FolderTableData -SharedFolders $sharedFolders -Pattern $normalizedPattern -TitlePattern $titlePattern)
    
    $recordResults = @($recordResults | Sort-Object @{Expression={if ($_.'Deleted At') { $_.'Deleted At' } else { [DateTime]::MinValue }}; Descending=$true}, Name)
    $folderResults = @($folderResults | Sort-Object @{Expression={if ($_.'Deleted At') { $_.'Deleted At' } else { [DateTime]::MinValue }}; Descending=$true}, Name)
    
    $results = @($recordResults) + @($folderResults)

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

    if ($null -eq $Records -or $null -eq $Records.Values) {
        Write-Warning "No records provided or records collection is empty"
        return @()
    }

    $results = @()

    foreach ($record in $Records.Values) {
        if ($null -eq $record) {
            Write-Warning "Null record found, skipping"
            continue
        }

        $metadata = Get-RecordMetadata -DataUnencrypted $record.DataUnencrypted
        
        if ($null -ne $Pattern -and $null -ne $TitlePattern -and $metadata.Title -notmatch $TitlePattern) {
            continue
        }

        $status = if ($IsShared) { "Share" } else { "Record" }
        $dateDeleted = if (-not $IsShared) { Get-DeletedDate -Timestamp $record.DateDeleted } else { $null }

        $results += [PSCustomObject]@{
            'Folder UID' = ""
            'Record UID' = $record.RecordUid
            'Name' = $metadata.Title
            'Record Type' = $metadata.Type
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

    foreach ($folder in $SharedFolders.Folders.Values) {
        $folderName = Get-FolderName -Folder $folder -FolderUid $folder.FolderUidString
        $folderRecords = $SharedFolders.Records.Values | Where-Object { $_.FolderUid -eq $folder.FolderUidString }
        
        $folderMatches = Test-FolderMatchesPattern -FolderName $folderName -FolderRecords $folderRecords -Pattern $Pattern -TitlePattern $TitlePattern
        
        if ($folderMatches) {
            if ($VerbosePreference -eq 'Continue') {
                $results += [PSCustomObject]@{
                    'Folder UID' = $folder.FolderUidString
                    'Record UID' = ""
                    'Name' = $folderName
                    'Record Type' = "Shared Folder"
                    'Deleted At' = $null
                    'Status' = "Folder"
                }
                
                foreach ($record in $folderRecords) {
                    $metadata = Get-RecordMetadata -DataUnencrypted $record.DataUnencrypted
                    $recordMatches = $null -eq $Pattern -or $metadata.Title -match $TitlePattern
                    
                    if ($recordMatches) {
                        $results += [PSCustomObject]@{
                            'Folder UID' = $folder.FolderUidString
                            'Record UID' = $record.RecordUid
                            'Name' = $metadata.Title
                            'Record Type' = $metadata.Type
                            'Deleted At' = Get-DeletedDate -Timestamp $record.DateDeleted
                            'Status' = "Share"
                        }
                    }
                }
            }
            else {
                $recordCount = $folderRecords.Count
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

function Test-FolderMatchesPattern {
    # Internal: Tests if folder name or any record matches the search pattern
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderName,
        
        [Parameter(Mandatory = $true)]
        $FolderRecords,
        
        [string]$Pattern,
        [regex]$TitlePattern
    )
    
    if ([string]::IsNullOrEmpty($Pattern)) {
        return $true
    }
    
    if ($FolderName -match $TitlePattern) {
        return $true
    }
    
    foreach ($record in $FolderRecords) {
        $metadata = Get-RecordMetadata -DataUnencrypted $record.DataUnencrypted
        if ($metadata.Title -match $TitlePattern) {
            return $true
        }
    }
    
    return $false
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
        Write-Verbose "Invalid encoding in folder $($FolderUid): $($_.Exception.Message)"
        return $FolderUid
    }
    catch [System.ArgumentException] {
        Write-Verbose "Invalid JSON data in folder $($FolderUid): $($_.Exception.Message)"
        return $FolderUid
    }
    catch {
        Write-Verbose "Unexpected error parsing folder data for $($FolderUid): $($_.Exception.Message)"
        return $FolderUid
    }
}

function ConvertFrom-UnixTimestamp {
    # Internal: Converts Unix timestamp (seconds or milliseconds) to DateTime
    [CmdletBinding()]
    [OutputType([DateTime])]
    param(
        [Parameter(Mandatory = $true)]
        [long]$Timestamp,
        
        [switch]$AsMilliseconds
    )
    
    if ($Timestamp -le 0) {
        return $null
    }
    
    try {
        $isMilliseconds = $AsMilliseconds -or $Timestamp -gt 9999999999
        
        if ($isMilliseconds) {
            $seconds = $Timestamp / 1000
            if ($seconds -lt 0 -or $seconds -gt $script:MAX_TIMESTAMP) {
                return $null
            }
            return [DateTimeOffset]::FromUnixTimeMilliseconds($Timestamp).DateTime
        }
        else {
            if ($Timestamp -lt 0 -or $Timestamp -gt $script:MAX_TIMESTAMP) {
                return $null
            }
            return [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).DateTime
        }
    }
    catch {
        Write-Verbose "Failed to convert timestamp $Timestamp`: $($_.Exception.Message)"
        return $null
    }
}

function Get-DeletedDate {
    param([long]$Timestamp)
    
    if ($Timestamp -le 0) {
        return $null
    }
    
    return ConvertFrom-UnixTimestamp -Timestamp $Timestamp -AsMilliseconds
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

    .OUTPUTS
    None. Displays status messages to console.

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
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateCount(1, 10000)]
        [ValidateLength(1, 100)]
        [string[]]$Records,
        
        [Parameter()]
        [switch]$Force
    )

    Write-Verbose "Starting trash restore operation with $($Records.Count) record(s)"
    
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
        $vault = Get-VaultOrThrow
        $restoreTask = [KeeperSecurity.Vault.TrashManagement]::RestoreTrashRecords($vault, $validationResult.ValidRecords)
        Invoke-TaskAndWait -Task $restoreTask
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
            $errors += "Record $($record) at index $($i + 1) must not be empty or whitespace"
            continue
        }
        
        if ($record.Length -gt $script:STRING_LENGTH_LIMIT) {
            $errors += "Record $($record) at index $($i + 1) exceeds maximum length ($script:STRING_LENGTH_LIMIT characters)"
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
function Remove-TrashedKeeperRecordShares {
    <#
    .SYNOPSIS
    Removes shares from deleted records in trash

    .DESCRIPTION
    Removes all non-owner shares from orphaned records in the trash.
    This is useful for cleaning up shared records before permanently deleting them.

    .PARAMETER Records
    Array of record UIDs or patterns to unshare. Supports wildcards (* and ?).
    Use "*" to process all orphaned records.

    .PARAMETER Force
    Skip confirmation prompts and remove shares immediately.

    .OUTPUTS
    None. Displays status messages to console.

    .EXAMPLE
    Remove-TrashedKeeperRecordShares -Records "NyTgDxKnMRhcgpR_BGkFkw"
    Removes shares from a specific orphaned record by UID

    .EXAMPLE
    Remove-TrashedKeeperRecordShares -Records "test*", "MyRecord"
    Removes shares from records matching "test*" pattern and a specific record

    .EXAMPLE
    Remove-TrashedKeeperRecordShares -Records "*" -Force
    Removes shares from all orphaned records without confirmation
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateCount(1, 10000)]
        [ValidateLength(1, 100)]
        [string[]]$Records,
        
        [Parameter()]
        [switch]$Force
    )

    Write-Verbose "Starting trash unshare operation with $($Records.Count) record(s)"
    
    $validationResult = Test-RecordParameters -Records $Records
    if (-not $validationResult.IsValid) {
        Write-Error $validationResult.ErrorMessage
        return
    }

    if ($validationResult.ValidRecords.Count -eq 0) {
        Write-Host "No valid records specified"
        return
    }

    try {
        $vault = Get-VaultOrThrow
        $loadTask = [KeeperSecurity.Vault.TrashManagement]::EnsureDeletedRecordsLoaded($vault)
        Invoke-TaskAndWait -Task $loadTask
    }
    catch {
        Write-Error "Failed to load deleted records: $($_.Exception.Message)"
        return
    }

    $orphanedRecords = [KeeperSecurity.Vault.TrashManagement]::GetOrphanedRecords()
    
    if ($null -eq $orphanedRecords -or $orphanedRecords.Count -eq 0) {
        Write-Host "Trash is empty"
        return
    }

    $recordsToUnshare = Find-RecordsToUnshare -RecordPatterns $validationResult.ValidRecords -OrphanedRecords $orphanedRecords
    
    if ($recordsToUnshare.Count -eq 0) {
        Write-Host "There are no records to unshare"
        return
    }

    if (-not (Confirm-UnshareOperation -Force:$Force -RecordCount $recordsToUnshare.Count)) {
        Write-Host "Operation cancelled by user"
        return
    }

    Remove-SharesFromRecords -RecordsToUnshare $recordsToUnshare
}
function Find-RecordsToUnshare {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RecordPatterns,
        
        [Parameter(Mandatory = $true)]
        $OrphanedRecords
    )

    $recordsToUnshare = New-Object System.Collections.Generic.HashSet[string]

    foreach ($pattern in $RecordPatterns) {
        if ($OrphanedRecords.ContainsKey($pattern)) {
            [void]$recordsToUnshare.Add($pattern)
        }
        else {
            Add-MatchingRecords -Pattern $pattern -OrphanedRecords $OrphanedRecords -RecordsToUnshare $recordsToUnshare
        }
    }

    return @($recordsToUnshare)
}
function Add-MatchingRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Pattern,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $OrphanedRecords,
        
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$RecordsToUnshare
    )

    if ($null -eq $RecordsToUnshare) {
        Write-Warning "RecordsToUnshare collection is null"
        return
    }

    $titlePattern = New-WildcardRegex -Pattern $Pattern
    if ($null -eq $titlePattern) {
        return
    }

    foreach ($kvp in $OrphanedRecords.GetEnumerator()) {
        $recordUid = $kvp.Key
        $record = $kvp.Value

        if ($RecordsToUnshare.Contains($recordUid)) {
            continue
        }

        $metadata = Get-RecordMetadata -DataUnencrypted $record.DataUnencrypted
        if (-not [string]::IsNullOrEmpty($metadata.Title) -and $titlePattern.IsMatch($metadata.Title)) {
            [void]$RecordsToUnshare.Add($recordUid)
        }
    }
}

function Confirm-UnshareOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [switch]$Force,
        
        [Parameter(Mandatory = $true)]
        [int]$RecordCount
    )

    if ($Force) {
        return $true
    }

    $confirmation = Read-Host "Do you want to remove shares from $RecordCount record(s)? (yes/No)"
    return ($confirmation -match '^(y|yes)$')
}

function Remove-SharesFromRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RecordsToUnshare
    )

    try {
        $vault = Get-VaultOrThrow
        $recordSharesTask = $vault.GetSharesForRecords($RecordsToUnshare)
        Invoke-TaskAndWait -Task $recordSharesTask
        
        $recordShares = $recordSharesTask.Result
        if ($null -eq $recordShares) {
            Write-Verbose "No shares found for the specified records"
            return
        }

        $removeShareRequests = Build-RemoveShareRequests -RecordShares $recordShares
        if ($removeShareRequests.Count -eq 0) {
            Write-Verbose "No share removal requests to process"
            return
        }

        Invoke-ShareRemovalRequests -RemoveRequests $removeShareRequests
    }
    catch {
        Write-Error "Error getting record shares: $($_.Exception.Message)"
    }
}

function Build-RemoveShareRequests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $RecordShares
    )

    $removeRequests = New-Object System.Collections.Generic.List[Records.SharedRecord]

    foreach ($recordShare in $recordShares) {
        if (-not $recordShare.UserPermissions) {
            continue
        }

        foreach ($userPermission in $recordShare.UserPermissions) {
            if (-not $userPermission.Owner) {
                $shareRequest = New-Object Records.SharedRecord
                $shareRequest.ToUsername = $userPermission.Username
                $shareRequest.RecordUid = [Google.Protobuf.ByteString]::CopyFrom(
                    [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($recordShare.RecordUid)
                )
                $removeRequests.Add($shareRequest)
            }
        }
    }

    return $removeRequests
}

function Invoke-ShareRemovalRequests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[Records.SharedRecord]]$RemoveRequests
    )

    $chunkSize = 100
    $processedCount = 0
    
    for ($i = 0; $i -lt $RemoveRequests.Count; $i += $chunkSize) {
        $remainingCount = $RemoveRequests.Count - $i
        $currentChunkSize = [Math]::Min($chunkSize, $remainingCount)
        $chunk = $RemoveRequests.GetRange($i, $currentChunkSize)
        
        Invoke-ShareRemovalChunk -Chunk $chunk
        $processedCount += $chunk.Count
        Write-Verbose "Processed $processedCount of $($RemoveRequests.Count) share removal requests"
    }
    
    Write-Host "Successfully removed shares from $processedCount record(s)"
}

function Invoke-ShareRemovalChunk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Chunk
    )

    try {
        $vault = Get-VaultOrThrow
        $updateRequest = New-Object Records.RecordShareUpdateRequest
        $updateRequest.RemoveSharedRecord.AddRange($Chunk)

        $responseTask = $vault.Auth.ExecuteAuthRest(
            "vault/records_share_update", 
            $updateRequest, 
            [Records.RecordShareUpdateResponse]
        )
        $response = $responseTask.GetAwaiter().GetResult() -as [Records.RecordShareUpdateResponse]
        
        Write-ShareRemovalErrors -Response $response
    }
    catch {
        Write-Error "Error removing shares: $($_.Exception.Message)"
        throw
    }
}

function Write-ShareRemovalErrors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Response
    )

    foreach ($status in $Response.RemoveSharedRecordStatus) {
        if ($status.Status -ne $script:STATUS_SUCCESS) {
            $recordUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($status.RecordUid.ToByteArray())
            Write-Warning "Remove share '$($status.Username)' from record UID '$recordUid' error: $($status.Message)"
        }
    }
}

function Get-KeeperTrashedRecordDetails {
    <#
    .SYNOPSIS
    Gets detailed information about a deleted record in trash

    .DESCRIPTION
    Displays detailed information about a specific deleted record including all fields,
    custom fields, and share information if the record is shared.

    .PARAMETER RecordUid
    The unique identifier (UID) of the deleted record to retrieve

    .OUTPUTS
    None. Displays formatted record details to console.

    .EXAMPLE
    Get-KeeperTrashedRecordDetails -RecordUid "QGMaKCr9ksOOkhIMSvIWtg"
    Displays detailed information about the specified deleted record

    .EXAMPLE
    Get-KeeperTrashedRecordDetails "hlPKPNt9rsIqC_mCwwfP5A"
    Displays details using positional parameter
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(16, 64)]
        [ValidatePattern('^[A-Za-z0-9_-]+$')]
        [string]$RecordUid
    )

    Write-Verbose "Retrieving details for record: $RecordUid"
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if ($null -eq $vault) {
        Write-Error "Failed to get vault instance"
        return
    }

    try {
        $loadTask = [KeeperSecurity.Vault.TrashManagement]::EnsureDeletedRecordsLoaded($vault)
        Invoke-TaskAndWait -Task $loadTask
    }
    catch {
        Write-Error "Failed to load deleted records: $($_.Exception.Message)"
        return
    }

    $deletedRecords = [KeeperSecurity.Vault.TrashManagement]::GetDeletedRecords()
    $orphanedRecords = [KeeperSecurity.Vault.TrashManagement]::GetOrphanedRecords()

    $record = $null
    $isShared = $false

    if ($deletedRecords.ContainsKey($RecordUid)) {
        $record = $deletedRecords[$RecordUid]
        $isShared = $false
    }
    elseif ($orphanedRecords.ContainsKey($RecordUid)) {
        $record = $orphanedRecords[$RecordUid]
        $isShared = $true
    }
    else {
        Write-Error "$RecordUid is not a valid deleted record UID"
        return
    }

    if ($null -eq $record.RecordKeyUnencrypted) {
        Write-Error "Cannot retrieve record $RecordUid`: no decryption key available"
        return
    }

    try {
        $recordData = ConvertTo-ParsedRecord -DeletedRecord $record
        if (-not $recordData) {
            Write-Error "Cannot parse record $RecordUid"
            return
        }

        Show-RecordDetails -RecordData $recordData

        if ($isShared) {
            Show-RecordShares -Vault $vault -RecordUid $RecordUid
        }
    }
    catch {
        Write-Error "Error displaying record details: $($_.Exception.Message)"
        Write-Verbose $_.Exception.ToString()
    }
}

function Get-DecryptedRecordData {
    # Internal: Decrypts record data using appropriate AES version
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $DeletedRecord
    )
    
    if ($null -ne $DeletedRecord.DataUnencrypted) {
        return $DeletedRecord.DataUnencrypted
    }
    
    $encryptedData = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($DeletedRecord.Data)
    
    if ($DeletedRecord.Version -ge $script:RECORD_VERSION_V3) {
        return [KeeperSecurity.Utils.CryptoUtils]::DecryptAesV2($encryptedData, $DeletedRecord.RecordKeyUnencrypted)
    }
    else {
        return [KeeperSecurity.Utils.CryptoUtils]::DecryptAesV1($encryptedData, $DeletedRecord.RecordKeyUnencrypted)
    }
}

function ConvertTo-LegacyPasswordRecord {
    # Internal: Converts decrypted data (v0-2) to PasswordRecord
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.PasswordRecord])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$DecryptedData,
        
        [Parameter(Mandatory = $true)]
        $DeletedRecord
    )
    
    $recordData = [KeeperSecurity.Utils.JsonUtils]::ParseJson([KeeperSecurity.Commands.RecordData], $DecryptedData)
    
    $passwordRecord = New-Object KeeperSecurity.Vault.PasswordRecord
    $passwordRecord.Uid = $DeletedRecord.RecordUid
    $passwordRecord.Version = $DeletedRecord.Version
    $passwordRecord.Title = $recordData.Title
    $passwordRecord.Login = $recordData.Secret1
    $passwordRecord.Password = $recordData.Secret2
    $passwordRecord.Link = $recordData.Link
    $passwordRecord.Notes = $recordData.Notes
    
    if ($recordData.Custom) {
        foreach ($cr in $recordData.Custom) {
            if ($cr) {
                $customField = New-Object KeeperSecurity.Vault.CustomField
                $customField.Name = $cr.Name
                $customField.Value = $cr.Value
                $customField.Type = $cr.Type
                $passwordRecord.Custom.Add($customField)
            }
        }
    }
    
    return $passwordRecord
}

function ConvertTo-ModernTypedRecord {
    # Internal: Converts decrypted JSON data (v3-6) to TypedRecord
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.TypedRecord])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$DecryptedData,
        
        [Parameter(Mandatory = $true)]
        $DeletedRecord
    )
    
    $jsonString = [System.Text.Encoding]::UTF8.GetString($DecryptedData)
    $jsonData = $jsonString | ConvertFrom-Json
    
    $recordType = if ($jsonData.type) { $jsonData.type } else { "login" }
    $typedRecord = New-Object KeeperSecurity.Vault.TypedRecord($recordType)
    $typedRecord.Uid = $DeletedRecord.RecordUid
    $typedRecord.Version = $DeletedRecord.Version
    $typedRecord.Title = if ($jsonData.title) { $jsonData.title } else { "" }
    $typedRecord.Notes = if ($jsonData.notes) { $jsonData.notes } else { "" }
    
    if ($jsonData.fields) {
        foreach ($fieldData in $jsonData.fields) {
            $field = ConvertTo-TypedField -FieldData $fieldData
            if ($field) {
                $typedRecord.Fields.Add($field)
            }
        }
    }
    
    if ($jsonData.custom) {
        foreach ($fieldData in $jsonData.custom) {
            $field = ConvertTo-TypedField -FieldData $fieldData
            if ($field) {
                $typedRecord.Custom.Add($field)
            }
        }
    }
    
    return $typedRecord
}

function ConvertTo-ParsedRecord {
    # Internal: Decrypts and parses DeletedRecord to TypedRecord (v3+) or PasswordRecord (v0-2)
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.TypedRecord], [KeeperSecurity.Vault.PasswordRecord])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $DeletedRecord
    )

    try {
        Write-Verbose "Parsing record $($DeletedRecord.RecordUid) (Version $($DeletedRecord.Version))"
        
        $decryptedData = Get-DecryptedRecordData -DeletedRecord $DeletedRecord
        
        if ($null -eq $decryptedData) {
            Write-Error "Failed to decrypt record $($DeletedRecord.RecordUid). The record key may be invalid."
            return $null
        }

        if ($DeletedRecord.Version -ge $script:RECORD_VERSION_LEGACY_MIN -and $DeletedRecord.Version -le $script:RECORD_VERSION_LEGACY_MAX) {
            return ConvertTo-LegacyPasswordRecord -DecryptedData $decryptedData -DeletedRecord $DeletedRecord
        }
        elseif ($DeletedRecord.Version -in $script:RECORD_VERSION_V3, $script:RECORD_VERSION_V4, $script:RECORD_VERSION_V5, $script:RECORD_VERSION_V6) {
            return ConvertTo-ModernTypedRecord -DecryptedData $decryptedData -DeletedRecord $DeletedRecord
        }
        else {
            Write-Error "Unsupported record version $($DeletedRecord.Version) for record $($DeletedRecord.RecordUid)"
            return $null
        }
    }
    catch {
        Write-Error "Error parsing record $($DeletedRecord.RecordUid) (Version $($DeletedRecord.Version)): $($_.Exception.Message)"
        Write-Verbose $_.Exception.ToString()
        return $null
    }
}

function ConvertTo-TypedField {
    # Internal: Converts JSON field data to TypedField with proper value formatting
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $FieldData
    )

    try {
        $fieldType = if ($FieldData.type) { $FieldData.type } else { "text" }
        $label = if ($FieldData.label) { $FieldData.label } else { $null }
        
        Write-Verbose "Converting field type='$fieldType' label='$label'"
        
        $field = New-Object "KeeperSecurity.Vault.TypedField[object]"($fieldType, $label)
        
        if ($null -ne $FieldData.value) {
            if ($FieldData.value -is [array]) {
                foreach ($val in $FieldData.value) {
                    if ($null -ne $val) {
                        $convertedValue = ConvertTo-FieldValue -Value $val -FieldType $fieldType
                        $field.Values.Add($convertedValue)
                    }
                }
            }
            else {
                $convertedValue = ConvertTo-FieldValue -Value $FieldData.value -FieldType $fieldType
                $field.Values.Add($convertedValue)
            }
        }
        
        return $field
    }
    catch {
        Write-Verbose "Error converting field '$fieldType': $($_.Exception.Message)"
        Write-Verbose $_.Exception.ToString()
        return $null
    }
}

function ConvertTo-NameFieldValue {
    # Internal: Formats name field with first, middle, last components
    param([PSCustomObject]$Value)
    
    $parts = @()
    if ($Value.first) { $parts += $Value.first }
    if ($Value.middle) { $parts += $Value.middle }
    if ($Value.last) { $parts += $Value.last }
    
    if ($parts.Count -gt 0) {
        return ($parts -join ' ')
    }
    return $null
}

function ConvertTo-AddressFieldValue {
    # Internal: Formats address field with street, city, state, zip, country components
    param([PSCustomObject]$Value)
    
    $parts = @()
    if ($Value.street1) { $parts += $Value.street1 }
    if ($Value.street2) { $parts += $Value.street2 }
    if ($Value.city) { $parts += $Value.city }
    if ($Value.state) { $parts += $Value.state }
    if ($Value.zip) { $parts += $Value.zip }
    if ($Value.country) { $parts += $Value.country }
    
    if ($parts.Count -gt 0) {
        return ($parts -join ', ')
    }
    return $null
}

function ConvertTo-PhoneFieldValue {
    # Internal: Formats phone field with number, extension, and type
    param([PSCustomObject]$Value)
    
    if ($Value.number) {
        $result = $Value.number
        if ($Value.ext) {
            $result += " ext. $($Value.ext)"
        }
        if ($Value.type) {
            $result += " ($($Value.type))"
        }
        return $result
    }
    return $null
}

function ConvertTo-DateFieldValue {
    # Internal: Formats date field from Unix timestamp
    param($Value)
    
    if ($Value -is [long] -or ($Value -match '^\d+$')) {
        try {
            $timestamp = [long]$Value
            $dateTime = ConvertFrom-UnixTimestamp -Timestamp $timestamp
            if ($null -ne $dateTime) {
                return $dateTime.ToString('yyyy-MM-dd')
            }
        }
        catch {
            Write-Warning "Failed to convert date value '$Value': $($_.Exception.Message)"
        }
    }
    return $Value
}

function ConvertTo-FieldValue {
    # Internal: Formats field values (dates, names, addresses, phones) to readable strings
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value,
        
        [Parameter(Mandatory = $true)]
        [string]$FieldType
    )

    if ($Value -is [PSCustomObject]) {
        $formatted = switch ($FieldType) {
            'name'    { ConvertTo-NameFieldValue -Value $Value }
            'address' { ConvertTo-AddressFieldValue -Value $Value }
            'phone'   { ConvertTo-PhoneFieldValue -Value $Value }
            default   { $null }
        }
        
        if ($null -ne $formatted) {
            return $formatted
        }
        
        return ($Value | ConvertTo-Json -Compress -Depth 10)
    }
    
    if ($FieldType -eq 'date') {
        return ConvertTo-DateFieldValue -Value $Value
    }
    
    return $Value
}

function Show-RecordDetails {
    # Internal: Formats and displays TypedRecord or PasswordRecord fields
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $RecordData
    )

    try {
        if ($RecordData -is [KeeperSecurity.Vault.TypedRecord]) {
            Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Title", $RecordData.Title)
            Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Type", $RecordData.TypeName)

            if ($RecordData.Fields.Count -gt 0) {
                foreach ($field in $RecordData.Fields) {
                    Show-RecordField -Field $field
                }
            }

            if ($RecordData.Custom.Count -gt 0) {
                foreach ($field in $RecordData.Custom) {
                    Show-RecordField -Field $field
                }
            }
        }
        elseif ($RecordData -is [KeeperSecurity.Vault.PasswordRecord]) {
            Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Title", $RecordData.Title)
            Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Type", [KeeperSecurity.Vault.VaultExtensions]::KeeperRecordType($RecordData))

            if (-not [string]::IsNullOrEmpty($RecordData.Login)) {
                Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Login", $RecordData.Login)
            }
            if (-not [string]::IsNullOrEmpty($RecordData.Password)) {
                Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Password", $RecordData.Password)
            }
            if (-not [string]::IsNullOrEmpty($RecordData.Link)) {
                Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "URL", $RecordData.Link)
            }
            if (-not [string]::IsNullOrEmpty($RecordData.Notes)) {
                Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f "Notes", $RecordData.Notes)
            }
            if ($RecordData.Custom.Count -gt 0) {
                foreach ($custom in $RecordData.Custom) {
                    if (-not [string]::IsNullOrEmpty($custom.Value)) {
                        $name = if (-not [string]::IsNullOrEmpty($custom.Name)) { $custom.Name } else { "Custom" }
                        Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f $name, $custom.Value)
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Error displaying record details: $($_.Exception.Message)"
        Write-Verbose $_.Exception.ToString()
    }
}

function Show-RecordField {
    # Internal: Displays field name and value(s), handling multi-value fields
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Field
    )

    try {
        $fieldName = if (-not [string]::IsNullOrEmpty($Field.FieldLabel)) { 
            $Field.FieldLabel 
        } 
        elseif (-not [string]::IsNullOrEmpty($Field.FieldName)) { 
            $Field.FieldName 
        }
        else {
            try {
                $name = [KeeperSecurity.Utils.RecordTypesUtils]::GetTypedFieldName($Field)
                if (-not [string]::IsNullOrEmpty($name)) {
                    $name
                }
                else {
                    Write-Verbose "Could not determine field name for field type $($Field.FieldName)"
                    "Unknown"
                }
            }
            catch {
                Write-Verbose "Could not get field name: $($_.Exception.Message)"
                "Unknown"
            }
        }

        $valueArray = @()
        
        if ($Field.Values.Count -gt 0) {
            $valueArray = @($Field.Values)
        }
        else {
            try {
                $values = [KeeperSecurity.Utils.RecordTypesUtils]::GetTypedFieldValues($Field)
                if ($null -ne $values) {
                    $valueArray = @($values)
                }
            }
            catch {
                Write-Verbose "Could not get typed field values for '$fieldName': $($_.Exception.Message)"
            }
        }

        for ($i = 0; $i -lt [Math]::Max($valueArray.Count, 1); $i++) {
            $value = if ($i -lt $valueArray.Count) { $valueArray[$i] } else { "" }
            if (-not [string]::IsNullOrEmpty($value)) {
                if ($i -eq 0) {
                    Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1}" -f $fieldName, $value)
                }
                else {
                    Write-Host ("{0,$script:FIELD_LABEL_WIDTH}  {1}" -f "", $value)
                }
            }
        }
    }
    catch {
        Write-Verbose "Error displaying field: $($_.Exception.Message)"
    }
}

function Show-RecordShares {
    # Internal: Retrieves and displays user permissions for a shared record
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [KeeperSecurity.Vault.VaultOnline]$Vault,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RecordUid
    )

    try {
        Write-Verbose "Retrieving share information for record $RecordUid"
        
        $sharesTask = $Vault.GetSharesForRecords(@($RecordUid))
        Invoke-TaskAndWait -Task $sharesTask
        
        $shares = $sharesTask.Result
        $recordShares = $shares | Select-Object -First 1

        if ($null -ne $recordShares -and $null -ne $recordShares.UserPermissions -and $recordShares.UserPermissions.Length -gt 0) {
            $sortedPermissions = $recordShares.UserPermissions | 
                Sort-Object @{Expression={if ($_.Owner) { " 1" } elseif ($_.CanEdit) { " 2" } elseif ($_.CanShare) { " 3" } else { "" }}}, Username

            $isFirst = $true
            foreach ($permission in $sortedPermissions) {
                if ($permission.Owner) {
                    continue
                }

                $flags = [System.Collections.Generic.List[string]]::new()
                if ($permission.CanEdit) {
                    $flags.Add("Can Edit")
                }
                if ($permission.CanShare) {
                    $flags.Add($(if ($flags.Count -gt 0) { "& Can Share" } else { "Can Share" }))
                }
                $flagsText = if ($flags.Count -gt 0) { $flags -join " " } else { "Read Only" }

                $selfFlag = if ($null -ne $Vault.Auth -and $permission.Username -eq $Vault.Auth.Username) { "self" } else { "" }
                $header = if ($isFirst) { "Direct User Shares" } else { "" }

                Write-Host ("{0,$script:FIELD_LABEL_WIDTH}: {1,-26} ({2}) {3}" -f $header, $permission.Username, $flagsText, $selfFlag)
                $isFirst = $false
            }
        }
    }
    catch {
        Write-Verbose "Error loading share information for record $RecordUid`: $($_.Exception.Message)"
    }
}

function Clear-KeeperTrash {
    <#
    .SYNOPSIS
    Permanently deletes all records in trash
    
    .DESCRIPTION
    Permanently deletes all records in the trash. This action cannot be undone.
    
    .PARAMETER Force
    Skip confirmation prompts and purge immediately.
    
    .OUTPUTS
    None. Displays status messages to console.
    
    .EXAMPLE
    Clear-KeeperTrash
    Purges all trash records with confirmation prompt
    
    .EXAMPLE
    Clear-KeeperTrash -Force
    Purges all trash records without confirmation
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter()]
        [switch]$Force
    )
    
    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to permanently delete all records in trash? This action cannot be undone. (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Purge operation cancelled"
            return
        }
    }
    
    try {
        $vault = Get-VaultOrThrow
        $request = New-Object KeeperSecurity.Commands.PurgeDeletedRecordsCommand
        $task = [KeeperSecurity.Authentication.AuthExtensions]::ExecuteAuthCommand($vault.Auth, $request)
        Invoke-TaskAndWait -Task $task
        Write-Host "Successfully purged all records from trash"
    }
    catch {
        Write-Error "Failed to purge trash: $($_.Exception.Message)"
    }
}

Set-Alias -Name ktrash -Value Get-KeeperTrashList
Set-Alias -Name ktrash-restore -Value Restore-KeeperTrashRecords
Set-Alias -Name ktrash-unshare -Value Remove-TrashedKeeperRecordShares
Set-Alias -Name ktrash-get -Value Get-KeeperTrashedRecordDetails
Set-Alias -Name ktrash-purge -Value Clear-KeeperTrash
