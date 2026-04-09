#requires -Version 5.1

function getKeeperAuth {
    <#
    SkipSync REST helpers only need IAuthentication — not a populated vault.
    Use this instead of getVault so commands work when vault SyncDown was skipped (-SkipSync) or the cache is empty.
    #>
    if (-not $Script:Context.Auth) {
        Write-Error -Message 'Not connected. Run Connect-Keeper first.' -ErrorAction Stop
    }
    $Script:Context.Auth
}

function __ResolveSharedFolderUidSkipSync {
    param($SharedFolder)
    if ($SharedFolder -is [Array]) {
        if ($SharedFolder.Count -ne 1) {
            throw 'Only one shared folder is expected.'
        }
        $SharedFolder = $SharedFolder[0]
    }
    $uid = $null
    if ($SharedFolder -is [string]) {
        $uid = $SharedFolder
    }
    elseif ($null -ne $SharedFolder.Uid) {
        $uid = $SharedFolder.Uid
    }
    if (-not $uid) {
        throw "Cannot resolve shared folder UID from: $SharedFolder"
    }

    $vault = $Script:Context.Vault
    if ($vault) {
        [KeeperSecurity.Vault.SharedFolder]$sf = $null
        if ($vault.TryGetSharedFolder($uid, [ref]$sf)) {
            return $sf.Uid
        }
        $sf = $vault.SharedFolders | Where-Object { $_.Name -eq $uid } | Select-Object -First 1
        if ($sf) {
            return $sf.Uid
        }
    }
    return $uid
}

function __NewSharedFolderUserOptionsSkipSync {
    param(
        [System.Nullable[bool]] $ManageRecords,
        [System.Nullable[bool]] $ManageUsers,
        [System.Nullable[DateTimeOffset]] $Expiration
    )
    $options = New-Object KeeperSecurity.Vault.SharedFolderUserOptions
    if ($null -ne $ManageRecords) {
        $options.ManageRecords = $ManageRecords
    } else {
        $options.ManageRecords = $null
    }
    if ($null -ne $ManageUsers) {
        $options.ManageUsers = $ManageUsers
    } else {
        $options.ManageUsers = $null
    }
    if ($null -ne $Expiration) {
        $options.Expiration = $Expiration
    } else {
        $options.Expiration = $null
    }
    return $options
}

function __GetSharedFolderObjectFromResponseSkipSync {
    param($GetSharedFoldersResponse, [string]$SharedFolderUid)
    if (-not $GetSharedFoldersResponse -or -not $GetSharedFoldersResponse.SharedFolders) {
        return $null
    }
    $uid = $SharedFolderUid.Trim()
    foreach ($sharedFolder in $GetSharedFoldersResponse.SharedFolders) {
        if ($sharedFolder -and [string]::Equals($sharedFolder.SharedFolderUid, $uid, [StringComparison]::OrdinalIgnoreCase)) {
            return $sharedFolder
        }
    }
    if ($GetSharedFoldersResponse.SharedFolders.Length -eq 1) {
        return $GetSharedFoldersResponse.SharedFolders[0]
    }
    $null
}

function __TestSharedFolderOwnerIsCurrentUserSkipSync {
    param($SharedFolderObject, [KeeperSecurity.Authentication.IAuthentication]$Auth)
    if (-not $SharedFolderObject -or -not $Auth.AuthContext.AccountUid) {
        return $false
    }
    $owner = $SharedFolderObject.Owner
    if ([string]::IsNullOrWhiteSpace($owner)) {
        return $false
    }
    $myUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($Auth.AuthContext.AccountUid)
    [string]::Equals($owner.Trim(), $myUid.Trim(), [StringComparison]::OrdinalIgnoreCase)
}

function __WriteRecordDetailsSkipSyncResult {
    param(
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.RecordDetailsSkipSyncResult] $Result,
        [string] $EmptyMessage = 'No records in this shared folder (or folder unavailable).'
    )
    if ($Result.Records.Count -eq 0 -and $Result.FailedRecordUids.Count -eq 0 -and $Result.NoPermissionRecordUids.Count -eq 0) {
        Write-Host $EmptyMessage
        return
    }
    foreach ($record in $Result.Records) {
        $title = $record.Title
        if ([string]::IsNullOrEmpty($title)) { $title = '(no title)' }
        Write-Host "  $($record.Uid): $title"
    }
    if ($Result.NoPermissionRecordUids.Count -gt 0) {
        Write-Host "  No permission: $($Result.NoPermissionRecordUids -join ', ')"
    }
    if ($Result.FailedRecordUids.Count -gt 0) {
        Write-Host "  Failed to decrypt: $($Result.FailedRecordUids -join ', ')"
    }
    if ($Result.InvalidRecordUids.Count -gt 0) {
        Write-Host "  Invalid UID format: $($Result.InvalidRecordUids -join ', ')"
    }
}

function __GetRecordDetailsSkipSyncIncludeValue {
    param([string]$Include)
    switch ($Include) {
        'DataOnly' { 1 }
        'ShareOnly' { 2 }
        Default { 0 }
    }
}

function __GetRequestedRecordUidsMissingFromLoadedRecords {
    param(
        [string[]]$RequestedUids,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.RecordDetailsSkipSyncResult]$Result
    )
    $loaded = @{}
    foreach ($record in $Result.Records) {
        if ($record.Uid) { $loaded[$record.Uid] = $true }
    }
    $missing = [System.Collections.ArrayList]::new()
    foreach ($uid in $RequestedUids) {
        if ([string]::IsNullOrWhiteSpace($uid)) { continue }
        $trimmedUid = $uid.Trim()
        $found = $false
        foreach ($key in $loaded.Keys) {
            if ([string]::Equals($key, $trimmedUid, [StringComparison]::OrdinalIgnoreCase)) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            [void]$missing.Add($trimmedUid)
        }
    }
    @($missing)
}

function __TryFindSharedFolderUidForRecordFromVault {
    param([string]$RecordUid)
    if ([string]::IsNullOrWhiteSpace($RecordUid)) {
        return $null
    }
    $vault = $Script:Context.Vault
    if (-not $vault) {
        return $null
    }
    $trimmedRecordUid = $RecordUid.Trim()
    foreach ($sf in $vault.SharedFolders) {
        foreach ($recordPermission in $sf.RecordPermissions) {
            if ($recordPermission.RecordUid -and [string]::Equals($recordPermission.RecordUid.Trim(), $trimmedRecordUid, [StringComparison]::OrdinalIgnoreCase)) {
                return $sf.Uid
            }
        }
    }
    $null
}

function __MergeRecordDetailsSkipSyncResultsForSameRequest {
    param(
        [string[]]$RequestedUids,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.RecordDetailsSkipSyncResult]$OwnedResult,
        [Parameter(Mandatory = $true)]$SharedFolderResults
    )
    $records = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperRecord]]::new()
    foreach ($record in $OwnedResult.Records) {
        $records.Add($record)
    }
    foreach ($sf in $SharedFolderResults) {
        foreach ($record in $sf.Records) {
            $records.Add($record)
        }
    }
    $loaded = [System.Collections.Generic.Dictionary[string, bool]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $records) {
        if ($record.Uid) {
            $loaded[$record.Uid] = $true
        }
    }
    $noPerm = [System.Collections.ArrayList]::new()
    foreach ($uid in $OwnedResult.NoPermissionRecordUids) {
        if ($uid -and -not $loaded.ContainsKey($uid)) {
            [void]$noPerm.Add($uid)
        }
    }
    foreach ($sfr in $SharedFolderResults) {
        foreach ($uid in $sfr.NoPermissionRecordUids) {
            if ($uid -and -not $loaded.ContainsKey($uid)) {
                [void]$noPerm.Add($uid)
            }
        }
    }
    $invalid = [System.Collections.ArrayList]::new()
    foreach ($uid in $OwnedResult.InvalidRecordUids) {
        if ($uid) { [void]$invalid.Add($uid) }
    }
    foreach ($sfr in $SharedFolderResults) {
        foreach ($uid in $sfr.InvalidRecordUids) {
            if ($uid) { [void]$invalid.Add($uid) }
        }
    }
    $failed = [System.Collections.ArrayList]::new()
    foreach ($uid in $RequestedUids) {
        if ([string]::IsNullOrWhiteSpace($uid)) { continue }
        $trimmedUid = $uid.Trim()
        if (-not $loaded.ContainsKey($trimmedUid)) {
            [void]$failed.Add($trimmedUid)
        }
    }
    New-Object KeeperSecurity.Vault.RecordDetailsSkipSyncResult(
        $records.ToArray(),
        [string[]]@($noPerm),
        [string[]]@($failed),
        [string[]]@($invalid))
}

function __ConvertSharedFolderObjectToDetailsView {
    param(
        [Parameter(Mandatory = $true)] $SharedFolderObject,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.GetSharedFoldersResponse] $ApiResponse,
        [Parameter(Mandatory = $false)][switch] $IncludePermissions
    )
    if (-not $IncludePermissions) {
        $recordUids = [System.Collections.ArrayList]::new()
        foreach ($record in @($SharedFolderObject.Records)) {
            if ($record -and $record.RecordUid) { [void]$recordUids.Add($record.RecordUid) }
        }
        $userEmails = [System.Collections.ArrayList]::new()
        foreach ($uid in @($SharedFolderObject.Users)) {
            if ($uid -and $uid.Email) { [void]$userEmails.Add($uid.Email) }
        }
        $teamUids = [System.Collections.ArrayList]::new()
        foreach ($team in @($SharedFolderObject.Teams)) {
            if ($team -and $team.TeamUid) { [void]$teamUids.Add($team.TeamUid) }
        }
        return [pscustomobject][ordered]@{
            ApiResult       = $ApiResponse.result
            ApiIsSuccess    = $ApiResponse.IsSuccess
            ApiMessage      = $ApiResponse.message
            ApiCommand      = $ApiResponse.command
            SharedFolderUid = $SharedFolderObject.SharedFolderUid
            Name            = $SharedFolderObject.Name
            Owner           = $SharedFolderObject.Owner
            Revision        = $SharedFolderObject.Revision
            RecordCount     = $recordUids.Count
            UserCount       = $userEmails.Count
            TeamCount       = $teamUids.Count
            RecordUids      = @($recordUids)
            UserEmails      = @($userEmails)
            TeamUids        = @($teamUids)
        }
    }

    $recObjs = @()
    foreach ($record in @($SharedFolderObject.Records)) {
        if (-not $record) { continue }
        $recObjs += [pscustomobject]@{
            RecordUid = $record.RecordUid
            CanEdit   = $record.CanEdit
            CanShare  = $record.CanShare
        }
    }
    $userObjs = @()
    foreach ($uid in @($SharedFolderObject.Users)) {
        if (-not $uid) { continue }
        $userObjs += [pscustomobject]@{
            Email         = $uid.Email
            ManageUsers   = $uid.ManageUsers
            ManageRecords = $uid.ManageRecords
        }
    }
    $teamObjs = @()
    foreach ($team in @($SharedFolderObject.Teams)) {
        if (-not $team) { continue }
        $teamObjs += [pscustomobject]@{
            TeamUid       = $team.TeamUid
            Name          = $team.Name
            ManageUsers   = $team.ManageUsers
            ManageRecords = $team.ManageRecords
            RestrictEdit  = $team.RestrictEdit
            RestrictShare = $team.RestrictShare
        }
    }
    [pscustomobject][ordered]@{
        ApiResult     = $ApiResponse.result
        ApiIsSuccess  = $ApiResponse.IsSuccess
        ApiMessage    = $ApiResponse.message
        ApiCommand    = $ApiResponse.command
        SharedFolderUid = $SharedFolderObject.SharedFolderUid
        Name            = $SharedFolderObject.Name
        Owner           = $SharedFolderObject.Owner
        Revision        = $SharedFolderObject.Revision
        KeyType         = $SharedFolderObject.KeyType
        ManageUsers     = $SharedFolderObject.ManageUsers
        ManageRecords   = $SharedFolderObject.ManageRecords
        DefaultCanEdit  = $SharedFolderObject.DefaultCanEdit
        DefaultCanShare = $SharedFolderObject.DefaultCanShare
        DefaultManageRecords = $SharedFolderObject.DefaultManageRecords
        DefaultManageUsers   = $SharedFolderObject.DefaultManageUsers
        AccountFolder   = $SharedFolderObject.AccountFolder
        FullSync        = $SharedFolderObject.FullSync
        RecordCount     = $recObjs.Count
        UserCount       = $userObjs.Count
        TeamCount       = $teamObjs.Count
        Records         = $recObjs
        Users           = $userObjs
        Teams           = $teamObjs
    }
}

function Get-KeeperSharedFolderDetailsSkipSync {
    <#
    .SYNOPSIS
    Fetches shared folder payload from the server (get_shared_folders) without a full vault sync.

    .DESCRIPTION
    By default returns a compact PSCustomObject: RecordUids, UserEmails, and TeamUids string arrays plus basic
    folder identity (uid, name, owner, revision) and counts. Raw API objects format poorly in the console
    (e.g. SharedFolders shown as a one-line collection).
     Use Format-List or Select-Object -ExpandProperty Records/Users/Teams to inspect nested data when using -IncludePermissions.

    .PARAMETER IncludePermissions
    When set, includes per-record CanEdit/CanShare, per-user and per-team permission flags, and folder-level
    key and default-permission fields. Omit for list-only output.

    .PARAMETER PassThru
    Return the raw GetSharedFoldersResponse from the SDK.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string] $SharedFolderUid,
        [Parameter()][switch] $IncludePermissions,
        [Parameter()][switch] $PassThru
    )

    $auth = getKeeperAuth
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetSharedFolderAsync($auth, $SharedFolderUid)
    $rs = $task.GetAwaiter().GetResult()
    if (-not $rs) {
        Write-Warning "Shared folder not found or get_shared_folders returned no data for: $SharedFolderUid"
        return $null
    }
    if ($PassThru) {
        return $rs
    }
    $sf = __GetSharedFolderObjectFromResponseSkipSync $rs $SharedFolderUid
    if (-not $sf) {
        Write-Warning 'No matching shared folder in the API response.'
        return $null
    }
    __ConvertSharedFolderObjectToDetailsView -SharedFolderObject $sf -ApiResponse $rs -IncludePermissions:$IncludePermissions
}

function Get-KeeperSharedFolderRecordUidsSkipSync {
    <#
    .SYNOPSIS
    Returns record UIDs linked to a shared folder from get_shared_folders (no record bodies).

    .DESCRIPTION
    Lightweight folder membership: only the list of record UIDs from the shared-folder payload.

    Use Get-KeeperSharedFolderRecordsSkipSync when you need every record in the folder decrypted in one step.
    Use Get-KeeperRecordDetailsByUidSkipSync when you already know which record UIDs to load; it does not discover
    which records belong to a folder. 
    
    This cmdlet fills that gap for "what UIDs are in this folder?" without pulling
    full details — useful for counts, logging, or fetching a subset of records by UID afterward.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    Param(
        [Parameter(Mandatory = $true)][string] $SharedFolderUid
    )

    $auth = getKeeperAuth
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetRecordUidsFromSharedFolderAsync($auth, $SharedFolderUid)
    $task.GetAwaiter().GetResult()
}

function Get-KeeperSharedFolderRecordsSkipSync {
    <#
    .SYNOPSIS
    Lists decrypted records in a shared folder without full vault sync. Chooses decryption path automatically unless you override -Mode.

    .PARAMETER SharedFolder
    Shared folder UID (base64url), name if present in vault cache, or object with a Uid property.

    .PARAMETER Mode
    Auto: use get_shared_folders owner flag — shared-folder record keys if you are not owner, owned record keys if you are owner.
    SharedKey: always decrypt via shared-folder record keys (RecordSkipSyncDown.GetSharedFolderRecordsAsync).
    OwnedKey: always load UIDs from the folder then decrypt with per-record keys (GetOwnedRecordsAsync).

    .PARAMETER Include
    RecordDetailsInclude: DataPlusShare (default), DataOnly, or ShareOnly.

    .PARAMETER PassThru
    Return RecordDetailsSkipSyncResult instead of printing uid/title lines.
    #>
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.RecordDetailsSkipSyncResult])]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter()]
        [ValidateSet('DataPlusShare', 'DataOnly', 'ShareOnly')]
        [string] $Include = 'DataPlusShare',
        [Parameter()]
        [ValidateSet('Auto', 'SharedKey', 'OwnedKey')]
        [string] $Mode = 'Auto',
        [Parameter()][switch] $PassThru
    )

    $auth = getKeeperAuth
    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $includeVal = __GetRecordDetailsSkipSyncIncludeValue $Include

    $useOwned = $false
    if ($Mode -eq 'OwnedKey') {
        $useOwned = $true
    }
    elseif ($Mode -eq 'SharedKey') {
        $useOwned = $false
    }
    else {
        $taskFolder = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetSharedFolderAsync($auth, $sfUid)
        $folderRs = $taskFolder.GetAwaiter().GetResult()
        $sfObj = __GetSharedFolderObjectFromResponseSkipSync $folderRs $sfUid
        $useOwned = __TestSharedFolderOwnerIsCurrentUserSkipSync $sfObj $auth
    }

    $result = if ($useOwned) {
        $taskUids = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetRecordUidsFromSharedFolderAsync($auth, $sfUid)
        $uids = $taskUids.GetAwaiter().GetResult()
        if ($null -eq $uids) {
            $uids = [string[]]@()
        }
        $taskRec = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetOwnedRecordsAsync($auth, $uids, $includeVal)
        $taskRec.GetAwaiter().GetResult()
    }
    else {
        $task = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetSharedFolderRecordsAsync($auth, $sfUid, $includeVal)
        $task.GetAwaiter().GetResult()
    }

    if ($PassThru) {
        return $result
    }
    __WriteRecordDetailsSkipSyncResult $result
}

function Get-KeeperRecordDetailsByUidSkipSync {
    <#
    .SYNOPSIS
    Loads record details by UID via vault/get_records_details without a full vault sync.

    .DESCRIPTION
    Default -Mode Auto loads owned records first (per-record keys), then retries any missing UIDs using shared-folder
    keys from get_shared_folders. Use -SharedFolderUid when you know the folder,
    or run Sync-Keeper so the vault can map each record to a shared folder.

    .PARAMETER RecordUid
    One or more record UIDs.

    .PARAMETER SharedFolderUid
    Optional. When set, Auto mode uses this folder for the second-step shared-folder decrypt for UIDs that failed
    the owned path. SharedKey mode requires this parameter.

    .PARAMETER Mode
    Auto (default): owned decrypt first, then shared-folder decrypt for remaining UIDs.
    OwnedKey: only owned-record keys (previous behavior when SharedFolderUid was omitted).
    SharedKey: only shared-folder keys for the folder given by -SharedFolderUid.

    .PARAMETER PassThru
    Return RecordDetailsSkipSyncResult instead of printing lines.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)][string[]] $RecordUid,
        [Parameter()][string] $SharedFolderUid,
        [Parameter()]
        [ValidateSet('Auto', 'OwnedKey', 'SharedKey')]
        [string] $Mode = 'Auto',
        [Parameter()]
        [ValidateSet('DataPlusShare', 'DataOnly', 'ShareOnly')]
        [string] $Include = 'DataPlusShare',
        [Parameter()][switch] $PassThru
    )

    $auth = getKeeperAuth
    $includeVal = __GetRecordDetailsSkipSyncIncludeValue -Include $Include

    if ($Mode -eq 'SharedKey') {
        if (-not $SharedFolderUid) {
            throw 'SharedKey mode requires -SharedFolderUid.'
        }
        $task = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetSharedFolderRecordsAsync($auth, $SharedFolderUid.Trim(), $RecordUid, $includeVal)
        $result = $task.GetAwaiter().GetResult()
    }
    elseif ($Mode -eq 'OwnedKey') {
        $task = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetOwnedRecordsAsync($auth, $RecordUid, $includeVal)
        $result = $task.GetAwaiter().GetResult()
    }
    else {
        $taskOwned = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetOwnedRecordsAsync($auth, $RecordUid, $includeVal)
        $owned = $taskOwned.GetAwaiter().GetResult()
        $needSf = __GetRequestedRecordUidsMissingFromLoadedRecords -RequestedUids $RecordUid -Result $owned
        if ($needSf.Count -eq 0) {
            $result = $owned
        }
        else {
            Write-Verbose "SkipSync: $($needSf.Count) record UID(s) not loaded with owned keys; trying shared-folder keys."
            $sfResults = [System.Collections.ArrayList]::new()
            if ($SharedFolderUid) {
                $tSf = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetSharedFolderRecordsAsync(
                    $auth, $SharedFolderUid.Trim(), [string[]]$needSf, $includeVal)
                [void]$sfResults.Add($tSf.GetAwaiter().GetResult())
            }
            else {
                $groups = @{}
                foreach ($uid in $needSf) {
                    $sfUid = __TryFindSharedFolderUidForRecordFromVault -RecordUid $uid
                    if (-not $sfUid) {
                        Write-Verbose "SkipSync: no shared folder in vault cache for record $uid; specify -SharedFolderUid or run Sync-Keeper."
                        continue
                    }
                    if (-not $groups.ContainsKey($sfUid)) {
                        $groups[$sfUid] = [System.Collections.ArrayList]::new()
                    }
                    [void]$groups[$sfUid].Add($uid)
                }
                foreach ($group in $groups.GetEnumerator()) {
                    $uids = [string[]]@($group.Value)
                    $tSf = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetSharedFolderRecordsAsync($auth, $group.Key, $uids, $includeVal)
                    [void]$sfResults.Add($tSf.GetAwaiter().GetResult())
                }
            }
            if ($sfResults.Count -eq 0) {
                if ($needSf.Count -gt 0 -and -not $SharedFolderUid) {
                    Write-Warning 'One or more records were not loaded with owned keys. They may live in a shared folder: pass -SharedFolderUid <folderUid> or run Sync-Keeper so the vault can resolve the folder.'
                }
                $result = $owned
            }
            else {
                $result = __MergeRecordDetailsSkipSyncResultsForSameRequest -RequestedUids $RecordUid -OwnedResult $owned -SharedFolderResults @($sfResults)
            }
        }
    }

    if ($PassThru) {
        return $result
    }
    __WriteRecordDetailsSkipSyncResult $result
}

function Get-KeeperAvailableTeamsSkipSync {
    <#
    .SYNOPSIS
    Lists teams available for sharing (get_available_teams). Use with SET 3 team sharing.
    #>
    [CmdletBinding()]
    Param()

    $auth = getKeeperAuth
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetAvailableTeamsForShareAsync($auth)
    $task.GetAwaiter().GetResult()
}

function Get-KeeperTeamUidSkipSync {
    <#
    .SYNOPSIS
    Resolves a team display name to a team UID (for SET 3).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true)][string] $TeamName
    )

    $auth = getKeeperAuth
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetTeamUidFromNameAsync($auth, $TeamName)
    $task.GetAwaiter().GetResult()
}


function Grant-KeeperSharedFolderUserSkipSync {
    <#
    .SYNOPSIS
    Adds or updates a user on a shared folder without a full vault sync (PutUserToSharedFolderAsync).

    .DESCRIPTION
    By default, only performs the API call. Use -ShowDetail to also list decrypted records in the folder (shared-folder key path) and write a summary.

    .PARAMETER ShowDetail
    If set, after a successful grant runs Get-KeeperSharedFolderRecordsSkipSync and writes a summary.

    .PARAMETER PassThru
    When -ShowDetail is used, returns RecordDetailsSkipSyncResult from the listing step.

    .PARAMETER ExpireIn
    Optional. Expiration offset from now: a TimeSpan, integer (minutes), or a string that parses as minutes or TimeSpan (same as Grant-KeeperRecordAccess).

    .PARAMETER ExpireAt
    Optional. Absolute expiration as ISO 8601 or RFC 1123 (e.g. "2025-05-23T08:59:11Z").
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true, Position = 1)][string] $User,
        [Parameter()][System.Nullable[bool]] $ManageRecords,
        [Parameter()][System.Nullable[bool]] $ManageUsers,
        [Parameter()][System.Object] $ExpireIn,
        [Parameter()][string] $ExpireAt,
        [Parameter()][switch] $ShowDetail,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $email = $User.Trim()
    try {
        $expirationDto = Get-ExpirationDate -ExpireIn $ExpireIn -ExpireAt $ExpireAt
    } catch {
        Write-Error "Error: $($_.Exception.Message)" -ErrorAction Stop
        throw
    }
    $options = __NewSharedFolderUserOptionsSkipSync -ManageRecords $ManageRecords -ManageUsers $ManageUsers -Expiration $expirationDto
    $didGrant = $false
    if ($PSCmdlet.ShouldProcess("$sfUid", "Grant shared folder access to $email")) {
        $auth = getKeeperAuth
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::PutUserToSharedFolderAsync($auth, $sfUid, $email, $options)
        $task.GetAwaiter().GetResult() | Out-Null
        Write-Host "OK: Shared folder $sfUid — user $email added or updated."
        $didGrant = $true
    }
    if ($didGrant -and $ShowDetail) {
        $listed = Get-KeeperSharedFolderRecordsSkipSync -SharedFolder $sfUid -Mode SharedKey -PassThru
        __WriteRecordDetailsSkipSyncResult $listed "No records listed on this shared folder (user $User has folder access)."
        if ($PassThru) { $listed }
    }
}

function Revoke-KeeperSharedFolderUserSkipSync {
    <#
    .SYNOPSIS
    Removes a user from a shared folder without a full vault sync (RemoveUserFromSharedFolderAsync).

    .DESCRIPTION
    By default, only performs the API call. Use -ShowDetail to also list decrypted records still in the folder.

    .PARAMETER ShowDetail
    If set, after a successful revoke runs Get-KeeperSharedFolderRecordsSkipSync and writes a summary.

    .PARAMETER PassThru
    When -ShowDetail is used, returns RecordDetailsSkipSyncResult from the listing step.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true, Position = 1)][string] $User,
        [Parameter()][switch] $ShowDetail,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $email = $User.Trim()
    $didRevoke = $false
    if ($PSCmdlet.ShouldProcess("$sfUid", "Remove shared folder access for $email")) {
        $auth = getKeeperAuth
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::RemoveUserFromSharedFolderAsync($auth, $sfUid, $email)
        $task.GetAwaiter().GetResult() | Out-Null
        Write-Host "OK: Shared folder $sfUid — user $email removed."
        $didRevoke = $true
    }
    if ($didRevoke -and $ShowDetail) {
        $listed = Get-KeeperSharedFolderRecordsSkipSync -SharedFolder $sfUid -Mode SharedKey -PassThru
        __WriteRecordDetailsSkipSyncResult $listed 'No records listed on this shared folder after remove.'
        if ($PassThru) { $listed }
    }
}

function Grant-KeeperSharedFolderTeamSkipSync {
    <#
    .SYNOPSIS
    Adds or updates a team on a shared folder without a full vault sync.
    Team may be a team UID (base64url) or a team name resolved via the SDK.

    .DESCRIPTION
    By default, only performs the API call. Use -ShowDetail to also list decrypted records in the folder.

    .PARAMETER ShowDetail
    If set, after a successful grant runs Get-KeeperSharedFolderRecordsSkipSync and writes a summary.

    .PARAMETER PassThru
    When -ShowDetail is used, returns RecordDetailsSkipSyncResult from the listing step.

    .PARAMETER ExpireIn
    Optional. Same semantics as Grant-KeeperRecordAccess / Grant-KeeperSharedFolderUserSkipSync.

    .PARAMETER ExpireAt
    Optional. Absolute expiration (ISO 8601 or RFC 1123).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true, Position = 1)][string] $Team,
        [Parameter()][System.Nullable[bool]] $ManageRecords,
        [Parameter()][System.Nullable[bool]] $ManageUsers,
        [Parameter()][System.Object] $ExpireIn,
        [Parameter()][string] $ExpireAt,
        [Parameter()][switch] $ShowDetail,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $teamKey = $Team.Trim()
    try {
        $expirationDto = Get-ExpirationDate -ExpireIn $ExpireIn -ExpireAt $ExpireAt
    } catch {
        Write-Error "Error: $($_.Exception.Message)" -ErrorAction Stop
        throw
    }
    $options = __NewSharedFolderUserOptionsSkipSync -ManageRecords $ManageRecords -ManageUsers $ManageUsers -Expiration $expirationDto
    $didGrant = $false
    if ($PSCmdlet.ShouldProcess("$sfUid", "Grant shared folder access to team $Team")) {
        $auth = getKeeperAuth
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::PutTeamToSharedFolderAsync($auth, $sfUid, $teamKey, $options)
        $task.GetAwaiter().GetResult() | Out-Null
        Write-Host "OK: Shared folder $sfUid — team $teamKey added or updated."
        $didGrant = $true
    }
    if ($didGrant -and $ShowDetail) {
        $listed = Get-KeeperSharedFolderRecordsSkipSync -SharedFolder $sfUid -Mode SharedKey -PassThru
        __WriteRecordDetailsSkipSyncResult $listed "No records listed on this shared folder (team $Team has folder access)."
        if ($PassThru) { $listed }
    }
}

function Revoke-KeeperSharedFolderTeamSkipSync {
    <#
    .SYNOPSIS
    Removes a team from a shared folder without a full vault sync (RemoveTeamFromSharedFolderAsync).

    .DESCRIPTION
    By default, only performs the API call. Use -ShowDetail to also list decrypted records still in the folder.

    .PARAMETER ShowDetail
    If set, after a successful revoke runs Get-KeeperSharedFolderRecordsSkipSync and writes a summary.

    .PARAMETER PassThru
    When -ShowDetail is used, returns RecordDetailsSkipSyncResult from the listing step.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true, Position = 1)][string] $Team,
        [Parameter()][switch] $ShowDetail,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $teamKey = $Team.Trim()
    $didRevoke = $false
    if ($PSCmdlet.ShouldProcess("$sfUid", "Remove shared folder access for team $Team")) {
        $auth = getKeeperAuth
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::RemoveTeamFromSharedFolderAsync($auth, $sfUid, $teamKey)
        $task.GetAwaiter().GetResult() | Out-Null
        Write-Host "OK: Shared folder $sfUid — team $teamKey removed."
        $didRevoke = $true
    }
    if ($didRevoke -and $ShowDetail) {
        $listed = Get-KeeperSharedFolderRecordsSkipSync -SharedFolder $sfUid -Mode SharedKey -PassThru
        __WriteRecordDetailsSkipSyncResult $listed 'No records listed on this shared folder after remove.'
        if ($PassThru) { $listed }
    }
}

