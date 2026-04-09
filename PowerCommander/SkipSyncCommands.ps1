#requires -Version 5.1

<#
.SYNOPSIS
Skip-sync helpers call the same Keeper APIs as KeeperSdk RecordSkipSyncDown / SharedFolderSkipSyncDown
without updating the in-memory vault. Run Sync-Keeper after mutations elsewhere if you need a consistent local vault.
#>

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

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    [KeeperSecurity.Vault.SharedFolder]$sf = $null
    if ($vault.TryGetSharedFolder($uid, [ref]$sf)) {
        return $sf.Uid
    }
    $sf = $vault.SharedFolders | Where-Object { $_.Name -eq $uid } | Select-Object -First 1
    if ($sf) {
        return $sf.Uid
    }
    return $uid
}

function __NewSharedFolderUserOptionsSkipSync {
    param(
        $BoundParameters,
        $ManageRecords,
        $ManageUsers,
        $Expiration
    )
    if (-not ($BoundParameters.ContainsKey('ManageRecords') -or $BoundParameters.ContainsKey('ManageUsers') -or
        ($BoundParameters.ContainsKey('Expiration') -and $null -ne $Expiration))) {
        return $null
    }
    $opt = New-Object KeeperSecurity.Vault.SharedFolderUserOptions
    if ($BoundParameters.ContainsKey('ManageRecords')) {
        $opt.ManageRecords = $ManageRecords
    }
    if ($BoundParameters.ContainsKey('ManageUsers')) {
        $opt.ManageUsers = $ManageUsers
    }
    if ($BoundParameters.ContainsKey('Expiration') -and $null -ne $Expiration) {
        $opt.Expiration = [DateTimeOffset]$Expiration
    }
    $opt
}

function Get-KeeperOwnedRecordsSkipSync {
    <#
    .SYNOPSIS
    Loads record details by UID via vault/get_records_details (RecordSkipSyncDown.GetOwnedRecordsAsync). Does not run a full vault sync.

    .PARAMETER RecordUid
    One or more record UIDs (base64url).

    .PARAMETER SharedFolderUid
    Optional. When set, decrypt using shared-folder record keys for this folder (required for many SF-linked records).

    .PARAMETER Include
    RecordDetailsInclude: DataPlusShare (default), DataOnly, or ShareOnly.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)][string[]] $RecordUid,
        [Parameter()][string] $SharedFolderUid,
        [Parameter()]
        [ValidateSet('DataPlusShare', 'DataOnly', 'ShareOnly')]
        [string] $Include = 'DataPlusShare'
    )

    $vault = getVault
    # Numeric values match Records.RecordDetailsInclude (avoid parse-time SDK enum dependency)
    $includeVal = switch ($Include) {
        'DataOnly' { 1 }
        'ShareOnly' { 2 }
        Default { 0 }
    }
    if ($SharedFolderUid) {
        $task = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetSharedFolderRecordsAsync($vault.Auth, $SharedFolderUid, $RecordUid, $includeVal)
    }
    else {
        $task = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetOwnedRecordsAsync($vault.Auth, $RecordUid, $includeVal)
    }
    $task.GetAwaiter().GetResult()
}

function Get-KeeperSharedFolderRecordsSkipSync {
    <#
    .SYNOPSIS
    Loads all records in a shared folder without full vault sync (RecordSkipSyncDown.GetSharedFolderRecordsAsync).

    .PARAMETER SharedFolderUid
    Shared folder UID (base64url).

    .PARAMETER Include
    RecordDetailsInclude: DataPlusShare (default), DataOnly, or ShareOnly.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string] $SharedFolderUid,
        [Parameter()]
        [ValidateSet('DataPlusShare', 'DataOnly', 'ShareOnly')]
        [string] $Include = 'DataPlusShare'
    )

    $vault = getVault
    $includeVal = switch ($Include) {
        'DataOnly' { 1 }
        'ShareOnly' { 2 }
        Default { 0 }
    }
    $task = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetSharedFolderRecordsAsync($vault.Auth, $SharedFolderUid, $includeVal)
    $task.GetAwaiter().GetResult()
}

function Get-KeeperSharedFolderRecordUidsSkipSync {
    <#
    .SYNOPSIS
    Returns record UIDs linked to a shared folder from get_shared_folders (SharedFolderSkipSyncDown.GetRecordUidsFromSharedFolderAsync). Does not load record bodies.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    Param(
        [Parameter(Mandatory = $true)][string] $SharedFolderUid
    )

    $vault = getVault
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetRecordUidsFromSharedFolderAsync($vault.Auth, $SharedFolderUid)
    $task.GetAwaiter().GetResult()
}

function Get-KeeperSharedFolderSkipSync {
    <#
    .SYNOPSIS
    Fetches shared folder payload from the server (SharedFolderSkipSyncDown.GetSharedFolderAsync). Returns $null if the folder is unavailable.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string] $SharedFolderUid
    )

    $vault = getVault
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetSharedFolderAsync($vault.Auth, $SharedFolderUid)
    $task.GetAwaiter().GetResult()
}

function Grant-KeeperSharedFolderUserSkipSync {
    <#
    .SYNOPSIS
    Adds or updates a user on a shared folder without loading a full vault sync (SharedFolderSkipSyncDown.PutUserToSharedFolderAsync).

    .PARAMETER SharedFolder
    Shared folder UID, display name (if present in the current vault cache), or object with a Uid property.

    .PARAMETER User
    User email address.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $User,
        [Parameter()][System.Nullable[bool]] $ManageRecords,
        [Parameter()][System.Nullable[bool]] $ManageUsers,
        [Parameter()] $Expiration
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $email = ([System.Net.Mail.MailAddress]$User).Address
    $opts = __NewSharedFolderUserOptionsSkipSync -BoundParameters $PSBoundParameters -ManageRecords $ManageRecords `
        -ManageUsers $ManageUsers -Expiration $Expiration
    if ($PSCmdlet.ShouldProcess("$sfUid", "Grant shared folder access to $email")) {
        $vault = getVault
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::PutUserToSharedFolderAsync($vault.Auth, $sfUid, $email, $opts)
        $task.GetAwaiter().GetResult()
    }
}

function Revoke-KeeperSharedFolderUserSkipSync {
    <#
    .SYNOPSIS
    Removes a user from a shared folder without a full vault sync (SharedFolderSkipSyncDown.RemoveUserFromSharedFolderAsync).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $User
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $email = ([System.Net.Mail.MailAddress]$User).Address
    if ($PSCmdlet.ShouldProcess("$sfUid", "Remove shared folder access for $email")) {
        $vault = getVault
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::RemoveUserFromSharedFolderAsync($vault.Auth, $sfUid, $email)
        $task.GetAwaiter().GetResult()
    }
}

function Grant-KeeperSharedFolderTeamSkipSync {
    <#
    .SYNOPSIS
    Adds or updates a team on a shared folder without a full vault sync (SharedFolderSkipSyncDown.PutTeamToSharedFolderAsync).
    Team may be a team UID (base64url) or a team name resolved via the same API as the SDK.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $Team,
        [Parameter()][System.Nullable[bool]] $ManageRecords,
        [Parameter()][System.Nullable[bool]] $ManageUsers,
        [Parameter()] $Expiration
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $opts = __NewSharedFolderUserOptionsSkipSync -BoundParameters $PSBoundParameters -ManageRecords $ManageRecords `
        -ManageUsers $ManageUsers -Expiration $Expiration
    if ($PSCmdlet.ShouldProcess("$sfUid", "Grant shared folder access to team $Team")) {
        $vault = getVault
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::PutTeamToSharedFolderAsync($vault.Auth, $sfUid, $Team.Trim(), $opts)
        $task.GetAwaiter().GetResult()
    }
}

function Revoke-KeeperSharedFolderTeamSkipSync {
    <#
    .SYNOPSIS
    Removes a team from a shared folder without a full vault sync (SharedFolderSkipSyncDown.RemoveTeamFromSharedFolderAsync).

    .PARAMETER Team
    Team UID (base64url) or team name (resolved the same way as the SDK RemoveTeam API).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $Team
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    if ($PSCmdlet.ShouldProcess("$sfUid", "Remove shared folder access for team $Team")) {
        $vault = getVault
        $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::RemoveTeamFromSharedFolderAsync($vault.Auth, $sfUid, $Team.Trim())
        $task.GetAwaiter().GetResult()
    }
}

function Get-KeeperAvailableTeamsSkipSync {
    <#
    .SYNOPSIS
    Lists teams available for sharing (SharedFolderSkipSyncDown.GetAvailableTeamsForShareAsync / get_available_teams).
    #>
    [CmdletBinding()]
    Param()

    $vault = getVault
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetAvailableTeamsForShareAsync($vault.Auth)
    $task.GetAwaiter().GetResult()
}

function Get-KeeperTeamUidSkipSync {
    <#
    .SYNOPSIS
    Resolves a team display name to a team UID (SharedFolderSkipSyncDown.GetTeamUidFromNameAsync).
    Throws if the name is missing or ambiguous.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true)][string] $TeamName
    )

    $vault = getVault
    $task = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetTeamUidFromNameAsync($vault.Auth, $TeamName)
    $task.GetAwaiter().GetResult()
}

function __GetSharedFolderObjectFromResponseSkipSync {
    param($GetSharedFoldersResponse, [string]$SharedFolderUid)
    if (-not $GetSharedFoldersResponse -or -not $GetSharedFoldersResponse.SharedFolders) {
        return $null
    }
    $uid = $SharedFolderUid.Trim()
    foreach ($f in $GetSharedFoldersResponse.SharedFolders) {
        if ($f -and [string]::Equals($f.SharedFolderUid, $uid, [StringComparison]::OrdinalIgnoreCase)) {
            return $f
        }
    }
    if ($GetSharedFoldersResponse.SharedFolders.Length -eq 1) {
        return $GetSharedFoldersResponse.SharedFolders[0]
    }
    $null
}

function __TestSharedFolderOwnerIsCurrentUserSkipSync {
    param($SharedFolderObject, [KeeperSecurity.Vault.VaultOnline]$Vault)
    if (-not $SharedFolderObject -or -not $Vault.Auth.AuthContext.AccountUid) {
        return $false
    }
    $owner = $SharedFolderObject.Owner
    if ([string]::IsNullOrWhiteSpace($owner)) {
        return $false
    }
    $myUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($Vault.Auth.AuthContext.AccountUid)
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
    foreach ($r in $Result.Records) {
        $title = $r.Title
        if ([string]::IsNullOrEmpty($title)) { $title = '(no title)' }
        Write-Host "  $($r.Uid): $title"
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

function Get-KeeperSharedFolderRecordsSharedKeySkipSync {
    <#
    .SYNOPSIS
    Lists decrypted records using shared-folder record keys (same as Sample ListSharedFolderRecordsAsync / RecordSkipSyncDown.GetSharedFolderRecordsAsync).

    .PARAMETER SharedFolder
    Shared folder UID, name (if in vault cache), or object with Uid.
    #>
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.RecordDetailsSkipSyncResult])]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter()]
        [ValidateSet('DataPlusShare', 'DataOnly', 'ShareOnly')]
        [string] $Include = 'DataPlusShare'
    )
    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    Get-KeeperSharedFolderRecordsSkipSync -SharedFolderUid $sfUid -Include $Include
}

function Get-KeeperSharedFolderRecordsOwnedSkipSync {
    <#
    .SYNOPSIS
    Lists decrypted records using per-record keys from get_records_details (same as Sample ListSharedFolderRecordsOwnedAsync).

    .PARAMETER SharedFolder
    Shared folder UID, name (if in vault cache), or object with Uid.
    #>
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.RecordDetailsSkipSyncResult])]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter()]
        [ValidateSet('DataPlusShare', 'DataOnly', 'ShareOnly')]
        [string] $Include = 'DataPlusShare'
    )

    $vault = getVault
    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $includeVal = __GetRecordDetailsSkipSyncIncludeValue $Include
    $taskUids = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetRecordUidsFromSharedFolderAsync($vault.Auth, $sfUid)
    $uids = $taskUids.GetAwaiter().GetResult()
    if ($null -eq $uids) {
        $uids = [string[]]@()
    }
    $taskRec = [KeeperSecurity.Vault.RecordSkipSyncDown]::GetOwnedRecordsAsync($vault.Auth, $uids, $includeVal)
    $taskRec.GetAwaiter().GetResult()
}

function Get-KeeperSharedFolderRecordDetailsSkipSync {
    <#
    .SYNOPSIS
    Loads decrypted records for a shared folder. With -Mode Auto, uses owned-record keys when get_shared_folders marks you as folder owner; otherwise uses shared-folder record keys.

    .PARAMETER SharedFolder
    Shared folder UID, name (if in vault cache), or object with Uid.

    .PARAMETER Mode
    Auto (default): choose by owner flag from get_shared_folders. SharedKey: always GetSharedFolderRecordsAsync. OwnedKey: always GetRecordUids + GetOwnedRecordsAsync.

    .PARAMETER Show
    Print a short listing to the host (like the C# sample), in addition to returning the result object.
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
        [Parameter()][switch] $Show
    )

    $vault = getVault
    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $useOwned = $false
    if ($Mode -eq 'OwnedKey') {
        $useOwned = $true
    }
    elseif ($Mode -eq 'SharedKey') {
        $useOwned = $false
    }
    else {
        $taskFolder = [KeeperSecurity.Vault.SharedFolderSkipSyncDown]::GetSharedFolderAsync($vault.Auth, $sfUid)
        $folderRs = $taskFolder.GetAwaiter().GetResult()
        $sfObj = __GetSharedFolderObjectFromResponseSkipSync $folderRs $sfUid
        $useOwned = __TestSharedFolderOwnerIsCurrentUserSkipSync $sfObj $vault
    }

    $result = if ($useOwned) {
        Get-KeeperSharedFolderRecordsOwnedSkipSync -SharedFolder $sfUid -Include $Include
    }
    else {
        Get-KeeperSharedFolderRecordsSharedKeySkipSync -SharedFolder $sfUid -Include $Include
    }

    if ($Show) {
        __WriteRecordDetailsSkipSyncResult $result
    }
    $result
}

function Set-KeeperSharedFolderUserSkipSync {
    <#
    .SYNOPSIS
    Same as Grant-KeeperSharedFolderUserSkipSync, then prints decrypted folder records (Sample PutUserToSharedFolder).

    .PARAMETER PassThru
    Returns RecordDetailsSkipSyncResult after listing.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $User,
        [Parameter()][System.Nullable[bool]] $ManageRecords,
        [Parameter()][System.Nullable[bool]] $ManageUsers,
        [Parameter()] $Expiration,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $grantParams = @{ SharedFolder = $SharedFolder; User = $User }
    if ($PSBoundParameters.ContainsKey('ManageRecords')) { $grantParams['ManageRecords'] = $ManageRecords }
    if ($PSBoundParameters.ContainsKey('ManageUsers')) { $grantParams['ManageUsers'] = $ManageUsers }
    if ($PSBoundParameters.ContainsKey('Expiration')) { $grantParams['Expiration'] = $Expiration }
    Grant-KeeperSharedFolderUserSkipSync @grantParams -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -Verbose:$VerbosePreference

    if (-not $WhatIfPreference) {
        $listed = Get-KeeperSharedFolderRecordsSharedKeySkipSync -SharedFolder $sfUid
        __WriteRecordDetailsSkipSyncResult $listed "No records listed on this shared folder (user $User has folder access)."
        if ($PassThru) { $listed }
    }
}

function Remove-KeeperSharedFolderUserSkipSync {
    <#
    .SYNOPSIS
    Same as Revoke-KeeperSharedFolderUserSkipSync, then prints decrypted folder records (Sample RemoveUserFromSharedFolder).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $User,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    Revoke-KeeperSharedFolderUserSkipSync -SharedFolder $SharedFolder -User $User -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -Verbose:$VerbosePreference

    if (-not $WhatIfPreference) {
        $listed = Get-KeeperSharedFolderRecordsSharedKeySkipSync -SharedFolder $sfUid
        __WriteRecordDetailsSkipSyncResult $listed 'No records listed on this shared folder after remove.'
        if ($PassThru) { $listed }
    }
}

function Set-KeeperSharedFolderTeamSkipSync {
    <#
    .SYNOPSIS
    Same as Grant-KeeperSharedFolderTeamSkipSync, then prints decrypted folder records (Sample PutTeamToSharedFolder).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $Team,
        [Parameter()][System.Nullable[bool]] $ManageRecords,
        [Parameter()][System.Nullable[bool]] $ManageUsers,
        [Parameter()] $Expiration,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    $grantParams = @{ SharedFolder = $SharedFolder; Team = $Team }
    if ($PSBoundParameters.ContainsKey('ManageRecords')) { $grantParams['ManageRecords'] = $ManageRecords }
    if ($PSBoundParameters.ContainsKey('ManageUsers')) { $grantParams['ManageUsers'] = $ManageUsers }
    if ($PSBoundParameters.ContainsKey('Expiration')) { $grantParams['Expiration'] = $Expiration }
    Grant-KeeperSharedFolderTeamSkipSync @grantParams -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -Verbose:$VerbosePreference

    if (-not $WhatIfPreference) {
        $listed = Get-KeeperSharedFolderRecordsSharedKeySkipSync -SharedFolder $sfUid
        __WriteRecordDetailsSkipSyncResult $listed "No records listed on this shared folder (team $Team has folder access)."
        if ($PassThru) { $listed }
    }
}

function Remove-KeeperSharedFolderTeamSkipSync {
    <#
    .SYNOPSIS
    Same as Revoke-KeeperSharedFolderTeamSkipSync, then prints decrypted folder records (Sample RemoveTeamFromSharedFolder).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $SharedFolder,
        [Parameter(Mandatory = $true)][string] $Team,
        [Parameter()][switch] $PassThru
    )

    $sfUid = __ResolveSharedFolderUidSkipSync $SharedFolder
    Revoke-KeeperSharedFolderTeamSkipSync -SharedFolder $SharedFolder -Team $Team -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -Verbose:$VerbosePreference

    if (-not $WhatIfPreference) {
        $listed = Get-KeeperSharedFolderRecordsSharedKeySkipSync -SharedFolder $sfUid
        __WriteRecordDetailsSkipSyncResult $listed 'No records listed on this shared folder after remove.'
        if ($PassThru) { $listed }
    }
}
