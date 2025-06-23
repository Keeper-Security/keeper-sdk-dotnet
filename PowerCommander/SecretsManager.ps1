#requires -Version 5.1

$Keeper_KSMAppCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [KeeperSecurity.Vault.VaultOnline]$private:vault = getVault
    if (-not $vault) {
        return $null
    }

    $toComplete = $wordToComplete
    if ($toComplete.Length -ge 1) {
        if ($toComplete[0] -eq '''') {
            $toComplete = $toComplete.Substring(1, $toComplete.Length - 1)
            $toComplete = $toComplete -replace '''''', ''''
        }
        if ($toComplete[0] -eq '"') {
            $toComplete = $toComplete.Substring(1, $toComplete.Length - 1)
            $toComplete = $toComplete -replace '""', '"'
            $toComplete = $toComplete -replace '`"', '"'
        }
    }

    $toComplete += '*'
    foreach ($app in $vault.KeeperApplications) {
        if ($app.Title -like $toComplete) {
            $name = $app.Title
            if ($name -match ' ') {
                $name = $name -replace '''', ''''''
                $name = '''' + $name + ''''
            }
            $result += $name
        }
    }

    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Get-KeeperSecretManagerApp {
    <#
        .Synopsis
        Get Keeper Secret Manager Applications

        .Parameter Uid
        Record UID

        .Parameter Filter
        Return matching applications only

        .Parameter Detail
        Application details
    #>
    [CmdletBinding()]
    Param (
        [string] $Uid,
        [string] $Filter,
        [Switch] $Detail
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if ($Uid) {
        [KeeperSecurity.Vault.ApplicationRecord] $application = $null
        if ($vault.TryGetKeeperRecord($Uid, [ref]$application)) {
            if (-not $application.Type -eq 'app') {
                throw "No application found with UID '$Uid'."
            }
            if ($Detail.IsPresent) {
                return $vault.GetSecretManagerApplication($application.Uid, $false).GetAwaiter().GetResult()
            }
            else {
                return $application
            }
        }
        else {
            throw "No application found with UID '$Uid'."
        }
    }
    else {
        $applications = $vault.KeeperRecords | Where-Object { $_.Type -eq 'app' }
        $results = @()

        foreach ($application in $applications) {
            if ($Filter) {
                $match = @($application.Uid, $application.Title) | Select-String $Filter | Select-Object -First 1
                if (-not $match) {
                    continue
                }
            }
            if ($Detail.IsPresent) {
                $results += $vault.GetSecretManagerApplication($application.Uid, $false).GetAwaiter().GetResult()
            }
            else {
                $results += $application
            }
        }
        return $results
    }
}
New-Alias -Name ksm -Value Get-KeeperSecretManagerApp

function Add-KeeperSecretManagerApp {
    <#
        .Synopsis
        Creates Keeper Secret Manager Application

        .Parameter Name
        Secret Manager Application
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string]$AppName
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $vault.CreateSecretManagerApplication($AppName).GetAwaiter().GetResult()
}
New-Alias -Name ksm-create -Value Add-KeeperSecretManagerApp

function Grant-KeeperSecretManagerFolderAccess {
    <#
        .Synopsis
        Adds shared folder to KSM Application

        .Parameter App
       KSM Application UID or Title

        .Parameter Secret
       Shared Folder UID or Name

        .Parameter CanEdit
        Enable write access to shared secrets

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter()][switch]$CanEdit
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApp -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    [string]$uid = $null
    $sfs = Get-KeeperSharedFolder -Filter $Secret
    if ($sfs) {
        $uid = $sfs[0].Uid
    }
    else {
        $recs = Get-KeeperRecord -Filter $Secret
        if ($recs) {
            $uid = $recs[0].Uid
        }
    }
    if (-not $uid) {
        Write-Error -Message "Cannot find Shared Folder: $Secret" -ErrorAction Stop
    }
    $vault.ShareToSecretManagerApplication($application.Uid, $uid, $CanEdit.IsPresent).GetAwaiter().GetResult()
}
Register-ArgumentCompleter -CommandName Grant-KeeperSecretManagerFolderAccess -ParameterName Secret -ScriptBlock $Keeper_SharedFolderCompleter
Register-ArgumentCompleter -CommandName Grant-KeeperSecretManagerFolderAccess -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-share -Value Grant-KeeperSecretManagerFolderAccess

function Revoke-KeeperSecretManagerFolderAccess {
    <#
        .Synopsis
        Removes Shared Folder from KSM Application

        .Parameter App
        Secret Manager Application

        .Parameter Secret
       Shared Folder UID or Name
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter(Mandatory = $true)][string]$Secret
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApp -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    [string]$uid = $null
    $sfs = Get-KeeperSharedFolder -Filter $Secret
    if ($sfs) {
        $uid = $sfs[0].Uid
    }
    else {
        $recs = Get-KeeperRecord -Filter $Secret
        if ($recs) {
            $uid = $recs[0].Uid
        }
    }
    if (-not $uid) {
        Write-Error -Message "Cannot find Shared Folder: $Secret" -ErrorAction Stop
    }
    $vault.UnshareFromSecretManagerApplication($application.Uid, $uid).GetAwaiter().GetResult()
}
Register-ArgumentCompleter -CommandName Revoke-KeeperSecretManagerFolderAccess -ParameterName Secret -ScriptBlock $Keeper_SharedFolderCompleter
Register-ArgumentCompleter -CommandName Revoke-KeeperSecretManagerFolderAccess -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-unshare -Value Revoke-KeeperSecretManagerFolderAccess

function Add-KeeperSecretManagerClient {
    <#
        .Synopsis
        Adds client/device to KSM Application

        .Parameter App
        KSM Application UID or Title

        .Parameter Name
        Client or Device Name

        .Parameter UnlockIP
        Enable write access to shared secrets
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter()][string]$Name,
        [Parameter()][switch]$UnlockIP,
        [Parameter()][switch]$B64
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApp -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    $rs = $vault.AddSecretManagerClient($application.Uid, $UnlockIP.IsPresent, $null, $null, $name).GetAwaiter().GetResult()
    if ($rs) {
        if ($B64.IsPresent) {
            $configuration = $vault.GetConfiguration($rs.Item2).GetAwaiter().GetResult()
            if ($configuration) {
                $configData = [KeeperSecurity.Utils.JsonUtils]::DumpJson($configuration, $true)
                [System.Convert]::ToBase64String($configData)
        
            }
        }
        else {
            $rs.Item2
        }
    
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperSecretManagerClient -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-addclient -Value Add-KeeperSecretManagerClient

function Remove-KeeperSecretManagerClient {
    <#
        .Synopsis
        Removes client/device from KSM Application

        .Parameter App
        KSM Application UID or Title

        .Parameter Name
        Client Id or Device Name

    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter(Mandatory = $true)][string]$Name
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApp -Filter $App -Detail
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    $device = $application.Devices | Where-Object { $_.Name -ceq $Name -or $_.ShortDeviceId -ceq $Name }
    if (-not $device) {
        Write-Error -Message "Cannot find Device: $Name" -ErrorAction Stop
    }

    if ($PSCmdlet.ShouldProcess($application.Title, "Removing KSM Device '$($device.Name)'")) {
        $vault.DeleteSecretManagerClient($application.Uid, $device.DeviceId).GetAwaiter().GetResult() | Out-Null
        Write-Information -MessageData "Device $($device.Name) has been deleted from KSM application `"$($application.Title)`"."
    }
}

Register-ArgumentCompleter -CommandName Remove-KeeperSecretManagerClient -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-rmclient -Value Remove-KeeperSecretManagerClient

function Test-KeeperUserNeedsUpdate {
    <#
    .SYNOPSIS
        Determines whether any of the user's record or folder shares need to be updated.

    .DESCRIPTION
        Iterates through a list of share UIDs and checks if any need their permissions updated
        for the given user.

    .PARAMETER Vault
        The Keeper VaultOnline context.

    .PARAMETER User
        The username/email of the user.

    .PARAMETER IsAdmin
        True if full permissions (edit/share/manage) are expected.

    .PARAMETER ShareUids
        A list of UIDs representing shared records or folders.

    .PARAMETER ApplicationUid
        The UID of the Secrets Manager Application record.

    .OUTPUTS
        Boolean — True if any share requires an update for the user.
    #>

    param (
        [Parameter(Mandatory)]
        $vault,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [bool]$IsAdmin,

        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$ShareUids,

        [Parameter(Mandatory)]
        [string]$ApplicationUid
    )

    foreach ($uid in $ShareUids) {
        $needsUpdate = Test-KeeperShareNeedsUpdate -Vault $vault -User $User -ShareUid $uid -Elevated $IsAdmin -ApplicationUid $ApplicationUid
        if ($needsUpdate) {
            return $true
        }
    }

    return $false
}

function Test-KeeperShareNeedsUpdate {
    <#
    .SYNOPSIS
        Determines whether a share (record or folder) needs its permissions updated for a user.

    .DESCRIPTION
        Compares current permissions of a user on a shared record or shared folder against expected `elevated` (admin) status.

    .PARAMETER Vault
        The VaultOnline object.

    .PARAMETER User
        Username/email of the user being evaluated.

    .PARAMETER ShareUid
        UID of the shared record or shared folder.

    .PARAMETER Elevated
        $true for admin-level (edit/share or manage), $false otherwise.

    .PARAMETER ApplicationUid
        UID of the Secrets Manager application record.

    .OUTPUTS
        [bool] — $true if an update is required, $false if current permissions match expected.
    #>

    param (
        [Parameter(Mandatory)] $Vault,
        [Parameter(Mandatory)] [string] $User,
        [Parameter(Mandatory)] [string] $ShareUid,
        [Parameter(Mandatory)] [bool] $Elevated,
        [Parameter(Mandatory)] [string] $ApplicationUid
    )

    $appInfo = $vault.GetSecretManagerApplication($ApplicationUid, $true).GetAwaiter().GetResult()

    if (-not $appInfo) {
        return $false
    }

    $isRecordShare = $false
    foreach ($share in $appInfo.Shares) {
        $shareId = $share.SecretUid
        $recordTypeEnum = [KeeperSecurity.Vault.SecretManagerSecretType]::Record
        if ($shareId -eq $ShareUid -and $share.SecretType -eq $recordTypeEnum) {
            $isRecordShare = $true
            break
        }
    }

    if ($isRecordShare) {
        $recordUids = [System.Collections.Generic.List[string]]::new()
        $recordUids.Add($ShareUid)

        $recordShares = $Vault.GetSharesForRecords($recordUids).GetAwaiter().GetResult()
        $shareInfo = $recordShares | Where-Object { $_.RecordUid -eq $ShareUid }

        if (-not $shareInfo) {
            return $false
        }

        $userPerms = $shareInfo.UserPermissions | Where-Object { $_.Username -eq $User }
        if (-not $userPerms) {
            return $true
        }

        return ($userPerms.CanEdit -ne $Elevated -or $userPerms.CanShare -ne $Elevated)
    }
    else {
        $sharedFolder = $null
        if (-not $Vault.TryGetSharedFolder($ShareUid, [ref]$sharedFolder)) {
            return $false
        }

        $folderPerms = $sharedFolder.UsersPermissions | Where-Object { $_.Uid -eq $User }
        if (-not $folderPerms) {
            return $true
        }

        return ($folderPerms.ManageUsers -ne $Elevated -or $folderPerms.ManageRecords -ne $Elevated)
    }
}


function Invoke-KeeperSharedFolderShareAction {
    <#
    .SYNOPSIS
        Adds or removes users from shared folders based on permission needs.

    .DESCRIPTION
        For each shared folder and user, checks if permissions are out of sync. If so:
        - Removes user from the folder if action is "remove"
        - Adds/updates user with appropriate permissions if action is "add"

    .PARAMETER Vault
        The VaultOnline context.

    .PARAMETER ApplicationUid
        UID of the Secrets Manager Application.

    .PARAMETER SharedFolders
        A list of shared folder UIDs.

    .PARAMETER Group
        The group name ("admins" or other) to determine permission level.

    .PARAMETER Users
        List of user emails or UIDs.

    .PARAMETER ShareFolderAction
        Either "remove" or "add" to define how permissions should be applied.

    .EXAMPLE
        Invoke-KeeperSharedFolderShareAction -Vault $vault -ApplicationUid "abc123" -SharedFolders @("UID1") -Group "admins" -Users @("user@example.com") -ShareFolderAction "add"
    #>

    param (
        [Parameter(Mandatory)]
        $vault,

        [Parameter(Mandatory)]
        [string]$ApplicationUid,

        [Parameter(Mandatory)]
        [string[]]$SharedFolders,

        [Parameter(Mandatory)]
        [string]$Group,

        [Parameter(Mandatory)]
        [string[]]$Users,

        [Parameter(Mandatory)]
        [ValidateSet("grant", "remove")]
        [string]$ShareFolderAction
    )

    foreach ($folder in $SharedFolders) {
        foreach ($user in $Users) {
            $isAdmin = ($Group -eq "admins")
            $needsUpdate = Test-KeeperShareNeedsUpdate -Vault $vault -User $user -ShareUid $folder -Elevated $isAdmin -ApplicationUid $ApplicationUid

            if ($needsUpdate) {
                if ($ShareFolderAction -eq "remove") {
                    Write-Debug "Removing user '$user' from shared folder '$folder'..."
                    $vault.RemoveUserFromSharedFolder($folder, $user, [KeeperSecurity.Vault.UserType]::User).GetAwaiter().GetResult() | Out-Null
                }
                else {
                    Write-Debug "Adding user '$user' to shared folder '$folder' with permissions (admin: $isAdmin)..."
                    $options = New-Object KeeperSecurity.Vault.SharedFolderUserOptions
                    $options.ManageUsers = $isAdmin
                    $options.ManageRecords = $isAdmin
                    $vault.PutUserToSharedFolder($folder, $user, [KeeperSecurity.Vault.UserType]::User, $options).GetAwaiter().GetResult() | Out-Null
                }
            }
        }
    }
}

function Invoke-KeeperHandleRecordShares {
    <#
    .SYNOPSIS
        Shares or revokes Keeper records for specified users based on group access level.

    .DESCRIPTION
        Iterates over records and users. If the user's permissions are out of sync:
        - Revokes the share if 'revoke' action is specified.
        - Otherwise, shares the record with edit/share permissions if the group is 'admins'.

    .PARAMETER Vault
        VaultOnline session object.

    .PARAMETER ApplicationUid
        UID of the application record (used to resolve appInfo for permission checks).

    .PARAMETER RecordShares
        List of records with RecordUid properties (e.g., RecordSharePermissions objects).

    .PARAMETER Group
        Group string ("admins" or anything else), used to determine full or limited permission.

    .PARAMETER Users
        List of user emails to apply actions to.

    .PARAMETER ShareRecordAction
        "revoke" to remove access, anything else to add/update the share.

    .EXAMPLE
        Invoke-KeeperHandleRecordShares -Vault $vault -ApplicationUid "abc123" -RecordShares $records -Group "admins" -Users @("user@example.com") -ShareRecordAction "add"
    #>

    param (
        [Parameter(Mandatory)]
        $vault,

        [Parameter(Mandatory)]
        [string]$ApplicationUid,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$RecordShares,

        [Parameter(Mandatory)]
        [string]$Group,

        [Parameter(Mandatory)]
        [string[]]$Users,

        [Parameter(Mandatory)]
        [ValidateSet("revoke", "share")]
        [string]$ShareRecordAction
    )

    foreach ($record in $RecordShares) {
        $recordUid = $record.RecordUid
        foreach ($user in $Users) {
            $isAdmin = ($Group -eq "admins")

            $needsUpdate = Test-KeeperShareNeedsUpdate -Vault $vault -User $user -ShareUid $recordUid -Elevated $isAdmin -ApplicationUid $ApplicationUid

            if ($needsUpdate) {
                if ($ShareRecordAction -eq "revoke") {
                    Write-Debug "Revoking user '$user' from record '$recordUid'..."
                    $vault.RevokeShareFromUser($recordUid, $user).GetAwaiter().GetResult() | Out-Null
                }
                else {
                    Write-Debug "Sharing record '$recordUid' with user '$user' (Edit: $isAdmin, Share: $isAdmin)..."
                    $options = New-Object KeeperSecurity.Vault.SharedFolderRecordOptions
                    $options.CanEdit = $isAdmin
                    $options.CanShare = $isAdmin
                    $vault.ShareRecordWithUser($recordUid, $user, $options).GetAwaiter().GetResult() | Out-Null
                }
            }
        }
    }
}

function Update-KeeperShareUserPermissions {
    <#
    .SYNOPSIS
        Updates app-related record and shared folder permissions for a given user.

    .DESCRIPTION
        Based on existing share state, grants/revokes appropriate permissions across shared folders and records.
        Uses app record metadata to determine what to share and with whom.

    .PARAMETER Vault
        The VaultOnline object.

    .PARAMETER ApplicationUid
        The UID of the Secrets Manager Application record.

    .PARAMETER UserUid
        The username or email of the user whose permissions need update.

    .PARAMETER Removed
        Optional string flag to indicate user should be unshared. If null, grants are applied instead.

    .EXAMPLE
        Update-KeeperShareUserPermissions -Vault $vault -ApplicationUid "abc123" -UserUid "bob@example.com"

        Update-KeeperShareUserPermissions -Vault $vault -ApplicationUid "abc123" -UserUid "bob@example.com" -Removed "true"
    #>

    param (
        [Parameter(Mandatory)]
        $vault,

        [Parameter(Mandatory)]
        [string]$ApplicationUid,

        [Parameter(Mandatory)]
        [string]$UserUid,

        [string]$Removed
    )
    $ApplicationUidsForShare = [System.Collections.Generic.List[string]]::new()
    $ApplicationUidsForShare.Add($ApplicationUid)

    $appShares = $vault.GetSharesForRecords($ApplicationUidsForShare).GetAwaiter().GetResult()
    $userPermissions = ($appShares | Where-Object { $_.RecordUid -eq $ApplicationUid }).UserPermissions

    $appInfo = $vault.GetSecretManagerApplication($ApplicationUid, $true).GetAwaiter().GetResult()

    $recordTypeEnum = [KeeperSecurity.Vault.SecretManagerSecretType]::Record
    $folderTypeEnum = [KeeperSecurity.Vault.SecretManagerSecretType]::Folder

    $shareUids = $appInfo.Shares | ForEach-Object { $_.SecretUid }
    $sharesRecords = $appInfo.Shares | Where-Object { $_.SecretType -eq $recordTypeEnum } | ForEach-Object { $_.SecretUid }
    $sharedFolders = $appInfo.Shares | Where-Object { $_.SecretType -eq $folderTypeEnum } | ForEach-Object { $_.SecretUid }

    $RecordUidsForShare = [System.Collections.Generic.List[string]]::new()
    if($null -ne $sharesRecords){
        $sharesRecords | ForEach-Object { $RecordUidsForShare.Add($_) }
    }
    $recordShares = $vault.GetSharesForRecords($RecordUidsForShare).GetAwaiter().GetResult()

    $admins = $userPermissions | Where-Object { $_.CanEdit -and $_.Username -ne $vault.Auth.Username } | Select-Object -ExpandProperty Username
    $viewers = $userPermissions | Where-Object { -not $_.CanEdit } | Select-Object -ExpandProperty Username
    $removedUsers = if ($Removed) { @($UserUid) } else { @() }

    $appUsersMap = @{
        "admins"  = $admins
        "viewers" = $viewers
        "removed" = $removedUsers
    }

    foreach ($group in $appUsersMap.Keys) {
        $usersList = $appUsersMap[$group]
        if ($usersList.Count -eq 0) { continue }

        $userResults = @()
        foreach ($user in $usersList) {
            $needsUpdate = Test-KeeperUserNeedsUpdate -Vault $vault -User $user -IsAdmin:($group -eq "admins") -ShareUids $shareUids -ApplicationUid $ApplicationUid
            if ($needsUpdate) {
                $userResults += $user
            }
        }

        $shareFolderAction = if ($Removed) { "remove" } else { "grant" }
        $shareRecordAction = if ($Removed) { "revoke" } else { "share" }

        Invoke-KeeperSharedFolderShareAction -Vault $vault -ApplicationUid $ApplicationUid -SharedFolders $sharedFolders -Group $group -Users $userResults -ShareFolderAction $shareFolderAction
        Invoke-KeeperHandleRecordShares -Vault $vault -ApplicationUid $ApplicationUid -RecordShares $recordShares -Group $group -Users $userResults -ShareRecordAction $shareRecordAction
    }
}

function Test-KeeperUserIsSharable {
    <#
    .SYNOPSIS
        Verifies if a given user UID is eligible for record sharing.

    .DESCRIPTION
        Calls `GetUsersForShare()` and checks if the specified user is in `GroupUsers` or `SharesWith`.
        Throws if no shareable users are available at all.

    .PARAMETER vault
        The VaultOnline object.

    .PARAMETER UserUid
        The UID or email of the user to validate for sharing.

    .OUTPUTS
        Boolean — $true if the user can be shared with, otherwise $false.

    .EXAMPLE
        Test-KeeperUserIsSharable -Vault $vault -UserUid "alice@example.com"
    #>

    param (
        [Parameter(Mandatory)]
        $vault,

        [Parameter(Mandatory)]
        [string]$UserUid
    )

    $users = $vault.GetUsersForShare().GetAwaiter().GetResult()

    if (-not $users -or ($users.SharesFrom.Count -eq 0 -and $users.GroupUsers.Count -eq 0 -and $users.SharesWith.Count -eq 0)) {
        Write-Error "No users found for sharing."
        throw "No users found for sharing. [ShareSecretsManagerApplicationWithUser: userUid=$UserUid]"
    }

    if ($users.GroupUsers -contains $UserUid -or $users.SharesWith -contains $UserUid) {
        return $true
    }
    else {
        Write-Host "User '$UserUid' is not found in the list of users eligible for sharing."
        return $false
    }
}

function Invoke-KeeperHandleAppSharePermissions {
    <#
    .SYNOPSIS
        Shares or revokes the Keeper Secrets Manager application record with a user.

    .DESCRIPTION
        If sharing, checks whether the user is eligible for sharing. If not, sends an invite.
        If unsharing, revokes the user's access to the application record.

    .PARAMETER Vault
        The VaultOnline object.

    .PARAMETER AppInfo
        The AppInfo object representing the application and its shares.

    .PARAMETER UserUid
        The UID (email) of the user.

    .PARAMETER IsAdmin
        If true, grants CanEdit and CanShare permissions.

    .PARAMETER Unshare
        If true, revokes the share instead of granting it.

    .EXAMPLE
        Invoke-KeeperHandleAppSharePermissions -Vault $vault -AppInfo $appInfo -UserUid "alice@example.com" -IsAdmin $true -Unshare:$false
    #>

    param (
        [Parameter(Mandatory)]
        $Vault,

        [Parameter(Mandatory)]
        $AppInfo,

        [Parameter(Mandatory)]
        [string]$UserUid,

        [Parameter(Mandatory)]
        [bool]$IsAdmin,

        [Parameter(Mandatory)]
        [bool]$Unshare
    )

    $recordUid = $AppInfo.Uid

    if (-not $Unshare) {
        $isShareable = Test-KeeperUserIsSharable -Vault $Vault -UserUid $UserUid

        if (-not $isShareable) {
            $Vault.SendShareInvitationRequest($UserUid).GetAwaiter().GetResult() | Out-Null
            Write-Host "Share invitation request has been sent to user '$UserUid'. Please wait for the user to accept before sharing the application."
            return
        }

        $recordPermissions = New-Object KeeperSecurity.Vault.SharedFolderRecordOptions
        $recordPermissions.CanEdit = $IsAdmin
        $recordPermissions.CanShare = $IsAdmin

        Write-Debug "Sharing application record '$recordUid' with user '$UserUid' (Edit: $IsAdmin, Share: $IsAdmin)..."
        $Vault.ShareRecordWithUser($recordUid, $UserUid, $recordPermissions).GetAwaiter().GetResult() | Out-Null
    }
    else {
        Write-Debug "Revoking user '$UserUid' from application record '$recordUid'..."
        $Vault.RevokeShareFromUser($recordUid, $UserUid).GetAwaiter().GetResult() | Out-Null
    }
}


function Invoke-KeeperAppShareWithUser {
    <#
    .SYNOPSIS
        Shares or unshares a Secrets Manager Application with a user.

    .DESCRIPTION
        Handles full flow of granting/revoking access to an application record, its shared folders,
        and records by calling permission update helpers and syncing the vault state.

    .PARAMETER ApplicationId
        UID of the Application record.

    .PARAMETER UserUid
        Username or email of the target user.

    .PARAMETER Unshare
        Switch to unshare instead of share.

    .PARAMETER IsAdmin
        Whether to give full edit/share/manage access when sharing.

    .EXAMPLE
        Invoke-KeeperAppShareWithUser -Vault $vault -ApplicationId "abc123" -UserUid "alice@example.com" -IsAdmin $true

    .EXAMPLE
        Invoke-KeeperAppShareWithUser -Vault $vault -ApplicationId "abc123" -UserUid "bob@example.com" -Unshare
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter(Mandatory)]
        [string]$UserUid,

        [Parameter()]
        [switch]$Unshare,

        [Parameter()]
        [switch]$IsAdmin
    )

    [KeeperSecurity.Vault.VaultOnline]$private:vault = getVault
    $record = $null
    
    if (-not $vault) {
        return $null
    }

    if (-not $vault.TryGetKeeperRecord($ApplicationId, [ref]$record)) {
        throw "Application record not found for UID '$ApplicationId'"
    }

    if (-not ($record -is [KeeperSecurity.Vault.ApplicationRecord])) {
        throw "Record with UID '$ApplicationId' is not an application record."
    }

    $application = [KeeperSecurity.Vault.ApplicationRecord]$record

    $appInfo = $vault.GetSecretManagerApplication($ApplicationId, $true).GetAwaiter().GetResult()

    if (-not $appInfo) {
        throw "AppInfo not found for application UID '$($application.Uid)'"
    }

    Invoke-KeeperHandleAppSharePermissions -Vault $vault -AppInfo $appInfo -UserUid $UserUid -IsAdmin $IsAdmin.IsPresent -Unshare $Unshare.IsPresent

    $vault.SyncDown().GetAwaiter().GetResult() | Out-Null

    $removedUser = if ($Unshare.IsPresent) { $UserUid } else { $null }
    Update-KeeperShareUserPermissions -Vault $vault -ApplicationUid $ApplicationId -UserUid $UserUid -Removed $removedUser

    # Do a Full Sync
    $vault.Storage.Clear()
    $vault.Storage.VaultSettings.Load()
    $vault.ScheduleSyncDown([TimeSpan]::FromMilliseconds(0)) | Out-Null
}

function Grant-KeeperAppAccess {
    <#
    .SYNOPSIS
        Grants a user access to a Secrets Manager Application.

    .DESCRIPTION
        Shares the application record, associated shared folders, and records
        with the specified user. Supports admin or viewer level access.

    .PARAMETER ApplicationId
        UID of the application record.

    .PARAMETER UserUid
        Email or UID of the user to grant access to.

    .PARAMETER IsAdmin
        If specified, grants edit/share/manage permissions (admin access).

    .EXAMPLE
        Grant-KeeperAppAccess -ApplicationId "abc123" -UserUid "alice@example.com" -IsAdmin
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter(Mandatory)]
        [string]$UserUid,

        [Parameter()]
        [switch]$IsAdmin
    )

    try {
        Write-Host "Granting Secrets Manager application access to '$UserUid'..." -ForegroundColor Cyan

        Invoke-KeeperAppShareWithUser -ApplicationId $ApplicationId -UserUid $UserUid -IsAdmin:$IsAdmin

        Write-Host "Successfully granted access to application '$ApplicationId' for user '$UserUid'." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to grant access to '$UserUid'. Error: $_" -ForegroundColor Red
    }
}


function Revoke-KeeperAppAccess {
    <#
    .SYNOPSIS
        Revokes a user's access to a Secrets Manager Application.

    .DESCRIPTION
        Unshares the application record, shared folders, and any related records
        from the specified user and updates permissions accordingly.

    .PARAMETER ApplicationId
        UID of the application record.

    .PARAMETER UserUid
        Email or UID of the user to revoke access from.

    .EXAMPLE
        Revoke-KeeperAppAccess -ApplicationId "abc123" -UserUid "bob@example.com"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter(Mandatory)]
        [string]$UserUid
    )

    try {
        Write-Host "Revoking Secrets Manager application access from '$UserUid'..." -ForegroundColor Cyan

        Invoke-KeeperAppShareWithUser -ApplicationId $ApplicationId -UserUid $UserUid -Unshare

        Write-Host "Successfully revoked access to application '$ApplicationId' from user '$UserUid'." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to revoke access from '$UserUid'. Error: $_" -ForegroundColor Red
    }
}
