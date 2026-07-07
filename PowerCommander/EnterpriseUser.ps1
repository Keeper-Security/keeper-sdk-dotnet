# Enterprise User Management Functions

function Add-KeeperEnterpriseUser {
    <#
    .SYNOPSIS
    Invites Enterprise Users

    .PARAMETER Node
    Node Name or ID

    .PARAMETER Email
    Email address to invite

    .PARAMETER Emails
    Extra email addresses to invite
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $FullName,        
        [Parameter()][string] $Node,        
        [Parameter(Position = 0, Mandatory = $true)] $Email,
        [Parameter(ValueFromRemainingArguments = $true)] $Emails
    )

    [Enterprise]$enterprise = getEnterprise
    [Int64] $nodeId = 0
    if ($Node) {
        $n = resolveSingleNode $Node
        if ($n) {
            $nodeId = $n.Id
        }
    } else {
        $nodeId = $enterprise.enterpriseData.RootNode.Id
    }

    $inviteOptions = New-Object KeeperSecurity.Enterprise.InviteUserOptions
    if ($nodeId -gt 0) {
        $inviteOptions.NodeId = $nodeId
    }
    if ($FullName) {
        $inviteOptions.FullName = $FullName
    }

    $user = $enterprise.enterpriseData.InviteUser($Email, $inviteOptions).GetAwaiter().GetResult()
    if ($user) {
        Write-Output "User `"$Email`" is invited"
    }

    $inviteOptions.FullName = $null
    foreach ($e in $Emails) {
        $user = $enterprise.enterpriseData.InviteUser($e, $inviteOptions).GetAwaiter().GetResult()
        if ($user) {
            Write-Output "User `"$e`" is invited"
        }
    }
}
New-Alias -Name invite-user -Value Add-KeeperEnterpriseUser

function Lock-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Locks Enterprise User

        .Parameter User
	    User email, enterprise Id, or instance.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    $saved = $enterprise.enterpriseData.SetUserLocked($userObject, $true).GetAwaiter().GetResult()
    if ($saved) {
        Write-Output "User `"$($saved.Email)`" was locked"
    }
}
Register-ArgumentCompleter -CommandName Lock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name lock-user -Value Lock-KeeperEnterpriseUser

function Unlock-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Unlocks Enterprise User

        .Parameter User
	    User email, enterprise Id, or instance.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    $saved = $enterprise.enterpriseData.SetUserLocked($userObject, $false).GetAwaiter().GetResult()
    if ($saved) {
        Write-Output "User `"$($saved.Email)`" was unlocked"
    }
}
Register-ArgumentCompleter -CommandName Unlock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_LockedUserCompleter
New-Alias -Name unlock-user -Value Unlock-KeeperEnterpriseUser

function Move-KeeperEnterpriseUser {
    <#
        .Synopsis
        Transfers an enterprise user's vault (records, shared folders, teams) to another user

        .Parameter FromUser
        Email or enterprise user ID of the source user whose vault will be transferred

        .Parameter TargetUser
        Email or enterprise user ID of the destination user who will receive the vault

        .Parameter Force
        Skip confirmation prompt in non-interactive sessions

        .Description
        Transfers all records, shared folders, and team memberships from one enterprise user to another.
        The source user's vault contents are merged into the target user's vault. Use -Force to skip
        confirmation in automated scripts.

        .Example
        Move-KeeperEnterpriseUser -FromUser "departing@company.com" -TargetUser "replacement@company.com"
        Transfers the departing user's vault to the replacement user (prompts for confirmation)

        .Example
        transfer-user "departing@company.com" "replacement@company.com" -Force
        Transfers vault without confirmation prompt
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$FromUser,
        [Parameter(Position = 1, Mandatory = $true)]$TargetUser,
        [Switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise

    $fromUserObject = resolveUser $enterprise.enterpriseData $FromUser
    if (-not $fromUserObject) {
        return
    }
    $targetUserObject = resolveUser $enterprise.enterpriseData $TargetUser
    if (-not $targetUserObject) {
        return
    }
    if (-not $Force.IsPresent) {
        if (Test-InteractiveSession) {
            Write-Output "This action cannot be undone.`n"
            $answer = Read-Host -Prompt "Do you want to proceed with transferring $($fromUserObject.Email) account (Yes/No)? > "
        }
        else {
            Write-Output('Non-interactive session. Use -Force parameter')
            $answer = 'no'
        }
        if ($answer -ne 'yes' -and $answer -ne 'y') {
            return
        }
    }
    $transferResult = $enterprise.enterpriseData.TransferUserAccount($enterprise.roleData, $fromUserObject, $targetUserObject).GetAwaiter().GetResult()
    if ($transferResult) {
        Write-Information "Successfully Transferred:"
        Write-Information "        Records: $($transferResult.RecordsTransfered)"
        Write-Information " Shared Folders: $($transferResult.SharedFoldersTransfered)"
        Write-Information "           Team: $($transferResult.TeamsTransfered)"
        if ($transferResult.RecordsCorrupted -gt 0 -or $transferResult.SharedFoldersCorrupted -gt 0 -or $transferResult.TeamsCorrupted -gt 0) {
            Write-Information "Failed to Transfer:"
            if ($transferResult.RecordsCorrupted -gt 0) {
                Write-Information "        Records: $($transferResult.RecordsCorrupted)"
            }
            if ($transferResult.SharedFoldersCorrupted -gt 0) {
                Write-Information " Shared Folders: $($transferResult.SharedFoldersCorrupted)"
            }
            if ($transferResult.TeamsCorrupted -gt 0) {
                Write-Information "           Team: $($transferResult.TeamsCorrupted)"
            }
        }
    }
}
Register-ArgumentCompleter -CommandName Move-KeeperEnterpriseUser -ParameterName FromUser -ScriptBlock $Keeper_LockedUserCompleter
Register-ArgumentCompleter -CommandName Move-KeeperEnterpriseUser -ParameterName TargetUser -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name transfer-user -Value Move-KeeperEnterpriseUser

function Remove-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Removes Enterprise User

        .Parameter User
	    User email, enterprise Id, or instance.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User,
        [Switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    if (-not $Force.IsPresent) {
        Write-Output  "`nDeleting a user will also delete any records owned and shared by this user."
        "Before you delete this user, we strongly recommend you lock their account"
        "and transfer any important records to other user.`n"
        "This action cannot be undone."

        if ($PSCmdlet.ShouldProcess($userObject.Email, "Removing Enterprise User")) {
            $enterprise.enterpriseData.DeleteUser($userObject).GetAwaiter().GetResult() | Out-Null
            Write-Output "User $($userObject.Email) has been deleted"
        }
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
New-Alias -Name delete-user -Value Remove-KeeperEnterpriseUser

function Invoke-ResendKeeperEnterpriseInvite {
    <#
        .Synopsis
        Resends enterprise invitation email to a user

        .Parameter User
        User email address

        .Description
        Resends the enterprise invitation email to a user who has not yet accepted their invitation.
        The user must be in Inactive status (not yet accepted invitation).

        .Example
        Invoke-ResendKeeperEnterpriseInvite -User "user@example.com"
        Resends invitation email to user@example.com
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $User
    )

    [Enterprise]$enterprise = getEnterprise
    
    [KeeperSecurity.Enterprise.EnterpriseUser]$userObject = $null
    
    if ($enterprise.enterpriseData.TryGetUserByEmail($User, [ref]$userObject)) {
        # here user is found by email
        Write-Debug "User `"$User`" found by email"
    }
    elseif ($User -match '^\d+$') {
        $userId = [long]$User
        if (-not $enterprise.enterpriseData.TryGetUserById($userId, [ref]$userObject)) {
            Write-Error "User `"$User`" not found" -ErrorAction Stop
            return
        }
        # here user is found by ID
        Write-Debug "User `"$User`" found by ID"
    }
    else {
        # here user is not found by email or ID
        Write-Error "User `"$User`" not found" -ErrorAction Stop
        return
    }

    if ($userObject.UserStatus -ne [KeeperSecurity.Enterprise.UserStatus]::Inactive) {
        Write-Error "User has already accepted invitation. Only inactive users can have invitations resent." -ErrorAction Stop
        return
    }

    try {
        $enterprise.enterpriseData.ResendEnterpriseInvite($userObject).GetAwaiter().GetResult() | Out-Null
        Write-Output "Invite for $User resent."
    }
    catch {
        Write-Error "Failed to resend invite: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Invoke-ResendKeeperEnterpriseInvite -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter

function Set-KeeperEnterpriseUserMasterPasswordExpire {
    <#
        .Synopsis
        Sets master password expiration for an enterprise user

        .Parameter User
        User email address

        .Description
        Sets the master password expiration for an active enterprise user, requiring them to change their password on next login.

        .Example
        Set-KeeperEnterpriseUserMasterPasswordExpire -User "user@example.com"
        Sets master password expiration for user@example.com
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $User
    )

    [Enterprise]$enterprise = getEnterprise
    
    $userObject = resolveUser $enterprise.enterpriseData $User
    if (-not $userObject) {
        Write-Error "User `"$User`" not found" -ErrorAction Stop
        return
    }

    if ($userObject.UserStatus -ne [KeeperSecurity.Enterprise.UserStatus]::Active) {
        Write-Error "User $User is not active" -ErrorAction Stop
        return
    }

    try {
        $enterprise.enterpriseData.SetMasterPasswordExpire($userObject.Email).GetAwaiter().GetResult() | Out-Null
        Write-Output "Master password expiration set for $User"
    }
    catch {
        Write-Error "Failed to set master password expiration: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Set-KeeperEnterpriseUserMasterPasswordExpire -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter

class EnterpriseUserAliasState {
    [string]$NormalizedAlias
    [string]$ExistingSecondaryAlias
    [bool]$IsAlreadyPrimary
    [System.Collections.Generic.List[string]]$Aliases

    EnterpriseUserAliasState([string]$normalizedAlias) {
        $this.NormalizedAlias = $normalizedAlias
        $this.Aliases = [System.Collections.Generic.List[string]]::new()
        $this.IsAlreadyPrimary = $false
    }
}

function Get-MatchingEnterpriseUserAlias {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Aliases,
        [Parameter(Mandatory)][string]$Alias
    )
    $normalizedAlias = $Alias.Trim().ToLowerInvariant()
    foreach ($existingAlias in $Aliases) {
        if ($existingAlias.ToLowerInvariant() -eq $normalizedAlias) { return $existingAlias }
    }
    return $null
}

function Get-EnterpriseUserAliasState {
    param(
        [Parameter(Mandatory)][Enterprise]$Enterprise,
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.EnterpriseUser]$User,
        [Parameter(Mandatory)][string]$AliasEmail
    )

    $state = [EnterpriseUserAliasState]::new($AliasEmail.Trim().ToLowerInvariant())
    foreach ($alias in $Enterprise.userAliasData.GetAliasesForUser($User.Id)) {
        [void]$state.Aliases.Add($alias)
    }
    $state.ExistingSecondaryAlias = Get-MatchingEnterpriseUserAlias -Aliases $state.Aliases -Alias $state.NormalizedAlias
    $state.IsAlreadyPrimary = ($User.Email.ToLowerInvariant() -eq $state.NormalizedAlias)
    return $state
}

function Update-EnterpriseUserAliasCache {
    param(
        [Parameter(Mandatory)][Enterprise]$Enterprise
    )
    $Enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
}

function Set-KeeperEnterpriseUserPrimaryAlias {
    param(
        [Parameter(Mandatory)][Enterprise]$Enterprise,
        [Parameter(Mandatory)][long]$EnterpriseUserId,
        [Parameter(Mandatory)][string]$Alias
    )
    $rq = New-Object Authentication.EnterpriseUserAliasRequest
    $rq.EnterpriseUserId = $EnterpriseUserId
    $rq.Alias = $Alias
    $Enterprise.loader.Auth.ExecuteAuthRest("enterprise/enterprise_user_set_primary_alias", $rq).GetAwaiter().GetResult() | Out-Null
}

function Test-KeeperEnterpriseUserAliasConflict {
    param([string]$Status)
    return ($Status -and $Status.ToLowerInvariant().Contains('conflict'))
}

function Add-KeeperEnterpriseUserAlias {
    <#
        .SYNOPSIS
        Adds an alias email address to an enterprise user

        .DESCRIPTION
        Adds an alternate email alias for an enterprise user. If the alias already exists for the user,
        it is set as the primary alias.

        .PARAMETER User
        User email address, alias email address, or enterprise user ID

        .PARAMETER Alias
        Alias email address to add

        .EXAMPLE
        Add-KeeperEnterpriseUserAlias -User "user@example.com" -Alias "alias@example.com"
        Adds alias@example.com as an alias for user@example.com

        .EXAMPLE
        kuser-alias-add "user@example.com" "alias@example.com"
        Adds an alias using the kuser-alias-add alias
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $User,
        [Parameter(Position = 1, Mandatory = $true)][string] $Alias
    )

    if ([string]::IsNullOrWhiteSpace($Alias)) {
        Write-Error "Alias parameter is mandatory." -ErrorAction Stop
        return
    }

    $aliasEmail = $Alias.Trim().ToLowerInvariant()

    [Enterprise]$enterprise = getEnterprise
    try {
        Update-EnterpriseUserAliasCache -Enterprise $enterprise
    }
    catch {
        Write-Warning "Enterprise data reload failed before alias lookup: $($_.Exception.Message)"
    }

    $userObject = resolveUser $enterprise.enterpriseData $User $enterprise.userAliasData
    [EnterpriseUserAliasState]$aliasState = Get-EnterpriseUserAliasState -Enterprise $enterprise -User $userObject -AliasEmail $aliasEmail

    if ($aliasState.IsAlreadyPrimary) {
        Write-Output "Alias `"$($userObject.Email)`" already exists for this user."
        return
    }

    try {
        if ($aliasState.ExistingSecondaryAlias) {
            Set-KeeperEnterpriseUserPrimaryAlias -Enterprise $enterprise -EnterpriseUserId $userObject.Id -Alias $aliasState.ExistingSecondaryAlias
            Write-Output "Alias `"$($aliasState.ExistingSecondaryAlias)`" set as primary for user `"$($userObject.Email)`"."
        }
        else {
            $addRq = New-Object Authentication.EnterpriseUserAddAliasRequest
            $addRq.Primary = $true
            $addRq.EnterpriseUserId = $userObject.Id
            $addRq.Alias = $aliasState.NormalizedAlias

            $rq = New-Object Authentication.EnterpriseUserAddAliasRequestV2
            [void]$rq.EnterpriseUserAddAliasRequest.Add($addRq)

            $rs = $enterprise.loader.Auth.ExecuteAuthRest(
                "enterprise/enterprise_user_add_alias",
                $rq,
                [Authentication.EnterpriseUserAddAliasResponse],
                1
            ).GetAwaiter().GetResult()

            $statusList = @($rs.Status)
            if ($statusList.Count -eq 0) {
                Write-Error "Failed to add alias: no status returned from server." -ErrorAction Stop
            }

            $setPrimaryOnConflict = $false
            foreach ($st in $statusList) {
                if ($st.Status -ne 'success') {
                    if (Test-KeeperEnterpriseUserAliasConflict -Status $st.Status) {
                        $setPrimaryOnConflict = $true
                    }
                    else {
                        Write-Error "Failed to add alias for user $($st.EnterpriseUserId): $($st.Status)" -ErrorAction Stop
                    }
                }
            }

            if ($setPrimaryOnConflict) {
                $canonicalAlias = $aliasState.ExistingSecondaryAlias
                if (-not $canonicalAlias) {
                    $canonicalAlias = Get-MatchingEnterpriseUserAlias -Aliases $aliasState.Aliases -Alias $aliasState.NormalizedAlias
                }
                if (-not $canonicalAlias) { $canonicalAlias = $aliasState.NormalizedAlias }
                Set-KeeperEnterpriseUserPrimaryAlias -Enterprise $enterprise -EnterpriseUserId $userObject.Id -Alias $canonicalAlias
                Write-Output "Alias `"$canonicalAlias`" set as primary for user `"$($userObject.Email)`"."
            }
            else {
                Write-Output "Alias `"$($aliasState.NormalizedAlias)`" added for user `"$($userObject.Email)`"."
            }
        }
    }
    catch {
        if (Test-KeeperEnterpriseUserAliasConflict -Status $_.Exception.Message) {
            Set-KeeperEnterpriseUserPrimaryAlias -Enterprise $enterprise -EnterpriseUserId $userObject.Id -Alias $aliasState.NormalizedAlias
            Write-Output "Alias `"$($aliasState.NormalizedAlias)`" set as primary for user `"$($userObject.Email)`"."
        }
        else {
            Write-Error "Failed to add alias: $($_.Exception.Message)" -ErrorAction Stop
        }
    }

    try {
        Update-EnterpriseUserAliasCache -Enterprise $enterprise
    }
    catch {
        Write-Warning "Alias operation succeeded but enterprise data reload failed: $($_.Exception.Message)"
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseUserAlias -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
New-Alias -Name kuser-alias-add -Value Add-KeeperEnterpriseUserAlias

function Remove-KeeperEnterpriseUserAlias {
    <#
        .SYNOPSIS
        Removes an alias email address from an enterprise user

        .DESCRIPTION
        Removes an alternate email alias from an enterprise user.

        .PARAMETER User
        User email address, alias email address, or enterprise user ID

        .PARAMETER Alias
        Alias email address to remove. Cannot be the user's current primary email.

        .PARAMETER Force
        Skip confirmation prompt and remove the alias

        .EXAMPLE
        Remove-KeeperEnterpriseUserAlias -User "user@example.com" -Alias "alias@example.com"
        Removes alias@example.com from user@example.com

        .EXAMPLE
        Remove-KeeperEnterpriseUserAlias -User "user@example.com" -Alias "alias@example.com" -Force
        Removes the alias without a confirmation prompt

        .EXAMPLE
        kuser-alias-remove "user@example.com" "alias@example.com"
        Removes an alias using the kuser-alias-remove alias
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $User,
        [Parameter(Position = 1, Mandatory = $true)][string] $Alias,
        [Parameter()][switch] $Force
    )

    if ([string]::IsNullOrWhiteSpace($Alias)) {
        Write-Error "Alias parameter is mandatory." -ErrorAction Stop
        return
    }

    $aliasEmail = $Alias.Trim().ToLowerInvariant()

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User $enterprise.userAliasData

    if ($userObject.Email.ToLowerInvariant() -eq $aliasEmail) {
        Write-Error "Cannot remove the user's primary email address `"$($userObject.Email)`". Set another alias as primary first." -ErrorAction Stop
        return
    }

    if ($Force -or $PSCmdlet.ShouldProcess("$($userObject.Email) -> $aliasEmail", "Remove Enterprise User Alias")) {
        [EnterpriseUserAliasState]$aliasState = Get-EnterpriseUserAliasState -Enterprise $enterprise -User $userObject -AliasEmail $aliasEmail
        $canonicalAlias = $aliasState.ExistingSecondaryAlias
        if (-not $canonicalAlias) {
            $canonicalAlias = $aliasState.NormalizedAlias
        }

        try {
            $rq = New-Object Authentication.EnterpriseUserAliasRequest
            $rq.EnterpriseUserId = $userObject.Id
            $rq.Alias = $canonicalAlias
            $enterprise.loader.Auth.ExecuteAuthRest("enterprise/enterprise_user_delete_alias", $rq).GetAwaiter().GetResult() | Out-Null
            Write-Output "Alias `"$canonicalAlias`" removed from user `"$($userObject.Email)`"."
        }
        catch {
            Write-Error "Failed to remove alias: $($_.Exception.Message)" -ErrorAction Stop
        }

        try {
            Update-EnterpriseUserAliasCache -Enterprise $enterprise
        }
        catch {
            Write-Warning "Alias removal succeeded but enterprise data reload failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Output "Alias removal cancelled."
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseUserAlias -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
New-Alias -Name kuser-alias-remove -Value Remove-KeeperEnterpriseUserAlias

function Update-KeeperEnterpriseTeamUser {
    <#
        .Synopsis
        Updates a user's type in an enterprise team

        .Parameter Team
        Team name or UID

        .Parameter User
        User email address

        .Parameter UserType
        User type: 0, 1, or 2. 0 = User (normal member), 1 = Administrator (can manage team, sees shared folders), 2 = Administrator Only (can manage team but does not see shared folders)

        .Description
        Updates the user type for a user in a specific enterprise team. UserType must be 0, 1, or 2.

        .Example
        Update-KeeperEnterpriseTeamUser -Team "Engineering" -User "user@example.com" -UserType 1
        Makes user@example.com an Administrator in the Engineering team

        .Example
        Update-KeeperEnterpriseTeamUser -Team "Engineering" -User "user@example.com" -UserType 0
        Makes user@example.com a normal User in the Engineering team
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Team,
        [Parameter(Position = 1, Mandatory = $true)][string] $User,
        [Parameter(Position = 2, Mandatory = $true)][int] $UserType
    )

    [Enterprise]$enterprise = getEnterprise
    
    if ([string]::IsNullOrWhiteSpace($Team)) {
        Write-Error "Team name parameter is mandatory." -ErrorAction Stop
        return
    }

    if ([string]::IsNullOrWhiteSpace($User)) {
        Write-Error "User email parameter is mandatory." -ErrorAction Stop
        return
    }

    if ($UserType -lt 0 -or $UserType -gt 2) {
        Write-Error "User type must be 0, 1, or 2" -ErrorAction Stop
        return
    }

    $teamObject = resolveTeam $enterprise.enterpriseData $Team
    if (-not $teamObject) {
        Write-Error "Team `"$Team`" not found" -ErrorAction Stop
        return
    }

    $userObject = resolveUser $enterprise.enterpriseData $User
    if (-not $userObject) {
        Write-Error "User `"$User`" not found" -ErrorAction Stop
        return
    }

    if ($userObject.UserStatus -ne [KeeperSecurity.Enterprise.UserStatus]::Active) {
        Write-Error "User $User is not active" -ErrorAction Stop
        return
    }

    try {
        $enterprise.enterpriseData.TeamEnterpriseUserUpdate($teamObject, $userObject, $UserType).GetAwaiter().GetResult() | Out-Null
        Write-Output "Team user $User updated"
    }
    catch {
        Write-Error "Failed to update team user: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Update-KeeperEnterpriseTeamUser -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
Register-ArgumentCompleter -CommandName Update-KeeperEnterpriseTeamUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter

function Update-KeeperEnterpriseUser {
    <#
        .Synopsis
        Updates enterprise user information

        .Parameter User
        User email address

        .Parameter Node
        Node name or ID (optional)

        .Parameter FullName
        User's full name (optional)

        .Parameter JobTitle
        User's job title (optional)

        .Parameter InviteeLocale
        User's locale for invitations (optional)

        .Description
        Updates enterprise user information including node assignment, full name, job title, and invitee locale.
        If node is not specified, the user's current parent node is used.

        .Example
        Update-KeeperEnterpriseUser -User "user@example.com" -FullName "John Doe" -JobTitle "Software Engineer"
        Updates user's full name and job title

        .Example
        Update-KeeperEnterpriseUser -User "user@example.com" -Node "Engineering" -InviteeLocale "en-US"
        Moves user to Engineering node and sets locale
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $User,
        [Parameter()][string] $Node,
        [Parameter()][string] $FullName,
        [Parameter()][string] $JobTitle,
        [Parameter()][string] $InviteeLocale
    )

    [Enterprise]$enterprise = getEnterprise
    
    if ([string]::IsNullOrWhiteSpace($User)) {
        Write-Error "User email parameter is mandatory." -ErrorAction Stop
        return
    }

    $userObject = resolveUser $enterprise.enterpriseData $User
    if (-not $userObject) {
        Write-Error "User `"$User`" not found" -ErrorAction Stop
        return
    }

    if ($userObject.UserStatus -ne [KeeperSecurity.Enterprise.UserStatus]::Active) {
        Write-Error "User $User is not active" -ErrorAction Stop
        return
    }

    $nodeId = $null
    
    if ($Node) {
        $nodeObject = resolveSingleNode $Node
        if ($nodeObject) {
            $nodeId = $nodeObject.Id
        } else {
            Write-Warning "Node `"$Node`" not found so we are taking user's parent node"
        }
    }

    try {
        $updatedUser = $enterprise.enterpriseData.EnterpriseUserUpdate($userObject, $nodeId, $FullName, $JobTitle, $InviteeLocale).GetAwaiter().GetResult()
        Write-Output "User $User updated"
        return $updatedUser
    }
    catch {
        Write-Error "Failed to update user: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Update-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter

