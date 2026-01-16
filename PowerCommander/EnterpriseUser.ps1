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
    	Transfers enterprise user account to another user

        .Parameter FromUser
	    email or user ID to transfer vault from user

        .Parameter TargetUser
	    email or user ID to transfer vault to user
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

function Resend-KeeperEnterpriseInvite {
    <#
        .Synopsis
        Resends enterprise invitation email to a user

        .Parameter User
        User email address

        .Description
        Resends the enterprise invitation email to a user who has not yet accepted their invitation.
        The user must be in Inactive status (not yet accepted invitation).

        .Example
        Resend-KeeperEnterpriseInvite -User "user@example.com"
        Resends invitation email to user@example.com
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
Register-ArgumentCompleter -CommandName Resend-KeeperEnterpriseInvite -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter

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

function Update-KeeperEnterpriseTeamUser {
    <#
        .Synopsis
        Updates a user's type in an enterprise team

        .Parameter Team
        Team name or UID

        .Parameter User
        User email address

        .Parameter UserType
        User type: 0, 1, or 2

        .Description
        Updates the user type for a user in a specific enterprise team. User type must be 0, 1, or 2.

        .Example
        Update-KeeperEnterpriseTeamUser -Team "Engineering" -User "user@example.com" -UserType 1
        Updates the user type for user@example.com in the Engineering team
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

