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
    if (-not $userObject) {
        Write-Error "Invalid user: `"$User`" not found" -ErrorAction Stop
        return
    }
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
    if (-not $userObject) {
        Write-Error "Invalid user: `"$User`" not found" -ErrorAction Stop
        return
    }
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
        Write-Information "Successfully Transfered:"
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
    if (-not $userObject) {
        Write-Error "Invalid user: `"$User`" not found" -ErrorAction Stop
        return
    }
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

