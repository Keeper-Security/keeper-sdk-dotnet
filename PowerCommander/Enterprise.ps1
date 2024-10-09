function getEnterprise {
    [KeeperSecurity.Authentication.IAuthentication] $auth = $Script:Context.Auth
    if (-not $auth) {
        Write-Error -Message "Not Connected" -ErrorAction Stop
    }
    if (-not $auth.AuthContext.IsEnterpriseAdmin) {
        Write-Error -Message "Not an Enterprise Administrator" -ErrorAction Stop
    }
    $enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        $enterprise = New-Object Enterprise

        $enterprise.enterpriseData = New-Object KeeperSecurity.Enterprise.EnterpriseData
        $enterprise.roleData = New-Object KeeperSecurity.Enterprise.RoleData
        $enterprise.mspData = New-Object KeeperSecurity.Enterprise.ManagedCompanyData

        [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterprise.enterpriseData, $enterprise.roleData, $enterprise.mspData

        $enterprise.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($auth, $plugins)
        $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null

        if ($enterprise.enterpriseData.EnterpriseLicense.licenseStatus.StartsWith("msp")) {
            $enterprise.ManagedCompanies = @{}
        }

        $Script:Context.Enterprise = $enterprise
        $Script:Context.ManagedCompanyId = 0
    }

    if ($Script:Context.ManagedCompanyId -gt 0) {
        if ($null -ne $enterprise.ManagedCompanies) {
            $enterpriseMc = $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId]
            if ($null -eq $enterpriseMc) {
                $authMc = New-Object KeeperSecurity.Enterprise.ManagedCompanyAuth
                $authMc.LoginToManagedCompany($Script:Context.Enterprise.loader, $Script:Context.ManagedCompanyId).GetAwaiter().GetResult() | Out-Null

                $enterpriseMc = New-Object Enterprise
                $enterpriseMc.enterpriseData = New-Object KeeperSecurity.Enterprise.EnterpriseData
                $enterpriseMc.roleData = New-Object KeeperSecurity.Enterprise.RoleData
        
                [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterpriseMc.enterpriseData, $enterprise.roleData
        
                $enterpriseMc.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($authMc, $plugins)
                $enterpriseMc.loader.Load().GetAwaiter().GetResult() | Out-Null
                $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId] = $enterpriseMc
            }
            $enterprise = $enterpriseMc
        } else {
            $Script:Context.ManagedCompanyId = 0
        }
    }

    return $enterprise
}

function Sync-KeeperEnterprise {
    <#
        .Synopsis
        Sync Keeper Enterprise Information
    #>

    [CmdletBinding()]
    [Enterprise]$enterprise = getEnterprise
    $task = $enterprise.loader.Load()
    $task.GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name ked -Value Sync-KeeperEnterprise


function Get-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Get a list of enterprise users
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Users
}
New-Alias -Name keu -Value Get-KeeperEnterpriseUser

function Get-KeeperEnterpriseTeam {
    <#
        .Synopsis
    	Get a list of enterprise teams
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Teams
}
New-Alias -Name ket -Value Get-KeeperEnterpriseTeam

$Keeper_TeamNameCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($team in $enterprise.enterpriseData.Teams) {
        if ($team.Name -like $to_complete) {
            $teamName = $team.Name
            if ($teamName -match '[\s'']') {
                $teamName = $teamName -replace '''', ''''''
                $teamName = "'${teamName}'"
            }

            $result += $teamName
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Get-KeeperEnterpriseTeamUser {
    <#
        .Synopsis
    	Get a list of enterprise users for team
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Team
    )

    [Enterprise]$enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $uid = $null

    if ($Team -is [String]) {
        $uids = Get-KeeperEnterpriseTeam | Where-Object { $_.Uid -ceq $Team -or $_.Name -ieq $Team } | Select-Object -Property Uid
        if ($uids.Length -gt 1) {
            Write-Error -Message "Team name `"$Team`" is not unique. Use Team UID" -ErrorAction Stop
        }

        if ($null -ne $uids.Uid) {
            $uid = $uids.Uid
        }
    }
    elseif ($null -ne $Team.Uid) {
        $uid = $Team.Uid
    }
    if ($uid) {
        $team = $null
        if ($enterpriseData.TryGetTeam($uid, [ref]$team)) {
            foreach ($userId in $enterpriseData.GetUsersForTeam($uid)) {
                $user = $null
                foreach ($userId in $enterpriseData.TryGetUserById($userId, [ref]$user)) {
                    $user
                }
            }
        }
        else {
            Write-Error -Message "Team `"$uid`" not found" -ErrorAction Stop
        }
    }
    else {
        Write-Error -Message "Team `"$Team`" not found" -ErrorAction Stop
    }
}
New-Alias -Name ketu -Value Get-KeeperEnterpriseTeamUser
Register-ArgumentCompleter -CommandName Get-KeeperEnterpriseTeamUser -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter

$Keeper_ActiveUserCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($user in $enterprise.enterpriseData.Users) {
        if ($user.UserStatus -in @([KeeperSecurity.Enterprise.UserStatus]::Active, [KeeperSecurity.Enterprise.UserStatus]::Disabled, [KeeperSecurity.Enterprise.UserStatus]::Blocked)) {
            if ($user.Email -like $to_complete) {
                $result += $user.Email
            }
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function New-KeeperEnterpriseNode {
    <#
    .SYNOPSIS
    Creates Enterprise Node

    .PARAMETER ParentNode
    Parent Node name or ID

    .PARAMETER NodeName
    Node name
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $ParentNode,        
        [Parameter(Position = 0, Mandatory = $true)] $NodeName
    )

    [Enterprise]$enterprise = getEnterprise

    [KeeperSecurity.Enterprise.EnterpriseNode] $parent = $null
    if ($ParentNode) {
        $parent = resolveSingleNode $ParentNode
    }

    $n = [KeeperSecurity.Enterprise.EnterpriseExtensions]::CreateNode($enterprise.enterpriseData, $NodeName, $parent).GetAwaiter().GetResult()
    Write-Information "Added node `"$($n.DisplayName)`""
}
New-Alias -Name kena -Value New-KeeperEnterpriseNode

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
    if ($userObject) {
        $saved = $enterprise.enterpriseData.SetUserLocked($userObject, $true).GetAwaiter().GetResult()
        if ($saved) {
            Write-Output "User `"$($saved.Email)`" was locked"
        }
    }
}
Register-ArgumentCompleter -CommandName Lock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name lock-user -Value Lock-KeeperEnterpriseUser

$Keeper_LockedUserCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($user in $enterprise.enterpriseData.Users) {
        if ($user.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Locked) {
            if ($user.Email -like $to_complete) {
                $result += $user.Email
            }
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

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
    if ($userObject) {
        $saved = $enterprise.enterpriseData.SetUserLocked($userObject, $false).GetAwaiter().GetResult()
        if ($saved) {
            Write-Output "User `"$($saved.Email)`" was unlocked"
        }
    }
}
Register-ArgumentCompleter -CommandName Unlock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_LockedUserCompleter
New-Alias -Name unlock-user -Value Unlock-KeeperEnterpriseUser

$Keeper_EnterpriseUserCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($user in $enterprise.enterpriseData.Users) {
        if ($user.Email -like $to_complete) {
            $result += $user.Email
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

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
        Write-Output "This action cannot be undone.`n"
        $answer = Read-Host -Prompt "Do you want to proceed with transferring $($fromUserObject.Email) account (Yes/No)? > "
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
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User,
        [Switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    if ($userObject) {
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
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
New-Alias -Name delete-user -Value Remove-KeeperEnterpriseUser

function resolveUser {
    Param (
        $enterpriseData,
        $user
    )
    [KeeperSecurity.Enterprise.EnterpriseUser] $u = $null

    if ($user -is [long]) {
        if ($enterpriseData.TryGetUserById($user, [ref]$u)) {
            return $u
        }
    }
    elseif ($user -is [string]) {
        if ($enterpriseData.TryGetUserByEmail($user, [ref]$u)) {
            return $u
        }
    }
    elseif ($user -is [KeeperSecurity.Enterprise.EnterpriseUser]) {
        if ($enterpriseData.TryGetUserById($user.Id, [ref]$u)) {
            return $u
        }
    }
    Write-Output "`"${user}`" cannot be resolved as enterprise user"
}

function resolveSingleNode {
    Param ($node)

    if ($node) {
        $nodes = Get-KeeperEnterpriseNode | Where-Object { $_.Id -eq $node }
        if ($nodes.Length -eq 0) {
            $nodes = Get-KeeperEnterpriseNode | Where-Object { $_.DisplayName -like $node + '*' }
        }
        if ($nodes.Length -eq 0) {
            Write-Error -Message "Node `"$node`" not found" -ErrorAction Stop
        }
        if ($nodes.Length -gt 1) {
            Write-Error -Message "Node name `"$node`" is not unique. Use Node ID." -ErrorAction Stop
        }
        $nodes[0]
    }
}

function Get-KeeperEnterpriseNode {
    <#
        .Synopsis
    	Get a list of enterprise nodes
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Nodes
}
New-Alias -Name ken -Value Get-KeeperEnterpriseNode

