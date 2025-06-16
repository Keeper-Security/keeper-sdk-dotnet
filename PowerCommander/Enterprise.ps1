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
        
                [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterpriseMc.enterpriseData, $enterpriseMc.roleData
        
                $enterpriseMc.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($authMc, $plugins)
                $enterpriseMc.loader.Load().GetAwaiter().GetResult() | Out-Null
                $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId] = $enterpriseMc
            }
            $enterprise = $enterpriseMc
        }
        else {
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

function  New-KeeperEnterpriseTeam {
    <#
        .Synopsis
        Create an enterprise team

    .PARAMETER ParentNode
    Parent Node name or ID

    .PARAMETER Team
        Team name

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string]$TeamName,
        [Parameter()][string] $ParentNode,  
        [Parameter()][Switch] $RestrictView,
        [Parameter()][Switch] $RestrictEdit,
        [Parameter()][Switch] $RestrictShare
    )

    [Enterprise]$enterprise = getEnterprise

    $team = New-Object Keepersecurity.Enterprise.EnterpriseTeam
    $team.Name = $TeamName
    [KeeperSecurity.Enterprise.EnterpriseNode] $parent = $null
    if ($ParentNode) {
        $parent = resolveSingleNode $ParentNode
        $team.ParentNodeId = $parent.Id
    }
    if ($RestrictView.IsPresent) {
        $team.RestrictView = $true
    }
    if ($RestrictEdit.IsPresent) {
        $team.RestrictEdit = $true
    }
    if ($RestrictShare.IsPresent) {
        $team.RestrictSharing = $true
    }

    $t = $enterprise.enterpriseData.CreateTeam($team).GetAwaiter().GetResult()
    $t
}
New-Alias -Name keta -Value New-KeeperEnterpriseTeam

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
    Write-Error "`"${user}`" cannot be resolved as enterprise user" -ErrorAction Stop
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

function Get-KeeperEnterpriseRole {
    <#
        .SYNOPSIS
    	Get a list of enterprise roles

        .PARAMETER Role
        Role Name or ID
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.roleData.Roles
}
New-Alias -Name ker -Value Get-KeeperEnterpriseRole

$Keeper_RoleNameCompleter = {
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
    foreach ($role in $enterprise.roleData.Roles) {
        if ($role.DisplayName -like $to_complete) {
            $roleName = $role.DisplayName
            if ($roleName -match '[\s'']') {
                $roleName = $roleName -replace '''', ''''''
                $roleName = "'${roleName}'"
            }

            $result += $roleName
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Get-KeeperEnterpriseRoleUsers {
    <#
        .SYNOPSIS
    	Get a list of enterprise users for a role

        .PARAMETER Role
        Role Name or ID
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role
    )

    [Enterprise]$enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $roleData = $enterprise.roleData
    $roleId = $null

    if ($Role -is [String]) {
        $ids = Get-KeeperEnterpriseRole | Where-Object { $_.Id -eq $Role -or $_.DisplayName -ieq $Role } | Select-Object -Property Id
        if ($ids.Length -gt 1) {
            Write-Error -Message "Role name `"$Role`" is not unique. Use Role ID" -ErrorAction Stop
        }

        if ($null -ne $ids.Id) {
            $roleId = $ids.Id
        }
    }
    elseif ($Role -is [long]) {
        $ids = Get-KeeperEnterpriseRole | Where-Object { $_.Id -ceq $Role } | Select-Object -First 1
        if ($ids.Length -eq 1) {
            $roleId = $ids[0].Id
        }
    }
    elseif ($null -ne $Role.Id) {
        $roleId = $Role.Id
    }
    if ($roleId) {
        $erole = $null
        if ($roleData.TryGetRole($roleId, [ref]$erole)) {
            foreach ($userId in $roleData.GetUsersForRole($erole.Id)) {
                $user = $null
                if ($enterpriseData.TryGetUserById($userId, [ref]$user)) {
                    $user
                }
            }
        }
        else {
            Write-Error -Message "Role `"$roleId`" not found" -ErrorAction Stop
        }
    }
    else {
        Write-Error -Message "Role `"$Role`" not found" -ErrorAction Stop
    }
}
New-Alias -Name keru -Value Get-KeeperEnterpriseRoleUsers
Register-ArgumentCompleter -CommandName Get-KeeperEnterpriseRoleUsers -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter

function Get-KeeperEnterpriseRoleTeams {
    <#
        .SYNOPSIS
    	Get a list of enterprise teams for a role

        .PARAMETER Role
        Role Name or ID
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role
    )

    [Enterprise]$enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $roleData = $enterprise.roleData
    $roleId = $null

    if ($Role -is [String]) {
        $ids = Get-KeeperEnterpriseRole | Where-Object { $_.Id -eq $Role -or $_.DisplayName -ieq $Role } | Select-Object -Property Id
        if ($ids.Length -gt 1) {
            Write-Error -Message "Role name `"$Role`" is not unique. Use Role ID" -ErrorAction Stop
        }

        if ($null -ne $ids.Id) {
            $roleId = $ids.Id
        }
    }
    elseif ($Role -is [long]) {
        $ids = Get-KeeperEnterpriseRole | Where-Object { $_.Id -ceq $Role } | Select-Object -First 1
        if ($ids.Length -eq 1) {
            $roleId = $ids[0].Id
        }
    }
    elseif ($null -ne $Role.Id) {
        $roleId = $Role.Id
    }
    if ($roleId) {
        $erole = $null
        if ($roleData.TryGetRole($roleId, [ref]$erole)) {
            foreach ($teamUid in $roleData.GetTeamsForRole($erole.Id)) {
                $team = $null
                if ($enterpriseData.TryGetTeam($teamUid, [ref]$team)) {
                    $team
                }
            }
        }
        else {
            Write-Error -Message "Role `"$roleId`" not found" -ErrorAction Stop
        }
    }
    else {
        Write-Error -Message "Role `"$Role`" not found" -ErrorAction Stop
    }
}
New-Alias -Name kert -Value Get-KeeperEnterpriseRoleTeams
Register-ArgumentCompleter -CommandName Get-KeeperEnterpriseRoleTeams -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter

function Get-KeeperEnterpriseAdminRole {
    <#
        .SYNOPSIS
    	Get a list of Administrator Permissions

        .PARAMETER Pattern
        Role search pattern
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false)]$Pattern
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData
    $roles = $null

    if ($Pattern -is [String]) {
        $roles = Get-KeeperEnterpriseRole | Where-Object { $_.Id -eq $Pattern -or $_.DisplayName -match $Pattern } 
    }
    elseif ($Pattern -is [long]) {
        $roles = Get-KeeperEnterpriseRole | Where-Object { $_.Id -eq $Pattern } 
    }
    elseif ($null -ne $Pattern.Id) {
        $roles = $Pattern
    }
    else {
        $roles = Get-KeeperEnterpriseRole
    }
    if ($null -ne $roles -and $roles.Length -gt 0 ) {
        $roles = $roles | Sort-Object -Property DisplayName
        foreach ($role in $roles) {
            if ($null -ne $role.Id) {
                foreach ($rp in $roleData.GetRolePermissions($role.Id)) {
                    $rp
                }
            }
        }
    }        
    else {
        Write-Error -Message "Role `"$Role`" not found" -ErrorAction Stop
    }
}
New-Alias -Name kerap -Value Get-KeeperEnterpriseAdminRole

function Script:Get-KeeperNodeName {
    Param (
        [long]$nodeId
    )
    $enterprise = getEnterprise
    [KeeperSecurity.Enterprise.EnterpriseNode]$node = $null
    if ($enterprise.enterpriseData.TryGetNode($nodeId, [ref]$node)) {
        if ($node.ParentNodeId -gt 0) {
            return $node.DisplayName
        }
        else {
            return $enterprise.loader.EnterpriseName
        }
    }
}

function Script:Get-KeeperRoleName {
    Param (
        [long]$roleId
    )
    $enterprise = getEnterprise
    [KeeperSecurity.Enterprise.EnterpriseRole]$role = $null
    if ($enterprise.roleData.TryGetRole($roleId, [ref]$role)) {
        return $role.DisplayName
    }
}

function Add-KeeperEnterpriseTeamMember {
    <#
        .SYNOPSIS
        Adds existing enterprise users to a Keeper team.

        .DESCRIPTION
        Adds one or more users (by email) to an existing Keeper Enterprise Team. The users must already exist in the enterprise.

        .PARAMETER Team
        Team UID or Team Name.

        .PARAMETER Emails
        Array of email addresses of users to add to the team.

        .EXAMPLE
        Add-KeeperEnterpriseTeamMember -Team "Engineering" -Emails "alice@example.com", "bob@example.com"

        .EXAMPLE
        Add-KeeperEnterpriseTeamMember -Team "1P7A8XZ9K3J9H" -Emails "eve@example.com", "frank@example.com"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Team,

        [Parameter(Mandatory = $true)]
        [string[]] $Emails
    )

    [Enterprise]$enterprise = GetEnterprise
    $teams = $enterprise.enterpriseData.Teams
    $selectedTeam = [KeeperSecurity.Enterprise.EnterpriseTeam]::new()
    try {

        for ($i = 0; $i -lt $teams.Count; $i++) {
            $t = $teams[$i]
            if (($t.Uid -eq $Team) -or ($t.Name -and ($t.Name.Trim().ToLower() -eq $Team.Trim().ToLower()))) {
                $selectedTeam = $t
                break
            }
        }
    
        if (-not $selectedTeam) {
            Write-Warning "No matching team found for input: $Team"
        }
    
        if ($Emails.Count -eq 0) {
            Write-Warning "No email addresses provided to add."
            return
        }
    
        [string[]] $teamData = @($selectedTeam.Uid)
        [string[]] $emailData = $Emails
        $enterprise.enterpriseData.AddUsersToTeams(
            $emailData, 
            $teamData
        ).GetAwaiter().GetResult() | Out-Null
    
        Write-Output "Requested addition of $($Emails.Count) user(s) to team '$($selectedTeam.Name)'."
    }
    catch {
        Write-Warning "❌ Failed to add users to team '$Team': $($_.Exception.Message)"
    }
}

function Remove-KeeperEnterpriseTeamMember {
    <#
        .SYNOPSIS
        Removes existing enterprise users from a Keeper team.

        .DESCRIPTION
        Removes one or more users (by email) from an existing Keeper Enterprise Team. 
        The specified users must already exist in the enterprise and must be members of the team.

        .PARAMETER Team
        Team UID or Team Name from which the users will be removed.

        .PARAMETER Emails
        Array of email addresses of users to remove from the team.

        .EXAMPLE
        Remove-KeeperEnterpriseTeamMember -Team "Engineering" -Emails "alice@example.com", "bob@example.com"

        .EXAMPLE
        Remove-KeeperEnterpriseTeamMember -Team "1P7A8XZ9K3J9H" -Emails "eve@example.com", "frank@example.com"

        This command removes the specified users from the given team.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Team,

        [Parameter(Mandatory = $true)]
        [string[]] $Emails
    )

    [Enterprise]$enterprise = GetEnterprise
    $teams = $enterprise.enterpriseData.Teams
    $selectedTeam = [KeeperSecurity.Enterprise.EnterpriseTeam]::new()

    try {
        for ($i = 0; $i -lt $teams.Count; $i++) {
            $t = $teams[$i]
            if (($t.Uid -eq $Team) -or ($t.Name -and ($t.Name.Trim().ToLower() -eq $Team.Trim().ToLower()))) {
                $selectedTeam = $t
                break
            }
        }
    
        if (-not $selectedTeam) {
            Write-Warning "❌ No matching team found for input: $Team"
            return
        }
    
        if ($Emails.Count -eq 0) {
            Write-Warning "⚠️ No email addresses provided to remove."
            return
        }
    
        [string[]] $teamData = @($selectedTeam.Uid)
        [string[]] $emailData = $Emails
    
        $enterprise.enterpriseData.RemoveUsersFromTeams(
            $emailData, 
            $teamData
        ).GetAwaiter().GetResult() | Out-Null
    
        Write-Output "✅ Requested removal of $($Emails.Count) user(s) from team '$($selectedTeam.Name)'."
    }
    catch {
        Write-Warning "❌ Failed to remove users from team '$Team': $($_.Exception.Message)"
    }
}
