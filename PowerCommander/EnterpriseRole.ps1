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

function Set-KeeperEnterpriseRole {
    <#
        .SYNOPSIS
        Updates Enterprise Role properties

        .DESCRIPTION
        Updates properties of an existing Enterprise Role, such as setting it as default for new users.

        .PARAMETER Role
        Role Name or ID, or EnterpriseRole object

        .PARAMETER NewUserInherit
        Set role as default for new users in the node. If specified, this will update the NewUserInherit property.

        .PARAMETER VisibleBelow
        Set role visibility to subnodes. If specified, this will update the VisibleBelow property.

        .PARAMETER NewDisplayName
        New role display name. If specified, this will update the role name.

        .EXAMPLE
        Set-KeeperEnterpriseRole -Role "MyRole" -NewUserInherit $true
        Sets the role "MyRole" as the default role for new users

        .EXAMPLE
        Set-KeeperEnterpriseRole -Role 123456789 -NewUserInherit $false
        Removes the role with ID 123456789 as the default role for new users

        .EXAMPLE
        Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Set-KeeperEnterpriseRole -NewUserInherit $true
        Sets the role using pipeline input
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]$Role,
        [Parameter()][bool]$NewUserInherit,
        [Parameter()][bool]$VisibleBelow,
        [Parameter()][string]$NewDisplayName
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData
    $roleObject = resolveRole $roleData $Role

    if (-not $roleObject) {
        return
    }

    $updateParams = @{}
    if ($PSBoundParameters.ContainsKey('NewUserInherit')) {
        $updateParams['newUserInherit'] = $NewUserInherit
    }
    if ($PSBoundParameters.ContainsKey('VisibleBelow')) {
        $updateParams['visibleBelow'] = $VisibleBelow
    }
    if ($PSBoundParameters.ContainsKey('NewDisplayName')) {
        $updateParams['displayName'] = $NewDisplayName
    }

    if ($updateParams.Count -eq 0) {
        Write-Warning "No properties specified to update. Use -NewUserInherit, -VisibleBelow, or -NewDisplayName parameters."
        return
    }

    $roleName = $roleObject.DisplayName
    if ($PSCmdlet.ShouldProcess($roleName, "Update Enterprise Role")) {
        try {
            $updatedRole = $roleData.UpdateRole(
                $roleObject,
                $updateParams['newUserInherit'],
                $updateParams['visibleBelow'],
                $updateParams['displayName']
            ).GetAwaiter().GetResult()
            
            if ($updatedRole) {
                Write-Output "Role `"$($updatedRole.DisplayName)`" updated successfully"
                $updatedRole
            }
        }
        catch {
            Write-Error "Failed to update role `"$roleName`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Set-KeeperEnterpriseRole -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name kers -Value Set-KeeperEnterpriseRole

function Grant-KeeperEnterpriseRoleToUser {
    <#
        .SYNOPSIS
        Adds a user to an Enterprise Role

        .DESCRIPTION
        Assigns an existing enterprise user to an enterprise role.

        .PARAMETER Role
        Role Name, ID, or EnterpriseRole object

        .PARAMETER User
        User email, ID, or EnterpriseUser object

        .EXAMPLE
        Grant-KeeperEnterpriseRoleToUser -Role "MyRole" -User "user@example.com"
        Adds the user to the role

        .EXAMPLE
        Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Grant-KeeperEnterpriseRoleToUser -User "user@example.com"
        Adds the user using pipeline input for the role
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)]$User
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData
    $enterpriseData = $enterprise.enterpriseData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $userObject = resolveUser $enterpriseData $User
    if (-not $userObject) {
        return
    }

    $roleName = $roleObject.DisplayName
    $userEmail = $userObject.Email
    if ($PSCmdlet.ShouldProcess("User `"$userEmail`" to Role `"$roleName`"", "Add")) {
        try {
            $roleData.AddUserToRole($roleObject, $userObject).GetAwaiter().GetResult() | Out-Null
            Write-Output "User `"$userEmail`" added to role `"$roleName`""
        }
        catch {
            Write-Error "Failed to add user `"$userEmail`" to role `"$roleName`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Grant-KeeperEnterpriseRoleToUser -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
Register-ArgumentCompleter -CommandName Grant-KeeperEnterpriseRoleToUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name kerua -Value Grant-KeeperEnterpriseRoleToUser

function Revoke-KeeperEnterpriseRoleFromUser {
    <#
        .SYNOPSIS
        Removes a user from an Enterprise Role

        .DESCRIPTION
        Removes an enterprise user from an enterprise role.

        .PARAMETER Role
        Role Name, ID, or EnterpriseRole object

        .PARAMETER User
        User email, ID, or EnterpriseUser object

        .EXAMPLE
        Revoke-KeeperEnterpriseRoleFromUser -Role "MyRole" -User "user@example.com"
        Removes the user from the role

        .EXAMPLE
        Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Revoke-KeeperEnterpriseRoleFromUser -User "user@example.com"
        Removes the user using pipeline input for the role
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)]$User
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData
    $enterpriseData = $enterprise.enterpriseData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $userObject = resolveUser $enterpriseData $User
    if (-not $userObject) {
        return
    }

    $roleName = $roleObject.DisplayName
    $userEmail = $userObject.Email
    if ($PSCmdlet.ShouldProcess("User `"$userEmail`" from Role `"$roleName`"", "Remove")) {
        try {
            $roleData.RemoveUserFromRole($roleObject, $userObject).GetAwaiter().GetResult() | Out-Null
            Write-Output "User `"$userEmail`" removed from role `"$roleName`""
        }
        catch {
            Write-Error "Failed to remove user `"$userEmail`" from role `"$roleName`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Revoke-KeeperEnterpriseRoleFromUser -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
Register-ArgumentCompleter -CommandName Revoke-KeeperEnterpriseRoleFromUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name kerur -Value Revoke-KeeperEnterpriseRoleFromUser

function Grant-KeeperEnterpriseRoleToTeam {
    <#
        .SYNOPSIS
        Adds a team to an Enterprise Role

        .DESCRIPTION
        Assigns an existing enterprise team to an enterprise role.

        .PARAMETER Role
        Role Name, ID, or EnterpriseRole object

        .PARAMETER Team
        Team UID, Name, or EnterpriseTeam object

        .EXAMPLE
        Grant-KeeperEnterpriseRoleToTeam -Role "MyRole" -Team "Engineering"
        Adds the team to the role

        .EXAMPLE
        Grant-KeeperEnterpriseRoleToTeam -Role "MyRole" -Team "1P7A8XZ9K3J9H"
        Adds the team using Team UID

        .EXAMPLE
        Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Grant-KeeperEnterpriseRoleToTeam -Team "Engineering"
        Adds the team using pipeline input for the role
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)]$Team
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData
    $enterpriseData = $enterprise.enterpriseData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $teamObject = resolveTeam $enterpriseData $Team
    if (-not $teamObject) {
        return
    }

    $roleName = $roleObject.DisplayName
    $teamName = $teamObject.Name
    if ($PSCmdlet.ShouldProcess("Team `"$teamName`" to Role `"$roleName`"", "Add")) {
        try {
            $roleData.AddTeamToRole($roleObject, $teamObject).GetAwaiter().GetResult() | Out-Null
            Write-Output "Team `"$teamName`" added to role `"$roleName`""
        }
        catch {
            Write-Error "Failed to add team `"$teamName`" to role `"$roleName`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Grant-KeeperEnterpriseRoleToTeam -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
Register-ArgumentCompleter -CommandName Grant-KeeperEnterpriseRoleToTeam -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
New-Alias -Name kerta -Value Grant-KeeperEnterpriseRoleToTeam

function Revoke-KeeperEnterpriseRoleFromTeam {
    <#
        .SYNOPSIS
        Removes a team from an Enterprise Role

        .DESCRIPTION
        Removes an enterprise team from an enterprise role.

        .PARAMETER Role
        Role Name, ID, or EnterpriseRole object

        .PARAMETER Team
        Team UID, Name, or EnterpriseTeam object

        .EXAMPLE
        Revoke-KeeperEnterpriseRoleFromTeam -Role "MyRole" -Team "Engineering"
        Removes the team from the role

        .EXAMPLE
        Revoke-KeeperEnterpriseRoleFromTeam -Role "MyRole" -Team "1P7A8XZ9K3J9H"
        Removes the team using Team UID

        .EXAMPLE
        Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Revoke-KeeperEnterpriseRoleFromTeam -Team "Engineering"
        Removes the team using pipeline input for the role
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)]$Team
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData
    $enterpriseData = $enterprise.enterpriseData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $teamObject = resolveTeam $enterpriseData $Team
    if (-not $teamObject) {
        return
    }

    $roleName = $roleObject.DisplayName
    $teamName = $teamObject.Name
    if ($PSCmdlet.ShouldProcess("Team `"$teamName`" from Role `"$roleName`"", "Remove")) {
        try {
            $roleData.RemoveTeamFromRole($roleObject, $teamObject).GetAwaiter().GetResult() | Out-Null
            Write-Output "Team `"$teamName`" removed from role `"$roleName`""
        }
        catch {
            Write-Error "Failed to remove team `"$teamName`" from role `"$roleName`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Revoke-KeeperEnterpriseRoleFromTeam -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
Register-ArgumentCompleter -CommandName Revoke-KeeperEnterpriseRoleFromTeam -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
New-Alias -Name kertr -Value Revoke-KeeperEnterpriseRoleFromTeam

