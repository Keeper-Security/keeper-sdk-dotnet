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

function New-KeeperEnterpriseRole {
    <#
        .SYNOPSIS
        Create new enterprise role in the Keeper Enterprise.

        .DESCRIPTION
        Creates new enterprise role with optional settings for parent node, new user inheritance, visibility, and enforcements.

        .PARAMETER Role
        Role Name of the new role.

        .PARAMETER ParentNode
        Parent node name or ID. If not specified, the role will be created in the root node.

        .PARAMETER NewUser
        Assign this role to new users. Valid values: 'ON', 'OFF'. Default is 'OFF'.

        .PARAMETER VisibleBelow
        Make role visible to all subnodes. Valid values: 'ON', 'OFF'. Default is 'OFF'.

        .PARAMETER Enforcement
        Sets role enforcement in KEY:VALUE format. Can be repeated multiple times.

        .PARAMETER Force
        Do not prompt for confirmation when a role with the same name already exists.

        .EXAMPLE
        New-KeeperEnterpriseRole -Role "Manager"
        Creates a role named "Manager" in the root node.

        .EXAMPLE
        New-KeeperEnterpriseRole -Role "Manager", "Employee" -ParentNode "Sales" -NewUser "ON"
        Creates two roles "Manager" and "Employee" in the "Sales" node, assigned to new users.

        .EXAMPLE
        New-KeeperEnterpriseRole -Role "Admin" -ParentNode 123456789 -VisibleBelow "ON" -Enforcement "logout_timer_desktop:3600"
        Creates an "Admin" role in node 123456789, visible to subnodes, with a logout timer enforcement.

        .EXAMPLE
        New-KeeperEnterpriseRole -Role "TestRole" -Force
        Creates a role even if one with the same name already exists, without prompting.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false)]
        [string[]]$Role,
        
        [Parameter()][string]$ParentNode,
        
        [Parameter()][ValidateSet('ON', 'OFF')][string]$NewUser = 'OFF',
        
        [Parameter()][ValidateSet('ON', 'OFF')][string]$VisibleBelow = 'OFF',
        
        [Parameter()][string[]]$Enforcement,
        
        [Parameter()][switch]$Force
    )

    [Enterprise]$enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $roleData = $enterprise.roleData
    $auth = $enterprise.loader.Auth

    if ($ParentNode) {
        $ParentNode = $ParentNode.Trim()
        if ([string]::IsNullOrWhiteSpace($ParentNode)) {
            $ParentNode = $null
        }
    }

    $nodeId = $null
    if ($ParentNode) {
        $parsedId = 0
        if ([long]::TryParse($ParentNode, [ref]$parsedId)) {
            $node = $null
            if ($enterpriseData.TryGetNode($parsedId, [ref]$node)) {
                $nodeId = $parsedId
            }
        }
        
        if (-not $nodeId) {
            $nodes = $enterpriseData.Nodes | Where-Object { $_.DisplayName -ieq $ParentNode }
            if ($nodes.Count -eq 1) {
                $nodeId = $nodes[0].Id
            }
            elseif ($nodes.Count -eq 0) {
                Write-Error "Node `"$ParentNode`" not found" -ErrorAction Stop
                return
            }
            else {
                Write-Error "More than one node with name `"$ParentNode`" are found. Use Node ID." -ErrorAction Stop
                return
            }
        }
    }
    else {
        $nodeId = $enterpriseData.RootNode.Id
    }

    $newUserInherit = $NewUser -eq 'ON'
    $visibleBelowBool = $VisibleBelow -eq 'ON'

    $uniqueRoles = $Role | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    if ($uniqueRoles.Count -ne ($Role | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count) {
        Write-Warning "Duplicate role names detected in input. Only unique names will be processed."
    }
    $Role = $uniqueRoles

    if ($Enforcement -and $Enforcement.Count -gt 0) {
        foreach ($enf in $Enforcement) {
            if (-not [string]::IsNullOrWhiteSpace($enf) -and $enf -notmatch '^[^:]+:.+$') {
                Write-Warning "Enforcement `"$enf`" does not match KEY:VALUE format. It will be skipped."
            }
        }
    }

    $createdRoles = @()
    foreach ($roleName in $Role) {
        if ([string]::IsNullOrWhiteSpace($roleName)) {
            Write-Warning "Skipping empty role name"
            continue
        }

        $roleName = $roleName.Trim()
        if ($roleName.Length -gt 255) {
            Write-Error "Role name `"$roleName`" exceeds maximum length of 255 characters" -ErrorAction Continue
            continue
        }
        if ($roleName.Length -eq 0) {
            Write-Warning "Skipping empty role name after trimming"
            continue
        }

        $existingRoles = Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -ieq $roleName }
        if ($existingRoles.Count -gt 0) {
            if (-not $Force) {
                $confirmation = Read-Host "Role with name `"$roleName`" already exists. Do you want to create a new one? (Yes/No)"
                if ($confirmation -notmatch '^[Yy]([Ee][Ss])?$') {
                    Write-Output "Skipping role `"$roleName`""
                    continue
                }
            }
            else {
                Write-Verbose "Role `"$roleName`" already exists, but Force is set. Creating anyway."
            }
        }

        $actionDescription = "Create Enterprise Role `"$roleName`""
        if ($PSCmdlet.ShouldProcess($actionDescription, "Create")) {
            try {
                $createdRole = $roleData.CreateRole($roleName, $nodeId, $newUserInherit).GetAwaiter().GetResult()
                
                if (-not $createdRole) {
                    Write-Error "Failed to create role `"$roleName`"" -ErrorAction Continue
                    continue
                }

                Write-Output "Role `"$roleName`" created successfully (ID: $($createdRole.Id))"

                if ($visibleBelowBool) {
                    try {
                        $updatedRole = $roleData.UpdateRole($createdRole, $null, $true, $null).GetAwaiter().GetResult()
                        if ($updatedRole) {
                            Write-Verbose "Role `"$roleName`" set to visible below subnodes"
                        }
                    }
                    catch {
                        Write-Warning "Failed to set VisibleBelow for role `"$roleName`": $($_.Exception.Message)"
                    }
                }

                if ($Enforcement -and $Enforcement.Count -gt 0) {
                    foreach ($enf in $Enforcement) {
                        if ([string]::IsNullOrWhiteSpace($enf)) {
                            continue
                        }

                        $parts = $enf -split ':', 2
                        if ($parts.Count -ne 2) {
                            Write-Warning "Invalid enforcement format `"$enf`". Expected KEY:VALUE format. Skipping."
                            continue
                        }

                        $enforcementKey = $parts[0].Trim()
                        $enforcementValue = $parts[1].Trim()

                        if ([string]::IsNullOrWhiteSpace($enforcementKey) -or [string]::IsNullOrWhiteSpace($enforcementValue)) {
                            Write-Warning "Invalid enforcement format `"$enf`". Key and Value cannot be empty. Skipping."
                            continue
                        }

                        try {
                            $enfCmd = New-Object KeeperSecurity.Commands.RoleEnforcementAddCommand
                            $enfCmd.RoleId = $createdRole.Id
                            $enfCmd.Enforcement = $enforcementKey
                            $enfCmd.Value = $enforcementValue

                            [KeeperSecurity.Authentication.AuthExtensions]::ExecuteAuthCommand($auth, $enfCmd).GetAwaiter().GetResult() | Out-Null
                            Write-Verbose "Added enforcement `"$enforcementKey`" = `"$enforcementValue`" to role `"$roleName`""
                        }
                        catch {
                            Write-Warning "Failed to add enforcement `"$enf`" to role `"$roleName`": $($_.Exception.Message)"
                        }
                    }
                }

                $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null

                $finalRole = $null
                if ($roleData.TryGetRole($createdRole.Id, [ref]$finalRole)) {
                    $createdRoles += $finalRole
                }
                else {
                    Write-Warning "Role `"$roleName`" was created (ID: $($createdRole.Id)) but could not be retrieved after reload. The role may still exist."
                    $createdRoles += $createdRole
                }
            }
            catch {
                Write-Error "Failed to create role `"$roleName`": $($_.Exception.Message)" `
                    -ErrorAction Continue `
                    -ErrorId "RoleCreationFailed" `
                    -Category InvalidOperation
                continue
            }
        }
    }

    if ($createdRoles.Count -gt 0) {
        return $createdRoles
    }
}
Register-ArgumentCompleter -CommandName New-KeeperEnterpriseRole -ParameterName ParentNode -ScriptBlock {
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
    foreach ($node in $enterprise.enterpriseData.Nodes) {
        if ($node.DisplayName -like $to_complete) {
            $nodeName = $node.DisplayName
            if ($nodeName -match '[\s'']') {
                $nodeName = $nodeName -replace '''', ''''''
                $nodeName = "'${nodeName}'"
            }
            $result += $nodeName
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}
New-Alias -Name keradd -Value New-KeeperEnterpriseRole

function Remove-KeeperEnterpriseRole {
    <#
        .SYNOPSIS
        Delete an enterprise role

        .DESCRIPTION
        Removes an enterprise role from the Keeper Enterprise. This operation cannot be undone.

        .PARAMETER Role
        Role Name, ID, or EnterpriseRole object to delete

        .PARAMETER Force
        Do not prompt for confirmation before deleting the role

        .EXAMPLE
        Remove-KeeperEnterpriseRole -Role "MyRole"
        Deletes the role named "TestRole" after confirmation

        .EXAMPLE
        Remove-KeeperEnterpriseRole -Role "MyRole" -Force
        Deletes the role named "MyRole" without prompting for confirmation

        .EXAMPLE
        Get-KeeperEnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Remove-KeeperEnterpriseRole
        Deletes a role using pipeline input
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]$Role,
        [Parameter()][switch]$Force
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $roleName = $roleObject.DisplayName
    $roleId = $roleObject.Id

    if (-not $Force -and -not $PSCmdlet.ShouldProcess("Role `"$roleName`" (ID: $roleId)", "Delete Enterprise Role")) {
        return
    }

    try {
        $roleData.DeleteRole($roleObject).GetAwaiter().GetResult() | Out-Null
        Write-Output "Role `"$roleName`" (ID: $roleId) deleted successfully"
    }
    catch {
        Write-Error "Failed to delete role `"$roleName`": $($_.Exception.Message)" `
            -ErrorAction Stop `
            -ErrorId "RoleDeletionFailed" `
            -Category InvalidOperation
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseRole -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name kerdel -Value Remove-KeeperEnterpriseRole
