function Get-EnterpriseRole {
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

function Get-KeeperEnterpriseRole {
    <#
        .SYNOPSIS
    	Get a list of enterprise roles

        .PARAMETER Name
        Role Name or ID (exact match)

        .PARAMETER Format
        Output format: table (default), json

        .PARAMETER Output
        Path to resulting output file (ignored for "table" format)
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Name,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    $roles = Get-EnterpriseRole
    if (-not $roles) {
        Write-Warning "No enterprise roles found."
        return @()
    }

    if ($Name) {
        $roles = $roles | Where-Object { ($_.DisplayName -eq $Name) -or ($_.Id.ToString() -eq $Name) }
    }

    $result = @($roles)
    if ($result.Count -eq 0 -and $Name) {
        Write-Host "No matching enterprise roles found." -ForegroundColor Yellow
        return @()
    }

    if ($Format -eq 'json') {
        $json = $result | ConvertTo-Json -Depth 5
        if ($Output) {
            Set-Content -Path $Output -Value $json -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $json
        }
    } else {
        if ($Output) {
            $result | Format-Table -AutoSize | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $result
        }
    }
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
        $ids = Get-EnterpriseRole | Where-Object { $_.Id -eq $Role -or $_.DisplayName -ieq $Role } | Select-Object -Property Id
        if ($ids.Length -gt 1) {
            Write-Error -Message "Role name `"$Role`" is not unique. Use Role ID" -ErrorAction Stop
        }

        if ($null -ne $ids.Id) {
            $roleId = $ids.Id
        }
    }
    elseif ($Role -is [long]) {
        $ids = Get-EnterpriseRole | Where-Object { $_.Id -ceq $Role } | Select-Object -First 1
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
        $ids = Get-EnterpriseRole | Where-Object { $_.Id -eq $Role -or $_.DisplayName -ieq $Role } | Select-Object -Property Id
        if ($ids.Length -gt 1) {
            Write-Error -Message "Role name `"$Role`" is not unique. Use Role ID" -ErrorAction Stop
        }

        if ($null -ne $ids.Id) {
            $roleId = $ids.Id
        }
    }
    elseif ($Role -is [long]) {
        $ids = Get-EnterpriseRole | Where-Object { $_.Id -ceq $Role } | Select-Object -First 1
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
        $roles = Get-EnterpriseRole | Where-Object { $_.Id -eq $Pattern -or $_.DisplayName -match $Pattern } 
    }
    elseif ($Pattern -is [long]) {
        $roles = Get-EnterpriseRole | Where-Object { $_.Id -eq $Pattern } 
    }
    elseif ($null -ne $Pattern.Id) {
        $roles = $Pattern
    }
    else {
        $roles = Get-EnterpriseRole
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
        Get-EnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Set-KeeperEnterpriseRole -NewUserInherit $true
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
        Get-EnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Grant-KeeperEnterpriseRoleToUser -User "user@example.com"
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
        Get-EnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Revoke-KeeperEnterpriseRoleFromUser -User "user@example.com"
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
        Get-EnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Grant-KeeperEnterpriseRoleToTeam -Team "Engineering"
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
        Get-EnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Revoke-KeeperEnterpriseRoleFromTeam -Team "Engineering"
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

    $nodeId = $null
    if (-not [string]::IsNullOrWhiteSpace($ParentNode)) {
        $ParentNode = $ParentNode.Trim()
        $parsedId = 0
        if ([long]::TryParse($ParentNode, [ref]$parsedId)) {
            $node = $null
            if ($enterpriseData.TryGetNode($parsedId, [ref]$node)) {
                $nodeId = $parsedId
            }
        }
        
        if (-not $nodeId) {
            $nodes = @($enterpriseData.Nodes | Where-Object { $_.DisplayName -ieq $ParentNode })
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
    $allRoles = Get-EnterpriseRole

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

        $existingRoles = $allRoles | Where-Object { $_.DisplayName -ieq $roleName }
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

        if ($PSCmdlet.ShouldProcess($roleName, "Create Enterprise Role")) {
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

                try {
                    $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
                }
                catch {
                    Write-Warning "Failed to reload enterprise data after creating role `"$roleName`": $($_.Exception.Message)"
                }

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

    return $createdRoles
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
        Deletes the role named "MyRole" after confirmation

        .EXAMPLE
        Remove-KeeperEnterpriseRole -Role "MyRole" -Force
        Deletes the role named "MyRole" without prompting for confirmation

        .EXAMPLE
        Get-EnterpriseRole | Where-Object { $_.DisplayName -eq "MyRole" } | Remove-KeeperEnterpriseRole
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

    if (-not $Force -and -not $PSCmdlet.ShouldProcess($roleName, "Delete Enterprise Role")) {
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

function Add-KeeperEnterpriseRoleManagedNode {
    <#
    .SYNOPSIS
    Adds a managed node to an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Node
    Node name or ID to add as a managed node

    .PARAMETER Cascade
    Cascade node management to subnodes

    .DESCRIPTION
    Adds a node as a managed node to an enterprise role. This allows the role to manage the specified node and optionally cascade management to subnodes.

    .EXAMPLE
    Add-KeeperEnterpriseRoleManagedNode -Role "AdminRole" -Node "Sales"
    Adds the Sales node as a managed node to the AdminRole

    .EXAMPLE
    Add-KeeperEnterpriseRoleManagedNode -Role 123456789 -Node 987654321 -Cascade
    Adds node 987654321 as a managed node to role 123456789 with cascade enabled
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string]$Node,
        [Parameter()][bool]$Cascade = $false
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    try {
        $roleData.RoleManagedNodeAdd($roleObject, $targetNode, ($Cascade -eq $true)).GetAwaiter().GetResult() | Out-Null
        $nodeDisplayName = if ([string]::IsNullOrEmpty($targetNode.DisplayName)) { $targetNode.Id.ToString() } else { $targetNode.DisplayName }
        Write-Output "Managed node `"$nodeDisplayName`" added to role `"$($roleObject.DisplayName)`" successfully."
    }
    catch {
        Write-Error -Message "Failed to add managed node: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseRoleManagedNode -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Add-KeeperRoleManagedNode -Value Add-KeeperEnterpriseRoleManagedNode

function Update-KeeperEnterpriseRoleManagedNode {
    <#
    .SYNOPSIS
    Updates a managed node configuration for an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Node
    Node name or ID of the managed node to update

    .PARAMETER Cascade
    Cascade node management to subnodes

    .DESCRIPTION
    Updates the cascade setting for a managed node in an enterprise role.

    .EXAMPLE
    Update-KeeperEnterpriseRoleManagedNode -Role "AdminRole" -Node "Sales" -Cascade
    Updates the Sales managed node in AdminRole to enable cascade
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string]$Node,
        [Parameter()][bool]$Cascade = $false
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    try {
        $roleData.RoleManagedNodeUpdate($roleObject, $targetNode, ($Cascade -eq $true)).GetAwaiter().GetResult() | Out-Null
        $nodeDisplayName = if ([string]::IsNullOrEmpty($targetNode.DisplayName)) { $targetNode.Id.ToString() } else { $targetNode.DisplayName }
        Write-Output "Managed node `"$nodeDisplayName`" updated for role `"$($roleObject.DisplayName)`" successfully."
    }
    catch {
        Write-Error -Message "Failed to update managed node: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Update-KeeperEnterpriseRoleManagedNode -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Update-KeeperRoleManagedNode -Value Update-KeeperEnterpriseRoleManagedNode

function Remove-KeeperEnterpriseRoleManagedNode {
    <#
    .SYNOPSIS
    Removes a managed node from an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Node
    Node name or ID of the managed node to remove

    .DESCRIPTION
    Removes a node from the managed nodes list of an enterprise role.

    .EXAMPLE
    Remove-KeeperEnterpriseRoleManagedNode -Role "AdminRole" -Node "Sales"
    Removes the Sales node from the managed nodes of AdminRole
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string]$Node
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    $nodeDisplayName = if ([string]::IsNullOrEmpty($targetNode.DisplayName)) { $targetNode.Id.ToString() } else { $targetNode.DisplayName }

    if ($PSCmdlet.ShouldProcess("Managed node `"$nodeDisplayName`" from role `"$($roleObject.DisplayName)`"", "Remove")) {
        try {
            $roleData.RoleManagedNodeRemove($roleObject, $targetNode).GetAwaiter().GetResult() | Out-Null
            Write-Output "Managed node `"$nodeDisplayName`" deleted from role `"$($roleObject.DisplayName)`" successfully."
        }
        catch {
            Write-Error -Message "Failed to remove managed node: $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseRoleManagedNode -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Remove-KeeperRoleManagedNode -Value Remove-KeeperEnterpriseRoleManagedNode

function Add-KeeperEnterpriseRolePrivilege {
    <#
    .SYNOPSIS
    Adds privileges to a managed node for an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Node
    Node name or ID of the managed node

    .PARAMETER Privilege
    One or more privilege names to add. Valid values: MANAGE_NODES, MANAGE_USER, MANAGE_LICENCES, MANAGE_ROLES, MANAGE_TEAMS, TRANSFER_ACCOUNT, RUN_REPORTS, VIEW_TREE, MANAGE_BRIDGE, MANAGE_COMPANIES, SHARING_ADMINISTRATOR, APPROVE_DEVICE, MANAGE_RECORD_TYPES, RUN_COMPLIANCE_REPORTS

    .DESCRIPTION
    Adds privileges to a managed node for an enterprise role. The node must already be a managed node for the role.

    .EXAMPLE
    Add-KeeperEnterpriseRolePrivilege -Role "AdminRole" -Node "Sales" -Privilege "MANAGE_USERS", "MANAGE_TEAMS"
    Adds MANAGE_USERS and MANAGE_TEAMS privileges to the Sales managed node for AdminRole

    .EXAMPLE
    Add-KeeperEnterpriseRolePrivilege -Role 123456789 -Node "Sales" -Privilege "RUN_REPORTS"
    Adds RUN_REPORTS privilege using role ID
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string]$Node,
        [Parameter(Position = 2, Mandatory = $true)][string[]]$Privilege
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    $managedNodes = $roleData.GetManagedNodes() | Where-Object { $_.RoleId -eq $roleObject.Id -and $_.ManagedNodeId -eq $targetNode.Id }
    if ($managedNodes.Count -eq 0) {
        $nodeDisplayName = if ([string]::IsNullOrEmpty($targetNode.DisplayName)) { $targetNode.Id.ToString() } else { $targetNode.DisplayName }
        Write-Error -Message "Role `"$($roleObject.DisplayName)`" does not have node `"$nodeDisplayName`" as a managed node. Use Add-KeeperEnterpriseRoleManagedNode first." -ErrorAction Stop
    }

    $privilegeList = New-Object System.Collections.Generic.List[KeeperSecurity.Enterprise.RoleManagedNodePrivilege]
    $invalidPrivileges = @()

    foreach ($priv in $Privilege) {
        $privTrimmed = $priv.Trim()
        if ([System.Enum]::TryParse([KeeperSecurity.Enterprise.RoleManagedNodePrivilege], $privTrimmed, $true, [ref]$null)) {
            $parsedPriv = [System.Enum]::Parse([KeeperSecurity.Enterprise.RoleManagedNodePrivilege], $privTrimmed, $true)
            $privilegeList.Add($parsedPriv)
        }
        else {
            $invalidPrivileges += $privTrimmed
        }
    }

    if ($invalidPrivileges.Count -gt 0) {
        $validValues = [System.Enum]::GetNames([KeeperSecurity.Enterprise.RoleManagedNodePrivilege]) -join ", "
        Write-Error -Message "Invalid privileges: $($invalidPrivileges -join ', '). Valid values: $validValues" -ErrorAction Stop
    }

    if ($privilegeList.Count -eq 0) {
        Write-Error -Message "No valid privileges specified." -ErrorAction Stop
    }

    try {
        $responses = $roleData.RoleManagedNodePrivilegeAddBatch($roleObject, $targetNode, $privilegeList).GetAwaiter().GetResult()
        
        for ($i = 0; $i -lt $responses.Count; $i++) {
            $response = $responses[$i]
            $privilege = $privilegeList[$i]
            if ($response.IsSuccess) {
                Write-Output "Command: $($response.command), Privilege: $privilege, Result: $($response.result)"
            }
            else {
                Write-Output "Command: $($response.command), Privilege: $privilege, Result: $($response.result), Code: $($response.resultCode), Message: $($response.message)"
            }
        }
    }
    catch {
        Write-Error -Message "Failed to add privileges: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseRolePrivilege -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Add-KeeperRolePrivilege -Value Add-KeeperEnterpriseRolePrivilege

function Remove-KeeperEnterpriseRolePrivilege {
    <#
    .SYNOPSIS
    Removes privileges from a managed node for an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Node
    Node name or ID of the managed node

    .PARAMETER Privilege
    One or more privilege names to remove. Valid values: MANAGE_NODES, MANAGE_USER, MANAGE_LICENCES, MANAGE_ROLES, MANAGE_TEAMS, TRANSFER_ACCOUNT, RUN_REPORTS, VIEW_TREE, MANAGE_BRIDGE, MANAGE_COMPANIES, SHARING_ADMINISTRATOR, APPROVE_DEVICE, MANAGE_RECORD_TYPES, RUN_COMPLIANCE_REPORTS

    .DESCRIPTION
    Removes privileges from a managed node for an enterprise role.

    .EXAMPLE
    Remove-KeeperEnterpriseRolePrivilege -Role "AdminRole" -Node "Sales" -Privilege "MANAGE_USERS"
    Removes MANAGE_USERS privilege from the Sales managed node for AdminRole
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string]$Node,
        [Parameter(Position = 2, Mandatory = $true)][string[]]$Privilege
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    $targetNode = resolveSingleNode $Node
    if (-not $targetNode) {
        Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop
    }

    $managedNodes = $roleData.GetManagedNodes() | Where-Object { $_.RoleId -eq $roleObject.Id -and $_.ManagedNodeId -eq $targetNode.Id }
    if ($managedNodes.Count -eq 0) {
        $nodeDisplayName = if ([string]::IsNullOrEmpty($targetNode.DisplayName)) { $targetNode.Id.ToString() } else { $targetNode.DisplayName }
        Write-Error -Message "Role `"$($roleObject.DisplayName)`" does not have node `"$nodeDisplayName`" as a managed node. Use Add-KeeperEnterpriseRoleManagedNode first." -ErrorAction Stop
    }

    $privilegeList = New-Object System.Collections.Generic.List[KeeperSecurity.Enterprise.RoleManagedNodePrivilege]
    $invalidPrivileges = @()

    foreach ($priv in $Privilege) {
        $privTrimmed = $priv.Trim()
        if ([System.Enum]::TryParse([KeeperSecurity.Enterprise.RoleManagedNodePrivilege], $privTrimmed, $true, [ref]$null)) {
            $parsedPriv = [System.Enum]::Parse([KeeperSecurity.Enterprise.RoleManagedNodePrivilege], $privTrimmed, $true)
            $privilegeList.Add($parsedPriv)
        }
        else {
            $invalidPrivileges += $privTrimmed
        }
    }

    if ($invalidPrivileges.Count -gt 0) {
        $validValues = [System.Enum]::GetNames([KeeperSecurity.Enterprise.RoleManagedNodePrivilege]) -join ", "
        Write-Error -Message "Invalid privileges: $($invalidPrivileges -join ', '). Valid values: $validValues" -ErrorAction Stop
    }

    if ($privilegeList.Count -eq 0) {
        Write-Error -Message "No valid privileges specified." -ErrorAction Stop
    }

    try {
        $responses = $roleData.RoleManagedNodePrivilegeRemoveBatch($roleObject, $targetNode, $privilegeList).GetAwaiter().GetResult()
        
        for ($i = 0; $i -lt $responses.Count; $i++) {
            $response = $responses[$i]
            $privilege = $privilegeList[$i]
            if ($response.IsSuccess) {
                Write-Output "Command: $($response.command), Privilege: $privilege, Result: $($response.result)"
            }
            else {
                Write-Output "Command: $($response.command), Privilege: $privilege, Result: $($response.result), Code: $($response.resultCode), Message: $($response.message)"
            }
        }
    }
    catch {
        Write-Error -Message "Failed to remove privileges: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseRolePrivilege -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Remove-KeeperRolePrivilege -Value Remove-KeeperEnterpriseRolePrivilege

function Add-KeeperEnterpriseRoleEnforcement {
    <#
    .SYNOPSIS
    Adds enforcements to an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Enforcement
    Enforcement(s) in KEY=value format. Can be semicolon or comma separated. Multiple enforcements can be provided as an array.

    .DESCRIPTION
    Adds enforcement policies to an enterprise role. Enforcements are specified in KEY=value format.
    Multiple enforcements can be provided separated by semicolons or commas, or as an array.

    .EXAMPLE
    Add-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB=3600"
    Adds a two-factor authentication duration enforcement

    .EXAMPLE
    Add-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB=3600;MASTER_PASSWORD_MINIMUM_LENGTH=12"
    Adds multiple enforcements separated by semicolons
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string[]]$Enforcement
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    if ($null -eq $Enforcement -or $Enforcement.Count -eq 0) {
        Write-Error -Message "Enforcement parameter is required. Format: KEY=value;KEY2=value2 (semicolon or comma separated)." -ErrorAction Stop
    }

    $enforcementDict = New-Object 'System.Collections.Generic.Dictionary[KeeperSecurity.Enterprise.RoleEnforcementPolicies,string]'
    $enforcementKeys = New-Object System.Collections.Generic.List[KeeperSecurity.Enterprise.RoleEnforcementPolicies]
    $invalidEnforcements = @()

    foreach ($item in $Enforcement) {
        # since we are using the same separator for both semicolon and comma
        $parts = $item -split '[;,]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        foreach ($part in $parts) {
            $trimmedPart = $part.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmedPart)) { continue }

            $separatorIndex = $trimmedPart.IndexOf('=')
            if ($separatorIndex -lt 0) {
                $separatorIndex = $trimmedPart.IndexOf(':')
            }

            $key = $null
            $value = $null

            if ($separatorIndex -gt 0) {
                $key = $trimmedPart.Substring(0, $separatorIndex).Trim()
                $value = $trimmedPart.Substring($separatorIndex + 1).Trim()
            }
            else {
                $key = $trimmedPart
            }

            $parsedKey = ConvertTo-RoleEnforcementPolicy $key
            if ($null -ne $parsedKey) {
                $enforcementDict[$parsedKey] = $value
                $enforcementKeys.Add($parsedKey)
            }
            else {
                $invalidEnforcements += $key
            }
        }
    }

    if ($invalidEnforcements.Count -gt 0) {
        $validValues = [System.Enum]::GetNames([KeeperSecurity.Enterprise.RoleEnforcementPolicies]) -join ", "
        Write-Error -Message "Invalid enforcements: $($invalidEnforcements -join ', '). Valid values: $validValues" -ErrorAction Stop
    }

    if ($enforcementKeys.Count -eq 0) {
        Write-Error -Message "No valid enforcements specified." -ErrorAction Stop
    }

    try {
        $responses = $roleData.RoleEnforcementAddBatch($roleObject, $enforcementDict).GetAwaiter().GetResult()
        
        for ($i = 0; $i -lt $responses.Count; $i++) {
            $response = $responses[$i]
            $enforcementKey = $enforcementKeys[$i]
            if ($response.IsSuccess) {
                $value = if ($enforcementDict.ContainsKey($enforcementKey) -and $enforcementDict[$enforcementKey]) { "=$($enforcementDict[$enforcementKey])" } else { "" }
                Write-Output "Command: $($response.command), Enforcement: $enforcementKey$value, Result: $($response.result)"
            }
            else {
                Write-Output "Command: $($response.command), Enforcement: $enforcementKey, Result: $($response.result), Code: $($response.resultCode), Message: $($response.message)"
            }
        }
    }
    catch {
        Write-Error -Message "Failed to add enforcements: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseRoleEnforcement -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Add-KeeperRoleEnforcement -Value Add-KeeperEnterpriseRoleEnforcement

function Update-KeeperEnterpriseRoleEnforcement {
    <#
    .SYNOPSIS
    Updates enforcements for an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Enforcement
    Enforcement(s) in KEY=value format. Can be semicolon or comma separated. Multiple enforcements can be provided as an array.

    .DESCRIPTION
    Updates enforcement policies for an enterprise role. Enforcements are specified in KEY=value format.

    .EXAMPLE
    Update-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB=7200"
    Updates the two-factor authentication duration enforcement

    .EXAMPLE
    Update-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB=7200,MASTER_PASSWORD_MINIMUM_LENGTH=16"
    Updates multiple enforcements separated by commas
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string[]]$Enforcement
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    if ($null -eq $Enforcement -or $Enforcement.Count -eq 0) {
        Write-Error -Message "Enforcement parameter is required. Format: KEY=value;KEY2=value2 (semicolon or comma separated)." -ErrorAction Stop
    }

    $enforcementDict = New-Object 'System.Collections.Generic.Dictionary[KeeperSecurity.Enterprise.RoleEnforcementPolicies,string]'
    $enforcementKeys = New-Object System.Collections.Generic.List[KeeperSecurity.Enterprise.RoleEnforcementPolicies]
    $invalidEnforcements = @()

    foreach ($item in $Enforcement) {
        $parts = $item -split '[;,]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        foreach ($part in $parts) {
            $trimmedPart = $part.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmedPart)) { continue }

            $separatorIndex = $trimmedPart.IndexOf('=')
            if ($separatorIndex -lt 0) {
                $separatorIndex = $trimmedPart.IndexOf(':')
            }

            $key = $null
            $value = $null

            if ($separatorIndex -gt 0) {
                $key = $trimmedPart.Substring(0, $separatorIndex).Trim()
                $value = $trimmedPart.Substring($separatorIndex + 1).Trim()
            }
            else {
                $key = $trimmedPart
            }

            $parsedKey = ConvertTo-RoleEnforcementPolicy $key
            if ($null -ne $parsedKey) {
                $enforcementDict[$parsedKey] = $value
                $enforcementKeys.Add($parsedKey)
            }
            else {
                $invalidEnforcements += $key
            }
        }
    }

    if ($invalidEnforcements.Count -gt 0) {
        $validValues = [System.Enum]::GetNames([KeeperSecurity.Enterprise.RoleEnforcementPolicies]) -join ", "
        Write-Error -Message "Invalid enforcements: $($invalidEnforcements -join ', '). Valid values: $validValues" -ErrorAction Stop
    }

    if ($enforcementKeys.Count -eq 0) {
        Write-Error -Message "No valid enforcements specified." -ErrorAction Stop
    }

    try {
        $responses = $roleData.RoleEnforcementUpdateBatch($roleObject, $enforcementDict).GetAwaiter().GetResult()
        
        for ($i = 0; $i -lt $responses.Count; $i++) {
            $response = $responses[$i]
            $enforcementKey = $enforcementKeys[$i]
            if ($response.IsSuccess) {
                $value = if ($enforcementDict.ContainsKey($enforcementKey) -and $enforcementDict[$enforcementKey]) { "=$($enforcementDict[$enforcementKey])" } else { "" }
                Write-Output "Command: $($response.command), Enforcement: $enforcementKey$value, Result: $($response.result)"
            }
            else {
                Write-Output "Command: $($response.command), Enforcement: $enforcementKey, Result: $($response.result), Code: $($response.resultCode), Message: $($response.message)"
            }
        }
    }
    catch {
        Write-Error -Message "Failed to update enforcements: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Update-KeeperEnterpriseRoleEnforcement -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Update-KeeperRoleEnforcement -Value Update-KeeperEnterpriseRoleEnforcement

function Remove-KeeperEnterpriseRoleEnforcement {
    <#
    .SYNOPSIS
    Removes enforcements from an Enterprise Role

    .PARAMETER Role
    Role Name or ID

    .PARAMETER Enforcement
    Enforcement key(s) to remove. Can be semicolon or comma separated. For remove operations, use KEY only (no value).

    .DESCRIPTION
    Removes enforcement policies from an enterprise role. Only the enforcement key is required (no value).

    .EXAMPLE
    Remove-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB"
    Removes the TWO_FACTOR_DURATION_WEB enforcement

    .EXAMPLE
    Remove-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB;MASTER_PASSWORD_MINIMUM_LENGTH"
    Removes multiple enforcements separated by semicolons

    .EXAMPLE
    Remove-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB,MASTER_PASSWORD_MINIMUM_LENGTH"
    Removes multiple enforcements separated by commas
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Role,
        [Parameter(Position = 1, Mandatory = $true)][string[]]$Enforcement
    )

    [Enterprise]$enterprise = getEnterprise
    $roleData = $enterprise.roleData

    $roleObject = resolveRole $roleData $Role
    if (-not $roleObject) {
        return
    }

    if ($null -eq $Enforcement -or $Enforcement.Count -eq 0) {
        Write-Error -Message "Enforcement parameter is required. Format: KEY (for remove operations, use KEY only)." -ErrorAction Stop
    }

    $enforcementKeys = New-Object System.Collections.Generic.List[KeeperSecurity.Enterprise.RoleEnforcementPolicies]
    $invalidEnforcements = @()

    foreach ($item in $Enforcement) {
        $parts = $item -split '[;,]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        foreach ($part in $parts) {
            $trimmedPart = $part.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmedPart)) { continue }

            $separatorIndex = $trimmedPart.IndexOf('=')
            if ($separatorIndex -lt 0) {
                $separatorIndex = $trimmedPart.IndexOf(':')
            }

            $key = if ($separatorIndex -gt 0) { $trimmedPart.Substring(0, $separatorIndex).Trim() } else { $trimmedPart }

            $parsedKey = ConvertTo-RoleEnforcementPolicy $key
            if ($null -ne $parsedKey) {
                $enforcementKeys.Add($parsedKey)
            }
            else {
                $invalidEnforcements += $key
            }
        }
    }

    if ($invalidEnforcements.Count -gt 0) {
        $validValues = [System.Enum]::GetNames([KeeperSecurity.Enterprise.RoleEnforcementPolicies]) -join ", "
        Write-Error -Message "Invalid enforcements: $($invalidEnforcements -join ', '). Valid values: $validValues" -ErrorAction Stop
    }

    if ($enforcementKeys.Count -eq 0) {
        Write-Error -Message "No valid enforcements specified." -ErrorAction Stop
    }

    try {
        $responses = $roleData.RoleEnforcementRemoveBatch($roleObject, $enforcementKeys).GetAwaiter().GetResult()
        
        for ($i = 0; $i -lt $responses.Count; $i++) {
            $response = $responses[$i]
            $enforcementKey = $enforcementKeys[$i]
            if ($response.IsSuccess) {
                Write-Output "Command: $($response.command), Enforcement: $enforcementKey, Result: $($response.result)"
            }
            else {
                Write-Output "Command: $($response.command), Enforcement: $enforcementKey, Result: $($response.result), Code: $($response.resultCode), Message: $($response.message)"
            }
        }
    }
    catch {
        Write-Error -Message "Failed to remove enforcements: $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseRoleEnforcement -ParameterName Role -ScriptBlock $Keeper_RoleNameCompleter
New-Alias -Name Remove-KeeperRoleEnforcement -Value Remove-KeeperEnterpriseRoleEnforcement

function Copy-KeeperEnterpriseRole {
    <#
        .SYNOPSIS
        Copies an enterprise role to another node with enforcements, users, and teams.

        .DESCRIPTION
        Creates a new role on the target node with the same NewUserInherit and VisibleBelow as the source role,
        copies all enforcements, and optionally copies users and teams from the source role to the new role.

        .PARAMETER SourceRole
        Role name, ID, or EnterpriseRole object to copy from.

        .PARAMETER TargetNode
        Target node name or ID where the new role will be created.

        .PARAMETER NewRoleName
        Display name for the new role.

        .PARAMETER CopyUsers
        Copy users from the source role to the new role. Default is $true.

        .PARAMETER CopyTeams
        Copy teams from the source role to the new role. Default is $true.

        .PARAMETER Force
        Reload enterprise data before running.

        .EXAMPLE
        Copy-KeeperEnterpriseRole -SourceRole "Test-App" -TargetNode "dev" -NewRoleName "second dev"
        Creates a new role "second dev" on node "dev" with enforcements, users, and teams from "Test-App".

        .EXAMPLE
        Copy-KeeperEnterpriseRole -SourceRole "AdminRole" -TargetNode 123456789 -NewRoleName "AdminRole-Copy" -CopyUsers $false
        Copies only enforcements and teams (no users) to the new role.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$SourceRole,
        [Parameter(Position = 1, Mandatory = $true)][string]$TargetNode,
        [Parameter(Position = 2, Mandatory = $true)][string]$NewRoleName,
        [Parameter()][bool]$CopyUsers = $true,
        [Parameter()][bool]$CopyTeams = $true,
        [Parameter()][switch]$Force
    )

    if ($Force) {
        Sync-KeeperEnterprise | Out-Null
    }

    [Enterprise]$enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $roleData = $enterprise.roleData

    $sourceRoleObject = resolveRole $roleData $SourceRole
    if (-not $sourceRoleObject) {
        return
    }

    $targetNodeObject = resolveSingleNode $TargetNode
    if (-not $targetNodeObject) {
        return
    }

    $nodeId = $targetNodeObject.Id
    $newRoleNameTrimmed = $NewRoleName.Trim()
    $sourceName = $sourceRoleObject.DisplayName

    if ($PSCmdlet.ShouldProcess("Role `"$newRoleNameTrimmed`" on node `"$($targetNodeObject.DisplayName)`"", "Copy from `"$sourceName`"")) {
        try {
            $newRole = $roleData.CreateRole($newRoleNameTrimmed, $nodeId, $sourceRoleObject.NewUserInherit).GetAwaiter().GetResult()
            if (-not $newRole) {
                Write-Error "Failed to create role `"$newRoleNameTrimmed`"" -ErrorAction Stop
                return
            }

            if ($newRole.VisibleBelow -ne $sourceRoleObject.VisibleBelow) {
                try {
                    $updated = $roleData.UpdateRole($newRole, $null, $sourceRoleObject.VisibleBelow, $null).GetAwaiter().GetResult()
                    if ($updated) {
                        $newRole = $updated
                    }
                }
                catch {
                    Write-Warning "Failed to set VisibleBelow for role `"$newRoleNameTrimmed`": $($_.Exception.Message)"
                }
            }

            $sourceEnforcements = @($roleData.GetEnforcementsForRole($sourceRoleObject.Id))
            if ($sourceEnforcements.Count -gt 0) {
                $enforcementDict = New-Object 'System.Collections.Generic.Dictionary[KeeperSecurity.Enterprise.RoleEnforcementPolicies,string]'
                foreach ($re in $sourceEnforcements) {
                    $enforcementTypeStr = $re.EnforcementType
                    if ([string]::IsNullOrWhiteSpace($enforcementTypeStr)) { continue }
                    $normalized = $enforcementTypeStr -replace '_', ''
                    $parsed = $null
                    if ([System.Enum]::TryParse([KeeperSecurity.Enterprise.RoleEnforcementPolicies], $normalized, $true, [ref]$parsed)) {
                        $enforcementDict[$parsed] = if ($re.Value) { $re.Value } else { '' }
                    }
                }
                if ($enforcementDict.Count -gt 0) {
                    $roleData.RoleEnforcementAddBatch($newRole, $enforcementDict).GetAwaiter().GetResult() | Out-Null
                }
            }

            $usersCopied = 0
            if ($CopyUsers) {
                $sourceUserIds = @($roleData.GetUsersForRole($sourceRoleObject.Id))
                foreach ($userId in $sourceUserIds) {
                    $user = $null
                    if ($enterpriseData.TryGetUserById($userId, [ref]$user)) {
                        try {
                            $roleData.AddUserToRole($newRole, $user).GetAwaiter().GetResult() | Out-Null
                            $usersCopied++
                        }
                        catch {
                            Write-Warning "Could not add user `"$($user.Email)`" to new role: $($_.Exception.Message)"
                        }
                    }
                }
            }

            $teamsCopied = 0
            if ($CopyTeams) {
                $sourceTeamUids = @($roleData.GetTeamsForRole($sourceRoleObject.Id))
                foreach ($teamUid in $sourceTeamUids) {
                    $team = $null
                    if ($enterpriseData.TryGetTeam($teamUid, [ref]$team)) {
                        try {
                            $roleData.AddTeamToRole($newRole, $team).GetAwaiter().GetResult() | Out-Null
                            $teamsCopied++
                        }
                        catch {
                            Write-Warning "Could not add team `"$($team.Name)`" to new role: $($_.Exception.Message)"
                        }
                    }
                }
            }

            try {
                $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
            }
            catch {
                Write-Warning "Failed to reload enterprise data: $($_.Exception.Message)"
            }

            $msg = "Role `"$newRoleNameTrimmed`" created with enforcements from `"$sourceName`""
            if ($usersCopied -gt 0 -or $teamsCopied -gt 0) {
                $msg += " ($usersCopied user(s), $teamsCopied team(s) copied)"
            }
            $msg += "."
            Write-Output $msg
        }
        catch {
            Write-Error "Copy role failed: $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
Register-ArgumentCompleter -CommandName Copy-KeeperEnterpriseRole -ParameterName SourceRole -ScriptBlock $Keeper_RoleNameCompleter
Register-ArgumentCompleter -CommandName Copy-KeeperEnterpriseRole -ParameterName TargetNode -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) { return $null }
    $to_complete = if ($wordToComplete) { $wordToComplete + '*' } else { '*' }
    foreach ($node in $enterprise.enterpriseData.Nodes) {
        if ($node.DisplayName -like $to_complete) {
            $nodeName = $node.DisplayName
            if ($nodeName -match '[\s'']') { $nodeName = $nodeName -replace '''', ''''''; $nodeName = "'${nodeName}'" }
            $result += $nodeName
        }
    }
    if ($result.Count -gt 0) { return $result }
    return $null
}
New-Alias -Name kercopy -Value Copy-KeeperEnterpriseRole