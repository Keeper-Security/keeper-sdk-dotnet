$Script:Keeper_TeamNameCompleter = {
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

$Script:Keeper_ActiveUserCompleter = {
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

$Script:Keeper_LockedUserCompleter = {
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

$Script:Keeper_EnterpriseUserCompleter = {
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

$Script:Keeper_RoleNameCompleter = {
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

function resolveRole {
    Param (
        $roleData,
        $role
    )
    [KeeperSecurity.Enterprise.EnterpriseRole] $r = $null

    if ($role -is [long]) {
        if ($roleData.TryGetRole($role, [ref]$r)) {
            return $r
        }
    }
    elseif ($role -is [string]) {
        $roles = Get-KeeperEnterpriseRole | Where-Object { $_.Id -eq $role -or $_.DisplayName -ieq $role }
        if ($roles.Length -eq 1) {
            if ($roleData.TryGetRole($roles[0].Id, [ref]$r)) {
                return $r
            }
        }
        elseif ($roles.Length -gt 1) {
            Write-Error "Role name `"$role`" is not unique. Use Role ID" -ErrorAction Stop
            return $null
        }
    }
    elseif ($role -is [KeeperSecurity.Enterprise.EnterpriseRole]) {
        if ($roleData.TryGetRole($role.Id, [ref]$r)) {
            return $r
        }
    }
    Write-Error "`"${role}`" cannot be resolved as enterprise role" -ErrorAction Stop
    return $null
}

function resolveTeam {
    Param (
        $enterpriseData,
        $team
    )
    [KeeperSecurity.Enterprise.EnterpriseTeam] $t = $null

    if ($team -is [string]) {
        if ($enterpriseData.TryGetTeam($team, [ref]$t)) {
            return $t
        }

        $teams = $enterpriseData.Teams | Where-Object { $_.Name -ieq $team }
        if ($teams.Count -eq 1) {
            if ($enterpriseData.TryGetTeam($teams[0].Uid, [ref]$t)) {
                return $t
            }
        }
        elseif ($teams.Count -gt 1) {
            Write-Error "Team name `"$team`" is not unique. Use Team UID" -ErrorAction Stop
            return $null
        }
    }
    elseif ($team -is [KeeperSecurity.Enterprise.EnterpriseTeam]) {
        if ($enterpriseData.TryGetTeam($team.Uid, [ref]$t)) {
            return $t
        }
    }
    Write-Error "`"${team}`" cannot be resolved as enterprise team" -ErrorAction Stop
    return $null
}

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

function Get-KeeperNodePath {
    <#
    .SYNOPSIS
    Get the path string for an enterprise node (e.g. "Root \ Sales \ EMEA").
    .PARAMETER NodeId
    Enterprise node ID.
    .PARAMETER OmitRoot
    If set, root node name is omitted from the path.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][long] $NodeId,
        [Parameter()][switch] $OmitRoot
    )
    $enterprise = getEnterprise
    $ed = $enterprise.enterpriseData
    $node = $null
    if (-not $ed.TryGetNode($NodeId, [ref]$node)) { return '' }
    $parts = [System.Collections.Generic.List[string]]::new()
    $current = $node
    while ($null -ne $current) {
        $name = $current.DisplayName
        if ([string]::IsNullOrEmpty($name) -and $current.ParentNodeId -le 0) {
            $name = $enterprise.loader.EnterpriseName
        }
        if (-not [string]::IsNullOrEmpty($name)) {
            $parts.Insert(0, $name)
        }
        if ($current.ParentNodeId -le 0) { break }
        $parent = $null
        if (-not $ed.TryGetNode($current.ParentNodeId, [ref]$parent)) { break }
        $current = $parent
    }
    if ($OmitRoot -and $parts.Count -gt 1) {
        $parts.RemoveAt(0)
    }
    return ($parts -join '\')
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

function Get-KeeperTeamByNameOrUid {
    param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        
        [Parameter(Mandatory = $true)]
        [string] $TeamInput
    )

    foreach ($t in $EnterpriseData.Teams) {
        if (($t.Uid -eq $TeamInput) -or ($t.Name -and ($t.Name.Trim().ToLower() -eq $TeamInput.Trim().ToLower()))) {
            return $t
        }
    }
    return $null
}

