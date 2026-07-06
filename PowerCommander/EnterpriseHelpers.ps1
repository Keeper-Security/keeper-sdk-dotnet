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
        $user,
        $userAliasData = $null
    )
    [KeeperSecurity.Enterprise.EnterpriseUser] $u = $null

    if ($user -is [long]) {
        if ($enterpriseData.TryGetUserById($user, [ref]$u)) {
            return $u
        }
    }
    elseif ($user -is [int]) {
        if ($enterpriseData.TryGetUserById([long]$user, [ref]$u)) {
            return $u
        }
    }
    elseif ($user -is [string]) {
        if ($enterpriseData.TryGetUserByEmail($user, [ref]$u)) {
            return $u
        }
        if ($user -match '^\d+$') {
            if ($enterpriseData.TryGetUserById([long]$user, [ref]$u)) {
                return $u
            }
        }
        if ($userAliasData) {
            $normalizedUserEmail = $user.Trim().ToLowerInvariant()
            foreach ($enterpriseUser in $enterpriseData.Users) {
                foreach ($alias in $userAliasData.GetAliasesForUser($enterpriseUser.Id)) {
                    if ($alias.ToLowerInvariant() -eq $normalizedUserEmail) {
                        if ($enterpriseData.TryGetUserById($enterpriseUser.Id, [ref]$u)) {
                            return $u
                        }
                    }
                }
            }
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
        $nodes = Get-EnterpriseNode | Where-Object { $_.Id -eq $node }
        if ($nodes.Length -eq 0) {
            $nodes = Get-EnterpriseNode | Where-Object { $_.DisplayName -like $node + '*' }
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

function Script:Resolve-EnterpriseNodeFilter {
    param(
        [Parameter(Mandatory = $true)]
        [Enterprise] $Enterprise,

        [Parameter()]
        [string[]] $Nodes
    )

    if (-not $Nodes -or $Nodes.Count -eq 0) {
        return $null
    }

    $resolvedIds = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($nodeInput in $Nodes) {
        if ([string]::IsNullOrWhiteSpace($nodeInput)) {
            continue
        }

        $resolvedNode = resolveSingleNode $nodeInput.Trim()
        if ($null -eq $resolvedNode) {
            continue
        }

        $descendantIds = Get-EnterpriseNodeAndDescendantIds $Enterprise.enterpriseData $resolvedNode.Id
        foreach ($nodeId in $descendantIds) {
            [void]$resolvedIds.Add($nodeId)
        }
    }

    return $resolvedIds
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
        $roles = Get-EnterpriseRole | Where-Object { $_.Id -eq $role -or $_.DisplayName -ieq $role }
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

function Resolve-EnterpriseTeamTarget {
    param (
        [Parameter(Mandatory = $true)][Enterprise]$Enterprise,
        [Parameter(Mandatory = $true)][string]$TeamInput
    )

    if ([string]::IsNullOrWhiteSpace($TeamInput)) { return $null }

    $key = $TeamInput.Trim()
    $ed = $Enterprise.enterpriseData
    [KeeperSecurity.Enterprise.EnterpriseTeam]$team = $null

    if ($ed.TryGetTeam($key, [ref]$team)) {
        return [EnterpriseTeamTarget]::FromActiveTeam($team)
    }

    $nameMatches = @($ed.Teams | Where-Object { $_.Name -ieq $key })
    if ($nameMatches.Count -eq 1) {
        return [EnterpriseTeamTarget]::FromActiveTeam($nameMatches[0])
    }
    if ($nameMatches.Count -gt 1) {
        Write-Warning "Team name `"$key`" is not unique. Use Team UID."
        return $null
    }

    $queuedMatches = @(
        $Enterprise.queuedTeamData.QueuedTeams |
        Where-Object { $_.Uid -ceq $key -or $_.Name -ieq $key }
    )
    if ($queuedMatches.Count -eq 1) {
        return [EnterpriseTeamTarget]::FromQueuedTeam($queuedMatches[0])
    }
    if ($queuedMatches.Count -gt 1) {
        Write-Warning "Queued team name `"$key`" is not unique. Use Team UID."
        return $null
    }

    Write-Warning "Team `"$key`" not found."
    return $null
}

function Resolve-EnterpriseRoleList {
    param (
        [Parameter(Mandatory = $true)]$RoleData,
        [Parameter(Mandatory = $true)][string[]]$Roles
    )

    $resolved = [System.Collections.Generic.List[KeeperSecurity.Enterprise.EnterpriseRole]]::new()
    foreach ($roleInput in $Roles) {
        if ([string]::IsNullOrWhiteSpace($roleInput)) {
            Write-Warning "Skipping empty role value."
            continue
        }
        try {
            $role = resolveRole $RoleData $roleInput.Trim()
            if ($role) { [void]$resolved.Add($role) }
        }
        catch { Write-Warning $_.Exception.Message }
    }
    return $resolved
}

function Get-EnterpriseTeamMemberInputs {
    param (
        [AllowNull()]
        [string[]]$EmailInputs,
        [AllowNull()]
        [string[]]$UserInputs
    )

    $memberInputsList = [System.Collections.Generic.List[string]]::new()

    if ($null -ne $EmailInputs) {
        foreach ($email in $EmailInputs) {
            if ([string]::IsNullOrWhiteSpace($email)) {
                Write-Warning "Skipping empty email value."
                continue
            }
            [void]$memberInputsList.Add($email.Trim())
        }
    }

    if ($null -ne $UserInputs) {
        foreach ($userInput in $UserInputs) {
            if ([string]::IsNullOrWhiteSpace($userInput)) {
                Write-Warning "Skipping empty user value."
                continue
            }
            [void]$memberInputsList.Add($userInput.Trim())
        }
    }

    if ($memberInputsList.Count -eq 0) {
        throw "At least one user must be specified via -Emails or -User."
    }

    # Comma ensures a single user is returned as string[]
    return ,@($memberInputsList.ToArray())
}

function Get-EnterpriseTeamAdminUserTypeFromHideSharedFolders {
    <#
        .SYNOPSIS
        Maps -HideSharedFolders (on/off) to SDK TeamUserType admin values.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('on', 'off')]
        [string]$HideSharedFolders
    )

    if ($HideSharedFolders -eq 'on') {
        return [int][Enterprise.TeamUserType]::AdminOnly
    }
    return [int][Enterprise.TeamUserType]::Admin
}

function Test-EnterpriseRoleIsAdmin {
    param (
        [Parameter(Mandatory = $true)]$RoleData,
        [Parameter(Mandatory = $true)][long]$RoleId
    )
    return @($RoleData.GetManagedNodes() | Where-Object { $_.RoleId -eq $RoleId }).Count -gt 0
}

function Get-EnterpriseSdkWarningCallback {
    if ($null -eq $script:EnterpriseSdkWarningCallback) {
        $writeLine = [System.Console].GetMethod('WriteLine', [System.Type[]]@([string]))
        $script:EnterpriseSdkWarningCallback = [System.Delegate]::CreateDelegate(
            [System.Action[string]],
            $null,
            $writeLine
        )
    }
    return $script:EnterpriseSdkWarningCallback
}

function Invoke-EnterpriseAddUsersToTeams {
    param(
        [Parameter(Mandatory = $true)]$EnterpriseData,
        [Parameter(Mandatory = $true)][string[]]$Emails,
        [Parameter(Mandatory = $true)][string[]]$TeamUids
    )

    try {
        $callback = Get-EnterpriseSdkWarningCallback
        $EnterpriseData.AddUsersToTeams($Emails, $TeamUids, $callback).GetAwaiter().GetResult() | Out-Null
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        if ($message -match 'AddUsersToTeams' -and $message -match 'argument count') {
            $EnterpriseData.AddUsersToTeams($Emails, $TeamUids).GetAwaiter().GetResult() | Out-Null
        }
        else {
            throw
        }
    }
}

function Invoke-EnterpriseRemoveUsersFromTeams {
    param(
        [Parameter(Mandatory = $true)]$EnterpriseData,
        [Parameter(Mandatory = $true)][string[]]$Emails,
        [Parameter(Mandatory = $true)][string[]]$TeamUids
    )

    try {
        $callback = Get-EnterpriseSdkWarningCallback
        $EnterpriseData.RemoveUsersFromTeams($Emails, $TeamUids, $callback).GetAwaiter().GetResult() | Out-Null
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        if ($message -match 'RemoveUsersFromTeams' -and $message -match 'argument count') {
            $EnterpriseData.RemoveUsersFromTeams($Emails, $TeamUids).GetAwaiter().GetResult() | Out-Null
        }
        else {
            throw
        }
    }
}

function Add-EnterpriseUserToTeamMembership {
    param (
        [Parameter(Mandatory = $true)][EnterpriseTeamMembershipRequest]$Request
    )

    $Enterprise = $Request.Enterprise
    $User = $Request.User
    $TeamTarget = $Request.TeamTarget
    $HideSharedFolders = $Request.HideSharedFolders

    $ed = $Enterprise.enterpriseData
    $teamUid = $TeamTarget.Uid
    $teamName = $TeamTarget.Name
    $teamObject = $TeamTarget.Team

    if ($User.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Active) {
        if (-not $teamObject) {
            Write-Warning "Team `"$teamName`" is queued only. Active users cannot be added until the team is approved."
            return $false
        }

        $existingMember = @($ed.GetUsersForTeam($teamUid)) -contains $User.Id
        if ($existingMember) {
            if (-not [string]::IsNullOrWhiteSpace($HideSharedFolders)) {
                $userType = Get-EnterpriseTeamAdminUserTypeFromHideSharedFolders -HideSharedFolders $HideSharedFolders
                $ed.TeamEnterpriseUserUpdate($teamObject, $User, $userType).GetAwaiter().GetResult() | Out-Null
                Write-Output "User `"$($User.Email)`" team role updated in `"$teamName`"."
                return $true
            }
            Write-Warning "User `"$($User.Email)`" is already a member of team `"$teamName`"."
            return $false
        }

        Invoke-EnterpriseAddUsersToTeams -EnterpriseData $ed -Emails @($User.Email) -TeamUids @($teamUid)

        if (-not [string]::IsNullOrWhiteSpace($HideSharedFolders)) {
            $userType = Get-EnterpriseTeamAdminUserTypeFromHideSharedFolders -HideSharedFolders $HideSharedFolders
            $ed.TeamEnterpriseUserUpdate($teamObject, $User, $userType).GetAwaiter().GetResult() | Out-Null
        }

        Write-Output "User `"$($User.Email)`" added to team `"$teamName`"."
        return $true
    }

    # Commander queues inactive users via team_queue_user (no admin-type field on that API).
    # HideSharedFolders applies after the user is active and on the team (TeamEnterpriseUserUpdate).
    if (-not [string]::IsNullOrWhiteSpace($HideSharedFolders)) {
        Write-Warning "HideSharedFolders is not applied when queueing inactive user `"$($User.Email)`" to team `"$teamName`". Set admin type after the user is active."
    }

    $rq = New-Object KeeperSecurity.Commands.TeamQueueUserCommand
    $rq.TeamUid = $teamUid
    $rq.EnterpriseUserId = $User.Id
    $Enterprise.loader.Auth.ExecuteAuthCommand($rq).GetAwaiter().GetResult() | Out-Null
    $Enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
    Write-Output "User `"$($User.Email)`" queued to team `"$teamName`"."
    return $true
}


<#
.SYNOPSIS
    Parses an enforcement type string (from API or user) to RoleEnforcementPolicies enum.
.DESCRIPTION
    Tries the original string first, then underscore-removed, so both "REQUIRE_TWO_FACTOR" and "requiretwofactor" work.
    Used when reading enforcements from GetEnforcementsForRole (API) or when normalizing user input.
#>
function ConvertTo-RoleEnforcementPolicy {
    param([string]$EnforcementType)
    if ([string]::IsNullOrWhiteSpace($EnforcementType)) { return $null }
    $key = $EnforcementType.Trim()
    try {
        return [Enum]::Parse([KeeperSecurity.Enterprise.RoleEnforcementPolicies], $key, $true)
    }
    catch {
        $norm = $key -replace '_', ''
        try {
            return [Enum]::Parse([KeeperSecurity.Enterprise.RoleEnforcementPolicies], $norm, $true)
        }
        catch {
            return $null
        }
    }
}

<#
.SYNOPSIS
    Builds a dictionary of RoleEnforcementPolicies -> value from a role's enforcements.
.PARAMETER RoleData
    RoleData instance (from enterprise.roleData).
.PARAMETER RoleId
    Role ID to read enforcements for.
#>
function Get-RoleEnforcementDictionary {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Enterprise.RoleData]$RoleData,
        [Parameter(Mandatory = $true)]
        [long]$RoleId
    )
    $dict = [System.Collections.Generic.Dictionary[KeeperSecurity.Enterprise.RoleEnforcementPolicies, string]]::new()
    foreach ($re in $RoleData.GetEnforcementsForRole($RoleId)) {
        $policy = ConvertTo-RoleEnforcementPolicy $re.EnforcementType
        if ($null -ne $policy) {
            $dict[$policy] = if ($re.Value) { $re.Value } else { '' }
        }
    }
    return $dict
}
