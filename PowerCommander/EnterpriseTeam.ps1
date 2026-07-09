function New-KeeperEnterpriseTeam {
    <#
        .SYNOPSIS
        Create an enterprise team

        .DESCRIPTION
        Creates a new Keeper Enterprise Team under the specified parent node.

        .PARAMETER TeamName
        Team name (required)

        .PARAMETER ParentNode
        Parent node name or ID. Defaults to the enterprise root node.

        .PARAMETER RestrictView
        Disable password viewing/copying for team members.

        .PARAMETER RestrictEdit
        Disable record editing for team members.

        .PARAMETER RestrictShare
        Disable record re-sharing for team members.

        .EXAMPLE
        New-KeeperEnterpriseTeam -TeamName "Backend Team"
        Creates a team under the enterprise root node.

        .EXAMPLE
        New-KeeperEnterpriseTeam -TeamName "Support" -ParentNode 12345 -RestrictView
        Creates a team under node 12345 with restrict view enabled.

        .EXAMPLE
        keta "Frontend Team" -ParentNode "Engineering" -RestrictEdit -RestrictShare
        Creates a team using the keta alias with restrict edit and share enabled.
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
    } else {
        $team.ParentNodeId = $enterprise.enterpriseData.RootNode.Id
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

function Update-KeeperEnterpriseTeam {
    <#
        .SYNOPSIS
        Updates an existing enterprise team

        .DESCRIPTION
        Updates enterprise team properties including name, parent node, and restrict flags.
        Only specified parameters are changed; omitted parameters retain their current values.

        .PARAMETER Team
        Team UID or team name to update.

        .PARAMETER TeamName
        New team display name.

        .PARAMETER ParentNode
        Parent node name or ID to move the team under.

        .PARAMETER RestrictView
        Disable or enable password viewing/copying: ON or OFF.

        .PARAMETER RestrictEdit
        Disable or enable record editing: ON or OFF.

        .PARAMETER RestrictShare
        Disable or enable record re-sharing: ON or OFF.

        .EXAMPLE
        Update-KeeperEnterpriseTeam -Team "Developers" -RestrictEdit ON
        Enables restrict edit for the Developers team.

        .EXAMPLE
        Update-KeeperEnterpriseTeam -Team "1P7A8XZ9K3J9H" -RestrictShare OFF -RestrictView ON
        Updates restrict flags for a team identified by UID.

        .EXAMPLE
        Update-KeeperEnterpriseTeam -Team "Developers" -TeamName "Engineering" -ParentNode "IT" -RestrictShare OFF
        Renames the team, moves it to the IT node, and disables restrict share.

        .EXAMPLE
        kete "Developers" -RestrictEdit ON
        Updates a team using the kete alias.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Team,
        [Parameter()][string] $TeamName,
        [Parameter()][string] $ParentNode,
        [Parameter()][ValidateSet('ON', 'OFF')][string] $RestrictView,
        [Parameter()][ValidateSet('ON', 'OFF')][string] $RestrictEdit,
        [Parameter()][ValidateSet('ON', 'OFF')][string] $RestrictShare
    )

    [Enterprise]$enterprise = getEnterprise
    $teamObject = resolveTeam $enterprise.enterpriseData $Team
    if (-not $teamObject) {
        return
    }

    if ($PSBoundParameters.ContainsKey('TeamName')) {
        if ([string]::IsNullOrWhiteSpace($TeamName)) {
            Write-Error "TeamName cannot be empty." -ErrorAction Stop
        }
        $teamObject.Name = $TeamName.Trim()
    }
    if ($PSBoundParameters.ContainsKey('ParentNode')) {
        if ([string]::IsNullOrWhiteSpace($ParentNode)) {
            Write-Error "ParentNode cannot be empty." -ErrorAction Stop
        }
        $parent = resolveSingleNode $ParentNode
        $teamObject.ParentNodeId = $parent.Id
    }
    if ($PSBoundParameters.ContainsKey('RestrictView')) {
        $teamObject.RestrictView = ($RestrictView -eq 'ON')
    }
    if ($PSBoundParameters.ContainsKey('RestrictEdit')) {
        $teamObject.RestrictEdit = ($RestrictEdit -eq 'ON')
    }
    if ($PSBoundParameters.ContainsKey('RestrictShare')) {
        $teamObject.RestrictSharing = ($RestrictShare -eq 'ON')
    }

    $updateFields = @('TeamName', 'ParentNode', 'RestrictView', 'RestrictEdit', 'RestrictShare') |
        Where-Object { $PSBoundParameters.ContainsKey($_) }
    if ($updateFields.Count -eq 0) {
        Write-Warning "No changes specified. Use -TeamName, -ParentNode, or restrict flags to update the team."
        return
    }

    try {
        $updated = $enterprise.enterpriseData.UpdateTeam($teamObject).GetAwaiter().GetResult()
        Write-Output "Team `"$($updated.Name)`" updated."
        return $updated
    }
    catch {
        Write-Error "Failed to update team `"$($teamObject.Name)`": $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Update-KeeperEnterpriseTeam -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
New-Alias -Name kete -Value Update-KeeperEnterpriseTeam

function Remove-KeeperEnterpriseTeam {
    <#
        .SYNOPSIS
        Deletes an enterprise team

        .DESCRIPTION
        Permanently deletes an enterprise team by name or UID. This operation cannot be undone.
        Use -Force to skip the confirmation prompt.

        .PARAMETER Team
        Team UID or team name to delete.

        .PARAMETER Force
        Do not prompt for confirmation before deleting the team.

        .EXAMPLE
        Remove-KeeperEnterpriseTeam -Team "Old Team"
        Deletes the team after confirmation.

        .EXAMPLE
        Remove-KeeperEnterpriseTeam -Team "1P7A8XZ9K3J9H" -Force
        Deletes the team identified by UID without prompting for confirmation.

        .EXAMPLE
        ketdel "Old Team" -Force
        Deletes a team using the ketdel alias without confirmation.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)][string] $Team,
        [Parameter()][switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise
    $teamObject = resolveTeam $enterprise.enterpriseData $Team
    if (-not $teamObject) {
        return
    }

    $teamName = $teamObject.Name
    $teamUid = $teamObject.Uid

    if (-not $Force -and -not $PSCmdlet.ShouldProcess($teamName, "Delete Enterprise Team")) {
        return
    }

    try {
        $enterprise.enterpriseData.DeleteTeam($teamUid).GetAwaiter().GetResult() | Out-Null
        Write-Output "Team `"$teamName`" deleted successfully."
    }
    catch {
        Write-Error "Failed to delete team `"$teamName`": $($_.Exception.Message)" -ErrorAction Stop
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseTeam -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
New-Alias -Name ketdel -Value Remove-KeeperEnterpriseTeam

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
        $uids = Get-EnterpriseTeam | Where-Object { $_.Uid -ceq $Team -or $_.Name -ieq $Team } | Select-Object -Property Uid
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
            foreach ($memberUserId in (Get-EnterpriseDistinctUserIdsForTeam -EnterpriseData $enterpriseData -TeamUid $uid)) {
                $user = $null
                if ($enterpriseData.TryGetUserById($memberUserId, [ref]$user)) {
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

function Add-KeeperEnterpriseTeamMember {
    <#
        .SYNOPSIS
        Adds existing enterprise users to a Keeper team.

        .DESCRIPTION
        Adds one or more users by email (-Emails) or by email / enterprise user ID.
        At least one of -Emails or -User must be specified. Use -HideSharedFolders (on/off) for team
        admin types. Inactive users are queued to the team.

        If the user is already on the team, a warning is shown and no duplicate membership is created.
        When -HideSharedFolders is also specified, the team admin type is updated for that existing member.

        .PARAMETER Team
        Team UID or Team Name.

        .PARAMETER Emails
        One or more user email addresses to add to the team.

        .PARAMETER Users
        One or more user email addresses or enterprise user IDs to add to the team.
        -User is an alias for this parameter. Use -Emails, -User, or both together.

        .PARAMETER HideSharedFolders
        on = Admin Only (no shared folders). off = Admin with shared folder access.
        Applies when adding active users. Not applied when queueing inactive users
        (set admin type after the user is active).

        .EXAMPLE
        Add-KeeperEnterpriseTeamMember -Team "Engineering" -Emails "alice@example.com", "bob@example.com"

        .EXAMPLE
        Add-KeeperEnterpriseTeamMember -Team "Engineering" -User "user@example.com"

        .EXAMPLE
        Add-KeeperEnterpriseTeamMember -Team "Engineering" -User "user@example.com" -HideSharedFolders on
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string] $Team,
        [Parameter()][string[]] $Emails,
        [Parameter()][Alias('User')][string[]] $Users,
        [ValidateSet('on', 'off')][string]$HideSharedFolders
    )

    try {
        $userInputs = Get-EnterpriseTeamMemberInputs -EmailInputs $Emails -UserInputs $Users
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }

    [Enterprise]$enterprise = getEnterprise
    $teamTarget = Resolve-EnterpriseTeamTarget -Enterprise $enterprise -TeamInput $Team
    if (-not $teamTarget) { return }

    $processedUserIds = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($userInput in @($userInputs)) {
        try {
            $userObject = resolveUser $enterprise.enterpriseData $userInput
        }
        catch {
            Write-Warning $_.Exception.Message
            continue
        }

        if (-not $processedUserIds.Add($userObject.Id)) {
            Write-Warning "User `"$($userObject.Email)`" was already specified; skipping duplicate."
            continue
        }

        try {
            $request = [EnterpriseTeamMembershipRequest]::new()
            $request.Enterprise = $enterprise
            $request.User = $userObject
            $request.TeamTarget = $teamTarget
            if ($PSBoundParameters.ContainsKey('HideSharedFolders')) {
                $request.HideSharedFolders = $HideSharedFolders
            }
            [void](Add-EnterpriseUserToTeamMembership -Request $request)
        }
        catch {
            Write-Warning "Failed to add user `"$($userObject.Email)`" to team `"$($teamTarget.Name)`": $($_.Exception.Message)"
        }
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseTeamMember -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseTeamMember -ParameterName Emails -ScriptBlock $Keeper_EnterpriseUserCompleter
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseTeamMember -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
Register-ArgumentCompleter -CommandName Add-KeeperEnterpriseTeamMember -ParameterName Users -ScriptBlock $Keeper_EnterpriseUserCompleter

function Remove-KeeperEnterpriseTeamMember {
    <#
        .SYNOPSIS
        Removes existing enterprise users from a Keeper team.

        .DESCRIPTION
        Removes one or more users by email (-Emails) or by email / enterprise user ID (-User or -Users).
        At least one of -Emails or -User must be specified.

        If the user is not on the team, a warning is shown and no remove request is sent.

        .PARAMETER Team
        Team UID or Team Name from which the users will be removed.

        .PARAMETER Emails
        One or more user email addresses to remove from the team.

        .PARAMETER Users
        One or more user email addresses or enterprise user IDs to remove from the team.
        -User is an alias for this parameter. Use -Emails, -User, or both together.

        .EXAMPLE
        Remove-KeeperEnterpriseTeamMember -Team "Engineering" -Emails "alice@example.com", "bob@example.com"

        .EXAMPLE
        Remove-KeeperEnterpriseTeamMember -Team "Engineering" -User "user@example.com"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string] $Team,
        [Parameter()][string[]] $Emails,
        [Parameter()][Alias('User')][string[]] $Users
    )

    try {
        $userInputs = Get-EnterpriseTeamMemberInputs -EmailInputs $Emails -UserInputs $Users
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }

    [Enterprise]$enterprise = getEnterprise
    $teamTarget = Resolve-EnterpriseTeamTarget -Enterprise $enterprise -TeamInput $Team
    if (-not $teamTarget) { return }

    $teamUid = $teamTarget.Uid
    $emailList = [System.Collections.Generic.List[string]]::new()
    $processedUserIds = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($userInput in @($userInputs)) {
        try {
            $userObject = resolveUser $enterprise.enterpriseData $userInput
            if (-not $processedUserIds.Add($userObject.Id)) {
                Write-Warning "User `"$($userObject.Email)`" was already specified; skipping duplicate."
                continue
            }
            if (-not (Test-EnterpriseUserOnTeam -EnterpriseData $enterprise.enterpriseData -TeamUid $teamUid -UserId $userObject.Id)) {
                Write-Warning "User `"$($userObject.Email)`" is not a member of team `"$($teamTarget.Name)`"."
                continue
            }
            [void]$emailList.Add($userObject.Email)
        }
        catch { Write-Warning $_.Exception.Message }
    }

    if ($emailList.Count -eq 0) {
        Write-Warning "No team members were removed."
        return
    }

    try {
        Invoke-EnterpriseRemoveUsersFromTeams -EnterpriseData $enterprise.enterpriseData -Emails $emailList.ToArray() -TeamUids @($teamUid)
        $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
        Write-Output "Removed $($emailList.Count) user(s) from team '$($teamTarget.Name)'."
    }
    catch {
        Write-Warning "Failed to remove users from team '$($teamTarget.Name)': $($_.Exception.Message)"
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseTeamMember -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseTeamMember -ParameterName Emails -ScriptBlock $Keeper_EnterpriseUserCompleter
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseTeamMember -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseTeamMember -ParameterName Users -ScriptBlock $Keeper_EnterpriseUserCompleter

function Get-KeeperEnterpriseTeamRole {
    <#
        .SYNOPSIS
        Gets enterprise roles assigned to a team.

        .DESCRIPTION
        Read-only query matching enterprise-team role membership (used by -ar/-rr).
        Only approved teams are supported; queued-only teams return an empty list.

        .PARAMETER Team
        Team name, UID, or EnterpriseTeam object.

        .EXAMPLE
        Get-KeeperEnterpriseTeamRole -Team "Engineering"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Team
    )

    [Enterprise]$enterprise = getEnterprise
    $teamInput = if ($Team -is [string]) { $Team }
    elseif ($null -ne $Team.Uid) { [string]$Team.Uid }
    elseif ($Team.Name) { [string]$Team.Name }
    else { [string]$Team }

    $teamTarget = Resolve-EnterpriseTeamTarget -Enterprise $enterprise -TeamInput $teamInput
    if (-not $teamTarget) { return @() }
    if (-not $teamTarget.Team) {
        Write-Warning "Team `"$($teamTarget.Name)`" is queued only. Roles are listed after the team is approved."
        return @()
    }

    $roleIds = @($enterprise.roleData.GetRolesForTeam($teamTarget.Uid))
    if ($roleIds.Count -eq 0) { return @() }

    $roles = foreach ($roleId in $roleIds) {
        $role = $null
        if ($enterprise.roleData.TryGetRole($roleId, [ref]$role)) { $role }
    }
    return @($roles | Sort-Object { $_.DisplayName })
}
Register-ArgumentCompleter -CommandName Get-KeeperEnterpriseTeamRole -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter
New-Alias -Name ketr -Value Get-KeeperEnterpriseTeamRole

function Get-TeamMembersBatch {
    <#
    .SYNOPSIS
    Fetches team members in batches from the API.
    
    .DESCRIPTION
    Internal helper function that retrieves team member emails for multiple teams
    using parallel API calls in configurable batch sizes.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)][KeeperSecurity.Authentication.IAuthentication]$Auth,
        [Parameter(Mandatory)][array]$TeamUids,
        [int]$BatchSize = 20
    )
    
    if ($TeamUids.Count -eq 0) { return @{} }
    $results = @{}
    
    for ($i = 0; $i -lt $TeamUids.Count; $i += $BatchSize) {
        $batch = $TeamUids[$i..([Math]::Min($i + $BatchSize - 1, $TeamUids.Count - 1))]
        $tasks = @{}
        
        foreach ($uid in $batch) {
            try {
                $request = New-Object Enterprise.GetTeamMemberRequest
                $request.TeamUid = [Google.Protobuf.ByteString]::CopyFrom(
                    [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($uid))
                $tasks[$uid] = $Auth.ExecuteAuthRest(
                    "vault/get_team_members",
                    $request,
                    [Enterprise.GetTeamMemberResponse]
                )
            }
            catch {
                Write-Warning "Failed to create request for team $uid : $($_.Exception.Message)"
                $results[$uid] = [System.Collections.Generic.List[string]]::new()
            }
        }
        
        if ($tasks.Count -eq 0) { continue }
        
        try {
            [System.Threading.Tasks.Task]::WhenAll($tasks.Values).GetAwaiter().GetResult() | Out-Null
        }
        catch {
            Write-Warning "Some team member requests failed: $($_.Exception.Message)"
        }
        
        foreach ($uid in $tasks.Keys) {
            $task = $tasks[$uid]
            if ($task.IsCompletedSuccessfully) {
                $emails = [System.Collections.Generic.List[string]]::new()
                if ($task.Result.EnterpriseUser) {
                    foreach ($u in $task.Result.EnterpriseUser) {
                        $emails.Add($u.Email)
                    }
                }
                $results[$uid] = $emails
            }
            else {
                $results[$uid] = [System.Collections.Generic.List[string]]::new()
            }
        }
    }
    
    return $results
}

function Get-KeeperEnterpriseTeams {
    <#
        .SYNOPSIS
        Lists all Keeper Enterprise teams.

        .DESCRIPTION
        Show details for all teams you have access to within your organization.

        .PARAMETER ShowMembers
        List team members from cache (fast, may be incomplete). Alias: -v

        .PARAMETER ShowAllMembers
        List team members, fetching from server if cache is empty (slower, complete). Alias: -vv

        .PARAMETER All
        Show all teams including those from managed companies (MSP admin). Alias: -a

        .PARAMETER Sort
        Sort teams by column: company, team_uid, name (default: company)

        .EXAMPLE
        Get-KeeperEnterpriseTeams                         # Default sort by company
        Get-KeeperEnterpriseTeams -Sort name              # Sort by team name
        Get-KeeperEnterpriseTeams -Sort team_uid          # Sort by team UID
        Get-KeeperEnterpriseTeams -v                      # Show members from cache (fast)
        Get-KeeperEnterpriseTeams -vv                     # Show all members (fetches from server if needed)
        Get-KeeperEnterpriseTeams -a                      # Include teams outside primary organization (MSP admin)
        Get-KeeperEnterpriseTeams -vv -a                  # All teams (including managed companies) with complete member list
    #>
    [CmdletBinding()]
    param (
        [Parameter()][Alias('v')][Switch] $ShowMembers,
        [Parameter()][Alias('vv')][Switch] $ShowAllMembers,
        [Parameter()][Alias('a')][Switch] $All,
        [Parameter()][ValidateSet('company', 'team_uid', 'name')][string] $Sort = 'company'
    )

    if (-not $Script:Context.Auth) {
        Write-Error "Not connected. Please run Connect-Keeper first." -ErrorAction Stop
    }

    $includeManagedCompanyTeams = $All.IsPresent
    $memberMode = if ($ShowAllMembers.IsPresent) { 'full' } elseif ($ShowMembers.IsPresent) { 'cache' } else { 'none' }
    $showMemberInfo = $memberMode -ne 'none'

    [Enterprise]$enterprise = $null
    if ($showMemberInfo) {
        try {
            $enterprise = getEnterprise
        }
        catch {
            Write-Warning "Could not load enterprise data for member info: $($_.Exception.Message)"
            $enterprise = $null
        }
        if (-not $enterprise -or -not $enterprise.enterpriseData) {
            Write-Warning "Member information will not be displayed."
            $showMemberInfo = $false
        }
    }
    $results = [System.Collections.ArrayList]::new()
    $teamByUid = @{}

    try {
        $request = New-Object Records.GetShareObjectsRequest
        $response = $Script:Context.Auth.ExecuteAuthRest(
            "vault/get_share_objects",
            $request,
            [Records.GetShareObjectsResponse]
        ).GetAwaiter().GetResult()

        if (-not $response) {
            Write-Warning "Empty response from API"
            return
        }

        $enterpriseNames = @{}
        if ($response.ShareEnterpriseNames) {
            foreach ($ent in $response.ShareEnterpriseNames) {
                $enterpriseNames[$ent.EnterpriseId] = $ent.Enterprisename
            }
        }

        $apiTeams = if ($response.ShareTeams) { @($response.ShareTeams) } else { @() }
        if ($includeManagedCompanyTeams -and $response.ShareMCTeams) {
            $apiTeams += @($response.ShareMCTeams)
        }
        
        $primaryEnterpriseId = $null
        try {
            $primaryEnterpriseId = $Script:Context.Auth.AuthContext.License.EnterpriseId
        }
        catch {
            $primaryEnterpriseId = $null
        }
        $hasNoValidEnterpriseId = ($null -eq $primaryEnterpriseId -or $primaryEnterpriseId -le 0)
        $hasShareTeams = ($response.ShareTeams -and $response.ShareTeams.Count -gt 0)
        if ($hasNoValidEnterpriseId -and $hasShareTeams) {
            $primaryEnterpriseId = $response.ShareTeams[0].EnterpriseId
        }

        if (-not $includeManagedCompanyTeams -and $null -ne $primaryEnterpriseId -and $primaryEnterpriseId -gt 0) {
            $apiTeams = @($apiTeams | Where-Object { $_.EnterpriseId -eq $primaryEnterpriseId })
        }

        foreach ($team in $apiTeams) {
            $teamUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($team.TeamUid.ToByteArray())
            if ($teamByUid.ContainsKey($teamUid)) { continue }

            $companyName = $enterpriseNames[$team.EnterpriseId]

            $members = [System.Collections.Generic.List[string]]::new()
            if ($showMemberInfo) {
                foreach ($userId in $enterprise.enterpriseData.GetUsersForTeam($teamUid)) {
                    $user = $null
                    if ($enterprise.enterpriseData.TryGetUserById($userId, [ref]$user)) {
                        $members.Add($user.Email)
                    }
                }
            }

            $teamByUid[$teamUid] = @{
                Uid     = $teamUid
                Name    = $team.Teamname
                Company = $companyName
                Members = $members
            }
        }
    }
    catch {
        Write-Warning "Failed to fetch teams from API: $($_.Exception.Message)"
        return
    }

    $allTeams = @($teamByUid.Values)

    if ($memberMode -eq 'full' -and $showMemberInfo) {
        $teamsNeedToFetch = @($allTeams | Where-Object { $_.Members.Count -eq 0 } | ForEach-Object { $_.Uid })
        if ($teamsNeedToFetch.Count -gt 0) {
            $fetchedMembers = Get-TeamMembersBatch -Auth $Script:Context.Auth -TeamUids $teamsNeedToFetch
            
            if ($fetchedMembers) {
                foreach ($team in $allTeams) {
                    if ($team.Members.Count -eq 0 -and $fetchedMembers.ContainsKey($team.Uid)) {
                        $team.Members = $fetchedMembers[$team.Uid]
                    }
                }
            }
        }
    }

    $allTeams = @(switch ($Sort) {
        'team_uid' { $allTeams | Sort-Object { if ($_.Uid) { $_.Uid.ToLower() } else { '' } } }
        'name'     { $allTeams | Sort-Object { if ($_.Name) { $_.Name.ToLower() } else { '' } } }
        default    { $allTeams | Sort-Object { if ($_.Company) { $_.Company.ToLower() } else { '' } }, { if ($_.Name) { $_.Name.ToLower() } else { '' } } }
    })

    $index = 0
    foreach ($team in $allTeams) {
        $index++
        $props = [ordered]@{
            '#'        = $index
            'Company'  = $team.Company
            'Team UID' = $team.Uid
            'Name'     = $team.Name
        }
        if ($showMemberInfo) {
            $props['Member'] = if ($team.Members.Count -gt 0) { $team.Members[0] } else { '' }
        }
        [void]$results.Add([PSCustomObject]$props)

        if ($showMemberInfo) {
            for ($i = 1; $i -lt $team.Members.Count; $i++) {
                $memberRow = [ordered]@{ '#' = ''; 'Company' = ''; 'Team UID' = ''; 'Name' = ''; 'Member' = $team.Members[$i] }
                [void]$results.Add([PSCustomObject]$memberRow)
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "No teams found."
        return
    }

    Write-Host "`nFound $($allTeams.Count) team(s).`n"
    $results | Format-Table -AutoSize
}
New-Alias -Name list-team -Value Get-KeeperEnterpriseTeams