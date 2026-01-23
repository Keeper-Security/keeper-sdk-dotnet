function New-KeeperEnterpriseTeam {
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
    try {
        $selectedTeam = Get-KeeperTeamByNameOrUid -EnterpriseData $enterprise.enterpriseData -TeamInput $Team
        
        if (-not $selectedTeam) {
            Write-Warning "No matching team found for input: $Team"
        }
        if ($Emails.Count -eq 0) {
            Write-Warning "No email addresses provided to add."
            return
        }
    
        $enterprise.enterpriseData.AddUsersToTeams(
            $Emails, 
            @($selectedTeam.Uid)
        ).GetAwaiter().GetResult() | Out-Null
        Write-Output "Requested addition of $($Emails.Count) user(s) to team '$($selectedTeam.Name)'."
    }
    catch {
        Write-Warning "Failed to add users to team '$Team': $($_.Exception.Message)"
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
    try {
        $selectedTeam = Get-KeeperTeamByNameOrUid -EnterpriseData $enterprise.enterpriseData -TeamInput $Team
    
        if (-not $selectedTeam) {
            Write-Warning "No matching team found for input: $Team"
            return
        }
        if ($Emails.Count -eq 0) {
            Write-Warning "No email addresses provided to remove."
            return
        }
    
        $enterprise.enterpriseData.RemoveUsersFromTeams(
            $Emails, 
            @($selectedTeam.Uid)
        ).GetAwaiter().GetResult() | Out-Null
        Write-Output "Requested removal of $($Emails.Count) user(s) from team '$($selectedTeam.Name)'."
    }
    catch {
        Write-Warning "Failed to remove users from team '$Team': $($_.Exception.Message)"
    }
}

function Get-TeamMembersBatch {
    param (
        [Parameter(Mandatory)]$Auth,
        [Parameter(Mandatory)][array]$TeamUids,
        [int]$BatchSize = 20
    )
    
    if ($TeamUids.Count -eq 0) { return @{} }
    $results = @{}
    
    for ($i = 0; $i -lt $TeamUids.Count; $i += $BatchSize) {
        $batch = $TeamUids[$i..([Math]::Min($i + $BatchSize, $TeamUids.Count) - 1)]
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
                $results[$uid] = @()
            }
        }
        
        if ($tasks.Count -eq 0) { continue }
        
        try {
            [System.Threading.Tasks.Task]::WhenAll($tasks.Values).GetAwaiter().GetResult() | Out-Null
        }
        catch {
            Write-Warning "Batch API call failed: $($_.Exception.Message)"
        }
        
        foreach ($uid in $tasks.Keys) {
            $task = $tasks[$uid]
            if ($task.IsCompletedSuccessfully) {
                $emails = @()
                foreach ($u in $task.Result.EnterpriseUser) {
                    $emails += $u.Email
                }
                $results[$uid] = $emails
            }
            else {
                $results[$uid] = @()
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
        Get-KeeperEnterpriseTeams                    # Default sort by company
        Get-KeeperEnterpriseTeams -Sort name or team_uid        # Sort by team name
        Get-KeeperEnterpriseTeams -v -vv    # Sort by team UID and show all members
        Get-KeeperEnterpriseTeams -v -a              # All teams with members
    #>
    [CmdletBinding()]
    param (
        [Parameter()][Alias('v')][Switch] $ShowMembers,
        [Parameter()][Alias('vv')][Switch] $ShowAllMembers,
        [Parameter()][Alias('a')][Switch] $All,
        [Parameter()][ValidateSet('company', 'team_uid', 'name')][string] $Sort = 'company'
    )

    $includeManagedCompanyTeams = $All.IsPresent
    $memberMode = if ($ShowAllMembers.IsPresent) { 'full' } elseif ($ShowMembers.IsPresent) { 'cache' } else { 'none' }
    $showMemberInfo = $memberMode -ne 'none'

    [Enterprise]$enterprise = $null
    if ($showMemberInfo) {
        $enterprise = getEnterprise
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

        $enterpriseNames = @{}
        foreach ($ent in $response.ShareEnterpriseNames) {
            $enterpriseNames[$ent.EnterpriseId] = $ent.Enterprisename
        }

        $apiTeams = @($response.ShareTeams)
        if ($includeManagedCompanyTeams) {
            $apiTeams += @($response.ShareMCTeams)
        }
        
        $primaryEnterpriseId = $null
        try {
            $primaryEnterpriseId = $Script:Context.Auth.AuthContext.License.EnterpriseId
        }
        catch {
            $primaryEnterpriseId = $null
        }
        if (($null -eq $primaryEnterpriseId -or $primaryEnterpriseId -le 0) -and $response.ShareTeams.Count -gt 0) {
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
            if ($showMemberInfo -and $null -ne $enterprise) {
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

    if ($memberMode -eq 'full') {
        $teamsNeedToFetch = @($allTeams | Where-Object { $_.Members.Count -eq 0 } | ForEach-Object { $_.Uid })
        if ($teamsNeedToFetch.Count -gt 0) {
            $fetchedMembers = Get-TeamMembersBatch -Auth $Script:Context.Auth -TeamUids $teamsNeedToFetch
            
            foreach ($team in $allTeams) {
                if ($team.Members.Count -eq 0 -and $fetchedMembers.ContainsKey($team.Uid)) {
                    $team.Members = $fetchedMembers[$team.Uid]
                }
            }
        }
    }

    $allTeams = @(switch ($Sort) {
        'team_uid' { $allTeams | Sort-Object { ($_.Uid ?? '').ToLower() } }
        'name'     { $allTeams | Sort-Object { ($_.Name ?? '').ToLower() } }
        default    { $allTeams | Sort-Object { ($_.Company ?? '').ToLower() }, { ($_.Name ?? '').ToLower() } }
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

        for ($i = 1; $i -lt $team.Members.Count; $i++) {
            $memberRow = [ordered]@{ '#' = ''; 'Company' = ''; 'Team UID' = ''; 'Name' = ''; 'Member' = $team.Members[$i] }
            [void]$results.Add([PSCustomObject]$memberRow)
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