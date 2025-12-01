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

