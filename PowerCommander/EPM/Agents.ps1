class EpmAgentInfo {
    [string]$AgentUid
    [string]$MachineName
    [string]$Deployment
    [string]$Disabled
    [string]$Created
    [string]$Modified
}

class EpmAgentCollectionDetail {
    [string]$CollectionType
    [string]$CollectionUid
    [string]$Value
}

class EpmAgentCollectionSummary {
    [string]$CollectionType
    [int]$Count
}

function Resolve-KeeperEpmAgent {
    <#
    .Synopsis
        Resolve agent(s) by UID or machine name (case-insensitive). Returns matching agent(s) as an array.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
    )
    $uid = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($uid)) { return @() }

    $agent = $Plugin.Agents.GetEntity($uid)
    if ($null -ne $agent) { return @($agent) }

    $lUid = $uid.ToLowerInvariant()
    [array]$matched = @($Plugin.Agents.GetAll() | Where-Object { $null -ne $_ -and $_.MachineId -and $_.MachineId.ToLowerInvariant() -eq $lUid })
    return $matched
}

function script:Resolve-KeeperEpmSingleAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Identifier,
        [Parameter(Mandatory = $true)][object]$Plugin
    )
    [array]$agents = @(Resolve-KeeperEpmAgent -Identifier $Identifier -Plugin $Plugin | Where-Object { $null -ne $_ })
    if ($agents.Count -eq 0) {
        Write-Error -Message "Agent '$Identifier' not found." -ErrorAction Stop
    }
    if ($agents.Count -gt 1) {
        Write-Warning "Multiple agents found with machine name `"$Identifier`":"
        foreach ($a in $agents) {
            Write-Warning "  UID: $($a.AgentUid)  Machine: $($a.MachineId)"
        }
        Write-Error -Message "Machine name `"$Identifier`" is not unique. Use Agent UID." -ErrorAction Stop
    }
    return $agents[0]
}

function Get-KeeperEpmAgentList {
    <#
    .Synopsis
        List all EPM agents.
    .Description
        Takes no parameters; outputs a table of agents with deployment, machine name, and status.
    #>
    [CmdletBinding()]
    Param ()

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    [array]$agents = @($plugin.Agents.GetAll() | Where-Object { $null -ne $_ } | Sort-Object -Property AgentUid)
    if ($agents.Count -eq 0) {
        Write-Output "No agents found."
        return
    }

    $rows = [System.Collections.Generic.List[EpmAgentInfo]]::new()
    foreach ($ag in $agents) {
        $deploymentName = ''
        if (-not [string]::IsNullOrEmpty($ag.DeploymentUid)) {
            $dep = $plugin.Deployments.GetEntity($ag.DeploymentUid)
            if ($dep) { $deploymentName = if ($dep.Name) { $dep.Name } else { $ag.DeploymentUid } }
            else { $deploymentName = $ag.DeploymentUid }
        }
        $machineName = if ($ag.MachineId) { $ag.MachineId } else { '' }
        $disabled = if ($ag.Disabled) { 'True' } else { 'False' }
        $created = [DateTimeOffset]::FromUnixTimeMilliseconds($ag.Created).ToString("yyyy-MM-dd HH:mm:ss")
        $modified = [DateTimeOffset]::FromUnixTimeMilliseconds($ag.Modified).ToString("yyyy-MM-dd HH:mm:ss")
        $row = [EpmAgentInfo]::new()
        $row.AgentUid    = $ag.AgentUid
        $row.MachineName = $machineName
        $row.Deployment  = $deploymentName
        $row.Disabled    = $disabled
        $row.Created     = $created
        $row.Modified    = $modified
        $rows.Add($row)
    }
    $rows | Format-Table -AutoSize
}

function Get-KeeperEpmAgent {
    <#
    .Synopsis
        View a single EPM agent by UID or machine name.
    .Parameter AgentUidOrName
        Agent UID or machine name (case-insensitive).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $AgentUidOrName
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $agent = Resolve-KeeperEpmSingleAgent -Identifier $AgentUidOrName -Plugin $plugin

    $created = [DateTimeOffset]::FromUnixTimeMilliseconds($agent.Created).ToString("yyyy-MM-dd HH:mm:ss")
    $modified = [DateTimeOffset]::FromUnixTimeMilliseconds($agent.Modified).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "Agent: $($agent.MachineId)"
    Write-Output "  UID: $($agent.AgentUid)"
    Write-Output "  Status: $(if ($agent.Disabled) { 'Disabled' } else { 'Active' })"
    if (-not [string]::IsNullOrEmpty($agent.DeploymentUid)) {
        Write-Output "  Deployment: $($agent.DeploymentUid)"
    }
    Write-Output "  Created: $created"
    Write-Output "  Modified: $modified"
}

function Update-KeeperEpmAgent {
    <#
    .Synopsis
        Update EPM agent(s) - deployment and/or enable/disable.
    .Parameter AgentUidOrName
        One or more agent UIDs or machine names.
    .Parameter DeploymentUid
        Deployment UID to assign, if changing deployment.
    .Parameter Enable
        Use 'on' or 'off' to enable or disable the agent(s).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]] $AgentUidOrName,
        [Parameter()]
        [string] $DeploymentUid,
        [Parameter()]
        [ValidateSet('on', 'off')]
        [string] $Enable
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    [array]$identifiers = @($AgentUidOrName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($identifiers.Count -eq 0) {
        Write-Error -Message "Agent UID(s) or machine name(s) are required for 'update' command." -ErrorAction Stop
    }

    $deploymentUidValue = $null
    if (-not [string]::IsNullOrWhiteSpace($DeploymentUid)) {
        $deployment = $plugin.Deployments.GetEntity($DeploymentUid.Trim())
        if (-not $deployment) {
            Write-Error -Message "Deployment `"$DeploymentUid`" does not exist." -ErrorAction Stop
        }
        $deploymentUidValue = $DeploymentUid.Trim()
    }

    $disabledValue = $null
    if (-not [string]::IsNullOrWhiteSpace($Enable)) {
        $enableLower = $Enable.Trim().ToLowerInvariant()
        if ($enableLower -eq 'on') { $disabledValue = $false }
        elseif ($enableLower -eq 'off') { $disabledValue = $true }
    }

    $updateAgents = [System.Collections.Generic.List[KeeperSecurity.Plugins.EPM.UpdateAgent]]::new()
    foreach ($au in $identifiers) {
        try {
            $agent = Resolve-KeeperEpmSingleAgent -Identifier $au -Plugin $plugin
        } catch {
            Write-Warning "$($_.Exception.Message) Skipping."
            continue
        }
        $ua = New-Object KeeperSecurity.Plugins.EPM.UpdateAgent
        $ua.AgentUid = $agent.AgentUid
        $ua.DeploymentUid = $deploymentUidValue
        $ua.Disabled = $disabledValue
        $updateAgents.Add($ua)
    }

    if ($updateAgents.Count -eq 0) { return }

    try {
        $updateStatus = $plugin.ModifyAgents($updateAgents, $null).GetAwaiter().GetResult()

        $hasErrors = $false
        if ($updateStatus.UpdateErrors -and $updateStatus.UpdateErrors.Count -gt 0) {
            foreach ($err in $updateStatus.UpdateErrors) {
                if (-not $err.Success) {
                    Write-Error -Message "Failed to update agent `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                    $hasErrors = $true
                }
            }
        }
        if ($updateStatus.Update -and $updateStatus.Update.Count -gt 0) {
            Write-Output "$($updateStatus.Update.Count) agent(s) updated."
        } elseif (-not $hasErrors) {
            Write-Warning "No agents were updated. Check server response."
        }
        writeEpmModifyStatus -Status $updateStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error updating agent(s): $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperEpmAgent {
    <#
    .Synopsis
        Remove an EPM agent by UID or machine name.
    .Parameter AgentUidOrName
        Agent UID or machine name (case-insensitive).
    .Parameter Force
        If set, skip confirmation prompt before delete.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $AgentUidOrName,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $agent = Resolve-KeeperEpmSingleAgent -Identifier $AgentUidOrName -Plugin $plugin

    $label = if ($agent.MachineId) { $agent.MachineId } else { $agent.AgentUid }
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("agent '$label'", "Delete")) {
        return
    }

    try {
        $removeStatus = $plugin.ModifyAgents($null, [string[]]@($agent.AgentUid)).GetAwaiter().GetResult()

        if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
            $err = $removeStatus.RemoveErrors[0]
            Write-Error -Message "Failed to remove agent `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0) {
            Write-Output "Agent '$($agent.AgentUid)' removed."
        } else {
            Write-Warning "No agent was removed. Check server response."
        }
        writeEpmModifyStatus -Status $removeStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error removing agent: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Get-KeeperEpmAgentCollection {
    <#
    .Synopsis
        List collections linked to an EPM agent.
    .Description
        By default shows collection type and count. Use -CollectionVerbose for type, UID, and value per collection.
    .Parameter AgentUid
        The agent UID.
    .Parameter CollectionType
        Optional collection type number to filter results.
    .Parameter CollectionVerbose
        If set, show each collection's type, UID, and value instead of grouped counts.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $AgentUid,
        [Parameter()]
        [int] $CollectionType = -1,
        [Parameter()]
        [switch] $CollectionVerbose
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $agent = Resolve-KeeperEpmSingleAgent -Identifier $AgentUid -Plugin $plugin

    [array]$resourceUids = @($plugin.CollectionLinks.GetLinksForObject($agent.AgentUid) | Where-Object { $null -ne $_ -and $_.LinkType -eq [int][PEDM.CollectionLinkType]::CltAgent } | ForEach-Object { $_.CollectionUid })

    $collections = [System.Collections.Generic.List[object]]::new()
    foreach ($uid in $resourceUids) {
        $c = $plugin.Collections.GetEntity($uid)
        if ($null -ne $c) { $collections.Add($c) }
    }

    if ($PSBoundParameters.ContainsKey('CollectionType')) {
        [array]$filtered = @($collections | Where-Object { $_.CollectionType -eq $CollectionType })
        $collections = $filtered
    }

    if ($collections.Count -eq 0) {
        Write-Output "No collections found for agent '$($agent.AgentUid)'."
        return
    }

    if ($CollectionVerbose) {
        $collections = $collections | Sort-Object -Property CollectionType, CollectionUid
        $rows = [System.Collections.Generic.List[EpmAgentCollectionDetail]]::new()
        foreach ($collection in $collections) {
            $typeName = getEpmCollectionTypeName -CollectionType $collection.CollectionType
            $value = ''
            if ($collection.CollectionData -and $collection.CollectionData.Length -gt 0) {
                try {
                    $jsonStr = [System.Text.Encoding]::UTF8.GetString($collection.CollectionData)
                    $data = $jsonStr | ConvertFrom-Json
                    $parts = [System.Collections.Generic.List[string]]::new()
                    $data.PSObject.Properties | ForEach-Object { $parts.Add("$($_.Name)=$($_.Value)") }
                    $value = $parts -join ', '
                } catch {
                    $value = "(binary data, $($collection.CollectionData.Length) bytes)"
                }
            }
            $row = [EpmAgentCollectionDetail]::new()
            $row.CollectionType = "$typeName ($($collection.CollectionType))"
            $row.CollectionUid  = $collection.CollectionUid
            $row.Value          = $value
            $rows.Add($row)
        }
        $rows | Format-Table -AutoSize
    } else {
        $grouped = $collections | Group-Object -Property CollectionType | Sort-Object -Property Name
        $rows = [System.Collections.Generic.List[EpmAgentCollectionSummary]]::new()
        foreach ($g in $grouped) {
            $typeName = getEpmCollectionTypeName -CollectionType $g.Name
            $row = [EpmAgentCollectionSummary]::new()
            $row.CollectionType = "$typeName ($($g.Name))"
            $row.Count          = $g.Count
            $rows.Add($row)
        }
        $rows | Format-Table -AutoSize
    }
}

New-Alias -Name kepm-agent-list        -Value Get-KeeperEpmAgentList        -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-view        -Value Get-KeeperEpmAgent            -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-edit        -Value Update-KeeperEpmAgent          -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-delete      -Value Remove-KeeperEpmAgent         -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-collection  -Value Get-KeeperEpmAgentCollection   -ErrorAction SilentlyContinue
