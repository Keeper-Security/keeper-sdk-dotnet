$script:CltAgent = 1

function Resolve-KeeperEpmAgent {
    <#
    .Synopsis
        Resolve agent by UID or machine name (case-insensitive). Returns $null if not found or not unique.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
    )
    $uid = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($uid)) { return $null }

    $agent = $Plugin.Agents.GetEntity($uid)
    if ($null -ne $agent) { return $agent }

    $lUid = $uid.ToLowerInvariant()
    $agentMatches = @($Plugin.Agents.GetAll() | Where-Object { $_.MachineId -and $_.MachineId.ToLowerInvariant() -eq $lUid })
    if ($agentMatches.Count -eq 0) { return $null }
    if ($agentMatches.Count -gt 1) {
        Write-Warning "Multiple agents match machine name `"$uid`". Please specify Agent UID."
        return $null
    }
    return $agentMatches[0]
}

function Get-KeeperEpmAgentList {
    <#
    .Synopsis
        List all EPM agents.
    #>
    [CmdletBinding()]
    Param ()

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $agents = @($plugin.Agents.GetAll())
    if ($agents.Count -eq 0) {
        Write-Output "No agents found."
        return
    }

    $agents = $agents | Sort-Object -Property AgentUid
    $rows = foreach ($ag in $agents) {
        $deploymentName = ''
        if (-not [string]::IsNullOrEmpty($ag.DeploymentUid)) {
            $dep = $plugin.Deployments.GetEntity($ag.DeploymentUid)
            if ($dep) { $deploymentName = if ($dep.Name) { $dep.Name } else { $ag.DeploymentUid } }
            else { $deploymentName = $ag.DeploymentUid }
        }
        $machineName = if ($ag.MachineId) { $ag.MachineId } else { '' }
        $disabled = if ($ag.Disabled) { 'True' } else { 'False' }
        $created = [DateTimeOffset]::FromUnixTimeMilliseconds($ag.Created).ToString("yyyy-MM-dd HH:mm:ss")
        [PSCustomObject]@{
            'Agent UID'    = $ag.AgentUid
            'Machine Name' = $machineName
            'Deployment'   = $deploymentName
            'Disabled'     = $disabled
            'Created'      = $created
        }
    }
    $rows | Format-Table -AutoSize
}

function Get-KeeperEpmAgent {
    <#
    .Synopsis
        View a single EPM agent by UID or machine name.
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

    $agent = Resolve-KeeperEpmAgent -Identifier $AgentUidOrName -Plugin $plugin
    if (-not $agent) {
        Write-Error -Message "Agent '$AgentUidOrName' not found." -ErrorAction Stop
    }

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
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]] $AgentUid,
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

    $agentUids = @($AgentUid | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($agentUids.Count -eq 0) {
        Write-Error -Message "Agent UID(s) are required for 'update' command." -ErrorAction Stop
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
        else {
            Write-Error -Message "`"enable`" argument must be `"on`" or `"off`"." -ErrorAction Stop
        }
    }

    $updateAgents = [System.Collections.Generic.List[object]]::new()
    foreach ($au in $agentUids) {
        $agent = $plugin.Agents.GetEntity($au.Trim())
        if (-not $agent) {
            Write-Error -Message "Agent `"$au`" does not exist." -ErrorAction Stop
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

        if ($updateStatus.UpdateErrors -and $updateStatus.UpdateErrors.Count -gt 0) {
            foreach ($err in $updateStatus.UpdateErrors) {
                if (-not $err.Success) {
                    Write-Error -Message "Failed to update agent `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                }
            }
        }

        writeEpmModifyStatus $updateStatus

        $plugin.SyncDown($false).GetAwaiter().GetResult()
    } catch {
        Write-Error -Message "Error updating agent(s): $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperEpmAgent {
    <#
    .Synopsis
        Remove an EPM agent by UID or machine name.
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

    $agent = Resolve-KeeperEpmAgent -Identifier $AgentUidOrName -Plugin $plugin
    if (-not $agent) {
        Write-Error -Message "Agent `"$AgentUidOrName`" does not exist." -ErrorAction Stop
    }

    try {
        $removeStatus = $plugin.ModifyAgents($null, [string[]]@($agent.AgentUid)).GetAwaiter().GetResult()

        if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
            foreach ($err in $removeStatus.RemoveErrors) {
                if (-not $err.Success) {
                    Write-Error -Message "Failed to remove agent `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
                }
            }
            return
        }

        Write-Output "Agent '$($agent.AgentUid)' removed."
        writeEpmModifyStatus $removeStatus

        $plugin.SyncDown($false).GetAwaiter().GetResult()
    } catch {
        Write-Error -Message "Error removing agent: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Get-KeeperEpmAgentCollection {
    <#
    .Synopsis
        List collections linked to an EPM agent.
    .Description
        By default shows collection type and count. Use -Verbose for type, UID, and value per collection.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $AgentUid,
        [Parameter()]
        [Nullable[int]] $CollectionType,
        [Parameter()]
        [switch] $CollectionVerbose
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $agentUidTrim = $AgentUid?.Trim()
    if ([string]::IsNullOrEmpty($agentUidTrim)) {
        Write-Error -Message "Agent UID is required for 'collection' command." -ErrorAction Stop
    }

    $agent = $plugin.Agents.GetEntity($agentUidTrim)
    if (-not $agent) {
        Write-Error -Message "Agent '$AgentUid' not found." -ErrorAction Stop
    }

    $resourceUids = @($plugin.CollectionLinks.GetLinksForObject($agent.AgentUid) | Where-Object { $_.LinkType -eq $script:CltAgent } | ForEach-Object { $_.CollectionUid })

    $collections = @()
    foreach ($uid in $resourceUids) {
        $c = $plugin.Collections.GetEntity($uid)
        if ($null -ne $c) { $collections += $c }
    }

    if ($CollectionType.HasValue) {
        $collections = @($collections | Where-Object { $_.CollectionType -eq $CollectionType.Value })
    }

    if ($CollectionVerbose) {
        $collections = $collections | Sort-Object -Property CollectionType, CollectionUid
        $rows = foreach ($collection in $collections) {
            $typeName = getEpmCollectionTypeName -CollectionType $collection.CollectionType
            $value = ''
            if ($collection.CollectionData -and $collection.CollectionData.Length -gt 0) {
                try {
                    $jsonStr = [System.Text.Encoding]::UTF8.GetString($collection.CollectionData)
                    $data = $jsonStr | ConvertFrom-Json
                    $parts = @()
                    $data.PSObject.Properties | ForEach-Object { $parts += "$($_.Name)=$($_.Value)" }
                    $value = $parts -join ', '
                } catch {
                    $value = "(binary data, $($collection.CollectionData.Length) bytes)"
                }
            }
            [PSCustomObject]@{
                'Collection Type' = "$typeName ($($collection.CollectionType))"
                'Collection UID'  = $collection.CollectionUid
                'Value'           = $value
            }
        }
        $rows | Format-Table -AutoSize
    } else {
        $grouped = $collections | Group-Object -Property CollectionType | Sort-Object -Property Name
        $rows = foreach ($g in $grouped) {
            $typeName = getEpmCollectionTypeName -CollectionType $g.Name
            [PSCustomObject]@{
                'Collection Type' = "$typeName ($($g.Name))"
                'Count'           = $g.Count
            }
        }
        $rows | Format-Table -AutoSize
    }
}

New-Alias -Name kepm-agent-list        -Value Get-KeeperEpmAgentList        -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-edit        -Value Update-KeeperEpmAgent          -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-delete      -Value Remove-KeeperEpmAgent         -ErrorAction SilentlyContinue
New-Alias -Name kepm-agent-collection  -Value Get-KeeperEpmAgentCollection   -ErrorAction SilentlyContinue
