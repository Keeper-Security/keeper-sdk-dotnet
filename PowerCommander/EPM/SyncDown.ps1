function getEpmPlugin {
    <#
        .Synopsis
        returns the EPM plugin for the current enterprise context.
    #>
    [Enterprise] $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader) {
        return $null
    }
    if ($Script:EpmPlugin -and $Script:EpmPlugin -is [KeeperSecurity.Plugins.EPM.EpmPlugin]) {
        return $Script:EpmPlugin
    }
    try {
        $Script:EpmPlugin = New-Object KeeperSecurity.Plugins.EPM.EpmPlugin($enterprise.loader)
        return $Script:EpmPlugin
    }
    catch {
        throw Exception "Failed to create EPM plugin: $($_.Exception.Message)"
    }
}


function ensureEpmPlugin {
    <#
        .Synopsis
        Get EPM plugin and sync if needed. Returns plugin or throws exception if failed to create plugin.
    #>
    [CmdletBinding()]
    Param ([bool] $SyncIfNeeded = $true)

    $plugin = getEpmPlugin
    if (-not $plugin) { throw Exception "Failed to create EPM plugin" }
    if ($SyncIfNeeded -and $plugin.NeedSync) {
        Write-Output "Syncing EPM data..."
        $plugin.SyncDown($false).GetAwaiter().GetResult()
    }
    return $plugin
}

function parseEpmBool {
    <#
        .Synopsis
        Parse string to bool? (true/false/1/0/yes/no/on/off). Returns $true, $false, or $null.
    #>
    Param ([string] $Value)

    $v = $Value?.Trim()
    if ([string]::IsNullOrEmpty($v)) { return $null }
    $lower = $v.ToLowerInvariant()
    if ($lower -eq 'true' -or $lower -eq '1' -or $lower -eq 'yes' -or $lower -eq 'on') { return $true }
    if ($lower -eq 'false' -or $lower -eq '0' -or $lower -eq 'no' -or $lower -eq 'off') { return $false }
    return $null
}

function writeEpmModifyStatus {
    <#
        .Synopsis
        Write Added/Updated/Removed lines from ModifyStatus.
    #>
    Param ([object] $Status)

    if (-not $Status) { return }
    if ($Status.Add -and $Status.Add.Count -gt 0) { Write-Output "  Added: $($Status.Add -join ', ')" }
    if ($Status.Update -and $Status.Update.Count -gt 0) { Write-Output "  Updated: $($Status.Update -join ', ')" }
    if ($Status.Remove -and $Status.Remove.Count -gt 0) { Write-Output "  Removed: $($Status.Remove -join ', ')" }
}

function getEpmCollectionTypeName {
    <#
        .Synopsis
        Display name for collection type.
    #>
    Param ([int] $CollectionType)

    switch ($CollectionType) {
        1   { return 'OS Build' }
        2   { return 'Application' }
        3   { return 'User Account' }
        4   { return 'Group Account' }
        202 { return 'OS Version' }
        default { return "Type $CollectionType" }
    }
}

function resolveEpmPolicy {
    <#
        .Synopsis
        Resolve policy by UID or name (case-insensitive). Returns policy or $null.
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
    )

    $id = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($id)) { return $null }

    $policy = $Plugin.Policies.GetEntity($id)
    if ($null -ne $policy) { return $policy }

    $lName = $id.ToLowerInvariant()
    $policyMatches = @()
    foreach ($p in $Plugin.Policies.GetAll()) {
        $info = getEpmPolicyData -Policy $p -Plugin $Plugin
        if ($info.Name -and $info.Name.ToLowerInvariant() -eq $lName) { $policyMatches += $p }
    }
    if ($policyMatches.Count -eq 0) { return $null }
    if ($policyMatches.Count -gt 1) {
        Write-Warning "Multiple policies match name `"$id`". Please specify Policy UID."
        return $null
    }
    return $policyMatches[0]
}

function getEpmPolicyData {
    <#
        .Synopsis
        Parse policy for list/view (Name, Type, Controls, Users, Machines, Applications, Collections).
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [object] $Policy,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
    )

    $name = ''; $type = ''; $controls = [System.Collections.Generic.List[string]]::new()
    $users = ''; $machines = ''; $applications = ''; $collections = ''

    $data = $Policy.Data
    if (-not $data) {
        return [PSCustomObject]@{ Name = $name; Type = $type; Controls = $controls; Users = $users; Machines = $machines; Applications = $applications; Collections = $collections }
    }

    $name = if ($data.PolicyName) { $data.PolicyName } else { '' }
    $type = if ($data.PolicyType) { $data.PolicyType } else { '' }

    if ($data.Actions -and $data.Actions.OnSuccess -and $data.Actions.OnSuccess.Controls) {
        foreach ($c in $data.Actions.OnSuccess.Controls) {
            $cs = $c?.ToString().ToUpperInvariant()
            if ([string]::IsNullOrEmpty($cs)) { continue }
            if ($cs -eq 'APPROVAL' -or $cs.Contains('APPROVAL')) { $controls.Add('APPROVAL') }
            elseif ($cs -eq 'JUSTIFY' -or $cs.Contains('JUSTIFY')) { $controls.Add('JUSTIFY') }
            elseif ($cs -eq 'MFA' -or $cs.Contains('MFA')) { $controls.Add('MFA') }
            else { $controls.Add($cs) }
        }
    }
    if ($data.UserCheck -and $data.UserCheck.Count -gt 0) { $users = $data.UserCheck -join ', ' }
    if ($data.MachineCheck -and $data.MachineCheck.Count -gt 0) { $machines = $data.MachineCheck -join ', ' }
    if ($data.ApplicationCheck -and $data.ApplicationCheck.Count -gt 0) { $applications = $data.ApplicationCheck -join ', ' }

    try {
        $allAgentsUid = $Plugin.AllAgentsCollectionUid
        $links = @($Plugin.GetCollectionLinksForObject($Policy.PolicyUid))
        $cuids = [System.Collections.Generic.List[string]]::new()
        foreach ($link in $links) {
            $collUid = $link.Item1
            if (-not [string]::IsNullOrEmpty($collUid)) {
                if ($collUid -eq $allAgentsUid) { $cuids.Add('*') } else { $cuids.Add($collUid) }
            }
        }
        $cuids.Sort()
        $collections = $cuids -join ', '
    } catch { }

    return [PSCustomObject]@{ Name = $name; Type = $type; Controls = $controls; Users = $users; Machines = $machines; Applications = $applications; Collections = $collections }
}

function Sync-KeeperEpm {
    <#
        .Synopsis
        Sync EPM data from the server.

        .Description
        Synchronizes Enterprise Password Management (EPM/PEDM) data from the Keeper server.

        .Parameter Reload
        Perform a full sync instead of incremental.

        .Example
        Sync-KeeperEpm
        Performs incremental EPM sync.

        .Example
        Sync-KeeperEpm -Reload
        Performs full EPM sync.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch] $Reload
    )

    $plugin = getEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    if ($Reload) {
        Write-Output "Performing full sync..."
    }
    else {
        Write-Output "Syncing EPM data..."
    }

    try {
        $plugin.SyncDown($Reload.IsPresent).GetAwaiter().GetResult()
        Write-Output "EPM sync completed."
    }
    catch {
        Write-Error -Message "EPM sync failed: $($_.Exception.Message)" -ErrorAction Stop
    }
}

New-Alias -Name kepm-sync -Value Sync-KeeperEpm -ErrorAction SilentlyContinue
