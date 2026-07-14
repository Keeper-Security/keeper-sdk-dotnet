#requires -Version 5.1

function script:getPamPlugin {
    <#
        .Synopsis
        Returns the PAM plugin for the current enterprise context.
    #>
    [Enterprise] $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader) {
        return $null
    }
    if ($Script:PamPlugin -and $Script:PamPlugin -is [KeeperSecurity.Plugins.PAM.PamPlugin]) {
        return $Script:PamPlugin
    }
    try {
        $Script:PamPlugin = New-Object KeeperSecurity.Plugins.PAM.PamPlugin($enterprise.loader)
        return $Script:PamPlugin
    }
    catch {
        throw "Failed to create PAM plugin: $($_.Exception.Message)"
    }
}

function script:getPamControllerList {
    <#
        .Synopsis
        Materialize gateway controllers into a typed list for .NET SDK interop.
    #>
    Param (
        [Parameter(Mandatory = $true)][object] $Plugin
    )

    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Plugins.PAM.PamController]'
    foreach ($controller in $Plugin.Controllers.GetAll()) {
        if ($null -ne $controller) {
            [void]$list.Add($controller)
        }
    }
    # Prevent PowerShell from unrolling the list into Object[] for the caller.
    return , $list
}

function script:ensurePamPlugin {
    <#
        .Synopsis
        Get PAM plugin and sync if needed. Returns $null if plugin cannot be created.
    #>
    [CmdletBinding()]
    Param ([bool] $SyncIfNeeded = $true)

    $plugin = getPamPlugin
    if (-not $plugin) { return $null }

    if ($SyncIfNeeded) {
        $controllers = getPamControllerList -Plugin $plugin
        if ($controllers.Count -eq 0) {
            Write-Host "Syncing PAM data..."
            $plugin.SyncDownAsync($false).GetAwaiter().GetResult() | Out-Null
        }
    }
    return $plugin
}

function Sync-KeeperPam {
    <#
        .Synopsis
        Sync PAM gateway and rotation data from the server.

        .Description
        Sync PAM data from the server. Equivalent to Commander `pam-sync` / `pam-sync-down`.

        .Parameter Reload
        Perform a full sync.

        .Example
        Sync-KeeperPam
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch] $Reload
    )

    $plugin = getPamPlugin
    if (-not $plugin) {
        Write-Error -Message "PAM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    if ($Reload.IsPresent) {
        Write-Output "Performing full PAM sync..."
    }
    else {
        Write-Output "Syncing PAM data..."
    }

    try {
        $plugin.SyncDownAsync($Reload.IsPresent).GetAwaiter().GetResult() | Out-Null
        Write-Output "PAM sync completed."
    }
    catch {
        Write-Error -Message "PAM sync failed: $($_.Exception.Message)" -ErrorAction Stop
    }
}

New-Alias -Name pam-sync -Value Sync-KeeperPam -ErrorAction SilentlyContinue
