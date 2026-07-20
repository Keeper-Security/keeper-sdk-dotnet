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
        # Prefer Auth ctor when available (more reliable than loader-only in some sessions).
        if ($enterprise.loader.Auth) {
            $Script:PamPlugin = New-Object KeeperSecurity.Plugins.PAM.PamPlugin($enterprise.loader.Auth)
        }
        else {
            $Script:PamPlugin = New-Object KeeperSecurity.Plugins.PAM.PamPlugin($enterprise.loader)
        }
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
    try {
        foreach ($controller in $Plugin.Controllers.GetAll()) {
            if ($null -ne $controller) {
                [void]$list.Add($controller)
            }
        }
    }
    catch {}
    # Prevent PowerShell from unrolling the list into Object[] for the caller.
    return , $list
}

function script:syncPamPlugin {
    Param (
        [Parameter(Mandatory = $true)]
        [object] $Plugin,
        [bool] $Reload = $false,
        [bool] $ThrowOnError = $false
    )

    try {
        $task = $Plugin.SyncDownAsync($Reload)
        if ($null -eq $task) {
            throw 'SyncDownAsync returned null.'
        }
        $task.GetAwaiter().GetResult() | Out-Null
        return $true
    }
    catch {
        $msg = $_.Exception.Message
        $inner = $_.Exception.InnerException
        while ($null -ne $inner) {
            $msg = $inner.Message
            $inner = $inner.InnerException
        }
        if ($ThrowOnError) {
            throw "PAM sync failed: $msg"
        }
        Write-Warning "PAM sync failed: $msg"
        return $false
    }
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
            [void](syncPamPlugin -Plugin $plugin -Reload $false -ThrowOnError $false)
        }
    }
    return $plugin
}

function Sync-KeeperPam {
    <#
        .Synopsis
        Sync PAM data from the server.

        .Description
        Sync PAM data from the server. Equivalent to pam-sync / pam-sync-down.

        .Parameter Reload
        Perform a full sync.

        .Example
        Sync-KeeperPam

        .Example
        Sync-KeeperPam -Reload
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
        $task = $plugin.SyncDownAsync($Reload.IsPresent)
        if ($null -eq $task) {
            Write-Error -Message "PAM sync failed: SyncDownAsync returned null." -ErrorAction Stop
        }
        $task.GetAwaiter().GetResult() | Out-Null
        Write-Output "PAM sync completed."
    }
    catch {
        $msg = $_.Exception.Message
        $inner = $_.Exception.InnerException
        while ($null -ne $inner) {
            $msg = $inner.Message
            $inner = $inner.InnerException
        }
        Write-Error -Message "PAM sync failed: $msg. Tip: Sync-Keeper; then retry Sync-KeeperPam." -ErrorAction Stop
    }
}

New-Alias -Name pam-sync -Value Sync-KeeperPam -ErrorAction SilentlyContinue
