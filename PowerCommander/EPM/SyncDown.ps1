function script:getEpmPlugin {
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
        throw "Failed to create EPM plugin: $($_.Exception.Message)"
    }
}


function script:ensureEpmPlugin {
    <#
        .Synopsis
        Get EPM plugin and sync if needed. Returns $null if plugin cannot be created.
    #>
    [CmdletBinding()]
    Param ([bool] $SyncIfNeeded = $true)

    $plugin = getEpmPlugin
    if (-not $plugin) { return $null }
    if ($SyncIfNeeded -and $plugin.NeedSync) {
        Write-Host "Syncing EPM data..."
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    }
    return $plugin
}

function script:parseEpmBool {
    <#
        .Synopsis
        Parse string to bool? (true/false/1/0/yes/no/on/off). Returns $true, $false, or $null.
    #>
    Param ([string] $Value)

    $v = $null
    if ($Value) { $v = $Value.Trim() }
    if ([string]::IsNullOrEmpty($v)) { return $null }
    $lower = $v.ToLowerInvariant()
    if ($lower -eq 'true' -or $lower -eq '1' -or $lower -eq 'yes' -or $lower -eq 'on') { return $true }
    if ($lower -eq 'false' -or $lower -eq '0' -or $lower -eq 'no' -or $lower -eq 'off') { return $false }
    return $null
}

function script:writeEpmModifyStatus {
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

function script:readEpmJsonText {
    <#
        .Synopsis
        Read JSON text from a -Json string or -FilePath. Returns $null if both are empty.
    #>
    Param (
        [string] $Json,
        [string] $FilePath
    )
    if (-not [string]::IsNullOrEmpty($Json)) { return $Json }
    if (-not [string]::IsNullOrEmpty($FilePath)) {
        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw "File not found: $FilePath"
        }
        return [System.IO.File]::ReadAllText($FilePath)
    }
    return $null
}

function script:validateEpmJson {
    <#
        .Synopsis
        Validate that a string is well-formed JSON. Throws if invalid.
    #>
    Param (
        [Parameter(Mandatory = $true)][string] $JsonText,
        [Parameter(Mandatory = $true)][string] $ParameterName
    )
    try {
        $JsonText | ConvertFrom-Json -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Parameter '$ParameterName' contains invalid JSON: $($_.Exception.Message)"
    }
}

function script:getEpmCollectionTypeName {
    <#
        .Synopsis
        Display name for collection type.
    #>
    Param ([int] $CollectionType)

    $enumType = [KeeperSecurity.Plugins.EPM.EpmCollectionType]
    if ([System.Enum]::IsDefined($enumType, $CollectionType)) {
        $enumValue = [KeeperSecurity.Plugins.EPM.EpmCollectionType]$CollectionType
        switch ($enumValue) {
            ([KeeperSecurity.Plugins.EPM.EpmCollectionType]::OsBuild)      { return 'OS Build' }
            ([KeeperSecurity.Plugins.EPM.EpmCollectionType]::Application)  { return 'Application' }
            ([KeeperSecurity.Plugins.EPM.EpmCollectionType]::UserAccount)  { return 'User Account' }
            ([KeeperSecurity.Plugins.EPM.EpmCollectionType]::GroupAccount) { return 'Group Account' }
            ([KeeperSecurity.Plugins.EPM.EpmCollectionType]::OsVersion)    { return 'OS Version' }
        }
    }
    return "Type $CollectionType"
}

function Sync-KeeperEpm {
    <#
        .Synopsis
        Sync EPM data from the server.

        .Description
        Synchronizes Endpoint Privilege Management (EPM/PEDM) data from the Keeper server.

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
        $plugin.SyncDown($Reload.IsPresent).GetAwaiter().GetResult() | Out-Null
        Write-Output "EPM sync completed."
    }
    catch {
        Write-Error -Message "EPM sync failed: $($_.Exception.Message)" -ErrorAction Stop
    }
}

New-Alias -Name kepm-sync -Value Sync-KeeperEpm -ErrorAction SilentlyContinue
