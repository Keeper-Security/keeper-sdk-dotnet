#requires -Version 5.1

function script:writePamLaunchPrepareResult {
    Param (
        [KeeperSecurity.Plugins.PAM.PamLaunchPrepareResult] $Result
    )

    if ($null -eq $Result) {
        return
    }

    Write-Output 'PAM launch'
    Write-Output '----------'
    $recordUid = if ($null -eq $Result.Record) { '' } else { $Result.Record.Uid }
    $recordType = if ($null -eq $Result.Record) { '' } else { $Result.Record.TypeName }
    Write-Output ("Record UID: {0}" -f $recordUid)
    Write-Output ("Record type: {0}" -f $recordType)
    Write-Output ("Protocol: {0}" -f $Result.Protocol)
    $configUid = if ([string]::IsNullOrEmpty($Result.ConfigUid)) { '(not found)' } else { $Result.ConfigUid }
    Write-Output ("Configuration UID: {0}" -f $configUid)

    if (-not [string]::IsNullOrEmpty($Result.Host)) {
        $hostText = if ($null -ne $Result.Port) { "{0}:{1}" -f $Result.Host, $Result.Port } else { $Result.Host }
        Write-Output ("Target host: {0} ({1})" -f $hostText, $Result.HostSource)
    }

    if ($null -eq $Result.LaunchCredential) {
        Write-Output 'Launch credential: (not set)'
    }
    else {
        Write-Output ("Launch credential: {0} ({1})" -f $Result.LaunchCredential.Uid, $Result.LaunchCredential.Title)
    }

    if ([string]::IsNullOrEmpty($Result.GatewayUid)) {
        Write-Output 'Gateway: (not resolved)'
        return
    }

    $gwStatus = if ($Result.GatewayOnline -eq $true) {
        'Online'
    }
    elseif ($Result.GatewayOnline -eq $false) {
        'Offline'
    }
    else {
        'Unknown'
    }
    Write-Output ("Gateway: {0} ({1})" -f $Result.GatewayUid, $Result.GatewayName)
    Write-Output ("Gateway status: {0}" -f $gwStatus)
}

function Invoke-KeeperPamLaunch {
    <#
        .Synopsis
        Run PAM launch preflight for a resource record.

        .Description
        Resolves record, protocol, PAM configuration, launch credential, host, and gateway
        for a PAM connection. Does not start an interactive session.

        .Parameter Record
        PAM resource UID or title (pamMachine, pamDatabase, pamDirectory). Alias: -r.

        .Parameter Credential
        Launch credential PAM User UID or title. Alias: -cr.

        .Parameter Gateway
        Gateway UID or name override. Alias: -g.

        .Parameter Host
        Host override as host:port. For IPv6 use [address]:port, like [::1]:22. Alias: -H.
        Do not use with -HostRecord.

        .Parameter HostRecord
        Record UID/title to source host from host/pamHostname field. Alias: -hr.

        .Parameter Debug
        Common switch. Print pam-launch resolve diagnostics.

        .Example
        Invoke-KeeperPamLaunch -Record "<uid>"
        Invoke-KeeperPamLaunch -r "My Server" -Credential "admin-user" -Gateway "<gateway-uid>"
        pam-launch -r "<uid>" -Host "10.0.0.5:22" -Debug
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [Alias('cr')]
        [string] $Credential,

        [Parameter()]
        [Alias('g')]
        [string] $Gateway,

        [Parameter()]
        [Alias('H')]
        [string] $Host,

        [Parameter()]
        [Alias('hr')]
        [string] $HostRecord
    )

    if ([string]::IsNullOrWhiteSpace($Record)) {
        Write-Error -Message 'Record is required. Usage: Invoke-KeeperPamLaunch -Record <record> [-Credential <pamUser>] [-Gateway UID] [-Host host:port] [-HostRecord UID] [-Debug]' -ErrorAction Stop
    }

    $vault = getVault
    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message 'PAM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $options = New-Object KeeperSecurity.Plugins.PAM.PamLaunchOptions
    $options.Record = $Record.Trim()
    $options.Debug = $DebugPreference -eq 'Continue'
    $options.AvailableControllers = getPamControllerList -Plugin $plugin

    $propertiesToMap = @('Credential', 'Gateway', 'Host', 'HostRecord')
    foreach ($prop in $propertiesToMap) {
        if ($PSBoundParameters.ContainsKey($prop)) {
            $options.$prop = $PSBoundParameters[$prop]
        }
    }

    $result = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.LaunchUtils]::PrepareAsync($vault, $options).GetAwaiter().GetResult()
    }
    if ($null -eq $result) {
        return
    }

    writePamLaunchPrepareResult -Result $result
    Write-Output ''
    Write-Output 'Interactive terminal session is not available yet in this PowerCommander build.'
}

New-Alias -Name pam-launch -Value Invoke-KeeperPamLaunch -ErrorAction SilentlyContinue
