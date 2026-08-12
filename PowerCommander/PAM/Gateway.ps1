#requires -Version 5.1

function script:formatPamTimestamp {
    Param ([long] $TimestampMs)
    if ($TimestampMs -le 0) { return '' }
    return [DateTimeOffset]::FromUnixTimeMilliseconds($TimestampMs).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
}

function script:getPamRouterHost {
    $routerUrl = [Environment]::GetEnvironmentVariable('ROUTER_URL')
    if (-not [string]::IsNullOrWhiteSpace($routerUrl)) {
        return $routerUrl.TrimEnd('/')
    }

    $auth = $Script:Context.Auth
    if (-not $auth -or -not $auth.Endpoint) { return $null }

    $server = $auth.Endpoint.Server
    if ([string]::IsNullOrWhiteSpace($server)) { return $null }

    $uri = $null
    if ([Uri]::TryCreate($server, [UriKind]::Absolute, [ref]$uri)) {
        $server = $uri.Host
    }
    return "https://connect.$server"
}

function script:resolvePamKsmApplication {
    Param (
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)][string] $Identifier
    )

    $trimmed = $Identifier.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw (New-Object KeeperSecurity.Plugins.PAM.PamGatewayException('--application is required'))
    }

    $applications = @($Vault.KeeperRecords | Where-Object { $null -ne $_ -and $_.Type -eq 'app' })

    foreach ($app in $applications) {
        if ([string]::Equals($app.Uid, $trimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $app
        }
    }

    $byTitle = @($applications | Where-Object {
            [string]::Equals($_.Title, $trimmed, [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($byTitle.Count -gt 1) {
        throw (New-Object KeeperSecurity.Plugins.PAM.PamGatewayAmbiguousException($trimmed))
    }
    if ($byTitle.Count -eq 1) {
        return $byTitle[0]
    }

    throw (New-Object KeeperSecurity.Plugins.PAM.PamApplicationNotFoundException($trimmed))
}

function script:resolvePamSingleGatewayController {
    Param (
        [Parameter(Mandatory = $true)][object] $Plugin,
        [Parameter(Mandatory = $true)][string] $Identifier
    )

    $controller = resolvePamGatewayController -Plugin $Plugin -Identifier $Identifier
    if (-not $controller) {
        throw (New-Object KeeperSecurity.Plugins.PAM.PamGatewayNotFoundException($Identifier.Trim()))
    }
    return $controller
}

function script:invokePamGatewayMutation {
    Param (
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [Parameter(Mandatory = $true)][string] $FailureMessage,
        [Parameter(Mandatory = $true)][object] $Plugin
    )

    try {
        & $Action
    }
    catch [KeeperSecurity.Plugins.PAM.PamException] {
        throw
    }
    catch {
        throw (New-Object KeeperSecurity.Plugins.PAM.PamGatewayException("$FailureMessage $($_.Exception.Message)", $_.Exception))
    }

    [void](syncPamPlugin -Plugin $Plugin -Reload $false -ThrowOnError $false)
}

function script:handlePamRouterUnavailable {
    Param (
        [ref] $RouterDown,
        [bool] $Force
    )

    $RouterDown.Value = $true
    if (-not $Force) {
        Write-Output 'Router is unavailable. Use -Force to list registered gateways without online status.'
        return $false
    }

    Write-Output 'Router is unavailable. Showing registered gateways with UNKNOWN status.'
    return $true
}

function script:buildPamGatewayJsonItem {
    Param (
        [Parameter(Mandatory = $true)][object] $Summary,
        [bool] $VerboseOutput
    )

    $controller = $Summary.Controller
    $item = [ordered]@{
        ksm_app_name       = if ($Summary.KsmAppAccessible) { $Summary.KsmAppName } else { $null }
        ksm_app_uid        = $Summary.KsmAppUid
        ksm_app_accessible = $Summary.KsmAppAccessible
        gateway_name       = $controller.ControllerName
        gateway_uid        = $controller.ControllerUid
        status             = $Summary.Status
        gateway_version    = $Summary.GatewayVersion
    }

    if ($Summary.OnlineInstanceCount -gt 1) {
        $instances = New-Object 'System.Collections.Generic.List[object]'
        $index = 1
        foreach ($instance in $Summary.OnlineInstances) {
            $instanceItem = [ordered]@{
                instance_number = $index
                status          = [KeeperSecurity.Plugins.PAM.PamGatewayStatus]::Online
                gateway_version = $instance.Version
                ip_address      = $instance.IpAddress
                connected_on    = formatPamTimestamp $instance.ConnectedOn
            }
            if ($VerboseOutput) {
                $instanceItem.os = $instance.SystemInfo.Os
                $instanceItem.os_release = $instance.SystemInfo.OsRelease
                $instanceItem.machine_type = $instance.SystemInfo.MachineType
                $instanceItem.os_version = $instance.SystemInfo.OsVersion
            }
            $instances.Add([PSCustomObject]$instanceItem)
            $index++
        }
        $item.instances = $instances
    }

    if ($VerboseOutput) {
        $item.device_name = $controller.DeviceName
        $item.device_token = $controller.DeviceToken
        $item.created_on = formatPamTimestamp $controller.Created
        $item.last_modified = formatPamTimestamp $controller.LastModified
        $item.node_id = $controller.NodeId

        if ($Summary.OnlineInstanceCount -le 1) {
            $item.os = $Summary.SystemInfo.Os
            $item.os_release = $Summary.SystemInfo.OsRelease
            $item.machine_type = $Summary.SystemInfo.MachineType
            $item.os_version = $Summary.SystemInfo.OsVersion
        }
    }

    return [PSCustomObject]$item
}

function script:getPamGatewayTableRows {
    Param (
        [Parameter(Mandatory = $true)][object[]] $Summaries,
        [bool] $VerboseOutput
    )

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($summary in $Summaries) {
        $controller = $summary.Controller
        $ksmApp = if ($summary.KsmAppAccessible) {
            "$($summary.KsmAppName) ($($summary.KsmAppUid))"
        }
        else {
            "[APP NOT ACCESSIBLE OR DELETED] ($($summary.KsmAppUid))"
        }

        $isPool = $summary.OnlineInstanceCount -gt 1
        $gatewayVersion = if ($isPool) { '' } else { $summary.GatewayVersion }

        if ($VerboseOutput) {
            $systemInfo = if ($isPool) {
                New-Object KeeperSecurity.Plugins.PAM.PamGatewaySystemInfo
            }
            else {
                $summary.SystemInfo
            }
            $rows.Add([PSCustomObject]@{
                    'KSM Application Name (UID)' = $ksmApp
                    'Gateway Name'                 = $controller.ControllerName
                    'Gateway UID'                  = $controller.ControllerUid
                    'Status'                       = $summary.Status
                    'Gateway Version'              = $gatewayVersion
                    'Device Name'                  = $controller.DeviceName
                    'Device Token'                 = $controller.DeviceToken
                    'Created On'                   = (formatPamTimestamp $controller.Created)
                    'Last Modified'                = (formatPamTimestamp $controller.LastModified)
                    'Node ID'                      = $controller.NodeId
                    'OS'                           = $systemInfo.Os
                    'OS Release'                   = $systemInfo.OsRelease
                    'Machine Type'                 = $systemInfo.MachineType
                    'OS Version'                   = $systemInfo.OsVersion
                })
        }
        else {
            $rows.Add([PSCustomObject]@{
                    'KSM Application Name (UID)' = $ksmApp
                    'Gateway Name'                 = $controller.ControllerName
                    'Gateway UID'                  = $controller.ControllerUid
                    'Status'                       = $summary.Status
                    'Gateway Version'              = $gatewayVersion
                })
        }

        if ($summary.OnlineInstanceCount -gt 1) {
            $index = 1
            foreach ($instance in $summary.OnlineInstances) {
                $connectedOn = formatPamTimestamp $instance.ConnectedOn
                if ($VerboseOutput) {
                    $rows.Add([PSCustomObject]@{
                            'KSM Application Name (UID)' = ''
                            'Gateway Name'                 = "  |- Instance $index (connected: $connectedOn)"
                            'Gateway UID'                  = $instance.IpAddress
                            'Status'                       = [KeeperSecurity.Plugins.PAM.PamGatewayStatus]::Online
                            'Gateway Version'              = $instance.Version
                            'Device Name'                  = ''
                            'Device Token'                 = ''
                            'Created On'                   = $connectedOn
                            'Last Modified'                = ''
                            'Node ID'                      = ''
                            'OS'                           = $instance.SystemInfo.Os
                            'OS Release'                   = $instance.SystemInfo.OsRelease
                            'Machine Type'                 = $instance.SystemInfo.MachineType
                            'OS Version'                   = $instance.SystemInfo.OsVersion
                        })
                }
                else {
                    $rows.Add([PSCustomObject]@{
                            'KSM Application Name (UID)' = ''
                            'Gateway Name'                 = "  |- Instance $index (connected: $connectedOn)"
                            'Gateway UID'                  = $instance.IpAddress
                            'Status'                       = [KeeperSecurity.Plugins.PAM.PamGatewayStatus]::Online
                            'Gateway Version'              = $instance.Version
                        })
                }
                $index++
            }
        }
    }
    return $rows
}

function Get-KeeperPamGatewayList {
    <#
        .Synopsis
        List PAM gateways.

        .Description
        Lists registered PAM gateways with online status from the router when available.

        .Parameter Force
        List registered gateways when the router is unavailable. Alias: -f.

        .Parameter VerboseOutput
        Show verbose gateway and router details.

        .Parameter Format
        Output format: {table,json}.

        .Parameter Online
        Show only online gateways. Alias: -o.

        .Example
        Get-KeeperPamGatewayList
        Get-KeeperPamGatewayList -Online -Format json -VerboseOutput
        Get-KeeperPamGatewayList -Force
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('f')]
        [switch] $Force,

        [Parameter()]
        [switch] $VerboseOutput,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table',

        [Parameter()]
        [Alias('o')]
        [switch] $Online
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message "PAM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message "Vault is not available. Gateway listing requires a connected vault session." -ErrorAction Stop
    }

    $auth = $Script:Context.Auth
    $routerDown = $false
    $onlineControllers = $null

    try {
        $onlineControllers = [KeeperSecurity.Plugins.PAM.RouterUtils]::GetConnectedGatewaysAsync($auth).GetAwaiter().GetResult()
    }
    catch {
        $exception = $_.Exception
        $isRouterError = ($exception -is [System.Net.Http.HttpRequestException]) -or
            ($exception -is [System.Threading.Tasks.TaskCanceledException]) -or
            ($exception.GetType().FullName -eq 'KeeperSecurity.Authentication.KeeperApiException')

        if ($isRouterError) {
            if (-not (handlePamRouterUnavailable -RouterDown ([ref]$routerDown) -Force:$Force)) {
                return
            }
        }
        else {
            throw
        }
    }

    $controllerList = getPamControllerList -Plugin $plugin
    if ($controllerList.Count -eq 0) {
        if ($Format -eq 'json') {
            [PSCustomObject]@{
                gateways = @()
                message  = 'This Enterprise does not have Gateways yet.'
            } | ConvertTo-Json -Depth 6
        }
        else {
            Write-Output 'This Enterprise does not have Gateways yet. To create a new Gateway, use: pam-gateway-new'
        }
        return
    }

    $controllers = [System.Collections.Generic.IEnumerable[KeeperSecurity.Plugins.PAM.PamController]] $controllerList
    $allSummaries = [KeeperSecurity.Plugins.PAM.GatewayUtils]::BuildGatewaySummaries(
        $controllers, $onlineControllers, $routerDown, $vault)
    $allSummaries = @($allSummaries)
    if ($allSummaries.Count -eq 0) {
        Write-Error -Message 'Failed to build gateway summaries.' -ErrorAction Stop
    }

    $total = $allSummaries.Count
    $onlineCount = 0
    $offlineCount = 0
    if (-not $routerDown) {
        $onlineCount = @($allSummaries | Where-Object { $_.OnlineInstanceCount -gt 0 }).Count
        $offlineCount = $total - $onlineCount
    }

    $displaySummaries = if ($Online) {
        @($allSummaries | Where-Object { -not $routerDown -and $_.OnlineInstanceCount -gt 0 })
    }
    else {
        @($allSummaries)
    }

    if ($Format -eq 'json') {
        $gateways = @($displaySummaries | ForEach-Object { buildPamGatewayJsonItem -Summary $_ -VerboseOutput:$VerboseOutput })
        $result = [ordered]@{ gateways = $gateways }
        if ($Online) {
            $result.gateway_counts = [PSCustomObject]@{
                online  = $onlineCount
                offline = $offlineCount
                total   = $total
            }
        }
        if ($VerboseOutput) {
            $routerHost = getPamRouterHost
            if ($routerHost) {
                $result.router_host = $routerHost
            }
        }
        $result | ConvertTo-Json -Depth 8
        return
    }

    if ($VerboseOutput) {
        $routerHost = getPamRouterHost
        if ($routerHost) {
            Write-Output ''
            Write-Output "Router Host: $routerHost"
            Write-Output ''
        }
    }

    $rows = getPamGatewayTableRows -Summaries $displaySummaries -VerboseOutput:$VerboseOutput
    $rows | Format-Table -AutoSize

    if ($Online) {
        Write-Output ''
        Write-Output "Gateways: Online: $onlineCount, Offline: $offlineCount, Total: $total"
    }
}

function New-KeeperPamGateway {
    <#
        .Synopsis
        Create a PAM gateway.

        .Description
        Creates a PAM gateway in a KSM application and returns a one-time token or initialized
        gateway configuration for deployment.

        -Name (-n)
            Gateway name.
        -Application (-a)
            KSM application UID or title.
        -TokenExpiresInMinutes (-e)
            One-time token expiration in minutes. Default 60, maximum 1440.
        -ConfigInit (-c) {json,b64}
            Initialize client config and return the configuration string instead of a raw token.
        -ReturnValue (-r)
            Return only the token or config string.

        .Parameter Name
        Gateway name. Alias: -n.

        .Parameter Application
        KSM application UID or title. Alias: -a.

        .Parameter TokenExpiresInMinutes
        One-time token expiration in minutes. Default 60, maximum 1440. Alias: -e.

        .Parameter ConfigInit
        Initialize client config and return configuration string. Values: {json,b64}. Alias: -c.

        .Parameter ReturnValue
        Return token or config only. Alias: -r.

        .Example
        New-KeeperPamGateway -Name "Prod Gateway" -Application "My KSM App"
        New-KeeperPamGateway -n "Prod Gateway" -a "My KSM App" -r
        New-KeeperPamGateway -n "Prod Gateway" -a "My KSM App" -ConfigInit json
        New-KeeperPamGateway -n "Prod Gateway" -a "My KSM App" -c b64 -r
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Alias('n')]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [Alias('a')]
        [string] $Application,

        [Parameter()]
        [Alias('e', 'token-expires-in-min')]
        [int] $TokenExpiresInMinutes = 60,

        [Parameter()]
        [Alias('c', 'config-init')]
        [ValidateSet('json', 'b64')]
        [string] $ConfigInit,

        [Parameter()]
        [Alias('r', 'return_value')]
        [switch] $ReturnValue
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message "PAM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message "Vault is not available. Gateway creation requires a connected vault session." -ErrorAction Stop
    }

    $gatewayName = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($gatewayName)) {
        Write-Error -Message "-Name is required." -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($Application)) {
        Write-Error -Message "-Application is required." -ErrorAction Stop
    }

    $tokenExpire = if ($TokenExpiresInMinutes -gt 0) { $TokenExpiresInMinutes } else { 60 }
    if ($tokenExpire -lt 1) {
        Write-Error -Message "-TokenExpiresInMinutes must be at least 1." -ErrorAction Stop
    }
    if ($tokenExpire -gt 1440) {
        Write-Error -Message "-TokenExpiresInMinutes cannot exceed 1440 minutes." -ErrorAction Stop
    }

    try {
        $ksmApplication = resolvePamKsmApplication -Vault $vault -Identifier $Application
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayAmbiguousException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }
    catch [KeeperSecurity.Plugins.PAM.PamApplicationNotFoundException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    $configInitValue = if ($ConfigInit) { $ConfigInit.Trim().ToLowerInvariant() } else { $null }

    try {
        $token = [KeeperSecurity.Plugins.PAM.GatewayUtils]::CreateGatewayAsync(
            $vault,
            $gatewayName,
            $ksmApplication.Uid,
            $tokenExpire,
            $configInitValue
        ).GetAwaiter().GetResult()
    }
    catch [KeeperSecurity.Plugins.PAM.PamException] {
        Write-Error -Message "Failed to create gateway: $($_.Exception.Message)" -ErrorAction Stop
    }

    [void](syncPamPlugin -Plugin $plugin -Reload $false -ThrowOnError $false)

    if ($ReturnValue) {
        Write-Output $token
        return
    }

    Write-Output "The one time token has been created in application [$Application]."
    Write-Output ''
    Write-Output "The new Gateway named $gatewayName will show up in the gateway list once it is initialized."
    Write-Output ''
    if ($configInitValue) {
        Write-Output 'Use the following initialized config in the Gateway:'
    }
    else {
        Write-Output "Following one time token will expire in $tokenExpire minutes:"
    }
    Write-Output '-----------------------------------------------'
    Write-Output $token
    Write-Output '-----------------------------------------------'
}

function Set-KeeperPamGateway {
    <#
        .Synopsis
        Edit a PAM gateway.

        .Parameter Gateway
        Gateway UID or name. Alias: -g.

        .Parameter Name
        New gateway name. Alias: -n.

        .Parameter NodeId
        Enterprise node ID or name. Alias: -i.

        .Example
        Set-KeeperPamGateway -Gateway "Prod Gateway" -Name "Production Gateway"
        Set-KeeperPamGateway -g "Prod Gateway" -i "US-East"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Alias('g')]
        [string] $Gateway,

        [Parameter()]
        [Alias('n')]
        [string] $Name,

        [Parameter()]
        [Alias('i', 'node-id')]
        [string] $NodeId
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message "PAM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($Gateway)) {
        Write-Error -Message "-Gateway is required." -ErrorAction Stop
    }

    try {
        $controller = resolvePamSingleGatewayController -Plugin $plugin -Identifier $Gateway
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayAmbiguousException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayNotFoundException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    $hasName = -not [string]::IsNullOrWhiteSpace($Name)
    $hasNodeId = -not [string]::IsNullOrWhiteSpace($NodeId)
    if (-not $hasName -and -not $hasNodeId) {
        Write-Error -Message "Nothing to do. Provide -Name and/or -NodeId to edit the gateway." -ErrorAction Stop
    }

    $resolvedNodeId = $controller.NodeId
    if ($hasNodeId) {
        try {
            $node = resolveSingleNode $NodeId.Trim()
            $resolvedNodeId = $node.Id
        }
        catch {
            Write-Error -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    $gatewayName = if ($hasName) { $Name.Trim() } else { $controller.ControllerName }
    $auth = getPamEnterpriseAuth

    invokePamGatewayMutation -Plugin $plugin -FailureMessage 'Failed to edit gateway:' -Action {
        [KeeperSecurity.Plugins.PAM.GatewayUtils]::EditGatewayAsync(
            $auth,
            $controller.ControllerUid,
            $gatewayName,
            $resolvedNodeId
        ).GetAwaiter().GetResult() | Out-Null
    }

    Write-Output "Gateway $gatewayName has been edited."
}

function Remove-KeeperPamGateway {
    <#
        .Synopsis
        Remove a PAM gateway.

        .Parameter Gateway
        Gateway UID or name. Alias: -g.

        .Example
        Remove-KeeperPamGateway -Gateway "Prod Gateway"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Alias('g')]
        [string] $Gateway
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message "PAM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($Gateway)) {
        Write-Error -Message "-Gateway is required." -ErrorAction Stop
    }

    try {
        $controller = resolvePamSingleGatewayController -Plugin $plugin -Identifier $Gateway
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayAmbiguousException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayNotFoundException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    $auth = getPamEnterpriseAuth
    $gatewayName = $controller.ControllerName

    invokePamGatewayMutation -Plugin $plugin -FailureMessage 'Failed to remove gateway:' -Action {
        [KeeperSecurity.Plugins.PAM.GatewayUtils]::RemoveGatewayAsync(
            $auth,
            $controller.ControllerUid
        ).GetAwaiter().GetResult() | Out-Null
    }

    Write-Output "Gateway $gatewayName has been removed."
}

function Set-KeeperPamGatewayMaxInstances {
    <#
        .Synopsis
        Set maximum PAM gateway instances.

        .Parameter Gateway
        Gateway UID or name. Alias: -g.

        .Parameter MaxInstances
        Maximum number of gateway instances. Must be at least 1. Alias: -m.

        .Example
        Set-KeeperPamGatewayMaxInstances -Gateway "Prod Gateway" -MaxInstances 3
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Alias('g')]
        [string] $Gateway,

        [Parameter(Mandatory = $true)]
        [Alias('m', 'max-instances')]
        [int] $MaxInstances
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message "PAM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($Gateway)) {
        Write-Error -Message "-Gateway is required." -ErrorAction Stop
    }

    if ($MaxInstances -lt 1) {
        Write-Error -Message "-MaxInstances must be at least 1." -ErrorAction Stop
    }

    try {
        $controller = resolvePamSingleGatewayController -Plugin $plugin -Identifier $Gateway
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayAmbiguousException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayNotFoundException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    $auth = getPamEnterpriseAuth

    try {
        invokePamGatewayMutation -Plugin $plugin -FailureMessage 'Failed to set max instances:' -Action {
            [KeeperSecurity.Plugins.PAM.GatewayUtils]::SetGatewayMaxInstancesAsync(
                $auth,
                $controller.ControllerUid,
                $MaxInstances
            ).GetAwaiter().GetResult() | Out-Null
        }
    }
    catch [KeeperSecurity.Plugins.PAM.PamGatewayException] {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    Write-Output "$($controller.ControllerName): max instance count set to $MaxInstances"
}

New-Alias -Name pam-gateway-list -Value Get-KeeperPamGatewayList -ErrorAction SilentlyContinue
New-Alias -Name pam-gw-list -Value Get-KeeperPamGatewayList -ErrorAction SilentlyContinue
New-Alias -Name pam-gateway-new -Value New-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gw-new -Value New-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gateway-edit -Value Set-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gw-edit -Value Set-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gateway-remove -Value Remove-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gw-remove -Value Remove-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gateway-rm -Value Remove-KeeperPamGateway -ErrorAction SilentlyContinue
New-Alias -Name pam-gateway-set-max-instances -Value Set-KeeperPamGatewayMaxInstances -ErrorAction SilentlyContinue
New-Alias -Name pam-gw-set-max-instances -Value Set-KeeperPamGatewayMaxInstances -ErrorAction SilentlyContinue

if (Get-Variable -Name Keeper_KSMAppCompleter -Scope Script -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -CommandName New-KeeperPamGateway -ParameterName Application -ScriptBlock $Keeper_KSMAppCompleter
}
