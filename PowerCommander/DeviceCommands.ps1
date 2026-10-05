#requires -Version 5.1

function Get-KeeperDeviceManagementDevices {
    param([Parameter(Mandatory = $true)] [object] $Auth)

    $devices = [KeeperSecurity.Authentication.DeviceManagementExtensions]::GetUserDevices($Auth).GetAwaiter().GetResult()
    @($devices | Sort-Object -Property LastModifiedTime -Descending)
}

function Get-KeeperDeviceManagementToken {
    param([Parameter(Mandatory = $true)] [object] $Device)

    [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($Device.EncryptedDeviceToken.ToByteArray())
}

function Get-KeeperDeviceManagementTimestamp {
    param([Parameter(Mandatory = $true)] [long] $Timestamp)

    if ($Timestamp -le 0) { return '' }
    if ($Timestamp -gt 10000000000) {
        return [DateTimeOffset]::FromUnixTimeMilliseconds($Timestamp).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
    [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-KeeperDeviceManagementLoginStatus {
    param([Parameter(Mandatory = $true)] [object] $LoginState)

    switch ($LoginState.ToString()) {
        'LoggedIn' { 'LOGGED_IN'; break }
        'LoggedOut' { 'LOGGED_OUT'; break }
        'DeviceLocked' { 'DEVICE_LOCKED'; break }
        'DeviceAccountLocked' { 'DEVICE_ACCOUNT_LOCKED'; break }
        'AccountLocked' { 'ACCOUNT_LOCKED'; break }
        'LicenseExpired' { 'LICENSE_EXPIRED'; break }
        default { $LoginState.ToString().ToUpperInvariant() }
    }
}

function Resolve-KeeperDeviceManagementDevices {
    param(
        [Parameter(Mandatory = $true)] [object[]] $Devices,
        [Parameter(Mandatory = $true)] [string] $Identifier,
        [Parameter()] [switch] $RequireSingle
    )

    $Identifier = $Identifier.Trim()
    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        return @()
    }

    $numericIdentifier = 0
    if ([int]::TryParse($Identifier, [ref]$numericIdentifier)) {
        if ($numericIdentifier -ge 1 -and $numericIdentifier -le $Devices.Count) {
            return @($Devices[$numericIdentifier - 1])
        }
        return @()
    }

    $matches = @($Devices | Where-Object {
        $token = Get-KeeperDeviceManagementToken -Device $_
        ($token.StartsWith($Identifier, [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($_.DeviceName -and $_.DeviceName.IndexOf($Identifier, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    })
    if ($RequireSingle -and $matches.Count -gt 1) {
        throw "Multiple devices match `"$Identifier`". Please be more specific."
    }
    $matches
}

function Get-KeeperDeviceList {
    <#
    .SYNOPSIS
    Lists devices registered to the current Keeper account.

    .PARAMETER Format
    Output format: table or json. Default is table.

    .PARAMETER Output
    JSON output file. It is ignored for table output.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [ValidateSet('table', 'json')] [string] $Format = 'table',
        [Parameter()] [string] $Output
    )

    $auth = (getVault).Auth
    $devices = Get-KeeperDeviceManagementDevices -Auth $auth
    if ($devices.Count -eq 0) {
        Write-Output 'No devices found'
        return
    }

    if ($Format -eq 'json') {
        $jsonDevices = @()
        $deviceId = 0
        foreach ($device in $devices) {
            $deviceId++
            $jsonDevices += [ordered]@{
                id = $deviceId
                deviceName = $device.DeviceName
                clientType = $device.ClientType.ToString().ToUpperInvariant()
                loginStatus = Get-KeeperDeviceManagementLoginStatus -LoginState $device.LoginState
                lastAccessedTimestamp = Get-KeeperDeviceManagementTimestamp -Timestamp $device.LastModifiedTime
            }
        }
        $json = @{ devices = @($jsonDevices) } | ConvertTo-Json -Depth 4
        if ($Output) {
            Set-Content -LiteralPath $Output -Value $json -Encoding UTF8
            Write-Output "Results saved to $Output"
        }
        else {
            Write-Output $json
        }
        return
    }

    $displayIds = @{}
    $deviceId = 0
    foreach ($device in $devices) {
        $deviceId++
        $displayIds[(Get-KeeperDeviceManagementToken -Device $device)] = $deviceId
    }
    Write-Output "User Devices ($($devices.Count) found)"
    $devices | Format-Table -Property @(
        @{ Label = 'ID'; Expression = { $displayIds[(Get-KeeperDeviceManagementToken -Device $_)] } },
        @{ Label = 'Device Name'; Expression = { $_.DeviceName } },
        @{ Label = 'Client Type'; Expression = { $_.ClientType.ToString().ToUpperInvariant() } },
        @{ Label = 'Login Status'; Expression = { Get-KeeperDeviceManagementLoginStatus -LoginState $_.LoginState } },
        @{ Label = 'Last Accessed'; Expression = { Get-KeeperDeviceManagementTimestamp -Timestamp $_.LastModifiedTime } }
    ) -AutoSize
}

function Invoke-KeeperDeviceAction {
    <#
    .SYNOPSIS
    Performs an action on one or more devices owned by the current account.

    .PARAMETER Action
    logout, remove, lock, unlock, account-lock, account-unlock, link, or unlink.

    .PARAMETER Devices
    Device IDs, names, partial names, or device tokens.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('logout', 'remove', 'lock', 'unlock', 'account-lock', 'account-unlock', 'link', 'unlink')]
        [string] $Action,
        [Parameter(Mandatory = $true, Position = 1)] [ValidateNotNullOrEmpty()] [string[]] $Devices
    )

    $auth = (getVault).Auth
    $availableDevices = Get-KeeperDeviceManagementDevices -Auth $auth
    $selectedDevices = @()
    foreach ($identifier in $Devices) {
        try {
            $matches = @(Resolve-KeeperDeviceManagementDevices -Devices $availableDevices -Identifier $identifier -RequireSingle)
        }
        catch {
            Write-Output $_.Exception.Message
            continue
        }
        if ($matches.Count -eq 0) {
            Write-Output "No device found for `"$identifier`""
            continue
        }
        $selectedDevices += $matches
    }
    $selectedDevices = @($selectedDevices | Group-Object { Get-KeeperDeviceManagementToken -Device $_ } | ForEach-Object { $_.Group[0] })
    if ($selectedDevices.Count -eq 0) {
        Write-Output 'No devices to act on'
        return
    }
    if (($Action -eq 'link' -or $Action -eq 'unlink') -and $selectedDevices.Count -lt 2) {
        Write-Output "Action `"$Action`" requires at least 2 devices"
        return
    }

    $actionType = [DeviceManagement.DeviceActionType]::DaInvalid
    switch ($Action) {
        'logout' { $actionType = [DeviceManagement.DeviceActionType]::DaLogout }
        'remove' { $actionType = [DeviceManagement.DeviceActionType]::DaRemove }
        'lock' { $actionType = [DeviceManagement.DeviceActionType]::DaLock }
        'unlock' { $actionType = [DeviceManagement.DeviceActionType]::DaUnlock }
        'account-lock' { $actionType = [DeviceManagement.DeviceActionType]::DaDeviceAccountLock }
        'account-unlock' { $actionType = [DeviceManagement.DeviceActionType]::DaDeviceAccountUnlock }
        'link' { $actionType = [DeviceManagement.DeviceActionType]::DaLink }
        'unlink' { $actionType = [DeviceManagement.DeviceActionType]::DaUnlink }
    }

    $tokens = New-Object 'System.Collections.Generic.List[Google.Protobuf.ByteString]'
    foreach ($device in $selectedDevices) {
        [void]$tokens.Add($device.EncryptedDeviceToken)
    }
    $deviceNames = @{}
    foreach ($device in $selectedDevices) {
        $deviceNames[(Get-KeeperDeviceManagementToken -Device $device)] = $device.DeviceName
    }
    $results = [KeeperSecurity.Authentication.DeviceManagementExtensions]::ExecuteDeviceAction($auth, $actionType, $tokens).GetAwaiter().GetResult()
    $actionVerbs = @{
        logout = 'logged out'
        remove = 'removed'
        lock = 'locked'
        unlock = 'unlocked'
        'account-lock' = 'account locked'
        'account-unlock' = 'account unlocked'
        link = 'linked'
        unlink = 'unlinked'
    }
    $successful = $false
    foreach ($result in $results) {
        foreach ($token in $result.EncryptedDeviceToken) {
            $tokenText = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($token.ToByteArray())
            $deviceName = $deviceNames[$tokenText]
            if (-not $deviceName) { $deviceName = 'Unknown Device' }
            if ($result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::Success) {
                Write-Output "✓ Device '$deviceName' successfully $($actionVerbs[$Action])"
                $successful = $true
            }
            elseif ($result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::NotAllowed) {
                Write-Output "✗ Device '$deviceName': Operation not allowed"
            }
            else {
                Write-Output "✗ Device '$deviceName': Action failed ($($result.DeviceActionStatus.ToString().ToUpperInvariant()))"
            }
        }
    }
    if ($successful) {
        Write-Output ''
        Write-Output 'Updated device list:'
        Get-KeeperDeviceList
    }
}

function Rename-KeeperDevice {
    <#
    .SYNOPSIS
    Renames a device owned by the current Keeper account.

    .PARAMETER Device
    Device ID, name, partial name, or device token.

    .PARAMETER NewName
    New friendly name for the device.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)] [string] $Device,
        [Parameter(Mandatory = $true, Position = 1)] [ValidateNotNullOrEmpty()] [string] $NewName
    )

    $sanitizedName = ($NewName -replace '[<>"''\x00-\x1f\x7f-\x9f]', '').Trim()
    if (-not $sanitizedName) {
        Write-Error 'Device name contains only invalid characters' -ErrorAction Stop
    }

    $auth = (getVault).Auth
    $availableDevices = Get-KeeperDeviceManagementDevices -Auth $auth
    try {
        $matches = @(Resolve-KeeperDeviceManagementDevices -Devices $availableDevices -Identifier $Device -RequireSingle)
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }
    if ($matches.Count -eq 0) {
        Write-Output "No device found for `"$Device`""
        return
    }

    $result = [KeeperSecurity.Authentication.DeviceManagementExtensions]::RenameUserDevice(
        $auth, $matches[0].EncryptedDeviceToken, $sanitizedName).GetAwaiter().GetResult()
    if ($null -eq $result) {
        Write-Output 'Device rename failed: no response from server'
        return
    }
    if ($result.DeviceActionStatus -ne [DeviceManagement.DeviceActionStatus]::Success) {
        if ($result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::NotAllowed) {
            Write-Output "✗ Device '$($matches[0].DeviceName)': Operation not allowed"
        }
        else {
            Write-Output "✗ Device '$($matches[0].DeviceName)': Rename failed ($($result.DeviceActionStatus.ToString().ToUpperInvariant()))"
        }
        return
    }

    Write-Output "✓ Device name updated from '$($matches[0].DeviceName)' to '$($result.DeviceNewName)'"
    Write-Output ''
    Write-Output 'Updated device list:'
    Get-KeeperDeviceList
}

New-Alias -Name device-list -Value Get-KeeperDeviceList
New-Alias -Name device-action -Value Invoke-KeeperDeviceAction
New-Alias -Name device-rename -Value Rename-KeeperDevice
