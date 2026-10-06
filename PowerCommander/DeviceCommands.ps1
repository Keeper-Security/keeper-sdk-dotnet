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

    if ($Timestamp -le 0) { return 'N/A' }
    try {
        if ($Timestamp -gt 10000000000) {
            return [DateTimeOffset]::FromUnixTimeMilliseconds($Timestamp).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        return [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch {
        return "Invalid timestamp: $Timestamp"
    }
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
        (Get-KeeperDeviceManagementToken -Device $_).Equals($Identifier, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($matches.Count -eq 0) {
        $matches = @($Devices | Where-Object {
            (Get-KeeperDeviceManagementToken -Device $_).StartsWith($Identifier, [System.StringComparison]::OrdinalIgnoreCase)
        })
    }
    if ($matches.Count -eq 0) {
        $matches = @($Devices | Where-Object {
            $_.DeviceName -and $_.DeviceName.IndexOf($Identifier, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        })
    }

    if ($RequireSingle -and $matches.Count -gt 1) {
        throw "Multiple devices match `"$Identifier`". Use a row number or a more specific device token."
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

    try {
        $auth = (getVault).Auth
        $devices = @(Get-KeeperDeviceManagementDevices -Auth $auth)
    }
    catch {
        Write-Error "Failed to retrieve devices: $($_.Exception.Message)" -ErrorAction Stop
    }

    if ($Format -eq 'json') {
        $jsonDevices = New-Object 'System.Collections.Generic.List[object]'
        $deviceId = 0
        foreach ($device in $devices) {
            $deviceId++
            [void]$jsonDevices.Add([ordered]@{
                id = $deviceId
                deviceName = $device.DeviceName
                clientType = $device.ClientType.ToString().ToUpperInvariant()
                loginStatus = Get-KeeperDeviceManagementLoginStatus -LoginState $device.LoginState
                lastAccessedTimestamp = Get-KeeperDeviceManagementTimestamp -Timestamp $device.LastModifiedTime
            })
        }
        $json = @{ devices = [object[]]$jsonDevices.ToArray() } | ConvertTo-Json -Depth 4
        if ($Output) {
            try {
                Set-Content -LiteralPath $Output -Value $json -Encoding UTF8 -ErrorAction Stop
            }
            catch {
                Write-Error "Failed to save results to ${Output}: $($_.Exception.Message)" -ErrorAction Stop
            }
            Write-Output "Results saved to $Output"
        }
        else {
            Write-Output $json
        }
        return
    }

    if ($devices.Count -eq 0) {
        Write-Output 'No devices found'
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
    Comma-separated or array input of device row IDs, full or prefix device tokens, or device names.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('logout', 'remove', 'lock', 'unlock', 'account-lock', 'account-unlock', 'link', 'unlink')]
        [string] $Action,
        [Parameter(Mandatory = $true, Position = 1)] [ValidateNotNullOrEmpty()] [string[]] $Devices
    )

    try {
        $auth = (getVault).Auth
        $availableDevices = @(Get-KeeperDeviceManagementDevices -Auth $auth)
    }
    catch {
        Write-Error "Failed to retrieve devices: $($_.Exception.Message)" -ErrorAction Stop
    }
    if ($availableDevices.Count -eq 0) {
        Write-Error 'No devices found' -ErrorAction Stop
    }

    $identifiers = @($Devices | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
    if ($identifiers.Count -eq 0) {
        Write-Error 'At least one device identifier must be specified' -ErrorAction Stop
    }

    $selectedDevices = @()
    $resolutionErrors = New-Object 'System.Collections.Generic.List[string]'
    foreach ($identifier in $identifiers) {
        try {
            $matches = @(Resolve-KeeperDeviceManagementDevices -Devices $availableDevices -Identifier $identifier -RequireSingle)
            if ($matches.Count -eq 0) {
                [void]$resolutionErrors.Add("No device found for `"$identifier`"")
            }
            else {
                $selectedDevices += $matches
            }
        }
        catch {
            [void]$resolutionErrors.Add($_.Exception.Message)
        }
    }
    if ($resolutionErrors.Count -gt 0) {
        Write-Error ($resolutionErrors -join [Environment]::NewLine) -ErrorAction Stop
    }

    $selectedDevices = @($selectedDevices | Group-Object { Get-KeeperDeviceManagementToken -Device $_ } | ForEach-Object { $_.Group[0] })
    if (($Action -eq 'link' -or $Action -eq 'unlink') -and $selectedDevices.Count -lt 2) {
        Write-Error "Action `"$Action`" requires at least 2 devices" -ErrorAction Stop
    }

    $actionType = [DeviceManagement.DeviceActionType]::DaInvalid
    if (-not [KeeperSecurity.Authentication.DeviceManagementExtensions]::TryParseDeviceAction($Action, [ref]$actionType)) {
        Write-Error "Unsupported device action `"$Action`"" -ErrorAction Stop
    }

    $deviceNames = @{}
    $tokens = New-Object 'System.Collections.Generic.List[Google.Protobuf.ByteString]'
    foreach ($device in $selectedDevices) {
        $token = Get-KeeperDeviceManagementToken -Device $device
        $deviceNames[$token] = $device.DeviceName
        [void]$tokens.Add($device.EncryptedDeviceToken)
    }
    if (-not $PSCmdlet.ShouldProcess(($deviceNames.Values -join ', '), "Perform device action '$Action'")) {
        return
    }

    try {
        $results = @([KeeperSecurity.Authentication.DeviceManagementExtensions]::ExecuteDeviceAction(
            $auth, $actionType, $tokens).GetAwaiter().GetResult())
    }
    catch {
        Write-Error "Device action `"$Action`" failed: $($_.Exception.Message)" -ErrorAction Stop
    }

    $actionVerbs = @{
        logout = 'logged out'; remove = 'removed'; lock = 'locked'; unlock = 'unlocked'
        'account-lock' = 'account locked'; 'account-unlock' = 'account unlocked'; link = 'linked'; unlink = 'unlinked'
    }
    $successful = $false
    $successCount = 0
    $failureCount = 0
    $returnedTokens = @{}
    foreach ($result in $results) {
        foreach ($token in $result.EncryptedDeviceToken) {
            $tokenText = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($token.ToByteArray())
            if (-not $deviceNames.ContainsKey($tokenText) -or $returnedTokens.ContainsKey($tokenText)) {
                continue
            }
            $returnedTokens[$tokenText] = $true
            $deviceName = $deviceNames[$tokenText]
            if (-not $deviceName) { $deviceName = 'Unknown Device' }
            if ($result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::Success) {
                Write-Output ("{0} Device '{1}' successfully {2}" -f [char]0x2713, $deviceName, $actionVerbs[$Action])
                $successful = $true
                $successCount++
            }
            elseif ($result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::NotAllowed) {
                Write-Error "Device '$deviceName': Operation not allowed"
                $failureCount++
            }
            else {
                Write-Error "Device '$deviceName': Action failed ($($result.DeviceActionStatus.ToString().ToUpperInvariant()))"
                $failureCount++
            }
        }
    }
    $missingTokens = @($deviceNames.Keys | Where-Object { -not $returnedTokens.ContainsKey($_) })
    foreach ($tokenText in $missingTokens) {
        Write-Error "Device '$($deviceNames[$tokenText])': Action result was not returned by the server"
    }
    if ($failureCount -gt 0 -or $missingTokens.Count -gt 0) {
        Write-Error "Device action `"$Action`" completed with partial failure: $successCount succeeded, $($failureCount + $missingTokens.Count) failed or missing."
    }
    if ($successful) {
        Write-Output ''
        Write-Output 'Updated device list:'
        try {
            Get-KeeperDeviceList
        }
        catch {
            Write-Error "Device action completed, but failed to refresh the device list: $($_.Exception.Message)"
        }
    }
}

function Rename-KeeperDevice {
    <#
    .SYNOPSIS
    Renames a device owned by the current Keeper account.

    .PARAMETER Device
    Device row ID, full or prefix device token, or device name.

    .PARAMETER NewName
    New friendly name for the device.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true, Position = 0)] [string] $Device,
        [Parameter(Mandatory = $true, Position = 1)] [ValidateNotNullOrEmpty()] [string] $NewName
    )

    try {
        $normalizedName = [KeeperSecurity.Authentication.DeviceManagementExtensions]::NormalizeDeviceName($NewName)
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }

    try {
        $auth = (getVault).Auth
        $availableDevices = @(Get-KeeperDeviceManagementDevices -Auth $auth)
    }
    catch {
        Write-Error "Failed to retrieve devices: $($_.Exception.Message)" -ErrorAction Stop
    }
    if ($availableDevices.Count -eq 0) {
        Write-Error 'No devices found' -ErrorAction Stop
    }

    try {
        $matches = @(Resolve-KeeperDeviceManagementDevices -Devices $availableDevices -Identifier $Device -RequireSingle)
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }
    if ($matches.Count -eq 0) {
        Write-Error "No device found for `"$Device`"" -ErrorAction Stop
    }

    $target = $matches[0]
    foreach ($device in $availableDevices) {
        if ((Get-KeeperDeviceManagementToken -Device $device) -eq (Get-KeeperDeviceManagementToken -Device $target)) {
            continue
        }
        try {
            $existingName = [KeeperSecurity.Authentication.DeviceManagementExtensions]::NormalizeDeviceName($device.DeviceName)
            if ([string]::Equals($existingName, $normalizedName, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Error "Another device already uses the name '$normalizedName'" -ErrorAction Stop
            }
        }
        catch [System.ArgumentException] {
            # Existing legacy names that do not meet current validation are not comparable.
        }
    }
    if (-not $PSCmdlet.ShouldProcess($target.DeviceName, "Rename device to '$normalizedName'")) {
        return
    }
    try {
        $result = [KeeperSecurity.Authentication.DeviceManagementExtensions]::RenameUserDevice(
            $auth, $target.EncryptedDeviceToken, $normalizedName).GetAwaiter().GetResult()
    }
    catch {
        Write-Error "Device rename failed: $($_.Exception.Message)" -ErrorAction Stop
    }
    if ($null -eq $result) {
        Write-Error 'Device rename failed: no response from server' -ErrorAction Stop
    }
    if ($result.DeviceActionStatus -ne [DeviceManagement.DeviceActionStatus]::Success) {
        if ($result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::NotAllowed) {
            Write-Error "Device '$($target.DeviceName)': Operation not allowed" -ErrorAction Stop
        }
        Write-Error "Device '$($target.DeviceName)': Rename failed ($($result.DeviceActionStatus.ToString().ToUpperInvariant()))" -ErrorAction Stop
    }

    Write-Output ("{0} Device name updated from '{1}' to '{2}'" -f [char]0x2713, $target.DeviceName, $result.DeviceNewName)
    Write-Output ''
    Write-Output 'Updated device list:'
    try {
        Get-KeeperDeviceList
    }
    catch {
        Write-Error "Device rename completed, but failed to refresh the device list: $($_.Exception.Message)"
    }
}

New-Alias -Name device-list -Value Get-KeeperDeviceList
New-Alias -Name device-action -Value Invoke-KeeperDeviceAction
New-Alias -Name device-rename -Value Rename-KeeperDevice
