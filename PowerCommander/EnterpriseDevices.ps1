function Convert-DeviceTokenToString {
    <#
        .Synopsis
        Internal helper function to convert device token byte array to string
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [byte[]] $Token
    )
    
    $sb = New-Object System.Text.StringBuilder
    $maxLength = 50
    foreach ($b in $Token) {
        if ($sb.Length -ge $maxLength) {
            break
        }
        [void]$sb.AppendFormat("{0:x2}", $b)
    }
    return $sb.ToString()
}

function Convert-DeviceTokenToShortId {
    <#
        .Synopsis
        Internal helper function to convert a device token byte array to a short display ID,
        used by the device-admin commands. Distinct from Convert-DeviceTokenToString (used by
        the device-approval cmdlets) so that changing the display length here does not change
        matching behavior for Approve-/Deny-KeeperDevice.
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [byte[]] $Token
    )

    $sb = New-Object System.Text.StringBuilder
    $maxLength = 20
    foreach ($b in $Token) {
        if ($sb.Length -ge $maxLength) {
            break
        }
        [void]$sb.AppendFormat("{0:x2}", $b)
    }
    return $sb.ToString()
}

function Get-PendingKeeperDeviceApproval {
    <#
        .Synopsis
        List pending device approval requests
        
        .Description
        Displays a list of all pending device approval requests with details including user email, device ID, device name, client version, and IP address.
        
        .Parameter Reload
        Reload the list of pending device approvals from the server
        
        .Parameter Format
        Output format: table, csv, or json
        
        .Parameter Output
        File path to write output to (required for csv and json formats)
        
        .Example
        Get-PendingKeeperDeviceApproval
        Lists all pending device approvals in table format
        
        .Example
        Get-PendingKeeperDeviceApproval -Format csv -Output devices.csv
        Exports pending device approvals to CSV file
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][switch] $Reload,
        [Parameter()][ValidateSet('table', 'csv', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )
    
    [Enterprise]$enterprise = getEnterprise
    
    if ($Reload) {
        $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
    }
    
    $approvals = @($enterprise.deviceApproval.DeviceApprovalRequests)
    
    if ($approvals.Count -eq 0) {
        Write-Output "There are no pending devices"
        return
    }
    
    $deviceList = New-Object System.Collections.ArrayList
    foreach ($device in $approvals) {
        $user = $null
        if ($enterprise.enterpriseData.TryGetUserById($device.EnterpriseUserId, [ref]$user)) {
            $deviceTokenBytes = $device.EncryptedDeviceToken.ToByteArray()
            $deviceId = Convert-DeviceTokenToString -Token $deviceTokenBytes
            
            [void]$deviceList.Add([PSCustomObject]@{
                Email = $user.Email
                DeviceId = $deviceId
                DeviceName = $device.DeviceName
                ClientVersion = $device.ClientVersion
                IpAddress = $device.IpAddress
                DeviceType = $device.DeviceType
            })
        } else {
            Write-Warning "Skipping device for user ID $($device.EnterpriseUserId) - user not found"
        }
    }
    
    $deviceList = $deviceList.ToArray()
    
    $deviceList = $deviceList | Sort-Object DeviceId
    
    if ($Format -eq 'json') {
        $json = $deviceList | ConvertTo-Json
        if ($Output) {
            $json | Out-File -FilePath $Output -Encoding UTF8
            Write-Output "Output written to $Output"
        } else {
            Write-Output $json
        }
    }
    elseif ($Format -eq 'csv') {
        if (-not $Output) {
            Write-Error "Output file path is required for CSV format" -ErrorAction Stop
        }
        $deviceList | Export-Csv -Path $Output -NoTypeInformation
        Write-Output "Output written to $Output"
    }
    else {
        $deviceList | Format-Table -AutoSize Email, DeviceId, DeviceName, ClientVersion, IpAddress
    }
}

function Approve-KeeperDevice {
    <#
        .Synopsis
        Approve pending device requests
        
        .Description
        Approves pending device approval requests. You can specify devices by device ID (partial match supported) or user email.
        
        .Parameter Match
        Device ID (partial match supported) or user email to approve. If not specified, all pending devices will be approved.
        
        .Parameter Reload
        Reload the list of pending device approvals before processing
        
        .Parameter TrustedIp
        Approve devices from a trusted IP address
        
        .Example
        Approve-KeeperDevice -Match "user@example.com"
        Approves all pending devices for user@example.com
        
        .Example
        Approve-KeeperDevice -Match "a1b2c3"
        Approves devices with device ID starting with "a1b2c3"
        
        .Example
        Approve-KeeperDevice
        Approves all pending devices
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Parameter(Position = 0)]
        [string] $Match,
        [Parameter()]
        [switch] $Reload,
        [Parameter()]
        [switch] $TrustedIp
    )
    
    [Enterprise]$enterprise = getEnterprise
    
    if ($Reload) {
        try {
            $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
        } catch {
            Write-Error "Failed to reload enterprise data: $($_.Exception.Message)" -ErrorAction Stop
        }
    }
    
    $approvals = @($enterprise.deviceApproval.DeviceApprovalRequests)
    
    if ($approvals.Count -eq 0) {
        Write-Output "There are no pending devices"
        return
    }
    
    if (-not [string]::IsNullOrWhiteSpace($Match)) {
        $Match = $Match.Trim()
    }
    
    $devices = Get-MatchingDevices -Approvals $approvals -Enterprise $enterprise -Match $Match
    
    if ($devices.Count -eq 0) {
        $matchText = if ([string]::IsNullOrWhiteSpace($Match)) { "all pending devices" } else { "matching '$Match'" }
        Write-Output "No device found $matchText"
        return
    }
    
    $deviceDetails = $devices | ForEach-Object {
        $deviceTokenBytes = $_.EncryptedDeviceToken.ToByteArray()
        $deviceId = Convert-DeviceTokenToString -Token $deviceTokenBytes
        $user = $null
        if ($enterprise.enterpriseData.TryGetUserById($_.EnterpriseUserId, [ref]$user)) {
            "$($user.Email) ($deviceId)"
        } else {
            "User ID $($_.EnterpriseUserId) ($deviceId)"
        }
    }
    $deviceListText = $deviceDetails -join ", "
    
    if ($PSCmdlet.ShouldProcess("$($devices.Count) device(s)", "Approve", "This will approve the following devices: $deviceListText")) {
        try {
            $enterprisePrivateKeyBytes = $enterprise.loader.EcPrivateKey
            if (-not $enterprisePrivateKeyBytes) {
                Write-Error "Enterprise private key not available. Cannot approve devices without the enterprise private key."
                return
            }
            
            $enterpriseEcKey = [KeeperSecurity.Utils.CryptoUtils]::LoadEcPrivateKey($enterprisePrivateKeyBytes)
            
            $dataKeys = New-Object 'System.Collections.Generic.Dictionary[long,byte[]]'
            $userIdsToLoad = New-Object 'System.Collections.Generic.List[long]'
            
            foreach ($device in $devices) {
                if (-not $dataKeys.ContainsKey($device.EnterpriseUserId)) {
                    $userIdsToLoad.Add($device.EnterpriseUserId)
                }
            }
            
            if ($userIdsToLoad.Count -gt 0) {
                $dataKeyRq = New-Object Authentication.UserDataKeyRequest
                foreach ($userId in $userIdsToLoad) {
                    $dataKeyRq.EnterpriseUserId.Add($userId) | Out-Null
                }
                
                $dataKeyRs = $enterprise.loader.Auth.ExecuteAuthRest("enterprise/get_enterprise_user_data_key", $dataKeyRq, [Enterprise.EnterpriseUserDataKeys]).GetAwaiter().GetResult()
                
                foreach ($key in $dataKeyRs.Keys) {
                    if ($key.UserEncryptedDataKey.IsEmpty) {
                        continue
                    }
                    try {
                        $userDataKey = [KeeperSecurity.Utils.CryptoUtils]::DecryptEc($key.UserEncryptedDataKey.ToByteArray(), $enterpriseEcKey)
                        $dataKeys[$key.EnterpriseUserId] = $userDataKey
                    }
                    catch {
                        Write-Warning "Failed to decrypt data key for user $($key.EnterpriseUserId): $($_.Exception.Message)"
                    }
                }
            }
            
            $rq = New-Object Enterprise.ApproveUserDevicesRequest
            foreach ($device in $devices) {
                if (-not $dataKeys.ContainsKey($device.EnterpriseUserId)) {
                    continue
                }
                if ($device.DevicePublicKey.IsEmpty) {
                    continue
                }
                
                try {
                    $devicePublicKey = [KeeperSecurity.Utils.CryptoUtils]::LoadEcPublicKey($device.DevicePublicKey.ToByteArray())
                    $userDataKey = $dataKeys[$device.EnterpriseUserId]
                    $encryptedDataKey = [KeeperSecurity.Utils.CryptoUtils]::EncryptEc($userDataKey, $devicePublicKey)
                    
                    $deviceRq = New-Object Enterprise.ApproveUserDeviceRequest
                    $deviceRq.EnterpriseUserId = $device.EnterpriseUserId
                    $deviceRq.EncryptedDeviceToken = [Google.Protobuf.ByteString]::CopyFrom($device.EncryptedDeviceToken.ToByteArray())
                    $deviceRq.EncryptedDeviceDataKey = [Google.Protobuf.ByteString]::CopyFrom($encryptedDataKey)
                    
                    $rq.DeviceRequests.Add($deviceRq) | Out-Null
                }
                catch {
                    Write-Warning "Failed to prepare approval for device: $($_.Exception.Message)"
                }
            }
            
            if ($rq.DeviceRequests.Count -eq 0) {
                Write-Output "No device to approve"
                return
            }
            
            $rs = $enterprise.loader.Auth.ExecuteAuthRest("enterprise/approve_user_devices", $rq, [Enterprise.ApproveUserDevicesResponse]).GetAwaiter().GetResult()
            
            if ($rs.DeviceResponses -and $rs.DeviceResponses.Count -gt 0) {
                foreach ($approveRs in $rs.DeviceResponses) {
                    if ($approveRs.Failed) {
                        $user = $null
                        if ($enterprise.enterpriseData.TryGetUserById($approveRs.EnterpriseUserId, [ref]$user)) {
                            Write-Warning "Failed to approve device for $($user.Email): $($approveRs.Message)"
                        }
                        else {
                            Write-Warning "Failed to approve device for user ID $($approveRs.EnterpriseUserId): $($approveRs.Message)"
                        }
                    }
                }
            }
            
            try {
                $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
            } catch {
                Write-Warning "Failed to reload enterprise data after approval: $($_.Exception.Message)"
            }
            Write-Output "Approved $($rq.DeviceRequests.Count) device(s)"
        }
        catch {
            Write-Error "Failed to approve devices: $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}

function Deny-KeeperDevice {
    <#
        .Synopsis
        Deny pending device requests
        
        .Description
        Denies pending device approval requests. You can specify devices by device ID (partial match supported) or user email.
        
        .Parameter Match
        Device ID (partial match supported) or user email to deny. If not specified, all pending devices will be denied.
        
        .Parameter Reload
        Reload the list of pending device approvals before processing
        
        .Example
        Deny-KeeperDevice -Match "user@example.com"
        Denies all pending devices for user@example.com
        
        .Example
        Deny-KeeperDevice -Match "a1b2c3"
        Denies devices with device ID starting with "a1b2c3"
        
        .Example
        Deny-KeeperDevice
        Denies all pending devices
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Parameter(Position = 0)]
        [string] $Match,
        
        [Parameter()][switch] $Reload
    )
    
    [Enterprise]$enterprise = getEnterprise
    
    if ($Reload) {
        try {
            $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
        } catch {
            Write-Error "Failed to reload enterprise data: $($_.Exception.Message)" -ErrorAction Stop
        }
    }
    
    $approvals = @($enterprise.deviceApproval.DeviceApprovalRequests)
    
    if ($approvals.Count -eq 0) {
        Write-Output "There are no pending devices"
        return
    }
    
    if (-not [string]::IsNullOrWhiteSpace($Match)) {
        $Match = $Match.Trim()
    }
    
    $devices = Get-MatchingDevices -Approvals $approvals -Enterprise $enterprise -Match $Match
    
    if ($devices.Count -eq 0) {
        $matchText = if ([string]::IsNullOrWhiteSpace($Match)) { "all pending devices" } else { "matching '$Match'" }
        Write-Output "No device found $matchText"
        return
    }
    
    $deviceDetails = $devices | ForEach-Object {
        $deviceTokenBytes = $_.EncryptedDeviceToken.ToByteArray()
        $deviceId = Convert-DeviceTokenToString -Token $deviceTokenBytes
        $user = $null
        if ($enterprise.enterpriseData.TryGetUserById($_.EnterpriseUserId, [ref]$user)) {
            "$($user.Email) ($deviceId)"
        } else {
            "User ID $($_.EnterpriseUserId) ($deviceId)"
        }
    }
    $deviceListText = $deviceDetails -join ", "
    
    if ($PSCmdlet.ShouldProcess("$($devices.Count) device(s)", "Deny", "This will deny the following devices: $deviceListText")) {
        try {
            $rq = New-Object Enterprise.ApproveUserDevicesRequest
            foreach ($device in $devices) {
                $deviceRq = New-Object Enterprise.ApproveUserDeviceRequest
                $deviceRq.EnterpriseUserId = $device.EnterpriseUserId
                $deviceRq.EncryptedDeviceToken = [Google.Protobuf.ByteString]::CopyFrom($device.EncryptedDeviceToken.ToByteArray())
                $deviceRq.DenyApproval = $true
                
                $rq.DeviceRequests.Add($deviceRq) | Out-Null
            }
            
            if ($rq.DeviceRequests.Count -eq 0) {
                Write-Output "No device to deny"
                return
            }
            
            $rs = $enterprise.loader.Auth.ExecuteAuthRest("enterprise/approve_user_devices", $rq, [Enterprise.ApproveUserDevicesResponse]).GetAwaiter().GetResult()
            
            if ($rs.DeviceResponses -and $rs.DeviceResponses.Count -gt 0) {
                foreach ($approveRs in $rs.DeviceResponses) {
                    if ($approveRs.Failed) {
                        $user = $null
                        if ($enterprise.enterpriseData.TryGetUserById($approveRs.EnterpriseUserId, [ref]$user)) {
                            Write-Warning "Failed to deny device for $($user.Email): $($approveRs.Message)"
                        }
                        else {
                            Write-Warning "Failed to deny device for user ID $($approveRs.EnterpriseUserId): $($approveRs.Message)"
                        }
                    }
                }
            }
            
            try {
                $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
            } catch {
                Write-Warning "Failed to reload enterprise data after denial: $($_.Exception.Message)"
            }
            Write-Output "Denied $($rq.DeviceRequests.Count) device(s)"
        }
        catch {
            Write-Error "Failed to deny devices: $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}

function Get-KeeperAdminUserDevice {
    <#
        .Synopsis
        List devices registered to enterprise user(s)

        .Description
        Shows the devices registered to one or more enterprise users. Requires enterprise
        administrator privileges.

        .Parameter User
        Enterprise user email or ID. If omitted, devices for all enterprise users are listed.

        .Parameter Format
        Output format: table or json. Defaults to table.

        .Example
        Get-KeeperAdminUserDevice -User "user@example.com"
        Lists all devices registered to user@example.com

        .Example
        Get-KeeperAdminUserDevice
        Lists all devices registered to every enterprise user

        .Example
        Get-KeeperAdminUserDevice -User "user@example.com" -Format json
        Lists devices registered to user@example.com as JSON
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $User,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table'
    )

    [Enterprise]$enterprise = getEnterprise

    if ([string]::IsNullOrWhiteSpace($User) -or $User -eq 'all') {
        $userIds = @($enterprise.enterpriseData.Users | ForEach-Object { $_.Id })
    }
    else {
        $userObject = resolveUser $enterprise.enterpriseData $User
        if (-not $userObject) {
            Write-Error "No enterprise user found matching `"$User`"" -ErrorAction Stop
        }
        $userIds = @($userObject.Id)
    }

    if ($userIds.Count -eq 0) {
        Write-Warning "No enterprise users found"
        return
    }

    try {
        $userLists = @([KeeperSecurity.Authentication.DeviceManagementExtensions]::GetAdminUserDevices($enterprise.loader.Auth, [long[]]$userIds).GetAwaiter().GetResult())
    }
    catch {
        Write-Error "Failed to retrieve devices: $($_.Exception.Message)" -ErrorAction Stop
    }

    if ($userLists.Count -eq 0) {
        Write-Warning "No devices available"
        return
    }

    $devices = Get-KdAdminUserDeviceObject -Enterprise $enterprise -UserLists $userLists
    if ($devices.Count -eq 0) {
        Write-Warning "No devices available"
        return
    }

    if ($Format -eq 'json') {
        Write-Output ($devices | ConvertTo-Json)
    }
    else {
        $devices | Format-Table -AutoSize '#', Email, DeviceName, DeviceId, Status, LoginState, UiCategory, LastModified
    }
}

function Get-KdAdminUserDeviceObject {
    <#
        .Synopsis
        Builds the device rows for one or more enterprise users. Returns plain objects;
        formatting/output is left to the caller.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [Enterprise] $Enterprise,
        [Parameter(Mandatory = $true)] [object[]] $UserLists
    )

    $deviceList = New-Object System.Collections.ArrayList
    $rowNo = 1
    foreach ($userList in $UserLists) {
        $email = $userList.EnterpriseUserId
        $u = $null
        if ($Enterprise.enterpriseData.TryGetUserById($userList.EnterpriseUserId, [ref]$u)) {
            $email = $u.Email
        }

        foreach ($group in $userList.DeviceGroups) {
            foreach ($device in $group.Devices) {
                $deviceTokenBytes = $device.EncryptedDeviceToken.ToByteArray()
                $lastModified = ''
                if ($device.LastModifiedTime -gt 0) {
                    $lastModified = [DateTimeOffset]::FromUnixTimeMilliseconds($device.LastModifiedTime).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
                [void]$deviceList.Add([PSCustomObject]@{
                    '#'          = $rowNo
                    Email        = $email
                    DeviceName   = $device.DeviceName
                    DeviceId     = Convert-DeviceTokenToShortId -Token $deviceTokenBytes
                    Status       = $device.DeviceStatus
                    LoginState   = $device.LoginState
                    UiCategory   = [KeeperSecurity.Authentication.DeviceManagementExtensions]::GetUiCategory($device)
                    LastModified = $lastModified
                })
                $rowNo++
            }
        }
    }

    return $deviceList.ToArray()
}

function Invoke-KeeperAdminUserDeviceAction {
    <#
        .Synopsis
        Performs an action on enterprise user device(s)

        .Description
        Logs out, removes, locks, unlocks, or account-locks/unlocks one or more devices belonging
        to an enterprise user. Requires enterprise administrator privileges.

        .Parameter Action
        Device action: "logout", "remove", "lock", "unlock", "account-lock", "account-unlock"

        .Parameter User
        Enterprise user email or ID that owns the target device(s)

        .Parameter Devices
        Device ID(s), device name(s), row number(s) from
        Get-KeeperAdminUserDevice, or "all". Accepts a comma separated string or an array of strings.

        .Example
        Invoke-KeeperAdminUserDeviceAction -Action lock -User "user@example.com" -Devices "all"
        Locks all devices belonging to user@example.com

        .Example
        Invoke-KeeperAdminUserDeviceAction -Action remove -User "user@example.com" -Devices "a1b2c3"
        Removes the device whose ID starts with "a1b2c3" for user@example.com
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateSet('logout', 'remove', 'lock', 'unlock', 'account-lock', 'account-unlock')]
        [string] $Action,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $User,

        [Parameter(Position = 2, Mandatory = $true)]
        [string[]] $Devices
    )

    [Enterprise]$enterprise = getEnterprise

    $userObject = resolveUser $enterprise.enterpriseData $User
    if (-not $userObject) {
        Write-Error "No enterprise user found matching `"$User`"" -ErrorAction Stop
    }

    try {
        $userLists = @([KeeperSecurity.Authentication.DeviceManagementExtensions]::GetAdminUserDevices($enterprise.loader.Auth, [long[]]@($userObject.Id)).GetAwaiter().GetResult())
    }
    catch {
        Write-Error "Failed to retrieve devices for user `"$($userObject.Email)`": $($_.Exception.Message)" -ErrorAction Stop
    }

    $allDevices = @($userLists | ForEach-Object { $_.DeviceGroups } | ForEach-Object { $_.Devices })
    if ($allDevices.Count -eq 0) {
        Write-Warning "No devices found for user `"$($userObject.Email)`""
        return
    }

    $identifiers = @($Devices | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })

    $deviceIdSelector = { param($token) Convert-DeviceTokenToShortId -Token $token }
    $resolved = [KeeperSecurity.Authentication.DeviceManagementExtensions]::ResolveDevicesByIdentifiers(
        [DeviceManagement.Device[]]$allDevices,
        [string[]]$identifiers,
        $deviceIdSelector)

    foreach ($identifier in $resolved.NotFound) {
        Write-Warning "No device found for `"$identifier`""
    }

    foreach ($identifier in $resolved.Ambiguous) {
        Write-Warning "`"$identifier`" matches more than one device. Use `"id:`", `"name:`", `"#<row>`", or `"all`" to disambiguate."
    }

    $toAct = @($resolved.Matched)
    if ($toAct.Count -eq 0) {
        Write-Warning "No devices to act on"
        return
    }

    $actionType = [DeviceManagement.DeviceActionType]::DaInvalid
    if (-not [KeeperSecurity.Authentication.DeviceManagementExtensions]::TryParseDeviceAction($Action, [ref]$actionType)) {
        Write-Error "Unsupported device action `"$Action`"" -ErrorAction Stop
    }

    $deviceNames = ($toAct | ForEach-Object { "$(Convert-DeviceTokenToShortId -Token $_.EncryptedDeviceToken.ToByteArray()) ($($_.DeviceName))" }) -join ', '

    if ($PSCmdlet.ShouldProcess("$($toAct.Count) device(s) for $($userObject.Email): $deviceNames", $Action)) {
        $tokens = New-Object 'System.Collections.Generic.List[Google.Protobuf.ByteString]'
        foreach ($d in $toAct) {
            $tokens.Add($d.EncryptedDeviceToken)
        }

        try {
            $results = @([KeeperSecurity.Authentication.DeviceManagementExtensions]::ExecuteAdminDeviceAction($enterprise.loader.Auth, $actionType, $userObject.Id, $tokens).GetAwaiter().GetResult())
        }
        catch {
            Write-Error "Device action `"$Action`" failed: $($_.Exception.Message)" -ErrorAction Stop
        }

        foreach ($result in $results) {
            $isSuccess = $result.DeviceActionStatus -eq [DeviceManagement.DeviceActionStatus]::Success
            foreach ($token in $result.EncryptedDeviceToken) {
                $deviceId = Convert-DeviceTokenToShortId -Token $token.ToByteArray()
                $resultObject = [PSCustomObject]@{
                    DeviceId = $deviceId
                    Status   = $result.DeviceActionStatus
                }
                if ($isSuccess) {
                    Write-Output $resultObject
                }
                else {
                    Write-Error "Device $deviceId : $($result.DeviceActionStatus)"
                }
            }
        }

        try {
            $updatedUserLists = @([KeeperSecurity.Authentication.DeviceManagementExtensions]::GetAdminUserDevices($enterprise.loader.Auth, [long[]]@($userObject.Id)).GetAwaiter().GetResult())
            if ($updatedUserLists.Count -gt 0) {
                Get-KdAdminUserDeviceObject -Enterprise $enterprise -UserLists $updatedUserLists |
                    Format-Table -AutoSize '#', Email, DeviceName, DeviceId, Status, LoginState, UiCategory, LastModified
            }
        }
        catch {
            Write-Warning "Device action completed, but failed to refresh the device list: $($_.Exception.Message)"
        }
    }
}

function Get-MatchingDevices {
    param(
        [Parameter(Mandatory=$true)]
        $Approvals,
        
        [Parameter(Mandatory=$true)]
        $Enterprise,
        
        [string]$Match
    )

    if ([string]::IsNullOrWhiteSpace($Match)) {
        return @($Approvals)
    }
    
    $devices = New-Object System.Collections.ArrayList
    foreach ($device in $Approvals) {
        $deviceTokenBytes = $device.EncryptedDeviceToken.ToByteArray()
        $deviceId = Convert-DeviceTokenToString -Token $deviceTokenBytes
        
        if ($deviceId.StartsWith($Match, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$devices.Add($device)
            continue
        }
        
        $user = $null
        if ($Enterprise.enterpriseData.TryGetUserById($device.EnterpriseUserId, [ref]$user)) {
            if ($user.Email -ieq $Match) {
                [void]$devices.Add($device)
            }
        }
    }
    
    return $devices.ToArray()
}

function Get-TrustedIpDevices {
    param(
        [Parameter(Mandatory=$true)]
        $Devices,
        
        [Parameter(Mandatory=$true)]
        $Enterprise
    )
    
    try {
        $userIds = New-Object System.Collections.Generic.HashSet[long]
        $userEmails = New-Object System.Collections.Generic.Dictionary[long,string]
        
        foreach ($device in $Devices) {
            if (-not $userIds.Contains($device.EnterpriseUserId)) {
                $userIds.Add($device.EnterpriseUserId) | Out-Null
                $user = $null
                if ($Enterprise.enterpriseData.TryGetUserById($device.EnterpriseUserId, [ref]$user)) {
                    $userEmails[$device.EnterpriseUserId] = $user.Email
                }
            }
        }
        
        if ($userEmails.Count -eq 0) {
            return @()
        }
        
        $lastYear = (Get-Date).AddDays(-365)
        $fromTimestamp = [DateTimeOffset]::new($lastYear).ToUnixTimeSeconds()
        $toTimestamp = [DateTimeOffset]::new((Get-Date)).ToUnixTimeSeconds()
        
        $rq = New-Object KeeperSecurity.Enterprise.AuditLogCommands+GetAuditEventReportsCommand
        $rq.ReportType = "span"
        $rq.Scope = "enterprise"
        $rq.Columns = @("ip_address", "username")
        $rq.Limit = 1000
        
        $filter = New-Object KeeperSecurity.Enterprise.AuditLogCommands+ReportFilter
        $filter.EventTypes = @("login")
        $filter.Username = $userEmails.Values.ToArray()
        $filter.Created = New-Object KeeperSecurity.Enterprise.AuditLogCommands+CreatedFilter
        $filter.Created.Min = $fromTimestamp
        $filter.Created.Max = $toTimestamp
        $rq.Filter = $filter
        
        $auditResult = $Enterprise.loader.Auth.ExecuteAuthCommand(
            [KeeperSecurity.Enterprise.AuditLogCommands+GetAuditEventReportsCommand],
            [KeeperSecurity.Enterprise.AuditLogCommands+GetAuditEventReportsResponse],
            $rq
        ).GetAwaiter().GetResult()
        
        $auditEvents = $auditResult.Events
        
        $trustedIps = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.HashSet[string]]'
        
        foreach ($auditEvent in $auditEvents) {
            if ($auditEvent.ContainsKey('username') -and $auditEvent.ContainsKey('ip_address')) {
                $username = $auditEvent['username'].ToString().ToLowerInvariant()
                $ipAddress = $auditEvent['ip_address'].ToString()
                
                if (-not $trustedIps.ContainsKey($username)) {
                    $trustedIps[$username] = New-Object System.Collections.Generic.HashSet[string]
                }
                [void]$trustedIps[$username].Add($ipAddress)
            }
        }
        
        $trustedDevices = New-Object System.Collections.ArrayList
        
        foreach ($device in $Devices) {
            $user = $null
            if ($Enterprise.enterpriseData.TryGetUserById($device.EnterpriseUserId, [ref]$user)) {
                $username = $user.Email.ToLowerInvariant()
                $deviceIp = $device.IpAddress
                
                if ($trustedIps.ContainsKey($username) -and $trustedIps[$username].Contains($deviceIp)) {
                    [void]$trustedDevices.Add($device)
                } else {
                    Write-Warning "The user $($user.Email) attempted to login from an untrusted IP ($deviceIp). To force the approval, run the same command without the -TrustedIp argument"
                }
            }
        }
        
        return $trustedDevices.ToArray()
    }
    catch {
        Write-Warning "Failed to filter devices by trusted IP: $($_.Exception.Message). Approving all matching devices."
        return $Devices
    }
}
