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
