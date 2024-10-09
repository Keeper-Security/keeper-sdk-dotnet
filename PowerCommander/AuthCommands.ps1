#requires -Version 5.1

$expires = @(
    [KeeperSecurity.Authentication.TwoFactorDuration]::EveryLogin,
    [KeeperSecurity.Authentication.TwoFactorDuration]::Every30Days,
    [KeeperSecurity.Authentication.TwoFactorDuration]::Forever)

function twoFactorChannelToText ([KeeperSecurity.Authentication.TwoFactorChannel] $channel) {
    if ($channel -eq [KeeperSecurity.Authentication.TwoFactorChannel]::Authenticator) {
        return 'authenticator'
    }
    if ($channel -eq [KeeperSecurity.Authentication.TwoFactorChannel]::TextMessage) {
        return 'sms'
    }
    if ($channel -eq [KeeperSecurity.Authentication.TwoFactorChannel]::DuoSecurity) {
        return 'duo'
    }
    if ($channel -eq [KeeperSecurity.Authentication.TwoFactorChannel]::RSASecurID) {
        return 'rsa'
    }
    if ($channel -eq [KeeperSecurity.Authentication.TwoFactorChannel]::KeeperDNA) {
        return 'dna'
    }
    return ''
}

function deviceApprovalChannelToText ([KeeperSecurity.Authentication.DeviceApprovalChannel]$channel) {
    if ($channel -eq [KeeperSecurity.Authentication.DeviceApprovalChannel]::Email) {
        return 'email'
    }
    if ($channel -eq [KeeperSecurity.Authentication.DeviceApprovalChannel]::KeeperPush) {
        return 'keeper'
    }
    if ($channel -eq [KeeperSecurity.Authentication.DeviceApprovalChannel]::TwoFactorAuth) {
        return '2fa'
    }
    return ''
}

function twoFactorDurationToExpire ([KeeperSecurity.Authentication.TwoFactorDuration] $duration) {
    if ($duration -eq [KeeperSecurity.Authentication.TwoFactorDuration]::EveryLogin) {
        return 'now'
    }
    if ($duration -eq [KeeperSecurity.Authentication.TwoFactorDuration]::Forever) {
        return 'never'
    }
    return "$([int]$duration)_days"
}


function getStepPrompt ([KeeperSecurity.Authentication.IAuthentication] $auth) {
    $prompt = "`nUnsupported ($($auth.step.State.ToString()))"
    if ($auth.step -is [KeeperSecurity.Authentication.Sync.DeviceApprovalStep]) {
        $prompt = "`nDevice Approval ($(deviceApprovalChannelToText $auth.step.DefaultChannel))"
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.TwoFactorStep]) {
        $channelText = twoFactorChannelToText $auth.step.DefaultChannel
        $prompt = "`n2FA channel($($channelText)) expire[$(twoFactorDurationToExpire $auth.step.Duration)]"
    }

    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.PasswordStep]) {
        $prompt = "`nMaster Password"
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.SsoTokenStep]) {
        $prompt = "`nSSO Token"
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.SsoDataKeyStep]) {
        $prompt = "`nSSO Login Approval"
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.ReadyToLoginStep]) {
        $prompt = "`nLogin"
    }

    return $prompt
}

function printStepHelp ([KeeperSecurity.Authentication.IAuthentication] $auth) {
    $commands = @()
    if ($auth.step -is [KeeperSecurity.Authentication.Sync.DeviceApprovalStep]) {
        $channels = @()
        foreach ($ch in $auth.step.Channels) {
            $channels += deviceApprovalChannelToText $ch
        }
        if ($channels) {
            $commands += "channel=<$($channels -join ' | ')> to change channel."
        }
        $commands += "`"push`" to send a push to the channel"
        $commands += '<code> to send a code to the channel'
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.TwoFactorStep]) {
        $channels = @()
        foreach ($ch in $auth.step.Channels) {
            $channelText = twoFactorChannelToText $ch
            if ($channelText) {
                $channels += $channelText
            }
        }
        if ($channels) {
            $commands += "channel=<$($channels -join ' | ')> to change channel."
        }

        $channels = @()
        foreach ($ch in $auth.step.Channels) {
            $pushes = $auth.step.GetChannelPushActions($ch)
            if ($null -ne $pushes) {
                foreach ($push in $pushes) {
                    $channels += [KeeperSecurity.Authentication.AuthUIExtensions]::GetPushActionText($push)
                }
            }
        }
        if ($channels) {
            $commands += "`"$($channels -join ' | ')`" to send a push/code"
        }

        $channels = @()
        foreach ($exp in $expires) {
            $channels += twoFactorDurationToExpire $exp
        }
        $commands += "expire=<$($channels -join ' | ')> to set 2fa expiration."
        $commands += '<code> to send a 2fa code.'
    }

    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.PasswordStep]) {
        $commands += '<password> to send a master password.'
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.SsoTokenStep]) {
        $commands += $auth.step.SsoLoginUrl
        $commands += ''
        if (-not $auth.step.LoginAsProvider) {
            $commands += '"password" to login using master password.'
        }
        $commands += '<sso token> paste SSO login token.'
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.SsoDataKeyStep]) {
        $channels = @()
        foreach ($ch in $auth.step.Channels) {
            $channels += [KeeperSecurity.Authentication.AuthUIExtensions]::SsoDataKeyShareChannelText($ch)
        }
        if ($channels) {
            $commands += "`"$($channels -join ' | ')`" to request login approval"
        }
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.ReadyToLoginStep]) {
        $commands += '"login <Keeper Email>" login to Keeper as user'
        $commands += '"login_sso <Enterprise Domain>" login to Enterprise Domain'
    }

    if ($commands) {
        Write-Output "`nAvailable Commands`n"
        foreach ($command in $commands) {
            Write-Output $command
        }
        Write-Output '<Enter> to resume'
    }
}

function executeStepAction ([KeeperSecurity.Authentication.IAuthentication] $auth, [string] $action) {

    function tryExpireToTwoFactorDuration ([string] $expire, [ref] [KeeperSecurity.Authentication.TwoFactorDuration] $duration) {
        $result = $true
        if ($expire -eq 'now') {
            $duration.Value = [KeeperSecurity.Authentication.TwoFactorDuration]::EveryLogin
        }
        elseif ($expire -eq 'never') {
            $duration.Value = [KeeperSecurity.Authentication.TwoFactorDuration]::Forever
        }
        elseif ($expire -eq '30_days') {
            $duration.Value = [KeeperSecurity.Authentication.TwoFactorDuration]::Every30Days
        }
        else {
            $duration.Value = [KeeperSecurity.Authentication.TwoFactorDuration]::EveryLogin
        }

        return $result
    }

    function tryTextToDeviceApprovalChannel ([string] $text, [ref] [KeeperSecurity.Authentication.DeviceApprovalChannel] $channel) {
        $result = $true
        if ($text -eq 'email') {
            $channel.Value = [KeeperSecurity.Authentication.DeviceApprovalChannel]::Email
        }
        elseif ($text -eq 'keeper') {
            $channel.Value = [KeeperSecurity.Authentication.DeviceApprovalChannel]::KeeperPush
        }
        elseif ($text -eq '2fa') {
            $channel.Value = [KeeperSecurity.Authentication.DeviceApprovalChannel]::TwoFactorAuth
        }
        else {
            Write-Output 'Unsupported device approval channel:', $text
            $result = $false
        }

        return $result
    }

    function tryTextToTwoFactorChannel ([string] $text, [ref] [KeeperSecurity.Authentication.TwoFactorChannel] $channel) {
        $result = $true
        if ($text -eq 'authenticator') {
            $channel.Value = [KeeperSecurity.Authentication.TwoFactorChannel]::Authenticator
        }
        elseif ($text -eq 'sms') {
            $channel.Value = [KeeperSecurity.Authentication.TwoFactorChannel]::TextMessage
        }
        elseif ($text -eq 'duo') {
            $channel.Value = [KeeperSecurity.Authentication.TwoFactorChannel]::DuoSecurity
        }
        elseif ($text -eq 'rsa') {
            $channel.Value = [KeeperSecurity.Authentication.TwoFactorChannel]::RSASecurID
        }
        elseif ($text -eq 'dna') {
            $channel.Value = [KeeperSecurity.Authentication.TwoFactorChannel]::KeeperDNA
        }
        else {
            Write-Output 'Unsupported 2FA channel:', $text
            $result = $false
        }

        return $result
    }

    if ($auth.step -is [KeeperSecurity.Authentication.Sync.DeviceApprovalStep]) {
        if ($action -eq 'push') {
            $auth.step.SendPush($auth.step.DefaultChannel).GetAwaiter().GetResult() | Out-Null
        }
        elseif ($action -match 'channel\s*=\s*(.*)') {
            $ch = $Matches.1
            [KeeperSecurity.Authentication.DeviceApprovalChannel]$cha = $auth.step.DefaultChannel
            if (tryTextToDeviceApprovalChannel ($ch) ([ref]$cha)) {
                $auth.step.DefaultChannel = $cha
            }
        }
        else {
            Try {
                $auth.step.SendCode($auth.step.DefaultChannel, $action).GetAwaiter().GetResult() | Out-Null
            }
            Catch [KeeperSecurity.Authentication.KeeperApiException] {
                Write-Warning $_
            }
            Catch {
                Write-Error $_
            }
        }
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.TwoFactorStep]) {
        if ($action -match 'channel\s*=\s*(.*)') {
            $ch = $Matches.1
            [KeeperSecurity.Authentication.TwoFactorChannel]$cha = $auth.step.DefaultChannel
            if (tryTextToTwoFactorChannel($ch) ([ref]$cha)) {
                $auth.step.DefaultChannel = $cha
            }
        }
        elseif ($action -match 'expire\s*=\s*(.*)') {
            $exp = $Matches.1
            [KeeperSecurity.Authentication.TwoFactorDuration]$dur = $auth.step.Duration
            if (tryExpireToTwoFactorDuration($exp) ([ref]$dur)) {
                $auth.step.Duration = $dur
            }
        }
        else {
            foreach ($cha in $auth.step.Channels) {
                $pushes = $auth.step.GetChannelPushActions($cha)
                if ($null -ne $pushes) {
                    foreach ($push in $pushes) {
                        if ($action -eq [KeeperSecurity.Authentication.AuthUIExtensions]::GetPushActionText($push)) {
                            $auth.step.SendPush($push).GetAwaiter().GetResult() | Out-Null
                            return
                        }
                    }
                }
                Try {
                    $auth.step.SendCode($auth.step.DefaultChannel, $action).GetAwaiter().GetResult() | Out-Null
                }
                Catch {
                    Write-Error $_
                }
            }
        }
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.PasswordStep]) {
        Try {
            $auth.step.VerifyPassword($action).GetAwaiter().GetResult() | Out-Null
        }
        Catch [KeeperSecurity.Authentication.KeeperAuthFailed] {
            Write-Warning 'Invalid password'
        }
        Catch {
            Write-Error $_
        }
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.SsoTokenStep]) {
        if ($action -eq 'password') {
            $auth.step.LoginWithPassword().GetAwaiter().GetResult() | Out-Null
        }
        else {
            $auth.step.SetSsoToken($action).GetAwaiter().GetResult() | Out-Null
        }
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.SsoDataKeyStep]) {
        [KeeperSecurity.Authentication.DataKeyShareChannel]$channel = [KeeperSecurity.Authentication.DataKeyShareChannel]::KeeperPush
        if ([KeeperSecurity.Authentication.AuthUIExtensions]::TryParseDataKeyShareChannel($action, [ref]$channel)) {
            $auth.step.RequestDataKey($channel).GetAwaiter().GetResult() | Out-Null
        }
    }
    elseif ($auth.step -is [KeeperSecurity.Authentication.Sync.ReadyToLoginStep]) {
        if ($action -match '^login\s+(.*)$') {
            $username = $Matches.1
            $auth.Login($username).GetAwaiter().GetResult() | Out-Null
        }
        elseif ($action -match '^login_sso\s+(.*)$') {
            $providerName = $Matches.1
            $auth.LoginSso($providerName).GetAwaiter().GetResult() | Out-Null
        }
    }
}

function Connect-Keeper {
    <#
    .Synopsis
    Login to Keeper

   .Parameter Username
    User email

    .Parameter Password
    User password

    .Parameter NewLogin
    Do not use Last Login information

    .Parameter SsoPassword
    Use Master Password for SSO account

    .Parameter SsoProvider
    Login using SSO provider

    .Parameter Server
    Change default keeper server

    .Parameter Config
    Config file name
#>
    [CmdletBinding(DefaultParameterSetName = 'regular')]
    Param(
        [Parameter(Position = 0)][string] $Username,
        [Parameter()] [SecureString]$Password,
        [Parameter()][switch] $NewLogin,
        [Parameter(ParameterSetName = 'sso_password')][switch] $SsoPassword,
        [Parameter(ParameterSetName = 'sso_provider')][switch] $SsoProvider,
        [Parameter()][string] $Server,
        [Parameter()][string] $Config
    )

    Disconnect-Keeper -Resume | Out-Null
    if ($Config) {
        $storage = New-Object KeeperSecurity.Configuration.JsonConfigurationStorage $Config
    } else {
        $storage = New-Object KeeperSecurity.Configuration.JsonConfigurationStorage
    }
    if (-not $Server) {
        $Server = $storage.LastServer
        if ($Server) {
            Write-Information -MessageData "`nUsing Keeper Server: $Server`n"
        }
        else {
            Write-Information -MessageData "`nUsing Default Keeper Server: $([KeeperSecurity.Authentication.KeeperEndpoint]::DefaultKeeperServer)`n"
        }
    }


    $endpoint = New-Object KeeperSecurity.Authentication.KeeperEndpoint($Server, $storage.Servers)
    $endpoint.DeviceName = 'PowerShell Commander'
    $endpoint.ClientVersion = 'c16.1.0'
    $authFlow = New-Object KeeperSecurity.Authentication.Sync.AuthSync($storage, $endpoint)

    $authFlow.ResumeSession = $true
    $authFlow.AlternatePassword = $SsoPassword.IsPresent

    if (-not $NewLogin.IsPresent -and -not $SsoProvider.IsPresent) {
        if (-not $Username) {
            $Username = $storage.LastLogin
        }
    }

    $namePrompt = 'Keeper Username'
    if ($SsoProvider.IsPresent) {
        $namePrompt = 'Enterprise Domain'
    }

    if ($Username) {
        Write-Output "$(($namePrompt + ': ').PadLeft(21, ' ')) $Username"
    }
    else {
        while (-not $Username) {
            $Username = Read-Host -Prompt $namePrompt.PadLeft(20, ' ')
        }
    }
    if ($SsoProvider.IsPresent) {
        $authFlow.LoginSso($Username).GetAwaiter().GetResult() | Out-Null
    }
    else {
        $passwords = @()
        if ($Password) {
            if ($Password -is [SecureString]) {
                $passwords += [Net.NetworkCredential]::new('', $Password).Password
            }
            elseif ($Password -is [String]) {
                $passwords += $Password
            }
        }
        $authFlow.Login($Username, $passwords).GetAwaiter().GetResult() | Out-Null
    }
    Write-Output ""
    while (-not $authFlow.IsCompleted) {
        if ($lastStep -ne $authFlow.Step.State) {
            printStepHelp $authFlow
            $lastStep = $authFlow.Step.State
        }

        $prompt = getStepPrompt $authFlow

        if ($authFlow.Step -is [KeeperSecurity.Authentication.Sync.PasswordStep]) {
            $securedPassword = Read-Host -Prompt $prompt -AsSecureString
            if ($securedPassword.Length -gt 0) {
                $action = [Net.NetworkCredential]::new('', $securedPassword).Password
            }
            else {
                $action = ''
            }
        }
        else {
            $action = Read-Host -Prompt $prompt
        }

        if ($action) {
            if ($action -eq '?') {
            }
            else {
                executeStepAction $authFlow $action
            }
        }
    }

    if ($authFlow.Step.State -ne [KeeperSecurity.Authentication.Sync.AuthState]::Connected) {
        if ($authFlow.Step -is [KeeperSecurity.Authentication.Sync.ErrorStep]) {
            Write-Warning $authFlow.Step.Message
        }
        return
    }

    $auth = $authFlow
    if ([KeeperSecurity.Authentication.AuthExtensions]::IsAuthenticated($auth)) {
        Write-Debug -Message "Connected to Keeper as $Username"

        $vault = New-Object KeeperSecurity.Vault.VaultOnline($auth)
        $task = $vault.SyncDown()
        Write-Information -MessageData 'Syncing ...'
        $task.GetAwaiter().GetResult() | Out-Null
        $vault.AutoSync = $true

        $Script:Context.Auth = $auth
        $Script:Context.Vault = $vault

        [KeeperSecurity.Vault.VaultData]$vaultData = $vault
        Write-Information -MessageData "Decrypted $($vaultData.RecordCount) record(s)"
        Set-KeeperLocation -Path '\' | Out-Null
    }
}

$Keeper_ConfigServerCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $prefixes = @('', 'dev.', 'qa.')
    $suffixes = $('.com', '.eu')

    $prefixes | ForEach-Object { $p = $_; $suffixes | ForEach-Object { $s = $_; "${p}keepersecurity${s}" } } | Where-Object { $_.StartsWith($wordToComplete) }
}
Register-ArgumentCompleter -Command Connect-Keeper -ParameterName Server -ScriptBlock $Keeper_ConfigServerCompleter
New-Alias -Name kc -Value Connect-Keeper

function Disconnect-Keeper {
    <#
    .Synopsis
    Logout from Keeper
#>

    [CmdletBinding()]
    Param(
        [Parameter()][switch] $Resume
    )

    $Script:Context.AvailableTeams = $null
    $Script:Context.AvailableUsers = $null
    
    $Script:Context.ManagedCompanyId = 0
    $Script:Context.Enterprise = $null

    $vault = $Script:Context.Vault
    if ($vault) {
        $vault.Dispose() | Out-Null
    }
    $Script:Context.Vault = $null

    [KeeperSecurity.Authentication.IAuthentication] $auth = $Script:Context.Auth
    if ($auth) {
        if (-not $Resume.IsPresent) {
            $auth.Logout().GetAwaiter().GetResult() | Out-Null
        }
        $auth.Dispose() | Out-Null

    }
    $Script:Context.Auth = $null
}
New-Alias -Name kq -Value Disconnect-Keeper

function Sync-Keeper {
    <#
    .Synopsis
    Sync down with Keeper
#>

    [CmdletBinding()]
    [KeeperSecurity.Vault.VaultOnline]$vault = $Script:Context.Vault
    if ($vault) {
        $task = $vault.SyncDown()
        $task.GetAwaiter().GetResult() | Out-Null
    }
    else {
        Write-Error -Message "Not connected" -ErrorAction Stop
    }
}
New-Alias -Name ks -Value Sync-Keeper

function Get-KeeperInformation {
    <#
    .Synopsis
    Prints account license information
    #>

    $vault = getVault
    [KeeperSecurity.Authentication.IAuthentication]$auth = $vault.Auth

    [KeeperSecurity.Authentication.AccountLicense]$license = $auth.AuthContext.License
    switch ($license.AccountType) {
        0 { $accountType = $license.ProductTypeName }
        1 { $accountType = 'Family Plan'}
        2 { $accountType = 'Enterprise' }
        Default { $accountType = $license.ProductTypeName }
    }
    $accountType = 'Enterprise'
    [PSCustomObject]@{
        PSTypeName  = "KeeperSecurity.License.Info"
        User        = $auth.Username
        Server      = $auth.Endpoint.Server
        Admin       = $auth.AuthContext.IsEnterpriseAdmin
        AccountType = $accountType 
        RenewalDate = $license.ExpirationDate
        StorageCapacity = [int] [Math]::Truncate($license.BytesTotal / (1024 * 1024 * 1024))
        StorageUsage = [int] [Math]::Truncate($license.BytesUsed * 100 / $license.BytesTotal)
        StorageExpires = $license.StorageExpirationDate
    }

    if ($license.AccountType -eq 2) {
        $enterprise = getEnterprise
        if ($enterprise) {
            $enterpriseLicense = $enterprise.enterpriseData.EnterpriseLicense
            $productTypeId = $enterpriseLicense.ProductTypeId
            if ($productTypeId -in @(2, 5)) {
                $tier = $enterpriseLicense.Tier
                if ($tier -eq 1) {
                    $plan = 'Enterprise'
                } else {
                    $plan = 'Business'
                }
            }
            elseif ($productTypeId -in @(9, 10)) {
                $distributor = $enterpriseLicense.Distributor
                if ($distributor -eq $true) {
                    $plan = 'Distributor'
                } else {
                    $plan = 'Managed MSP'
                }
            }
            elseif ($productTypeId -in @(11, 12)) {
                $plan = 'Keeper MSP'
            }
            elseif ($productTypeId -eq 8) {
                $tier = $enterpriseLicense.Tier
                if ($tier -eq 1) {
                    $plan = 'Enterprise'
                } else {
                    $plan = 'Business'
                }
                $plan = "MC $plan"
            } else {
                $plan = 'Unknown'
            }
            if ($productTypeId -in @(5, 10, 12)) {
                $plan = "$plan Trial"
            }

            $enterpriseInfo = [PSCustomObject]@{
                PSTypeName  = "KeeperSecurity.License.EnterpriseInfo"
                LicenseType = 'Enterprise'
                EnterpriseName = $enterprise.loader.EnterpriseName
                BasePlan    = $plan
            }
            if ($enterpriseLicense.Paid) {
                $expiration = $enterpriseLicense.Expiration
                if ($expiration -gt 0) {
                    $exp = [KeeperSecurity.Utils.DateTimeOffsetExtensions]::FromUnixTimeMilliseconds($expiration)
                    $expDate = $exp.ToString('d')
                    Add-Member -InputObject $enterpriseInfo -MemberType NoteProperty -Name 'Expires' -Value $expDate
                }
                
                switch ($enterpriseLicense.filePlanTypeId) {
                    -1 { $filePlan = 'No Storage' }
                    0 { $filePlan = 'Trial' }
                    1 { $filePlan = '1GB' }
                    2 { $filePlan = '10GB' }
                    3 { $filePlan = '50GB' }
                    4 { $filePlan = '100GB' }
                    5 { $filePlan = '250GB' }
                    6 { $filePlan = '500GB' }
                    7 { $filePlan = '1TB' }
                    8 { $filePlan = '10TB' }
                    Default { $filePlan = '???' }
                }
                Add-Member -InputObject $enterpriseInfo -MemberType NoteProperty -Name 'StorageCapacity' -Value $filePlan

                $numberOfSeats = $enterpriseLicense.NumberOfSeats
                if ($numberOfSeats -gt 0) {
                    Add-Member -InputObject $enterpriseInfo -MemberType NoteProperty -Name 'TotalUsers' -Value $numberOfSeats
                }
                $seatsAllocated = $enterpriseLicense.SeatsAllocated
                if ($seatsAllocated -gt 0) {
                    Add-Member -InputObject $enterpriseInfo -MemberType NoteProperty -Name 'ActiveUsers' -Value $seatsAllocated
                }
                $seatsPending = $enterpriseLicense.SeatsPending
                if ($seatsAllocated -gt 0) {
                    Add-Member -InputObject $enterpriseInfo -MemberType NoteProperty -Name 'InvitedUsers' -Value $SeatsPending
                }

            }
            $enterpriseInfo
        }
    }
}
New-Alias -Name kwhoami -Value Get-KeeperInformation

function compareArrays {
    param ($array1, $array2)

    if ($array1.Length -eq $array2.Length) {
        foreach ($i in 0..($array1.Length-1)) {
            if ($array1[$i] -ne $array2[$i]) {
                return $false
            }
        }
        return $true
    }
    return $false
}

function formatTimeout {
    param ($timeout)

    if ($timeout -gt 0) {
        $dayMillis = [TimeSpan]::FromDays(1).TotalMilliseconds
        if ($logoutTimer -gt $dayMillis) { 
            return "$([Math]::Round($logoutTimer / $dayMillis)) day(s)"
        }

        $hourMillis = [TimeSpan]::FromHours(1).TotalMilliseconds
        if ($logoutTimer -gt $hourMillis) { 
            return "$([Math]::Round($logoutTimer / $hourMillis)) hour(s)"
        }

        $minuteMillis = [TimeSpan]::FromMinutes(1).TotalMilliseconds
        return "$([Math]::Round($logoutTimer / $minuteMillis)) minute(s)"
    }
}

function Get-KeeperDeviceSettings {
    <#
    .SYNOPSIS
    Display settings of the current device
    #>

    $vault = getVault
    $auth = $vault.Auth

    $accountSummary = [KeeperSecurity.Authentication.AuthExtensions]::LoadAccountSummary($auth).GetAwaiter().GetResult()
    $device = $accountSummary.Devices | Where-Object { compareArrays $_.EncryptedDeviceToken $auth.DeviceToken } | Select-Object -First 1
    if (-not $device) {
        Write-Error -Message "The current device could not be found" -ErrorAction Stop
    }

    $logoutTimer = $accountSummary.Settings.LogoutTimer
    if ($logoutTimer -gt 0) {
        $logoutTimerText = formatTimeout $logoutTimer
    } else {
        $logoutTimerText = '1 hour(s)'
    }

    $persistentLoginRestricted = $false
    if ($accountSummary.Enforcements.Booleans) {
        $plp = $accountSummary.Enforcements.Booleans | Where-Object { $_.Key -eq 'restrict_persistent_login' } | Select-Object -First 1
        if ($plp) {
            $persistentLoginRestricted = $plp.Value
        }
    }
    $persistentLoginEnabled = $false
    if (-not $persistentLoginRestricted) {
        $persistentLoginEnabled = $accountSummary.Settings.PersistentLogin
    }

    $settings = [PSCustomObject]@{
        PSTypeName  = "KeeperSecurity.Authentication.DeviceInfo"
        DeviceName = $device.DeviceName
        PersistentLogin = $persistentLoginEnabled
        DataKeyPresent = $device.EncryptedDataKeyPresent
        IpAutoApprove = -not $accountSummary.Settings.IpDisableAutoApprove
        IsSsoUser = $accountSummary.Settings.SsoUser
        DeviceLogoutTimeout = $logoutTimerText
    }

    if ($accountSummary.Enforcements.Longs) {
        $enf = $accountSummary.Enforcements.Longs | Where-Object { $_.Key -eq 'logout_timer_desktop' } | Select-Object -First 1
        if ($enf.Length -eq 1) {
            $entLogoutTimer = $enf.Value
            if ($entLogoutTimer -gt 0) {
                $entLogoutTimerText = formatTimeout $entLogoutTimer
                Add-Member -InputObject $settings -MemberType NoteProperty -Name 'EnterpriseLogoutTimeout' -Value $entLogoutTimerText
            }
        }
    }
    $settings
}

function Set-KeeperDeviceSettings {
    <#
    .SYNOPSIS
        Modifies the current device settings

    .PARAMETER NewName
        Modifies device name

    .PARAMETER Timeout
        Sets inactivity timeout. Format: NUMBER[h|d]
        default - minutes,  h - hours, d - days
    
    .PARAMETER Register
        Register current device for Persistent Login

    .PARAMETER PersistentLogin
        Enables or disables Persistent login for account
        ON | OFF

    .PARAMETER IpAutoApprove
        Enables or disables Automatic Approval by IP address for account
        ON | OFF

    .EXAMPLE
        C:\PS> Set-KeeperDeviceSettings -NewName 'Azure' -Timeout 30d -PersistentLogin ON -Register
    #>

    [CmdletBinding()]
    Param (
        [Parameter()][String] $NewName,
        [Parameter(HelpMessage='NUMBER[h|d]')][String] $Timeout,
        [Parameter()][Switch] $Register,
        [Parameter()][ValidateSet('ON', 'OFF')][String] $PersistentLogin,
        [Parameter()][ValidateSet('ON', 'OFF')][String] $IpAutoApprove
    )

    $vault = getVault
    $auth = $vault.Auth

    $accountSummary = [KeeperSecurity.Authentication.AuthExtensions]::LoadAccountSummary($auth).GetAwaiter().GetResult()
    $device = $accountSummary.Devices | Where-Object { compareArrays $_.EncryptedDeviceToken $auth.DeviceToken } | Select-Object -First 1
    if (-not $device) {
        Write-Error -Message "The current device could not be found" -ErrorAction Stop
    }

    $changed = $false

    if ($NewName) {
        $request = New-Object Authentication.DeviceUpdateRequest
        $request.ClientVersion = $auth.Endpoint.ClientVersion
        $request.DeviceStatus = [Authentication.DeviceStatus]::DeviceOk
        $request.DeviceName = $NewName
        $request.EncryptedDeviceToken = $device.EncryptedDeviceToken

        $auth.ExecuteAuthRest("authentication/update_device", $request, $null, 0).GetAwaiter().GetResult() | Out-Null
        Write-Information "Device name was changed to `"$NewName`""
        $changed = $true
    }

    $persistentLoginRestricted = $false
    if ($accountSummary.Enforcements.Booleans) {
        $plp = $accountSummary.Enforcements.Booleans | Where-Object { $_.Key -eq 'restrict_persistent_login' } | Select-Object -First 1
        if ($plp) {
            $persistentLoginRestricted = $plp.Value
        }
    }
    if ($Register.IsPresent) {
        if ($persistentLoginRestricted -eq $true) {
            Write-Error "Persistent Login feature is restricted by Enterprise Administrator" -ErrorAction Stop
        }

        $registered = [KeeperSecurity.Authentication.AuthExtensions]::RegisterDataKeyForDevice($auth, $device).GetAwaiter().GetResult()
        if ($registered) {
            Write-Information "Device is registered for Persistent Login"
        }
        $changed = $true
    }

    if ($PersistentLogin) {
        if ($persistentLoginRestricted -eq $true) {
            Write-Error "Persistent Login feature is restricted by Enterprise Administrator" -ErrorAction Stop
        }
        $value = '0'
        if ($PersistentLogin -eq 'ON') {
            $value = '1'
        }
        [KeeperSecurity.Authentication.AuthExtensions]::SetSessionParameter($auth, 'persistent_login', $value).GetAwaiter().GetResult() | Out-Null
        $changed = $true
    }

    if ($IpAutoApprove) {
        $value = '1'
        if ($IpAutoApprove -eq 'ON') {
            $value = '0'
        }
        [KeeperSecurity.Authentication.AuthExtensions]::SetSessionParameter($auth, 'ip_disable_auto_approve', $value).GetAwaiter().GetResult() | Out-Null
        $changed = $true
    }

    if ($Timeout) {
        $lastLetter = $Timeout[-1]
        if ($lastLetter -eq 'd') {
            $timeoutInt = $Timeout.Substring(0, $Timeout.Length - 1)
        }
        elseif ($lastLetter -eq 'h') {
            $timeoutInt = $Timeout.Substring(0, $Timeout.Length - 1)
        } else {
            $lastLetter = ''
            $timeoutInt = $Timeout
        }

        $minutes = $null
        $b = [int]::TryParse($timeoutInt, [ref]$minutes)
        if (-not $b) {
            Write-Error "Invalid timeout value `"$Timeout`". Format NUMBER[h|d]. d-days, h-hours. default minutes " -ErrorAction Stop
        }
        if ($lastLetter -eq 'h') {
            $minutes = $minutes * 60
        }
        elseif ($lastLetter -eq 'd') {
            $minutes = $minutes * (60 * 24) 
        }
        [KeeperSecurity.Authentication.AuthExtensions]::SetSessionInactivityTimeout($auth, $minutes).GetAwaiter().GetResult() | Out-Null
        $changed = $true
    }

    if (-not $changed) {
        Get-KeeperDeviceSettings
    }
}
New-Alias -Name this-device -Value Set-KeeperDeviceSettings