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

    .Parameter NewLogin
    Do not use Last Login information

    .Parameter SsoPassword
    Use Master Password for SSO account

    .Parameter Server
    Change default keeper server
#>
    [CmdletBinding(DefaultParameterSetName = 'regular')]
    Param(
        [Parameter(Position = 0)][string] $Username,
        [Parameter()] [SecureString]$Password,
        [Parameter()][switch] $NewLogin,
        [Parameter(ParameterSetName = 'sso_password')][switch] $SsoPassword,
        [Parameter(ParameterSetName = 'sso_provider')][switch] $SsoProvider,
        [Parameter()][string] $Server
    )

    Disconnect-Keeper -Resume | Out-Null

    $storage = New-Object KeeperSecurity.Configuration.JsonConfigurationStorage
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
