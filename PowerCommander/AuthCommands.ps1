#requires -Version 5.0

using namespace KeeperSecurity

class VaultCallback : Vault.IVaultUi {
    [System.Threading.Tasks.Task[bool]]Confirmation([string]$information) {
        Write-Host $information 
        Write-Host
        $answer = Read-Host -Prompt 'Please confirm (Y/N)'
        return [System.Threading.Tasks.Task]::FromResult($answer -eq 'Y')
    }
}

class AuthFlowCallback : Authentication.Sync.IAuthSyncCallback, Authentication.IAuthInfoUI {
    [bool]$ReadingInput = $false

    [void]RegionChanged([string]$newRegion) {
        Write-Information -MessageData "Region changed: $newRegion"
    }

    [void]SelectedDevice([string]$deviceToken) {
    }

    [void]OnNextStep() {
        if ($this.ReadingInput) {
            [Console]::WriteLine("`n<Enter> to resume.");
        }
    }

    $expires = @([Authentication.TwoFactorDuration]::EveryLogin, [Authentication.TwoFactorDuration]::Every30Days, [Authentication.TwoFactorDuration]::Forever)
    [string]TwoFactorDurationToExpire([Authentication.TwoFactorDuration]$duration) {
        if ($duration -eq [Authentication.TwoFactorDuration]::EveryLogin) {
            return 'now'
        }
        if ($duration -eq [Authentication.TwoFactorDuration]::Forever) {
            return 'never'
        }
        return "$([int]$duration)_days"
    }
    [bool]TryExpireToTwoFactorDuration([string]$expire, [ref]$duration)
    {
        $result = $true
        if ($expire -eq 'now') {
            $duration.Value = [Authentication.TwoFactorDuration]::EveryLogin
        }
        elseif ($expire -eq 'never') {
            $duration.Value = [Authentication.TwoFactorDuration]::Forever
        }
        elseif ($expire -eq '30_days') {
            $duration.Value = [Authentication.TwoFactorDuration]::Every30Days
        } else {
            $duration.Value = [Authentication.TwoFactorDuration]::EveryLogin
        }

        return $result
    }

    [string]DeviceApprovalChannelToText([Authentication.DeviceApprovalChannel]$channel) {
        if ($channel -eq [Authentication.DeviceApprovalChannel]::Email) {
            return 'email'
        }
        if ($channel -eq [Authentication.DeviceApprovalChannel]::KeeperPush) {
            return 'keeper'
        }
        if ($channel -eq [Authentication.DeviceApprovalChannel]::TwoFactorAuth) {
            return '2fa'
        }
        return ''
    }
    [bool]TryTextToDeviceApprovalChannel([string]$text, [ref]$channel)
    {
        $result = $true
        if ($text -eq 'email') {
            $channel.Value = [Authentication.DeviceApprovalChannel]::Email
        }
        elseif ($text -eq 'keeper') {
            $channel.Value = [Authentication.DeviceApprovalChannel]::KeeperPush
        }
        elseif ($text -eq '2fa') {
            $channel.Value = [Authentication.DeviceApprovalChannel]::TwoFactorAuth
        } else {
            Write-Host 'Unsupported device approval channel:', $text
            $result = $false
        }

        return $result
    }

    [string]TwoFactorChannelToText([KeeperSecurity.Authentication.TwoFactorChannel]$channel) {
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
    [bool]TryTextToTwoFactorChannel([string]$text, [ref]$channel)
    {
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
        } else {
            Write-Host 'Unsupported 2FA channel:', $text
            $result = $false
        }

        return $result
    }

    [void]ExecuteStepAction($auth, $action) {
        if ($auth.step -is [Authentication.Sync.DeviceApprovalStep]) {
            if ($action -eq 'push') {
                $_ = $auth.step.SendPush($auth.step.DefaultChannel).GetAwaiter().GetResult()
            }
            elseif ($action -match 'channel\s*=\s*(.*)') {
                $ch = $Matches.1
                [Authentication.DeviceApprovalChannel]$cha = $auth.step.DefaultChannel
                if ($this.TryTextToDeviceApprovalChannel($ch, [ref]$cha)) {
                    $auth.step.DefaultChannel = $cha
                }
            } else {
                Try {
                    $_ = $auth.step.SendCode($auth.step.DefaultChannel, $action).GetAwaiter().GetResult()
                }
                Catch [Authentication.KeeperApiException]{
                    Write-Host $_ -ForegroundColor Red
                }
                Catch {
                    Write-Host $_ -ForegroundColor Red
                }
            }
        }
        elseif ($auth.step -is [Authentication.Sync.TwoFactorStep]) {
            if ($action -match 'channel\s*=\s*(.*)') {
                $ch = $Matches.1
                [KeeperSecurity.Authentication.TwoFactorChannel]$cha = $auth.step.DefaultChannel
                if ($this.TryTextToTwoFactorChannel($ch, [ref]$cha)) {
                    $auth.step.DefaultChannel = $cha
                }
            }
            elseif ($action -match 'expire\s*=\s*(.*)') {
                $exp = $Matches.1
                [Authentication.TwoFactorDuration]$dur = $auth.step.Duration
                if ($this.TryExpireToTwoFactorDuration($exp, [ref]$dur)) {
                    $auth.step.Duration = $dur
                }
            } else {
                foreach($cha in $auth.step.Channels) {
                    $pushes = $auth.step.GetChannelPushActions($cha)
                    if ($pushes -ne $null) {
                        foreach($push in $pushes) {
                            if ($action -eq [Authentication.AuthUIExtensions]::GetPushActionText($push)) {
                                $_ = $auth.step.SendPush($push).GetAwaiter().GetResult()
                                return
                            }
                        }
                    }
                    Try {
                        $_ = $auth.step.SendCode($auth.step.DefaultChannel, $action).GetAwaiter().GetResult()
                    }
                    Catch {
                        Write-Host $_ -ForegroundColor Red
                    }
                }
            }
        }
        elseif ($auth.step -is [Authentication.Sync.PasswordStep]) {
            Try {
                $_ = $auth.step.VerifyPassword($action).GetAwaiter().GetResult()
            }
            Catch [Authentication.KeeperAuthFailed]{
                Write-Host 'Invalid password' -ForegroundColor Red
            }
            Catch {
                Write-Host $_ -ForegroundColor Red
            }
        }
        elseif ($auth.step -is [Authentication.Sync.SsoTokenStep]) {
            if ($action -eq 'password') {
                $_ = $auth.step.LoginWithPassword().GetAwaiter().GetResult()
            } else {
                $_ = $auth.step.SetSsoToken($action).GetAwaiter().GetResult()
            }
        }
        elseif ($auth.step -is [Authentication.Sync.SsoDataKeyStep]) {
            [Authentication.DataKeyShareChannel]$channel = [Authentication.DataKeyShareChannel]::KeeperPush
            if ([Authentication.AuthUIExtensions]::TryParseDataKeyShareChannel($action, [ref]$channel)) {
                $_ = $auth.step.RequestDataKey($channel).GetAwaiter().GetResult()
            }
        }
        elseif ($auth.step -is [Authentication.Sync.ReadyToLoginStep]) {
            if ($action -match '^login\s+(.*)$') {
                $username = $Matches.1
                $_ = $auth.Login($username).GetAwaiter().GetResult()
            }
            elseif ($action -match '^login_sso\s+(.*)$') {
                $providerName = $Matches.1
                $_ = $auth.LoginSso($providerName).GetAwaiter().GetResult()
            }
        }
        elseif ($auth.step -is [Authentication.Sync.HttpProxyStep]) {
            $args = Invoke-Expression ".{`$args} $action"
            if ($args.Count -eq 3 -and $args[0] -eq 'login') {
                $_ = $auth.step.SetProxyCredentials($args[1], $args[2]).GetAwaiter().GetResult()
            }
        }
    }

    [string]GetStepPrompt($auth) {
        $prompt = "`nUnsupported ($($auth.step.State.ToString()))"
        if ($auth.step -is [Authentication.Sync.DeviceApprovalStep]) {
            $prompt = "`nDevice Approval ($($this.DeviceApprovalChannelToText($auth.step.DefaultChannel)))"
        }
        elseif ($auth.step -is [Authentication.Sync.TwoFactorStep]) {
            $channelText = $this.TwoFactorChannelToText($auth.step.DefaultChannel)
            $prompt = "`n2FA channel($($channelText)) expire[$($this.TwoFactorDurationToExpire($auth.step.Duration))]"
        }

        elseif ($auth.step -is [Authentication.Sync.PasswordStep]) {
            $prompt = "`nMaster Password"
        }
        elseif ($auth.step -is [Authentication.Sync.SsoTokenStep]) {
            $prompt = "`nSSO Token"
        }
        elseif ($auth.step -is [Authentication.Sync.SsoDataKeyStep]) {
            $prompt = "`nSSO Login Approval"
        }
        elseif ($auth.step -is [Authentication.Sync.ReadyToLoginStep]) {
            $prompt = "`nLogin"
        }
        elseif ($auth.step -is [Authentication.Sync.HttpProxyStep]) {
            $prompt = "`nHTTP Proxy Login"
        }

        return $prompt
    }

    [void]PrintStepHelp($auth) {
        $commands = @()
        if ($auth.step -is [Authentication.Sync.DeviceApprovalStep]) {
            $channels = @()
            foreach($ch in $auth.step.Channels) {
                $channels += $this.DeviceApprovalChannelToText($ch)
            }
            if ($channels) {
                $commands += "channel=<$($channels -join ' | ')> to change channel."
            }
            $commands += "`"push`" to send a push to the channel"
            $commands += '<code> to send a code to the channel'
        }
        elseif ($auth.step -is [Authentication.Sync.TwoFactorStep]) {
            $channels = @()
            foreach($ch in $auth.step.Channels) {
                $channelText = $this.TwoFactorChannelToText($ch)
                if ($channelText) {
                    $channels += $channelText
                }
            }
            if ($channels) {
                $commands += "channel=<$($channels -join ' | ')> to change channel."
            }

            $channels = @()
            foreach($ch in $auth.step.Channels) {
                $pushes = $auth.step.GetChannelPushActions($ch)
                if ($pushes -ne $null) {
                    foreach($push in $pushes) {
                        $channels += [Authentication.AuthUIExtensions]::GetPushActionText($push)
                    }
                }
            }
            if ($channels) {
                $commands += "`"$($channels -join ' | ')`" to send a push/code"
            }

            $channels = @()
            foreach($exp in $this.Expires) {
                $channels += $this.TwoFactorDurationToExpire($exp)
            }
            $commands += "expire=<$($channels -join ' | ')> to set 2fa expiration."
            $commands += '<code> to send a 2fa code.'
        }

        elseif ($auth.step -is [Authentication.Sync.PasswordStep]) {
            $commands += '<password> to send a master password.'
        }
        elseif ($auth.step -is [Authentication.Sync.SsoTokenStep]) {
            $commands += $auth.step.SsoLoginUrl
            $commands += ''
            if (-not $auth.step.LoginAsProvider) {
                $commands += '"password" to login using master password.'
            }
            $commands += '<sso token> paste SSO login token.'
        }
        elseif ($auth.step -is [Authentication.Sync.SsoDataKeyStep]) {
            $channels = @()
            foreach($ch in $auth.step.Channels) {
                $channels += [Authentication.AuthUIExtensions]::SsoDataKeyShareChannelText($ch)
            }
            if ($channels) {
                $commands += "`"$($channels -join ' | ')`" to request login approval"
            }
        }
        elseif ($auth.step -is [Authentication.Sync.ReadyToLoginStep]) {
            $commands += '"login <Keeper Email>" login to Keeper as user'
            $commands += '"login_sso <Enterprise Domain>" login to Enterprise Domain'
        }

        if ($commands) {
            Write-Host "`nAvailable Commands`n"
            foreach ($command in $commands) {
                Write-Host $command
            }
            Write-Host '<Enter> to resume'
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
        [Parameter()][string] $Password,
        [Parameter()][switch] $NewLogin,
        [Parameter(ParameterSetName='sso_password')][switch] $SsoPassword,
        [Parameter(ParameterSetName='sso_provider')][switch] $SsoProvider,
        [Parameter()][string] $Server
    )

    $_ = Disconnect-Keeper -Resume

	$storage = New-Object Configuration.JsonConfigurationStorage
    if (-not $Server) {
        $Server = $storage.LastServer
        if ($Server) {
            Write-Information -MessageData "`nUsing Keeper Server: $Server`n"
        } else {
            Write-Information -MessageData "`nUsing Default Keeper Server: $([Authentication.KeeperEndpoint]::DefaultKeeperServer)`n"
        }
    }
    

	$endpoint = New-Object Authentication.KeeperEndpoint($Server, $storage.Servers)
    $endpoint.DeviceName = 'PowerShell Commander'
    $authFlow = New-Object Authentication.Sync.AuthSync($storage, $endpoint)

    $authFlow.UiCallback = New-Object AuthFlowCallback
    $authFlow.UiCallback.ReadingInput = $false

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
        Write-Host "$(($namePrompt + ': ').PadLeft(21, ' ')) $Username"
    } else {
        while (-not $Username) {
            $Username = Read-Host -Prompt $namePrompt.PadLeft(20, ' ')
        }    
    }
    if ($SsoProvider.IsPresent) {
        $_ = $authFlow.LoginSso($Username).GetAwaiter().GetResult()
    } else {
        $passwords = @()
        if ($Password) {
            $passwords += $Password
        }
        $_ = $authFlow.Login($Username, $passwords).GetAwaiter().GetResult()
    }
    $lastState = $null
    Write-Output ""
    while(-not $authFlow.IsCompleted) {
        if ($lastStep -ne $authFlow.Step.State) {
            $authFlow.UiCallback.PrintStepHelp($authFlow)
            $lastStep = $authFlow.Step.State
        }

        $prompt = $authFlow.UiCallback.GetStepPrompt($authFlow)

        $authFlow.UiCallback.ReadingInput = $true
        if ($authFlow.Step -is [Authentication.Sync.PasswordStep]) {
            $securedPassword = Read-Host -Prompt $prompt -AsSecureString 
            if ($securedPassword.Length -gt 0) {
                $action = [Net.NetworkCredential]::new('',$securedPassword).Password
            } else {
                $action = ''
            }
        } 
        elseif ($authFlow.Step -is [Authentication.Sync.HttpProxyStep]) {
            $proxyUser = Read-Host -Prompt 'Proxy username'
            $securedPassword = Read-Host -Prompt 'Proxy password' -AsSecureString 
            if ($securedPassword.Length -gt 0) {
                $action = [Net.NetworkCredential]::new('',$securedPassword).Password
            }
            $action = "login `"$proxyUser`" `"$proxyPassword`""
        } else {
            $action = Read-Host -Prompt $prompt
        }
        $authFlow.UiCallback.ReadingInput = $false

        if ($action) {
            if ($action -eq '?') {
                $lastState = $null
            } else {
                $authFlow.UiCallback.ExecuteStepAction($authFlow, $action)
            }
        }
    }

    if ($authFlow.Step.State -ne [Authentication.Sync.AuthState]::Connected) {
        if ($authFlow.Step -is [Authentication.Sync.ErrorStep]) {
            Write-Host $authFlow.Step.Message -ForegroundColor Red
        }
        return
    }

    $auth = $authFlow
    if ([Authentication.AuthExtensions]::IsAuthenticated($auth)) {
        $Script:Auth = $auth
        Write-Debug -Message "Connected to Keeper as $Username"

        $Script:Vault = New-Object Vault.VaultOnline($auth)
        $task = $Script:Vault.SyncDown()
        Write-Information -MessageData 'Syncing ...'
        $_ = $task.GetAwaiter().GetResult()
        $Script:Vault.AutoSync = $true

        [Vault.VaultData]$vault = $Script:Vault
        $vault.VaultUi = New-Object VaultCallback
        Write-Information -MessageData "Decrypted $($vault.RecordCount) record(s)"
        $_ = Set-KeeperLocation -Path '\'
    }
}

$Keeper_ConfigServerCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $prefixes = @('', 'dev.', 'qa.')
    $suffixes = $('.com', '.eu')

    $prefixes | % { $p = $_; $suffixes | % {$s = $_; "${p}keepersecurity${s}" }} | Where {$_.StartsWith($wordToComplete)}
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

    $vault = $Script.Vault
    if ($vault -ne $null) {
        $_ = $vault.Dispose()
    }
    $Script:Vault = $null

    [Authentication.IAuthentication] $auth = $Script:Auth
    if ($auth -ne $null) {
        if (-not $Resume.IsPresent) {
            $_ = $auth.Logout().GetAwaiter().GetResult()
        }
        $_ = $auth.Dispose()

    }
    $Script:Auth = $null
}
New-Alias -Name kq -Value Disconnect-Keeper

function Sync-Keeper {
<#
    .Synopsis
    Sync down with Keeper
#>

    [CmdletBinding()]
    [Vault.VaultOnline]$vault = $Script:Vault
    if ($vault) {
        $task = $vault.SyncDown()
        $_ = $task.GetAwaiter().GetResult()
    } else {
        Write-Error -Message "Not connected"
    }
}
New-Alias -Name ks -Value Sync-Keeper

function Out-Keeper {
<#
    .Synopsis
    Get access to SDK Library classes

    .Parameter ObjectType
    Object Type 

#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)][ValidateSet('Vault' ,'Auth')][string] $ObjectType
    )
    switch ($ObjectType) {
        'Auth' { $Script:Auth }
        'Vault' { $Script:Vault }
    }
}

