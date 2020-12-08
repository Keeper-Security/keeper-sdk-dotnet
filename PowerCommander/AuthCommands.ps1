#requires -Version 5.0

using namespace KeeperSecurity

class AuthFlowCallback : Authentication.IAuthFlowCallback {
    [bool]$ReadingInput = $false

    [void]OnMessage([string]$message) {
        Write-Information -MessageData $message
    }

    [void]OnNextStep() {
        if ($this.ReadingInput) {
            Write-Host "Press <Enter> to continue."
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

    [void]ExecuteStepAction($step, $action) {
        if ($step -is [Authentication.DeviceApprovalStep]) {
            if ($action -eq 'push') {
                $step.SendPush($step.DefaultChannel)
            }
            elseif ($action -match 'channel\s*=\s*(.*)') {
                $ch = $Matches.1
                [Authentication.DeviceApprovalChannel]$cha = $step.DefaultChannel
                if ($this.TryTextToDeviceApprovalChannel($ch, [ref]$cha)) {
                    $step.DefaultChannel = $cha
                }
            } else {
                $step.SencCode($action)
            }
        }
        elseif ($step -is [Authentication.TwoFactorStep]) {
            if ($action -match 'channel\s*=\s*(.*)') {
                $ch = $Matches.1
                [KeeperSecurity.Authentication.TwoFactorChannel]$cha = $step.DefaultChannel
                if ($this.TryTextToTwoFactorChannel($ch, [ref]$cha)) {
                    $step.DefaultChannel = $cha
                }
            }
            elseif ($action -match 'expire\s*=\s*(.*)') {
                $exp = $Matches.1
                [Authentication.TwoFactorDuration]$dur = $step.Duration
                if ($this.TryExpireToTwoFactorDuration($exp, [ref]$dur)) {
                    $step.Duration = $dur
                }
            } else {
                foreach($cha in $step.Channels) {
                    $pushes = $step.GetChannelPushActions($cha)
                    if ($pushes -ne $null) {
                        foreach($push in $pushes) {
                            if ($action -eq [Authentication.AuthUIExtensions]::GetPushActionText($push)) {
                                $step.SendPush($push)
                                return
                            }
                        }
                    }
                    Try {
                        $step.SendCode($step.DefaultChannel, $action)
                    }
                    Catch {
                        Write-Host $_ -ForegroundColor Red
                    }
                }
            }
        }
        elseif ($step -is [Authentication.PasswordStep]) {
            Try {
                $step.VerifyPassword($action);
            }
            Catch [KeeperSecurity.Authentication.KeeperAuthFailed]{
                Write-Host 'Invalid password' -ForegroundColor Red
            }
            Catch {
                Write-Host $_ -ForegroundColor Red
            }
        }
    }

    [string]GetStepPrompt($step) {
        $prompt = '?'
        if ($step -is [Authentication.DeviceApprovalStep]) {
            $prompt = "`nDevice Approval ($($this.DeviceApprovalChannelToText($step.DefaultChannel)))"
        }
        elseif ($step -is [Authentication.TwoFactorStep]) {
            $channelText = $this.TwoFactorChannelToText($step.DefaultChannel)
            $prompt = "`n2FA channel($($channelText)) expire[$($this.TwoFactorDurationToExpire($step.Duration))]"
        }

        elseif ($step -is [Authentication.PasswordStep]) {
            $prompt = "`nMaster Password"
        }
        return $prompt
    }

    [void]PrintStepHelp($step) {
        $commands = @()
        if ($step -is [Authentication.DeviceApprovalStep]) {
            $channels = @()
            foreach($ch in $step.Channels) {
                $channels += $this.DeviceApprovalChannelToText($ch)
            }
            if ($channels) {
                $commands += "channel=<$($channels -join ' | ')> to change channel."
            }
            $commands += "`"push`" to send a push to the channel"
            $commands += '<code> to send a code to the channel'
        }
        elseif ($step -is [Authentication.TwoFactorStep]) {
            $channels = @()
            foreach($ch in $step.Channels) {
                $channelText = $this.TwoFactorChannelToText($ch)
                if ($channelText) {
                    $channels += $channelText
                }
            }
            if ($channels) {
                $commands += "channel=<$($channels -join ' | ')> to change channel."
            }

            $channels = @()
            foreach($ch in $step.Channels) {
                $pushes = $step.GetChannelPushActions($ch)
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

        elseif ($step -is [Authentication.PasswordStep]) {
            $commands += '<password> to send a master password.'
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

    .Parameter Server
    Change default keeper server
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)][string] $Username,
        [Parameter()][switch] $NewLogin,
        [Parameter()][string] $Server
    )

    $_ = Disconnect-Keeper -Resume

	$storage = New-Object Configuration.JsonConfigurationStorage
    if ($Server) {
        Write-Debug "Using Keeper Server: $Server"
    } else {
        $Server = $storage.LastServer
    }
	$endpoint = New-Object Authentication.KeeperEndpoint($Server, $storage.Servers)
    $authFlow = New-Object Authentication.AuthSyncFlow($storage, $endpoint)

    $authFlow.UiCallback = New-Object AuthFlowCallback
    $authFlow.Step.ResumeSession = $true

    if (-not $NewLogin.IsPresent) {
        if (-not $Username) {
            $Username = $storage.LastLogin
        }
    }

    if ($Username) {
        Write-Host "$('Keeper Username:'.PadLeft(21, ' ')) $Username"
    } else {
        while (-not $Username) {
            $Username = Read-Host -Prompt 'Keeper Username'.PadLeft(20, ' ')
        }    
    }

    $_ = $authFlow.Step.Login($Username)
    $lastState = $null
    while(-not $authFlow.IsCompleted) {
        if ($lastStep -ne $authFlow.Step.State) {
            $authFlow.UiCallback.PrintStepHelp($authFlow.Step)
            $lastStep = $authFlow.Step.State
        }

        $prompt = $authFlow.UiCallback.GetStepPrompt($authFlow.Step)

        $authFlow.UiCallback.ReadingInput = $true
        if ($authFlow.Step -is [Authentication.PasswordStep]) {
            $securedPassword = Read-Host -Prompt $prompt -AsSecureString 
            if ($securedPassword.Length -gt 0) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedPassword)
			    $action = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            } else {
                $action = ''
            }
        } else {
            $action = Read-Host -Prompt $prompt
        }
        $authFlow.UiCallback.ReadingInput = $false

        if ($action) {
            if ($action -eq '?') {
                $lastState = $null
            } else {
                $authFlow.UiCallback.ExecuteStepAction($authFlow.Step, $action)
            }
        }
    }

    if ($authFlow.Step.State -ne [Authentication.AuthState]::Connected) {
        if ($authFlow.Step -is [Authentication.ErrorStep]) {
            Write-Host $authFlow.Step.Message -ForegroundColor Red
        }
        return
    }

    $auth = $authFlow.Auth
    if ([Authentication.AuthExtensions]::IsAuthenticated($auth)) {
        $Script:Auth = $auth
        Write-Debug -Message "Connected to Keeper as $Username"

        $Script:Vault = New-Object Vault.VaultOnline($auth)
        $task = $Script:Vault.SyncDown()
        Write-Information -MessageData 'Syncing ...'
        $_ = $task.GetAwaiter().GetResult()
        $Script:Vault.AutoSync = $true

        [Vault.VaultData]$vault = $Script:Vault
        Write-Information -MessageData "Decrypted $($vault.RecordCount) record(s)"
        $_ = Set-KeeperLocation -Path '\'
    }
}

$Keeper_ConfigUsernameCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    [Authentication.Auth] $auth = $Script:Auth
    [Configuration.IConfigurationStorage]$storage = $auth.Storage
    [Configuration.IConfiguration]$config = $storage.Get()
    $config.Users | Select-Object -ExpandProperty Username | Where {$_.StartsWith($wordToComplete)}
}
Register-ArgumentCompleter -Command Connect-Keeper -ParameterName Username -ScriptBlock $Keeper_ConfigUsernameCompleter

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

    [Authentication.Auth] $auth = $Script:Auth
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

