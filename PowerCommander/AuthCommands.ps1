#requires -Version 5.0

using namespace KeeperSecurity.Sdk

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

    .Parameter Server
    Change default keeper server
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)][string] $Username,
        [Parameter(Position = 1)][string] $Password,
        [Parameter()][switch] $NewLogin,
        [Parameter()][string] $Server
    )

    [Auth]$auth = $Script:Auth

    if (-not $NewLogin.IsPresent) {
        if (-not $Username) {
            [IConfigurationStorage]$storage = $auth.Storage
            $Username = $storage.LastLogin
            if ($Username) {
                [IConfigCollection[IUserConfiguration]]$userStorage = $storage.Users
                [IUserConfiguration]$userConfig = $userStorage.Get($Username)
                if ($userConfig) {
                    $Password = $userConfig.Password
                }
            }
        }
    }

    if ($Username) {
        if ($Password) {
            Write-Information -MessageData "Auto login as $Username"
        } else {
            Write-Host "$('Keeper Username:'.PadLeft(21, ' ')) $Username"
        }
    }
    else {
        $Password = ''
        while (-not $Username) {
            $Username = Read-Host -Prompt 'Keeper Username'.PadLeft(20, ' ')
        }
    }

    $_ = Disconnect-Keeper

    if ($Server) {
        Write-Debug "Using Keeper Server: $Server"
        $auth.Endpoint.Server = $Server
    }
    $auth.ResumeSession = $true
    $task = $auth.Login($Username, $Password)
    $_ = $task.GetAwaiter().GetResult()
    if ([AuthUtils]::IsAuthenticated($auth)) {
        Write-Debug -Message "Connected to Keeper as $Username"

        $Script:Vault = New-Object KeeperSecurity.Sdk.Vault($auth)
        $task = [KeeperSecurity.Sdk.SyncDownExtension]::SyncDown($Script:Vault)
        Write-Information -MessageData 'Syncing ...'
        $_ = $task.GetAwaiter().GetResult()
        [KeeperSecurity.Sdk.VaultData]$vault = $Script:Vault
        Write-Information -MessageData "Decrypted $($vault.RecordCount) record(s)"
    }
}

$Keeper_ConfigUsernameCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    [Auth] $auth = $Script:Auth
    [IConfigurationStorage]$storage = $auth.Storage
    [IConfiguration]$config = $storage.Get()
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
    $Script:Vault = $null

    [KeeperSecurity.Sdk.Auth] $auth = $Script:Auth
    $_ = $auth.Logout()
}
New-Alias -Name kq -Value Disconnect-Keeper

function Sync-Keeper {
<#
    .Synopsis
    Sync down with Keeper
#>

    [CmdletBinding()]
    [KeeperSecurity.Sdk.Vault]$vault = $Script:Vault
    if ($vault) {
        $task = [KeeperSecurity.Sdk.SyncDownExtension]::SyncDown($vault)
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

