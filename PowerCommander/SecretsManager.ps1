#requires -Version 5.0

$Keeper_KSMAppCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [KeeperSecurity.Vault.VaultOnline]$private:vault = getVault
    if (-not $vault) {
        return $null
    }

    $toComplete = $wordToComplete
    if ($toComplete.Length -ge 1) {
        if ($toComplete[0] -eq '''') {
            $toComplete = $toComplete.Substring(1, $toComplete.Length - 1)
            $toComplete = $toComplete -replace '''''', ''''
        }
        if ($toComplete[0] -eq '"') {
            $toComplete = $toComplete.Substring(1, $toComplete.Length - 1)
            $toComplete = $toComplete -replace '""', '"'
            $toComplete = $toComplete -replace '`"', '"'
        }
    }

    $toComplete += '*'
    foreach ($app in $vault.KeeperApplications) {
        if ($app.Title -like $toComplete) {
            $name = $app.Title
            if ($name -match ' ') {
                $name = $name -replace '''', ''''''
                $name = '''' + $name + ''''
            }
            $result += $name
        }
    }

    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Get-KeeperSecretManagerApps {
    <#
        .Synopsis
        Get Keeper Secret Manager Applications
    
        .Parameter Uid
        Record UID
    
        .Parameter Filter
        Return matching applications only

        .Parameter Detail
        Application details
    #>
    [CmdletBinding()]
    Param (
        [string] $Uid,
        [string] $Filter,
        [Switch] $Detail
    )
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if ($Uid) {
        [KeeperSecurity.Vault.ApplicationRecord] $application = $null
        if ($vault.TryGetKeeperApplication($uid, [ref]$application)) {
            if ($Detail.IsPresent) {
                $vault.GetSecretManagerApplication($application.Uid, $false).GetAwaiter().GetResult()
            }
            else {
                $application
            }
        }
    }
    else {
        foreach ($application in $vault.KeeperApplications) {
            if ($Filter) {
                $match = $($application.Uid, $application.Title) | Select-String $Filter | Select-Object -First 1
                if (-not $match) {
                    continue
                }
            }
            if ($Detail.IsPresent) {
                $vault.GetSecretManagerApplication($application.Uid, $false).GetAwaiter().GetResult()
            }
            else {
                $application
            }
        }
    }
}
New-Alias -Name ksm -Value Get-KeeperSecretManagerApps
    
function New-KeeperSecretManagerApp {
    <#
        .Synopsis
        Creates Keeper Secret Manager Application
    
        .Parameter Name
        Secret Manager Application
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string]$AppName
    )
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $vault.CreateSecretManagerApplication($AppName).GetAwaiter().GetResult()
}
New-Alias -Name ksm-create -Value New-KeeperSecretManagerApp

function Grant-KeeperSecretManagerFolderAccess {
    <#
        .Synopsis
        Adds shared folder to KSM Application
    
        .Parameter App
       KSM Application UID or Title

        .Parameter Secret
       Shared Folder UID or Name

        .Parameter CanEdit
        Enable write access to shared secrets

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter()][switch]$CanEdit
    )
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApps -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    [string]$uid = $null
    $sfs = Get-KeeperSharedFolders -Filter $Secret
    if ($sfs) {
        $uid = $sfs[0].Uid
    }
    else {
        $recs = Get-KeeperRecords -Filter $Secret
        if ($recs) {
            $uid = $recs[0].Uid
        }
    }
    if (-not $uid) {
        Write-Error -Message "Cannot find Shared Folder: $Secret" -ErrorAction Stop
    }
    $vault.ShareToSecretManagerApplication($application.Uid, $uid, $CanEdit.IsPresent).GetAwaiter().GetResult()
}
Register-ArgumentCompleter -CommandName Grant-KeeperSecretManagerFolderAccess -ParameterName Secret -ScriptBlock $Keeper_SharedFolderCompleter
Register-ArgumentCompleter -CommandName Grant-KeeperSecretManagerFolderAccess -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-share -Value Grant-KeeperSecretManagerFolderAccess

function Revoke-KeeperSecretManagerFolderAccess {
    <#
        .Synopsis
        Removes Shared Folder from KSM Application
    
        .Parameter App
        Secret Manager Application

        .Parameter Secret
       Shared Folder UID or Name
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter(Mandatory = $true)][string]$Secret
    )
    
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApps -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    [string]$uid = $null
    $sfs = Get-KeeperSharedFolders -Filter $Secret
    if ($sfs) {
        $uid = $sfs[0].Uid
    }
    else {
        $recs = Get-KeeperRecords -Filter $Secret
        if ($recs) {
            $uid = $recs[0].Uid
        }
    }
    if (-not $uid) {
        Write-Error -Message "Cannot find Shared Folder: $Secret" -ErrorAction Stop
    }
    $vault.UnshareFromSecretManagerApplication($application.Uid, $uid).GetAwaiter().GetResult()
}
Register-ArgumentCompleter -CommandName Revoke-KeeperSecretManagerFolderAccess -ParameterName Secret -ScriptBlock $Keeper_SharedFolderCompleter
Register-ArgumentCompleter -CommandName Revoke-KeeperSecretManagerFolderAccess -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-unshare -Value Revoke-KeeperSecretManagerFolderAccess
