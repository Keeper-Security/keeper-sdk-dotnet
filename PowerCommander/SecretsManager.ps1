#requires -Version 5.1

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

function Get-KeeperSecretManagerApp {
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
        if ($vault.TryGetKeeperRecord($Uid, [ref]$application)) {
            if (-not $application.Type -eq 'app') {
                throw "No application found with UID '$Uid'."
            }
            if ($Detail.IsPresent) {
                return $vault.GetSecretManagerApplication($application.Uid, $false).GetAwaiter().GetResult()
            } else {
                return $application
            }
        } else {
            throw "No application found with UID '$Uid'."
        }
    }
    else {
        $applications = $vault.KeeperRecords | Where-Object { $_.Type -eq 'app' }
        $results = @()

        foreach ($application in $applications) {
            if ($Filter) {
                $match = @($application.Uid, $application.Title) | Select-String $Filter | Select-Object -First 1
                if (-not $match) {
                    continue
                }
            }
            if ($Detail.IsPresent) {
                $results += $vault.GetSecretManagerApplication($application.Uid, $false).GetAwaiter().GetResult()
            }
            else {
                $results += $application
            }
        }
        return $results
    }
}
New-Alias -Name ksm -Value Get-KeeperSecretManagerApp

function Add-KeeperSecretManagerApp {
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
New-Alias -Name ksm-create -Value Add-KeeperSecretManagerApp

function Remove-KeeperSecretManagerApp {
    <#
        .SYNOPSIS
        Deletes a Keeper Secret Manager Application

        .DESCRIPTION
        This cmdlet deletes a Keeper Secrets Manager application by UID.

        .PARAMETER Uid
        The UID of the application to delete.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Uid
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if ($PSCmdlet.ShouldProcess("Secrets Manager App UID: $Uid", "Delete")) {
        $vault.DeleteSecretManagerApplication($Uid).GetAwaiter().GetResult()
        Write-Host "Secrets Manager Application with UID '$Uid' has been deleted." -ForegroundColor Green
    }
}
New-Alias -Name ksm-delete -Value Remove-KeeperSecretManagerApp

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
    $apps = Get-KeeperSecretManagerApp -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    [string]$uid = $null
    $sfs = Get-KeeperSharedFolder -Filter $Secret
    if ($sfs) {
        $uid = $sfs[0].Uid
    }
    else {
        $recs = Get-KeeperRecord -Filter $Secret
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
    $apps = Get-KeeperSecretManagerApp -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    [string]$uid = $null
    $sfs = Get-KeeperSharedFolder -Filter $Secret
    if ($sfs) {
        $uid = $sfs[0].Uid
    }
    else {
        $recs = Get-KeeperRecord -Filter $Secret
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

function Add-KeeperSecretManagerClient {
    <#
        .Synopsis
        Adds client/device to KSM Application

        .Parameter App
        KSM Application UID or Title

        .Parameter Name
        Client or Device Name

        .Parameter UnlockIP
        Enable write access to shared secrets
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter()][string]$Name,
        [Parameter()][switch]$UnlockIP,
        [Parameter()][switch]$B64
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApp -Filter $App
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    $rs = $vault.AddSecretManagerClient($application.Uid, $UnlockIP.IsPresent, $null, $null, $name).GetAwaiter().GetResult()
    if ($rs) {
        if ($B64.IsPresent) {
            $configuration = $vault.GetConfiguration($rs.Item2).GetAwaiter().GetResult()
            if ($configuration) {
                $configData = [KeeperSecurity.Utils.JsonUtils]::DumpJson($configuration, $true)
                [System.Convert]::ToBase64String($configData)
        
            }
        } else {
            $rs.Item2
        }
    
    }
}
Register-ArgumentCompleter -CommandName Add-KeeperSecretManagerClient -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-addclient -Value Add-KeeperSecretManagerClient

function Remove-KeeperSecretManagerClient {
    <#
        .Synopsis
        Removes client/device from KSM Application

        .Parameter App
        KSM Application UID or Title

        .Parameter Name
        Client Id or Device Name

    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter(Mandatory = $true)][string]$App,
        [Parameter(Mandatory = $true)][string]$Name
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $apps = Get-KeeperSecretManagerApp -Filter $App -Detail
    if (-not $apps) {
        Write-Error -Message "Cannot find Secret Manager Application: $App" -ErrorAction Stop
    }
    [KeeperSecurity.Vault.ApplicationRecord]$application = $apps[0]

    $device = $application.Devices | Where-Object { $_.Name -ceq $Name -or $_.ShortDeviceId -ceq $Name }
    if (-not $device) {
        Write-Error -Message "Cannot find Device: $Name" -ErrorAction Stop
    }

    if ($PSCmdlet.ShouldProcess($application.Title, "Removing KSM Device '$($device.Name)'")) {
        $vault.DeleteSecretManagerClient($application.Uid, $device.DeviceId).GetAwaiter().GetResult() | Out-Null
        Write-Information -MessageData "Device $($device.Name) has been deleted from KSM application `"$($application.Title)`"."
    }
}

Register-ArgumentCompleter -CommandName Remove-KeeperSecretManagerClient -ParameterName App -ScriptBlock $Keeper_KSMAppCompleter
New-Alias -Name ksm-rmclient -Value Remove-KeeperSecretManagerClient
