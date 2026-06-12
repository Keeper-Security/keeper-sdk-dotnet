#requires -Version 5.1

function Get-KeeperSharedFolder {
    <#
	.Synopsis
	Get Keeper Shared Folders

	.Parameter Uid
	Shared Folder UID

	.Parameter Filter
	Return matching shared folders only

	.Parameter RoeEligible
	If set, only return shared folders eligible for rotate-on-expiration (contain a pamUser
	record with rotation configured).
#>
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.SharedFolder[]])]
    Param (
        [string] $Uid,
        [string] $Filter,
        [switch] $RoeEligible
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    [KeeperSecurity.Vault.SharedFolder] $sharedFolder = $null
    if ($Uid) {
        if ($vault.TryGetSharedFolder($uid, [ref]$sharedFolder)) {
            if (-not $RoeEligible.IsPresent -or [KeeperSecurity.Vault.VaultShareExpirationExtensions]::SharedFolderHasPamUserWithRotation($vault, $sharedFolder.Uid)) {
                $sharedFolder
            }
        }
    }
    else {
        $folders = if ($RoeEligible.IsPresent) {
            [KeeperSecurity.Vault.VaultShareExpirationExtensions]::SearchRoeEligibleSharedFolders($vault, $Filter)
        } else {
            $vault.SharedFolders
        }
        foreach ($sharedFolder in $folders) {
            if ($Filter) {
                $match = $($sharedFolder.Uid, $sharedFolder.Name) | Select-String $Filter | Select-Object -First 1
                if (-not $match) {
                    continue
                }
            }
            $sharedFolder
        }
    }
}
New-Alias -Name ksf -Value Get-KeeperSharedFolder

<#
$Keeper_SharedFolderCompleter = {
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
    foreach ($sf in $vault.SharedFolders) {
        if ($sf.Name -like $toComplete) {
            $name = $sf.Name
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
#>