#requires -Version 5.0

using namespace KeeperSecurity.Sdk

function Get-KeeperSharedFolders {
<#
	.Synopsis
	Get Keeper Shared Folders

	.Parameter Uid
	Shared Folder UID

	.Parameter Filter
	Return matching shared folders only
#>
	[CmdletBinding()]
	[OutputType([Vault.SharedFolder[]])] 
	Param (
		[string] $Uid,
		[string] $Filter
	)
	Begin {
	}

	Process {
		[Vault.VaultOnline]$vault = $Script:Vault
		if ($vault) {
			[Vault.SharedFolder] $sharedFolder = $null
			if ($Uid) {
				if ($vault.TryGetSharedFolder($uid, [ref]$sharedFolder)) {
					$sharedFolder
				}
			} else {
				foreach ($sharedFolder in $vault.SharedFolders) {
					if ($Filter) {
						$match = $($record.Uid, $sharedFolder.Name) | Select-String $Filter | Select-Object -First 1
						if (-not $match) {
							continue
						}
					}
					$sharedFolder
				}
			}
		} else {
			Write-Error -Message "Not connected"
		}
	}

	End {
	}
}
New-Alias -Name ksf -Value Get-KeeperSharedFolders
