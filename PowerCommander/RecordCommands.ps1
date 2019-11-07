#requires -Version 5.0

using namespace KeeperSecurity.Sdk

function Get-KeeperRecords {
<#
	.Synopsis
	Get Keeper Records

	.Parameter Uid
	Record UID

	.Filter
	Return matching records only

	.ShowPassword
	Display record password
#>
	[CmdletBinding()]
	[OutputType([PasswordRecord[]])] 
	Param (
		[string] $Uid,
		[string] $Filter,
		[switch] $ShowPassword
	)
	Begin {
		if ($ShowPassword.IsPresent) {
			Set-KeeperPasswordVisible -Visible
		} else {
			Set-KeeperPasswordVisible
		}
	}

	Process {
		[Vault]$vault = $Script:Vault
		if ($vault) {
			if ($Uid) {
				[PasswordRecord] $record = $null
				if ($vault.TryGetRecord($uid, [ref]$record)) {
					$record
				}
			} else {
				foreach ($record in $vault.Records) {
					if ($Filter) {
						$match = $($record.Title, $record.Login, $record.Link, $record.Notes) | Select-String $Filter | Select -First 1
						if (-not $match) {
							continue
						}
					}
					$record
				}
			}
		} else {
			Write-Error -Message "Not connected"
		}
	}

	End {
		Set-KeeperPasswordVisible
	}
}
New-Alias -Name kr -Value Get-KeeperRecords


function Copy-KeeperToClipboard {
<#
	.Synopsis
	Copy record password to clipboard

	.Parameter Record
	Record UID or any object containg record UID

	.Field
	Record field to copy to clipboard. Record password is default.
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Record,
		[string] [ValidateSet('Login' ,'Password', 'WebAddress')] $Field = 'Password'
	)
	Process {
		if ($Record -is [Array]) {
			if ($Record.Count -ne 1) {
				Write-Error -Message 'Only one record is expected'
			}
			$Record = $Record[0]
		}

		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}

		$uid = $null
		if ($Record -is [String]) {
			$uid = $Record
		} 
		elseif ($Record.Uid -ne $null) {
			$uid = $Record.Uid
		}

		$found = $false
		if ($uid) {
			[PasswordRecord] $rec = $null
			if (-not $vault.TryGetRecord($uid, [ref]$rec)) {
				$entries = Get-KeeperChildItems -Filter $uid -ObjectType Record
				if ($entries.Uid) {
					$_ = $vault.TryGetRecord($entries[0].Uid, [ref]$rec)
				}
			}
			if ($rec) {
				$found = $true
				$value = ''
				switch($Field) {
					'Login' {$value = $rec.Login}
					'Password' {$value = $rec.Password}
					'WebAddress' {$value = $rec.Link}
				}
				if ($value) {
					Set-Clipboard -Value $value
					Write-Host "Copied to clipboard: $Field for $($rec.Title)"
				} else {
					Write-Host "Record $($rec.Title) has no $Field"
				}
			}
		} 
		if (-not $found) {
			Write-Error -Message "Cannot find a Keeper record: $Record"
		}
	}
}
New-Alias -Name kcc -Value Copy-KeeperToClipboard

function Get-KeeperPasswordVisible {
	if ($Script:PasswordVisible) {
		$true
	} else {
		$false
	}
}

function Set-KeeperPasswordVisible {
	[CmdletBinding()]
	Param ([switch] $Visible)
	$Script:PasswordVisible = $Visible.IsPresent
}