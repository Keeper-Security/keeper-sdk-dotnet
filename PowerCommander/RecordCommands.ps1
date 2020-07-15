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
						$match = $($record.Title, $record.Login, $record.Link, $record.Notes) | Select-String $Filter | Select-Object -First 1
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

function Show-TwoFactorCode {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Records
	)

	Begin {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}
		$totps = @()
	}

	Process {
		foreach ($r in $Records) {
			$uid = $null

			if ($r -is [String]) {
				$uid = $r
			} 
			elseif ($r.Uid -ne $null) {
				$uid = $r.Uid
			}
			if ($uid) {
				[PasswordRecord] $rec = $null
				if ($vault.TryGetRecord($uid, [ref]$rec)) {
					if ($rec.ExtraFields) {
						foreach ($ef in $rec.ExtraFields) {
							if ($ef.FieldType -eq 'totp') {
								$totps += [PSCustomObject]@{
									RecordUid    = $rec.Uid
									Title        = $rec.Title
									TotpType     = $ef.Custom['type']
									TotpData     = $ef.Custom['data']
								}
							}
						}
					}
				}
			}
		}
	}
	End {
		$output = @()
		foreach ($totp in $totps) {
			[Tuple[string, int, int]]$code = [CryptoUtils]::GetTotpCode($totps.TotpData)
			if ($code) {
				$output += [PSCustomObject]@{
					PSTypeName   = 'TOTP.Codes'
					RecordTitle  = $totp.Title
					TOTPCode     = $code.Item1
					Elapsed      = $code.Item2
					Left         = $code.Item3 - $code.Item2
				}
			}
		}
		$output | Format-Table
	}
}

New-Alias -Name 2fa -Value Show-TwoFactorCode

function Add-KeeperRecord {
<#
	.Synopsis
	Creates or Modifies a Keeper record in the current folder.

	.Parameter Title
	Title field

	.UpdateOnly 
	Do not create a new record

	.Login
	Login field

	.Password
	Password field

	.GeneratePassword
	Generate random password

	.URL
	Website Address field

	.Custom
	Comma-separated list of key:value pairs. 
	Example: -Custom "name1:value1, name2:value2"

	.Notes
	Notes field

#>

	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param (
		[Parameter(Position = 0, Mandatory = $true)][string] $Title,
		[Parameter()][switch] $UpdateOnly,
		[Parameter()][string] $Login,
		[Parameter()][switch] $GeneratePassword,
		[Parameter()][securestring] $Password,
		[Parameter()][string] $URL,
		[Parameter()][string[]] $Custom,
		[Parameter()][string] $Notes
	)

	Begin {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}
        [PasswordRecord]$record = $null
	}

	Process {
		$objs = Get-KeeperChildItems -ObjectType Record | where Name -eq $Title
		if ($objs.Length -eq 0 -and $UpdateOnly.IsPresent) {
            Write-Error -Message "Record `"$Title`" not found"
		}
        if ($objs.Length -eq 0) {
            $record = New-Object PasswordRecord
        }
        else {
            $record = Get-KeeperRecords -Uid $objs[0].UID
            if (-not $record) {
                Write-Error -Message "Record `"$Title`" not found"
            }
        }
        
        if ($Notes) {
            if ($record.Notes) {
                $record.Notes += "`n"
            }
            $record.Notes += $Notes
        }

        [string]$PlainPassword = ''
        if ($GeneratePassword.IsPresent) {
            if ($record.Password) {
                if ($record.Notes) {
                    $record.Notes += "`n"
                }
                $record.Notes += "Password generated on $(Get-Date)`nOld password: $($record.Password)`n"
            }
            $PlainPassword = [CryptoUtils]::GenerateUid()
        }
        elseif ($Password) {
        	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        	$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }

        if (-not $record.Uid) {
            $record.Title = $Title
        }
        if ($Login) {
            $record.Login = $Login
        }
        if ($PlainPassword) {
            $record.Password = $PlainPassword
        }
        if ($URL) {
            $record.Link = $URL
        }
        if ($Custom) {
            foreach($customField in $Custom) {
                $pos = $customField.IndexOf(':')
                if ($pos -gt 0 -and $pos -lt $customField.Length) {
                    $_ = $record.SetCustomField($customField.Substring(0, $pos), $customField.Substring($pos + 1))
                }
            }
        }
	}
    End {
        $_ = $vault.PutRecord($record).GetAwaiter().GetResult()
    }
}
New-Alias -Name kadd -Value Add-KeeperRecord

function Move-RecordToSharedFolder {
<#
	.Synopsis
	Moves owned records to Shared Folder.

	.Parameter Record
	Record UID, Title or any object containg property UID

	.UpdateOnly 
	Do not create a new record
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Records,
		[Parameter(Position = 0, Mandatory = $true)][string] $SharedFolder
	)

	Begin {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}
        $sourceRecords = @{}
		[SharedFolder]$targetFolder = $null
		if (-not $vault.TryGetSharedFolder($SharedFolder, [ref]$targetFolder)) {
			$fols = Get-KeeperSharedFolders -Filter $SharedFolder | Where-Object Name -eq $SharedFolder
			if ($fols.Length -eq 1) {
				$targetFolder = $fols[0]
			}
			elseif ($fols.Length -gt 1) {
				Write-Error -Message "There are more than one shared folders `"$($SharedFolder)`""
			}
		}
		if ($targetFolder -eq $null) {
			Write-Error -Message "Shared Folder `"$($SharedFolder)`" not found"
		}
	}

	Process {
		foreach ($r in $Records) {
    		$uid = $null

			if ($r -is [String]) {
				$uid = $r
			} 
			elseif ($r.Uid -ne $null) {
				$uid = $r.Uid
			}
			if ($uid) {
				[PasswordRecord] $rec = $null
				if ($vault.TryGetRecord($uid, [ref]$rec)) {
					if ($rec.Owner) {
	                    $sourceRecords[$rec.Uid] = $rec
					}
				} else {
					$recs = Get-KeeperRecords -Filter $uid | Where-Object Title -eq $uid
					foreach ($rec in $recs) {
						if ($rec.Owner) {
		                    $sourceRecords[$rec.Uid] = $rec
						}
					}
                }
            }
        }
	}

    End {
        if ($sourceRecords.Count -gt 0) {




			[SharedFolderUpdateCommand]$command = New-Object SharedFolderUpdateCommand
			$command.operation = 'update'
			$command.SharedFolderUid = $targetFolder.Uid
			$command.forceUpdate = $true
			$perm = $vault.ResolveSharedFolderAccessPath($command, $false, $ftrue)
			if ($perm) {
				$addRecords = @()
				foreach ($rec in $sourceRecords.Values) {
					$ur = New-Object SharedFolderUpdateRecord
					$ur.RecordUid = $rec.Uid
					$encKey = [CryptoUtils]::EncryptAesV1($rec.RecordKey, $targetFolder.SharedFolderKey)
					$ur.CanEdit = $targetFolder.DefaultCanEdit
					$ur.CanShare = $targetFolder.DefaultCanShare
					$ur.RecordKey = [CryptoUtils]::Base64UrlEncode($encKey)
					$addRecords += $ur
				}
				$command.addRecords = $addRecords
				$t = $vault.Auth.ExecuteAuthCommand($command, [SharedFolderUpdateResponse], $true)
				$rs = $t.GetAwaiter().GetResult()
				if ($rs.addRecords) {
					$recordsAdded = 0
					foreach ($status in $rs.addRecords) {
						if ($status.Status -eq 'success') {
							$recordsAdded++
						} else {
							Write-Information -MessageData "Shared Folder UID / Record UID  ($($command.SharedFolderUid) / $($status.RecordUid)) error: ($($status.Status))"
						}
					}
					if ($recordsAdded -gt 0) {
						$info = "Shared Folder '$($sharedFolder.Name)'. Added $($recordsAdded) records"
						Write-Information -MessageData $info
					}
				}
			} else {
				Write-Information "You don't have permissions on Shared Folder ($($targetFolder.Name)) ($($targetFolder.Uid))"
				return
			}
        } else {
			Write-Output -MessageData "No records"
		}
    }
}
New-Alias -Name kmv -Value Move-RecordToSharedFolder

$Keeper_SharedFolderNameCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

	Get-KeeperSharedFolders -Filter $wordToComplete `
        | ForEach-Object -MemberName Name `
        | Sort-Object `
        | ForEach-Object { 
            if ($_.Contains(' ')) {
                "'$($_)'"
            } else {
                $_
            }
        }
}
Register-ArgumentCompleter -Command Move-RecordToSharedFolder -ParameterName SharedFolder -ScriptBlock $Keeper_SharedFolderNameCompleter
