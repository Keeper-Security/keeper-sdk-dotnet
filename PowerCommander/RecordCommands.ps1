#requires -Version 5.0

function Get-KeeperRecords {
<#
	.Synopsis
	Get Keeper Records

	.Parameter Uid
	Record UID

	.Parameter Filter
	Return matching records only

	.Parameter ShowPassword
	Display record password
#>
	[CmdletBinding()]
	[OutputType([KeeperSecurity.Vault.PasswordRecord[]])] 
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
		[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Vault
		if ($vault) {
			if ($Uid) {
				[KeeperSecurity.Vault.PasswordRecord] $record = $null
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

	.Parameter Field
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
				return
			}
			$Record = $Record[0]
		}

		[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
			return
		}

		$uid = $null
		if ($Record -is [String]) {
			$uid = $Record
		} 
		elseif ($null -ne $Record.Uid) {
			$uid = $Record.Uid
		}

		$found = $false
		if ($uid) {
			[KeeperSecurity.Vault.PasswordRecord] $rec = $null
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
		[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
			return
		}
		$totps = @()
	}

	Process {
		foreach ($r in $Records) {
			$uid = $null

			if ($r -is [String]) {
				$uid = $r
			} 
			elseif ($null -ne $r.Uid) {
				$uid = $r.Uid
			}
			if ($uid) {
				[KeeperSecurity.Vault.PasswordRecord] $rec = $null
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
			[Tuple[string, int, int]]$code = [Utils.CryptoUtils]::GetTotpCode($totps.TotpData)
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

	.Parameter UpdateOnly 
	Do not create a new record

	.Parameter Login
	Login field

	.Parameter Password
	Password field

	.Parameter GeneratePassword
	Generate random password

	.Parameter URL
	Website Address field

	.Parameter Custom
	Comma-separated list of key:value pairs. 
	Example: -Custom name1:value1,name2:value2

	.Parameter Notes
	Notes field

#>

	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param (
		[Parameter(Position = 0, Mandatory = $true)][string] $Title,
		[Parameter()][switch] $UpdateOnly,
		[Parameter()][string] $Login,
		[Parameter()][switch] $GeneratePassword,
		[Parameter()][string] $Password,
		[Parameter()][string] $URL,
		[Parameter()][string[]] $Custom,
		[Parameter()][string] $Notes
	)

	Begin {
		[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
			return
		}
        [KeeperSecurity.Vault.PasswordRecord]$record = $null
	}

	Process {
		$objs = Get-KeeperChildItems -ObjectType Record | Where-Object Name -eq $Title
		if ($objs.Length -eq 0 -and $UpdateOnly.IsPresent) {
            Write-Error -Message "Record `"$Title`" not found"
			return
		}
        if ($objs.Length -eq 0) {
            $record = New-Object KeeperSecurity.Vault.PasswordRecord
        }
        else {
            $record = Get-KeeperRecords -Uid $objs[0].UID
            if (-not $record) {
                Write-Error -Message "Record `"$Title`" not found"
				return
            }
        }
        
        if ($Notes) {
            if ($record.Notes) {
                $record.Notes += "`n"
            }
            $record.Notes += $Notes
        }

        if ($GeneratePassword.IsPresent) {
            if ($record.Password) {
                if ($record.Notes) {
                    $record.Notes += "`n"
                }
                $record.Notes += "Password generated on $(Get-Date)`nOld password: $($record.Password)`n"
            }
            $Password = [Utils.CryptoUtils]::GenerateUid()
        }

        if (-not $record.Uid) {
            $record.Title = $Title
        }
        if ($Login) {
            $record.Login = $Login
        }
        if ($Password) {
            $record.Password = $Password
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
		if ($record.Uid) {
	        $task = $vault.UpdateRecord($record)
		} else {
			$task = $vault.CreateRecord($record, $Script:CurrentFolder)
		}
		$task.GetAwaiter().GetResult()
    }
}
New-Alias -Name kadd -Value Add-KeeperRecord


function Remove-KeeperRecord {
<#
	.Synopsis
	Removes Keeper record.

	.Parameter Name
	Folder name or Folder UID
#>

	[CmdletBinding(DefaultParameterSetName = 'Default')]
	Param (
		[Parameter(Position = 0, Mandatory = $true)][string] $Name
	)

	[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Vault
	if (-not $vault) {
		Write-Error -Message 'Not connected'
		return
	}
	$folderUid = $null
	$recordUid = $null
	[KeeperSecurity.Vault.PasswordRecord] $record = $null
	if ($vault.TryGetRecord($Name, [ref]$record)) {
		$recordUid = $record.Uid
		if (-not $vault.RootFolder.Records.Contains($recordUid)) {
			foreach ($f in $vault.Folders) {
				if ($f.Records.Contains($recordUid)) {
					$folderUid = $f.FolderUid
					break
				}
			}
		}
	}
	if (-not $recordUid) {
		$objs = Get-KeeperChildItems -ObjectType Record | Where-Object Name -eq $Name
		if (-not $objs) {
			Write-Error -Message "Record `"$Name`" does not exist"
			return
		}
		if ($objs.Length -gt 1) {
			Write-Error -Message "There are more than one records with name `"$Name`". Use Record UID do delete the correct one."
			return
		}
		$recordUid = $objs[0].Uid
		$folderUid = $Script:CurrentFolder
	}

	$recordPath = New-Object KeeperSecurity.Vault.RecordPath
	$recordPath.RecordUid = $recordUid
	$recordPath.FolderUid = $folderUid
	$task = $vault.DeleteRecords(@($recordPath))
	$_ = $task.GetAwaiter().GetResult()
}
New-Alias -Name kdel -Value Remove-KeeperRecord

function Move-RecordToFolder {
<#
	.Synopsis
	Moves owned records to Folder.

	.Parameter Record
	Record UID, Title or any object containg property UID.

	.Parameter Folder 
	Folder Name, Path, or UID
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Records,
		[Parameter(Position = 0, Mandatory = $true)][string] $Folder,
		[Parameter()][switch] $Link
	)
	
	Begin {
		[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
			return
		}

		$folderUid = resolveFolderUid $vault $Folder
		[KeeperSecurity.Vault.FolderNode]$folderNode = $null
		$_ = $vault.TryGetFolder($folderUid, [ref]$folderNode)

		$sourceRecords = @()
	}

	Process {
		$recordUids = @{}
		foreach ($r in $Records) {
    		$uid = $null

			if ($r -is [String]) {
				$uid = $r
			} 
			elseif ($null -ne $r.Uid) {
				$uid = $r.Uid
			}
			if ($uid) {
				[KeeperSecurity.Vault.PasswordRecord] $rec = $null
				if ($vault.TryGetRecord($uid, [ref]$rec)) {
					if ($rec.Owner) {
						$recordUids[$rec.Uid] = $true
					}
				} else {
					$recs = Get-KeeperRecords -Filter $uid | Where-Object Title -eq $uid
					foreach ($rec in $recs) {
						if ($rec.Owner) {
							$recordUids[$rec.Uid] = $true
						}
					}
				}
			}
		}
		if ($recordUids.Count -gt 0) {
			foreach ($recordUid in $recordUids.Keys) {
				if ($folderNode.Records.Contains($recordUid)) {
					continue
				}
				$rp = New-Object KeeperSecurity.Vault.RecordPath 
				$rp.RecordUid = $recordUid
				if ($vault.RootFolder.Records.Contains($recordUid)) {
					$sourceRecords += $rp
				} else {
					foreach ($fol in $vault.Folders) {
						if ($fol.FolderUid -eq $folderUid) {
							continue
						}
						if ($fol.Records.Contains($recordUid)) {
							$rp.FolderUid = $fol.FolderUid
							$sourceRecords += $rp
							break
						}
					}
				}
			}
		}
	}
	End {
		$_ = $vault.MoveRecords($sourceRecords, $folderUid, $Link.IsPresent).GetAwaiter().GetResult()
	}
}
New-Alias -Name kmv -Value Move-RecordToFolder
<#
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
# TODO
Register-ArgumentCompleter -Command Move-RecordToFolder -ParameterName Folder -ScriptBlock $Keeper_SharedFolderNameCompleter
Register-ArgumentCompleter -Command Copy-RecordToFolder -ParameterName Folder -ScriptBlock $Keeper_SharedFolderNameCompleter
#>

function resolveFolderUid {
	Param ([KeeperSecurity.Vault.VaultOnline]$vault, $folder)

	[KeeperSecurity.Vault.FolderNode]$targetFolder = $null
	if ($vault.TryGetFolder($folder, [ref]$targetFolder)) {
		return $targetFolder.FolderUid
	}

	$fols = Get-KeeperChildItems -ObjectType Folder -Filter $folder
	if ($fols.Length -gt 0) {
		return $fols[0].Uid
	}

	$fols = @()
	foreach ($fol in $vault.Folders) {
		if ($fol.Name -eq $folder) {
			$fols += $fol.FolderUid
		}
	}
	if ($fols.Length -eq 1) {
		return $fols[0]
	}
	# TODO resolve folder full path
	Write-Error "Folder $($folder) not found"
}
