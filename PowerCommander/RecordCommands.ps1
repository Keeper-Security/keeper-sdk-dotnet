#requires -Version 5.0

using namespace KeeperSecurity.Sdk

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
		elseif ($null -ne $Record.Uid) {
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
			elseif ($null -ne $r.Uid) {
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
	Example: -Custom "name1:value1, name2:value2"

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

        if ($GeneratePassword.IsPresent) {
            if ($record.Password) {
                if ($record.Notes) {
                    $record.Notes += "`n"
                }
                $record.Notes += "Password generated on $(Get-Date)`nOld password: $($record.Password)`n"
            }
            $Password = [CryptoUtils]::GenerateUid()
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
        $_ = $vault.PutRecord($record).GetAwaiter().GetResult()
		$_ = $vault.TryGetRecord($record.Uid, [ref]$record)
		$record
    }
}
New-Alias -Name kadd -Value Add-KeeperRecord

function Move-RecordToSharedFolder {
<#
	.Synopsis
	Moves owned records to Shared Folder.

	.Parameter Record
	Record UID, Title or any object containg property UID

	.Parameter SharedFolder 
	Shared Folder name

	.Parameter CanShare 
	Grant re-share permission. 

	.Parameter CanEdit 
	Grant edit permission. 
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Records,
		[Parameter(Position = 0, Mandatory = $true)][string] $SharedFolder,
		[Parameter()][ValidateSet('Yes' ,'No')][string] $CanShare,
		[Parameter()][ValidateSet('Yes' ,'No')] $CanEdit
	)
	
	Begin {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}
		$sourceRecords = @{}
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
		$_ = keeperRecordMoveCommand -sharedFolder:$SharedFolder -records:$sourceRecords.Values -canShare$:CanShare -canEdit:$CanEdit -isLink:$false
	}
}
New-Alias -Name kmv -Value Move-RecordToSharedFolder

function Copy-RecordToSharedFolder {
<#
	.Synopsis
	Copies owned records to Shared Folder.

	.Parameter Record
	Record UID, Title or any object containg property UID

	.Parameter SharedFolder 
	Shared Folder name

	.Parameter CanShare 
	Grant re-share permission. 

	.Parameter CanEdit 
	Grant edit permission. 
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Records,
		[Parameter(Position = 0, Mandatory = $true)][string] $SharedFolder,
		[Parameter()][ValidateSet('Yes' ,'No')][string] $CanShare,
		[Parameter()][ValidateSet('Yes' ,'No')] $CanEdit
	)
	
	Begin {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}
		$sourceRecords = @{}
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
		$_ = keeperRecordMoveCommand -sharedFolder:$SharedFolder -records:$sourceRecords.Values -canShare$:CanShare -canEdit:$CanEdit -isLink:$true
	}
}
New-Alias -Name kcp -Value Copy-RecordToSharedFolder

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
Register-ArgumentCompleter -Command Copy-RecordToSharedFolder -ParameterName SharedFolder -ScriptBlock $Keeper_SharedFolderNameCompleter


function keeperRecordMoveCommand {
	Param (
		[string]$sharedFolder, 
		[PasswordRecord[]]$records, 
		[string]$canShare,
		[string]$canEdit,
		[bool]$isLink
	)

	[Vault]$vault = $Script:Vault
	if (-not $vault) {
		Write-Error -Message 'Not connected'		
	}
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

	$er = @{}
	if ($targetFolder.RecordPermissions) {
		foreach ($rp in $targetFolder.RecordPermissions) {
			$er[$rp.RecordUid] = $true
		}
	}

    $sourceRecords = @{}
	foreach ($r in $records) {
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

    if ($sourceRecords.Count -gt 0) {
		[MoveCommand]$command = New-Object MoveCommand
		$command.toType = 'shared_folder'
		$command.toUid = $targetFolder.Uid
		$command.isLink = $isLink

		$moveObjects = @()
		$transitionObjects = @()

		$sfKey = $targetFolder.SharedFolderKey
		[PasswordRecord]$rec = $null
		[FolderNode]$folder = $null
		foreach ($rec in $sourceRecords.Values) {
			if ($er.ContainsKey($rec.Uid)) {
				continue
			}
			$folder = $null
			foreach ($rid in $vault.RootFolder.Records) {
				if ($rid -eq $rec.Uid) {
					$folder = $vault.RootFolder
					break
				}
			}
			if ($folder -eq $null) {
				foreach ($f in $vault.Folders) {
					if ($f.FolderUid -eq $targetFolder.Uid) {
						continue
					}
					foreach ($rid in $f.Records) {
						if ($rid -eq $rec.Uid) {
							$folder = $f
							break
						}
					}
					if ($folder) {
						if ($folder.FolderType -eq [FolderType]::UserFolder) {
							break
						}
					}
				}
			}
			if ($folder -eq $null) {
				continue
			}
			$mo = New-Object MoveObject
			$mo.type = 'record'
			$mo.uid = $rec.Uid
			$folderType = 'user_folder'
			if ($folder.FolderType -eq [FolderType]::SharedFolder) {
				$folderType = 'shared_folder'
			}
			elseif ($folder.FolderType -eq [FolderType]::SharedSharedFolder) {
				$folderType = 'shared_shared_folder'
			}
			$mo.fromType = $folderType
			$mo.fromUid = $folder.FolderUid
			$canFlag = $targetFolder.DefaultCanShare
			if ($canShare -eq 'Yes') {
				$canFlag = $true
			}
			elseif ($canShare -eq 'No') {
				$canFlag = $false
			}
			$mo.canShare = $canFlag

			$mo.canEdit = $canEdit
			$mo.cascade = $false
			$moveObjects += $mo

			$to = New-Object TransitionKey
			$to.uid = $rec.Uid
			$encKey = [CryptoUtils]::EncryptAesV1($rec.RecordKey, $sfKey)
			$to.key = [CryptoUtils]::Base64UrlEncode($encKey)
			$transitionObjects += $to
		}
		if ($moveObjects.Length -gt 0) {
			$command.moveObjects = $moveObjects
			$command.transitionKeys = $transitionObjects

			$command
			$t = $vault.Auth.ExecuteAuthCommand($command, [KeeperApiResponse], $true)
			$rs = $t.GetAwaiter().GetResult()
			$_ = Sync-Keeper
		} else {
			Write-Host "No records to be added to $($sharedFolder)"
		}
    } else {
		Write-Host "No records to be added to $($sharedFolder)"
	}
}