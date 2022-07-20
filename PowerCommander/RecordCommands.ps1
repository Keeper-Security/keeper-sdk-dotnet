#requires -Version 5.0

function Get-KeeperRecords {
<#
	.Synopsis
	Get Keeper Records

	.Parameter Uid
	Record UID

	.Parameter Filter
	Return matching records only
#>
	[CmdletBinding()]
	[OutputType([KeeperSecurity.Vault.KeeperRecord[]])] 
	Param (
		[string] $Uid,
		[string] $Filter
	)

	[KeeperSecurity.Vault.VaultOnline]$vault = getVault
	if ($Uid) {
		[KeeperSecurity.Vault.KeeperRecord] $record = $null
		if ($vault.TryGetKeeperRecord($uid, [ref]$record)) {
			$record
		}
	} else {
		foreach ($record in $vault.KeeperRecords) {
			if ($Filter) {
				$match = $($record.Uid, $record.TypeName, $record.Title, $record.Notes) | Select-String $Filter | Select-Object -First 1
				if (-not $match) {
					continue
				}
			}
			$record
		}
	}
}
New-Alias -Name kr -Value Get-KeeperRecords


function Copy-KeeperToClipboard {
<#
	.Synopsis
	Copy record password to clipboard or output 

	.Parameter Record
	Record UID or any object containing property Uid

	.Parameter Field
	Record field to copy to clipboard. Record password is default.

	.Parameter Output
	Password output destination. Clipboard is default. Use "Stdout" for scripting
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Record,
		[string] [ValidateSet('Login' ,'Password', 'URL')] $Field = 'Password',
		[string] [ValidateSet('Clipboard' ,'Stdout')] $Output = 'Clipboard'
	)
	Process {
		if ($Record -is [Array]) {
			if ($Record.Count -ne 1) {
				Write-Error -Message 'Only one record is expected'
				return
			}
			$Record = $Record[0]
		}

		[KeeperSecurity.Vault.VaultOnline]$vault = getVault

		$uid = $null
		if ($Record -is [String]) {
			$uid = $Record
		} 
		elseif ($null -ne $Record.Uid) {
			$uid = $Record.Uid
		}

		$found = $false
		if ($uid) {
			[KeeperSecurity.Vault.KeeperRecord] $rec = $null
			if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
				$entries = Get-KeeperChildItems -Filter $uid -ObjectType Record
				if ($entries.Uid) {
					$vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
				}
			}
			if ($rec) {
				$found = $true
				$value = ''

				if ($rec -is [KeeperSecurity.Vault.PasswordRecord]) {
					switch($Field) {
						'Login' {$value = $rec.Login}
						'Password' {$value = $rec.Password}
						'URL' {$value = $rec.Link}
					}
				}
				elseif ($rec -is [KeeperSecurity.Vault.TypedRecord]) {
					$fieldType = ''
					switch($Field) {
						'Login' {$fieldType = 'login'}
						'Password' {$fieldType = 'password'}
						'URL' {$fieldType = 'url'}
					}
					if ($fieldType) {
						$recordTypeField = New-Object KeeperSecurity.Vault.RecordTypeField $fieldType, $null
						[KeeperSecurity.Vault.ITypedField]$recordField = $null
						if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($rec, $recordTypeField, [ref]$recordField)) {
							$value = $recordField.Value
						}
					}
				}

				if ($value) {
					if ($Output -eq 'Stdout') {
						$value
					} else {
						Set-Clipboard -Value $value
						Write-Host "Copied to clipboard: $Field for $($rec.Title)"
					}
					if ($Field -eq 'Password') {
						$vault.AuditLogRecordCopyPassword($rec.Uid)
					}
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
<#
	.Synopsis
	Show/hide secret fields
#>
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
		[KeeperSecurity.Vault.VaultOnline]$vault = getVault
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
				[KeeperSecurity.Vault.KeeperRecord] $rec = $null
				if ($vault.TryGetKeeperRecord($uid, [ref]$rec)) {
					if ($rec -is [KeeperSecurity.Vault.PasswordRecord]) {
						if ($rec.ExtraFields) {
							foreach ($ef in $rec.ExtraFields) {
								if ($ef.FieldType -eq 'totp') {
									$totps += [PSCustomObject]@{
										RecordUid    = $rec.Uid
										Title        = $rec.Title
										TotpData     = $ef.Custom['data']
									}
								}
							}
						}
					}
					elseif ($rec -is [KeeperSecurity.Vault.TypedRecord]) {
						$recordTypeField = New-Object KeeperSecurity.Vault.RecordTypeField 'oneTimeCode', $null
						[KeeperSecurity.Vault.ITypedField]$recordField = $null
						if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($rec, $recordTypeField, [ref]$recordField)) {
							$data = $recordField.Value
							if ($data) {
								$totps += [PSCustomObject]@{
									RecordUid    = $rec.Uid
									Title        = $rec.Title
									TotpData     = $data
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
			[Tuple[string, int, int]]$code = [KeeperSecurity.Utils.CryptoUtils]::GetTotpCode($totp.TotpData)
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

$Keeper_RecordTypeNameCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
	$result = @()
	[KeeperSecurity.Vault.VaultOnline]$vault = $Script:Context.Vault
	if ($vault) {
		$toComplete = $wordToComplete + '*'
		foreach ($rt in $vault.RecordTypes) {
			if ($rt.Name -like $toComplete) {
				$result += $rt.Name
			}
		}
	} 
	if ($result.Count -gt 0) {
		return $result
	} else {
		return $null
	}

}

function Add-KeeperRecord {
<#
	.Synopsis
	Creates or Modifies a Keeper record in the current folder.

	.Parameter Uid 
	Record UID. If provided the existing record to be updated. Otherwise record is added.

	.Parameter RecordType
	Record Type (if account supports record types). 

	.Parameter Title
	Record Title. Mandatory field for added record.

	.Parameter Notes
	Record Notes.

	.Parameter GeneratePassword
	Generate random password. 

	.Parameter Fields
	A list of record Fields. Record field format NAME=VALUE
	Predefined fields are
	login 			Login Name
	password		Password
	url				Web Address
	Any other name is added to Custom Fields
	Example: login=username password=userpassword "Database Server=value1" 
#>

	[CmdletBinding(DefaultParameterSetName = 'add')]
	Param (
		[Parameter()][switch] $GeneratePassword,
		[Parameter(ParameterSetName='add')][string] $RecordType,
		[Parameter(ParameterSetName='add')][string] $Folder,
		[Parameter(ParameterSetName='edit', Mandatory = $True)][string] $Uid,
		[Parameter(ParameterSetName='add', Mandatory = $True)][string] $Title,
		[Parameter()][string] $Notes,
		[Parameter(ValueFromRemainingArguments=$true)][string[]] $Fields
	)

	Begin {
		[KeeperSecurity.Vault.VaultOnline]$vault = getVault
        [KeeperSecurity.Vault.KeeperRecord]$record = $null
	}

	Process {
		if ($Uid) {
			if (-not $vault.TryGetKeeperRecord($Uid, [ref]$record)) {
				$objs = Get-KeeperChildItems -ObjectType Record | Where-Object Name -eq $Uid
				if ($objs.Length -gt 1) {
					$vault.TryGetKeeperRecord($objs[0].Uid, [ref]$record)
				}
			}
			if (-not $record) {
				Write-Error -Message "Record `"$Uid`" not found"
				return
			}
		} else {
			if (-not $RecordType -or  $RecordType -eq 'legacy') {
				$record = New-Object KeeperSecurity.Vault.PasswordRecord
			} else {
				$record = New-Object KeeperSecurity.Vault.TypedRecord $RecordType
				[KeeperSecurity.Utils.RecordTypesUtils]::AdjustTypedRecord($vault, $record)
			}
			$record.Title = $Title
		}

        if ($Notes) {
            if ($record.Notes -and $Notes[0] -eq '+') {
                $record.Notes += "`n"
				$Notes = $Notes.Substring(1)
            }
            $record.Notes += $Notes
        }

		if ($GeneratePassword.IsPresent) {
			$generatedPassword = [Keepersecurity.Utils.CryptoUtils]::GenerateUid()
			$Fields +=  "password=${generatedPassword}"
		}

		foreach ($field in $Fields) {
			if ($field -match '^([^=\.]+)(\.[^=]+)?=(.*)$') {
				$fieldName = $Matches[1]
				$fieldLabel = $Matches[2]
				if ($fieldLabel) {
					$fieldLabel = $fieldLabel.Trim().Trim('.')
				}
				$fieldValue = $Matches[3]
				if ($fieldValue) {
					$fieldValue = $fieldValue.Trim()
				}
				if ($record -is [KeeperSecurity.Vault.PasswordRecord]) {
					switch($fieldName) {
						'login' {$record.Login = $fieldValue}
						'password' {$record.Password = $fieldValue}
						'url' {$record.Link = $fieldValue}
						Default {
							if ($fieldValue) {
								[KeeperSecurity.Vault.VaultExtensions]::SetCustomField($record, $fieldName, $fieldValue) | Out-Null
							} else {
								[KeeperSecurity.Vault.VaultExtensions]::DeleteCustomField($record, $fieldName) | Out-Null
							}
						}
					}
				}
				elseif ($record -is [KeeperSecurity.Vault.TypedRecord]) {
					$recordTypeField = New-Object KeeperSecurity.Vault.RecordTypeField $fieldName, $fieldLabel
					[KeeperSecurity.Vault.ITypedField]$typedField = $null
					if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($record, $recordTypeField, [ref]$typedField)) {
					} else {
						if ($fieldValue) {
							if (-not $fieldLabel) {
								[KeeperSecurity.Vault.RecordField]$recordField = $null
								if (-not [KeeperSecurity.Vault.RecordTypesConstants]::TryGetRecordField($fieldName, [ref]$recordField)) {
									$fieldLabel = $fieldName
									$fieldName = 'text'
								}
							}
							$typedField = [KeeperSecurity.Vault.VaultDataExtensions]::CreateTypedField($fieldName, $fieldLabel)
							if ($typedField) {
								$record.Custom.Add($typedField)
							}
						}
					}
					if ($typedField) {
						if ($fieldValue) {
							$typedField.ObjectValue = $fieldValue
						} else {
							$typedField.DeleteValueAt(0)
						}
					}
				}
			} else {
				Write-Error -Message "Invalid field `"$field`""
				return
			}
		}
	}
    End {
		if ($record.Uid) {
	        $task = $vault.UpdateRecord($record)
		} else {
			$folderUid = $Script:Context.CurrentFolder
			if ($Folder) {
				$folderNode = resolveFolderNode $vault $Folder
				$folderUid = $folderNode.FolderUid
			}

			$task = $vault.CreateRecord($record, $folderUid)
		}
		$task.GetAwaiter().GetResult()
    }
}
New-Alias -Name kadd -Value Add-KeeperRecord
Register-ArgumentCompleter -CommandName Add-KeeperRecord -ParameterName Folder -ScriptBlock $Keeper_FolderPathRecordCompleter
Register-ArgumentCompleter -CommandName Add-KeeperRecord -ParameterName RecordType -ScriptBlock $Keeper_RecordTypeNameCompleter


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

	[KeeperSecurity.Vault.VaultOnline]$vault = getVault

	$folderUid = $null
	$recordUid = $null
	[KeeperSecurity.Vault.KeeperRecord] $record = $null
	if ($vault.TryGetKeeperRecord($Name, [ref]$record)) {
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
		$folderUid = $Script:Context.CurrentFolder
	}

	$recordPath = New-Object KeeperSecurity.Vault.RecordPath
	$recordPath.RecordUid = $recordUid
	$recordPath.FolderUid = $folderUid
	$task = $vault.DeleteRecords(@($recordPath))
	$task.GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name kdel -Value Remove-KeeperRecord

function Move-RecordToFolder {
<#
	.Synopsis
	Moves records to Folder.

	.Parameter Record
	Record UID, Path or any object containing property Uid.

	.Parameter Folder 
	Folder Name, Path, or UID
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Records,
		[Parameter(Position = 0, Mandatory = $true)][string]$Folder,
		[Parameter()][switch]$Link
	)
	
	Begin {
		[KeeperSecurity.Vault.VaultOnline]$vault = getVault
		$folderNode = resolveFolderNode $vault $Folder
		$sourceRecords = @()
	}

	Process {
		foreach ($r in $Records) {
			if ($null -ne $r.Uid) {
				$r = $r.Uid
			}
			[KeeperSecurity.Vault.FolderNode]$folder = $null
			[KeeperSecurity.Vault.KeeperRecord]$record = $null
			if ($vault.TryGetKeeperRecord($r, [ref]$record)) {
				if ($record -is [KeeperSecurity.Vault.PasswordRecord] -or $record -is [KeeperSecurity.Vault.TypedRecord]) {
					if ($folderNode.FolderUid -and $vault.RootFolder.Records.Contains($record.Uid)) {
						$folder = $vault.RootFolder
					} else {
						foreach ($fol in $vault.Folders) {
							if ($fol.FolderUid -eq $folderNode.FolderUid) {
								continue
							}
							if ($fol.Records.Contains($record.Uid)) {
								$folder = $fol
								break
							}
						}
					}
				} else {
					Write-Error "`$r`" record type is not supported." -ErrorAction Stop
				}
			} else {
				[KeeperSecurity.Vault.FolderNode]$fol = $null
				if (-not $vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$fol)) {
					$fol = $vault.RootFolder
				}
			
				$comps = splitKeeperPath $r
				$folder, $rest = parseKeeperPath $comps $vault $fol
				if (-not $rest) {
					Write-Error "`"$r`" should be a record" -ErrorAction Stop
				}
				[KeeperSecurity.Vault.KeeperRecord]$rec = $null
				foreach ($recordUid in $folder.Records) {
					if ($vault.TryGetKeeperRecord($recordUid, [ref]$rec)) {
						if ($rec.Title -eq $rest) {
							if ($rec -is [KeeperSecurity.Vault.PasswordRecord] -or $rec -is [KeeperSecurity.Vault.TypedRecord]) {
								$record = $rec
								break
							}
						}
					}
				}
			}

			if (-not $record -or -not $folder) {
				Write-Error "Record `"$r`" cannot be found" -ErrorAction Stop
			}

			$rp = New-Object KeeperSecurity.Vault.RecordPath 
			$rp.RecordUid = $record.Uid
			$rp.FolderUid = $folder.FolderUid
			$sourceRecords += $rp
		}
	}
	End {
		if (-not $sourceRecords) {
			Write-Error "There are no records to move" -ErrorAction Stop
		}
		$vault.MoveRecords($sourceRecords, $folderNode.FolderUid, $Link.IsPresent).GetAwaiter().GetResult() | Out-Null
		$vault.ScheduleSyncDown([System.TimeSpan]::FromSeconds(0)).GetAwaiter().GetResult() | Out-Null
	}
}
New-Alias -Name kmv -Value Move-RecordToFolder
Register-ArgumentCompleter -CommandName Move-RecordToFolder -ParameterName Folder -ScriptBlock $Keeper_FolderPathRecordCompleter

function resolveFolderNode {
	Param ([KeeperSecurity.Vault.VaultOnline]$vault, $path)

	[KeeperSecurity.Vault.FolderNode]$folder = $null
	if (-not $vault.TryGetFolder($path, [ref]$folder)) {
		if (-not $vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$folder)) {
			$folder = $vault.RootFolder
		}
	
		$comps = splitKeeperPath $path
		$folder, $rest = parseKeeperPath $comps $vault $folder	
		if ($rest) {
			Write-Error "Folder $path not found" -ErrorAction Stop
		}
	}

	$folder
}
