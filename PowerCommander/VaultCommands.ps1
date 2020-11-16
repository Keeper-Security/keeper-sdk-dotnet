#requires -Version 5.0

using namespace KeeperSecurity

$Script:PathDelimiter = [System.IO.Path]::DirectorySeparatorChar

function Get-KeeperLocation {
<#
	.Synopsis
	Get current Keeper folder
#>
	[CmdletBinding()]

	[Vault]$vault = $Script:Vault
	if ($vault) {
		[string]$currentFolder = $Script:CurrentFolder
		[FolderNode]$folder = $vault.RootFolder
		if ($currentFolder) {
			$_ = $vault.TryGetFolder($currentFolder, [ref]$folder)
		}
		exportKeeperNode $folder
	} else {
		Write-Error -Message "Not connected"
	}
}
New-Alias -Name kpwd -Value Get-KeeperLocation

function Set-KeeperLocation {
<#
	.Synopsis
	Change current Keeper folder

	.Parameter Path
	New location
#>

	[CmdletBinding()]
	Param (
		[Parameter(Position = 0)][string] $Path
	)
	[Vault]$vault = $Script:Vault
	if ($vault) {
		if ($Path) {
			[FolderNode]$folder = $null
			if (!$vault.TryGetFolder($Script:CurrentFolder, [ref]$folder)) {
				$folder = $vault.RootFolder
			}

			$components = splitKeeperPath $Path
			$rs = parseKeeperPath $components $vault $folder
			if ($rs -and !$rs[1]) {
				$folder = $rs[0]
				$uid =  $folder.FolderUid
				if ($vault.TryGetFolder($uid, [ref]$folder)) {
					$Script:CurrentFolder = $uid
				} else {
					$Script:CurrentFolder = ''
				}
			}
		}
		getVaultFolderPath $vault $Script:CurrentFolder 
	} else {
		Write-Error -Message "Not connected"
	}
}

$Keeper_FolderPathRecordCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

	$result = @()
	[Vault]$vault = $Script:Vault
	if ($vault) {
		[FolderNode] $folder = $null
		if (!$vault.TryGetFolder($Script:CurrentFolder, [ref]$folder)) {
			$folder = $vault.RootFolder
		}

		$pattern = ''
		$toComplete = $wordToComplete
		if ($toComplete.Length -ge 2) {
			if ($toComplete[0] -eq '''' -and $toComplete[-1] -eq '''') {
				$toComplete = $toComplete.Substring(1, $toComplete.Length - 2)
				$toComplete = $toComplete -replace '''', ''''
			}
		}
		if ($toComplete) {
			$components = splitKeeperPath $toComplete
			if ($components.Count -gt 1) {
				if ($components[-1]) {
					$pattern = $components[-1]
					$components[-1] = ''
				}
				$rs = parseKeeperPath $components $vault $folder
				if ($rs -and $rs.Count -eq 2) {
					if (!$rs[1]) {
						$folder = $rs[0]
					} else {
						$folder = $null
					}
				}
			} else {
				if ($components) {
					$pattern = $components
					$components = @('')
				} else {
					$folder = $vault.RootFolder
					$pattern = ''
					$components = @('')
				}
			}
		} else {
			$components = @('')
			$pattern = $wordToComplete
		}

		if ($folder) {
			$pattern += '*'
			foreach ($uid in $folder.Subfolders) {
				$subfolder = $null
				if ($vault.TryGetFolder($uid, [ref]$subfolder)) {
					if ($subfolder.Name -like $pattern) {
						$path = @()
						$components | % { $path += $_ }
						$path[-1] = $subfolder.Name
						$path += ''
						$expansion = ($path | % {$_ -replace '\\', '\\'}) -join $Script:PathDelimiter 
						if ($expansion -match '[\s'']') {
							$expansion = $expansion -replace '''', ''''''
							$expansion = "'${expansion}'"
						}
						$result += $expansion
					}
				}
			}
		}
	} 
	if ($result.Count -gt 0) {
		return $result
	} else {
		return $null
	}
}
Register-ArgumentCompleter -CommandName Set-KeeperLocation -ParameterName Path -ScriptBlock $Keeper_FolderPathRecordCompleter
New-Alias -Name kcd -Value Set-KeeperLocation


function Get-KeeperChildItems {
<#
	.Synopsis
	Get the content of Keeper folder. Output and parameters are similar to Get-ChildItems cmdlet

	.Parameter Path
	Keeper folder

	.Parameter Filter
	Match the string in Title, Uid, Login, and Link fields

	.Parameter Recursive
	Get child items in subfolders recursively

	.Parameter Depth
	Recursion depth

	.Parameter SkipGrouping
	Do not group result set by folder
	
	.Parameter ObjectType
	Limit result set to Folders or Records only
#>

	[CmdletBinding()]
	Param (
		[Parameter(Position = 0)][string] $Path,
		[string] $Filter,
		[Switch] $Recursive,
		[int] $Depth,
		[Switch] $SkipGrouping,
		[ValidateSet('Folder' ,'Record')][string] $ObjectType
	)

	$showFolder = $true
	$showRecord = $true
	if ($ObjectType) {
		$showFolder = $ObjectType -eq 'Folder'
		$showRecord = !$showFolder
	}

	[Vault]$vault = $Script:Vault
	if ($vault) {
		[FolderNode] $baseDir = $null
		if (!$vault.TryGetFolder($Script:CurrentFolder, [ref]$baseDir)) {
			$baseDir = $vault.RootFolder
		}
		if ($Path) {
			$components = splitKeeperPath $Path
			$rs = parseKeeperPath $components $vault $baseDir
			$baseDir = $rs[0]
		}
		[FolderNode[]]$folders = @($baseDir)
		if ($Recursive.IsPresent) {
			$pos = 0
			$dep = 0
			while ($pos -lt $folders.Count) {
				if ($Depth -gt 0) {
					if ($dep -ge $Depth) {
						break
					}
				}
				$lastPos = $folders.Count
				for ($i = $pos; $i -lt $lastPos; $i++) {
					foreach($uid in $folders[$i].Subfolders) {
						[FolderNode] $sf = $null;
						if ($vault.TryGetFolder($uid, [ref]$sf)) {
							$folders += $sf
						}
					}
				}
				$pos = $lastPos
				$dep++
			}
		}
		$entries = @()
		$recordEntries = @{}
		for ($i = 0; $i -lt $folders.Count; $i++) {
			[FolderNode]$f = $folders[$i]
			$path = getVaultFolderPath $vault $f.FolderUid
			if ($showFolder) {
				foreach ($uid in $f.Subfolders) {
					[FolderNode]$sf = $null
					if ($vault.TryGetFolder($uid, [ref]$sf)) {
						$match = $true
						if ($Filter) {
							$match = @($sf.Name, $sf.FolderUid) | Select-String $Filter | Select -First 1
						}
						if ($match) {
							$entry = [PSCustomObject]@{
								PSTypeName = "KeeperSecurity.Commander.FolderEntry$(if ($SkipGrouping.IsPresent) {'Flat'} else {''})"
								Uid = $sf.FolderUid
								Name = $sf.Name
								OwnerFolder = $path
								FolderType = $sf.FolderType
								Shared = $sf.FolderType -ne [FolderType]::UserFolder
								SortGroup = 0
							}
							$entries += $entry
						}
					}
				}
			}
			if ($showRecord) {
				foreach ($uid in $f.Records) {
					[PasswordRecord] $r = $null
					if ($vault.TryGetRecord($uid, [ref]$r)) {
						$match = $true
						if ($Filter) {
							$match = @($r.Title, $r.Uid, $r.Login, $r.Link) | Select-String $Filter | Select -First 1
						}
						if ($match) {
							if ($Flat.IsPresent -and $recordEntries.ContainsKey($uid)) {
								$entry = $recordEntries[$uid]
								$entry.OwnerFolder += $path
							} else {
								$entry = [PSCustomObject]@{
									PSTypeName  = "KeeperSecurity.Commander.RecordEntry$(if ($SkipGrouping.IsPresent) {'Flat'} else {''})"
									Uid = $r.Uid
									Name = $r.Title
									Shared = $r.Shared
									Owner = $r.Owner
									HasAttachments = ($r.Attachments.Count -gt 0)
									Link = $r.Link
									Login = $r.Login
									SortGroup = 1
								}
								if ($SkipGrouping.IsPresent) {
									Add-Member -InputObject $entry -NotePropertyName OwnerFolder -NotePropertyValue @($path)
								} else {
									Add-Member -InputObject $entry -NotePropertyName OwnerFolder -NotePropertyValue $path
								}

								$recordEntries.Add($uid, $entry)
							}
						}
					}
				}
			}
		}
		if ($recordEntries) {
			$entries += $recordEntries.Values
		}
		if ($entries) {
			if ($SkipGrouping.IsPresent) {
				$entries | Sort-Object SortGroup, Name
			} else {
				$entries | Sort-Object OwnerFolder, SortGroup, Name
			}
		}
	} else {
		Write-Error -Message "Not connected"
	}
}
Register-ArgumentCompleter -CommandName Get-KeeperChildItems -ParameterName Path -ScriptBlock $Keeper_FolderPathRecordCompleter
New-Alias -Name kdir -Value Get-KeeperChildItems


function Get-KeeperObject {
<#
	.Synopsis
	Get Keeper object by Uid

	.Parameter Uid
	Keeper UID

	.Parameter ObjectType
	One of the following Record, SharedFolder, Folder, Team
	
	.Parameter PropertyName
	Return object property not the entire object
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)][string[]] $Uid,
		[string] [ValidateSet('Record' ,'SharedFolder', 'Folder', 'Team')] $ObjectType,
		[string] $PropertyName
	)

	Begin {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message 'Not connected'
		}

		$testRecord = if ($ObjectType) {$ObjectType -eq 'Record'} else {$true} 
		$testSharedFolder = if ($ObjectType) {$ObjectType -eq 'SharedFolder'} else {$true} 
		$testFolder = if ($ObjectType) {$ObjectType -eq 'Folder'} else {$true} 
		$testTeam = if ($ObjectType) {$ObjectType -eq 'Team'} else {$true} 
	}
	Process {
		ForEach($oid in $Uid) {
			if ($testRecord) {
				[PasswordRecord] $record = $null
				if ($vault.TryGetRecord($oid, [ref]$record)) {
					if ($PropertyName) {
						$mp = $record | Get-Member -MemberType Properties -Name $PropertyName
						if ($mp) {
							$record | Select -ExpandProperty $PropertyName
						}
					} else {
						$record
					}
					continue
				}
			}
			if ($testSharedFolder) {
				[SharedFolder] $sf = $null
				if ($vault.TryGetSharedFolder($oid, [ref]$sf)) {
					if ($PropertyName) {
						$mp = $sf | Get-Member -MemberType Properties -Name $PropertyName
						if ($mp) {
							$sf | Select -ExpandProperty $PropertyName
						}
					} else {
						$sf
					}
					continue
				}
			}
			if ($testFolder) {
				[FolderNode] $f = $null
				if ($vault.TryGetFolder($oid, [ref]$f)) {
					if ($PropertyName) {
						$mp = $f | Get-Member -MemberType Properties -Name $PropertyName
						if ($mp) {
							$f | Select -ExpandProperty $PropertyName
						}
					} else {
						$f
					}
					continue
				}
			}
			if ($testTeam) {
				[EnterpriseTeam] $t = $null
				if ($vault.TryGetTeam($oid, [ref]$t)) {
					if ($PropertyName) {
						$mp = $t | Get-Member -MemberType Properties -Name $PropertyName
						if ($mp) {
							$t | Select -ExpandProperty $PropertyName
						}
					} else {
						$t
					}
					continue
				}
			}

		}
	}
}
New-Alias -Name ko -Value Get-KeeperObject


function parseKeeperPath {
	Param (
		[string[]]$components,
		[Vault]$vault,
		[FolderNode]$folder
	)
	if ($components) {
		if (!$components[0]) {
			$folder = $vault.RootFolder
			$_, $components = $components
		}
		while ($components) {
			$resume = $false
			$component, $rest = $components
			if ($component -eq '..') {
				if ($folder.ParentUid) {
					$resume = $vault.TryGetFolder($folder.ParentUid, [ref]$folder) 
				} else {
					$folder = $vault.RootFolder
					$resume = $true
				}
			}
			elseif (!$component -or $component -eq '.') {
				$resume = $true
			}		
			else {
				foreach ($x in $folder.Subfolders) {
					[FolderNode] $subfolder = $null
					if ($vault.TryGetFolder($x, [ref]$subfolder)) {
						if ($subfolder.Name -eq $component) {
							$resume = $true
							$folder = $subfolder
							break
						}
					}
				}
			}

			if ($resume) {
				$isFirstComponent = $false
				$components = $rest
			} else {
				break
			}
		}
		$folder
		($components | % {escapePathComponent $_}) -join $Script:PathDelimiter
	} else {
		$folder
		$path
	}
}

function splitKeeperPath {
	Param ([string] $path)

	[bool]$isDelimiter = $false
	[string]$component = ''
	foreach ($x in $path.ToCharArray()) {
		if ($x -eq $Script:PathDelimiter) {
			if ($isDelimiter) {
				$component += $x
				$isDelimiter = $false
			} else {
				$isDelimiter = $true
			}
		} else {
			if ($isDelimiter) {
				$component
				$component = ''
				$isDelimiter = $false
			}
			$component += $x
		}
	}
	$component
	if ($isDelimiter) {
		''
	}
}

function exportKeeperNode {
	Param ([FolderNode] $folder)
	[PSCustomObject]@{
		PSTypeName  = 'KeeperSecurity.Commander.FolderInfo'
		FolderUid = $folder.FolderUid
		Path = getVaultFolderPath $vault $folder.FolderUid
		Name = $folder.Name
		ParentUid = $folder.ParentUid
		FolderType = $folder.FolderType
	}
}

function escapePathComponent {
	Param ([string] $component)
	
	$component = $component -replace '\\', '\\'
	$component = $component -replace '''', ''''''
	if ($component -match '[\s'']') {
		"'${component}'"
	} else {
		$component
	}
}

function getVaultFolderPath {
	Param (
		[KeeperSecurity.Sdk.Vault]$vault,
		[string] $folderUid
	)

	$comps = @()
	traverseFolderToRoot $vault $folderUid ([ref]$comps)
	$path = ''
	if ($comps) {
		[Array]::Reverse($comps)
		$comps += ''
		$path = ($comps | % {$_ -replace [Regex]::Escape($Script:PathDelimiter), "${Script:PathDelimiter}${Script:PathDelimiter}" }) -join $Script:PathDelimiter
	}
	"${Script:PathDelimiter}${path}"
}

function traverseFolderToRoot ([Vault]$vault, [string] $folderUid, [ref][string[]] $components) {
	if ($folderUid) {
		[FolderNode]$folder = $null
		if ($vault.TryGetFolder($folderUid, [ref]$folder)) {
			$components.Value += $folder.Name
			traverseFolderToRoot $vault $folder.ParentUid $components
		}
	}
}
