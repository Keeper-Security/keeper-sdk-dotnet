#requires -Version 5.0

using namespace KeeperSecurity.Sdk

function Get-KeeperSharedFolders {
<#
	.Synopsis
	Get Keeper Shared Folders

	.Parameter Uid
	Shared Folder UID

	.Filter
	Return matching shared folders only
#>
	[CmdletBinding()]
	[OutputType([SharedFolder[]])] 
	Param (
		[string] $Uid,
		[string] $Filter
	)
	Begin {
	}

	Process {
		[Vault]$vault = $Script:Vault
		if ($vault) {
			[SharedFolder] $sharedFolder = $null
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

[Flags()] 
enum Permissions {
	CanEdit = 1
	CanShare = 2
	ManageRecords = 4
	ManageUsers = 8
}


function Grant-KeeperSharedFolderPermissions {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] [SharedFolder[]]$SharedFolders,
		[string[]] $Records,
		[string[]] $Users,
		[switch] $CanShare,
		[switch] $CanEdit,
		[switch] $ManageRecords,
		[switch] $ManageUsers
	)

	Begin {
	}

	Process {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message "Not connected"
		}

		$sfs = @{}
		[SharedFolder] $sharedFolder = $null
		foreach ($sf in $SharedFolders) {
			if ($sf.GetType() -ne [SharedFolder]) {
				[string] $uid = $null
				if ($sf.GetType -eq [string]) {
					$uid = $sf
				} else {
					$uid = $sf.Uid
				}
				if ($uid) {
					$_ = $vault.TryGetSharedFolder($uid, [ref]$sharedFolder)
				}
			} else {
				$sharedFolder = $sf
			}
			if (-not $sharedFolder) {
				Write-Information -MessageData "Invalid Shared Folder: $sf"
			}
			if ($sfs.ContainsKey($sharedFolder.Uid)) {
				continue
			}
			$sfs[$sharedFolder.Uid] = $sharedFolder
		}

		$uids = New-Object System.Collections.Generic.HashSet[string]
		foreach($uid in $sfs.Keys) {
			$sharedFolder = $sfs[$uid]
			[Permissions]$permissions = 0
			if ($CanShare.IsPresent) { $permissions = $permissions -bOR [Permissions]::CanShare }
			if ($CanEdit.IsPresent) { $permissions = $permissions -bOR [Permissions]::CanEdit }
			if ($ManageRecords.IsPresent) { $permissions = $permissions -bOR [Permissions]::ManageRecords }
			if ($ManageUsers.IsPresent) { $permissions = $permissions -bOR [Permissions]::ManageUsers }

			modifySharedFolderPermissions -vault $vault -sharedFolder $sharedFolder -recordFilter $Records -userFilter $Users -isGrant $true -permissions $permissions
		}
	}

	End {
		Sync-Keeper
	}
}

function Revoke-KeeperSharedFolderPermissions {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)] [SharedFolder[]]$SharedFolders,
		[string[]] $Records,
		[string[]] $Users,
		[switch] $CanShare,
		[switch] $CanEdit,
		[switch] $ManageRecords,
		[switch] $ManageUsers
	)

	Begin {
	}

	Process {
		[Vault]$vault = $Script:Vault
		if (-not $vault) {
			Write-Error -Message "Not connected"
		}

		$sfs = @{}
		[SharedFolder] $sharedFolder = $null
		foreach ($sf in $SharedFolders) {
			if ($sf.GetType() -ne [SharedFolder]) {
				[string] $uid = $null
				if ($sf.GetType -eq [string]) {
					$uid = $sf
				} else {
					$uid = $sf.Uid
				}
				if ($uid) {
					$_ = $vault.TryGetSharedFolder($uid, [ref]$sharedFolder)
				}
			} else {
				$sharedFolder = $sf
			}
			if (-not $sharedFolder) {
				Write-Information -MessageData "Invalid Shared Folder: $sf"
			}
			if ($sfs.ContainsKey($sharedFolder.Uid)) {
				continue
			}
			$sfs[$sharedFolder.Uid] = $sharedFolder
		}

		$uids = New-Object System.Collections.Generic.HashSet[string]
		foreach($uid in $sfs.Keys) {
			$sharedFolder = $sfs[$uid]
			[Permissions]$permissions = 0
			if ($CanShare.IsPresent) { $permissions = $permissions -bOR [Permissions]::CanShare }
			if ($CanEdit.IsPresent) { $permissions = $permissions -bOR [Permissions]::CanEdit }
			if ($ManageRecords.IsPresent) { $permissions = $permissions -bOR [Permissions]::ManageRecords }
			if ($ManageUsers.IsPresent) { $permissions = $permissions -bOR [Permissions]::ManageUsers }

			modifySharedFolderPermissions -vault $vault -sharedFolder $sharedFolder -recordFilter $Records -userFilter $Users -isGrant $false -permissions $permissions
		}
	}

	End {
		Sync-Keeper
	}
}

function modifySharedFolderPermissions {
	Param (
		[Vault] $vault, [SharedFolder]$sharedFolder, [string[]] $recordFilter, [string[]] $userFilter, 
		[bool] $isGrant, [Permissions] $permissions
	)
	
	[SharedFolderUpdateCommand]$command = New-Object SharedFolderUpdateCommand
	$command.operation = 'update'
	$command.SharedFolderUid = $sharedFolder.Uid
	$command.forceUpdate = $true
	$forManageRecords = if ($recordFilter) {$true} else {$false}
	$forManageUsers = if ($userFilter) {$true} else {$false}
	$perm = $vault.ResolveSharedFolderAccessPath($command, $forManageUsers, $forManageRecords)
	if (-not $perm) {
		Write-Information -MessageData "You don't have permissions on Shared Folder ($($sharedFolder.Name)) ($($sharedFolder.Uid))"
		continue
	}
	
	$uids = New-Object System.Collections.Generic.HashSet[string]

	$hasCanEdit = ($permissions -band [Permissions]::CanEdit) -eq [Permissions]::CanEdit
	$hasCanShare = ($permissions -band [Permissions]::CanShare) -eq [Permissions]::CanShare 

	$rec_changes = @()
	[PasswordRecord] $record = $null
	if ($recordFilter -and ($hasCanEdit -or $hasCanShare)) {
		$recs = @{}
		[SharedFolderRecord]$rp = $null
		foreach ($rp in $sharedFolder.RecordPermissions) {
			if ($vault.TryGetRecord($rp.RecordUid, [ref]$record)) {
				$recs[$record.Uid] = $record
			}
		}
		
		$uids.Clear()
		foreach ($pattern in $recordFilter) {
			if ($recs.ContainsKey($pattern)) {
				$uids.Add($pattern)
			} else {
				foreach($record in $recs.Values) {
					if ($pattern -eq '*') {
						$_ = $uids.Add($record.Uid)
					} else {
						$m = $r.Title -match $pattern
						if ($m) {
							$_ = $uids.Add($r.Uid)
						}
					}
				}
			}
		}

		foreach ($rp in $sharedFolder.RecordPermissions) {
			if (-not $uids.Contains($rp.RecordUid)) {
				continue
			}
			if ($isGrant) {
				if ((-not $hasCanShare -or $rp.CanShare) -and (-not $hasCanEdit -or $rp.CanEdit)) {
					continue
				}
			} else {
				if ((-not $hasCanShare -or -not $rp.CanShare) -and (-not $hasCanEdit -or -not $rp.CanEdit)) {
					continue
				}
			}

			[SharedFolderUpdateRecord]$ru = New-Object SharedFolderUpdateRecord
			$ru.recordUid = $rp.RecordUid
			$rap = $vault.ResolveRecordAccessPath($ru, $hasCanEdit, $hasCanShare)
			if ($rap) {
				if ($hasCanEdit) {
					$ru.CanEdit = $isGrant
				} else {
					$ru.CanEdit = $rp.CanEdit
				}
								
				if ($hasCanShare) {
					$ru.CanShare = $isGrant
				} else {
					$ru.CanShare = $rp.CanShare
				}
				$rec_changes += $ru
			}
		}
	}

	$hasManageRecords = ($permissions -band [Permissions]::ManageRecords) -eq [Permissions]::ManageRecords
	$hasManageUsers = ($permissions -band [Permissions]::ManageUsers) -eq [Permissions]::ManageUsers 


	$user_changes = @()
	$team_changes = @()
	if ($userFilter -and ($hasManageRecords -or $hasManageUsers)) {
		$uts = @{}
		[SharedFolderPermission] $up = $null
		foreach ($up in $sharedFolder.UsersPermissions) {
			if ($up.UserType -eq ([KeeperSecurity.Sdk.UserType]::User)) {
				if ($up.UserId -ne $vault.Auth.Username) {
					$uts[$up.UserId] = $up.UserId
				}
			} else {
				[EnterpriseTeam] $team = $null
				if ($vault.TryGetTeam($up.UserId, [ref]$team)) {
					$uts[$up.UserId] = $team.Name.ToLower()
				}
			}
		}

		$uids.Clear();
		foreach ($uf in $userFilter) {
			if ($uts.ContainsKey($uf)) {
				$_ = $uids.Add($uf)
			} else {
				foreach ($key in $uts.Keys) {
					if ($uids.Contains($key)) {
						continue
					}
					$n = $uts[$key]
					if ($uf -eq '*') {
						$_ = $uids.Add($key)
					} else {
						$m = $n -match $uf
						if ($m) {
							$_ = $uids.Add($key)
						}
					}
				}
			}
		}
		
		foreach ($up in $sharedFolder.UsersPermissions) {
			if (-not $uids.Contains($up.UserId)) {
				continue
			}
			if ($isGrant) {
				if ((-not $hasManageRecords -or $up.ManageRecords) -and (-not $hasManageUsers -or $up.ManageUsers)) {
					continue
				}
			} else {
				if ((-not $hasManageRecords -or -not $up.ManageRecords) -and (-not $hasManageUsers -or -not $up.ManageUsers)) {
					continue
				}
			}

			if ($up.UserType -eq ([KeeperSecurity.Sdk.UserType]::User)) {
				[SharedFolderUpdateUser]$uu = New-Object SharedFolderUpdateUser
				$uu.Username = $up.UserId
				if ($hasManageRecords) {
					$uu.ManageRecords = $isGrant
				} else {
					$uu.ManageRecords = $up.ManageRecords
				}
				if ($hasManageUsers) {
					$uu.ManageUsers = $isGrant
				} else {
					$uu.ManageUsers = $up.ManageUsers
				}
				$user_changes += $uu
			} else {
				[SharedFolderUpdateTeam]$tu = New-Object SharedFolderUpdateTeam
				$tu.TeamUid = $up.UserId
				if ($hasManageRecords) {
					$tu.ManageRecords = $isGrant
				} else {
					$tu.ManageRecords = $up.ManageRecords
				}
				if ($hasManageUsers) {
					$tu.ManageUsers = $isGrant
				} else {
					$tu.ManageUsers = $up.ManageUsers
				}
				$team_changes += $tu
			}
		}
	}

	$recordsChanded = 0
	$usersChanged = 0
	while ($rec_changes -or $user_changes -or $team_changes) {
		$command.addUsers = $null
		$command.updateUsers = $null
		$command.removeUsers = $null
		$command.addRecords = $null
		$command.updateRecords = $null
		$command.removeRecords = $null
		$command.addTeams = $null
		$command.updateTeams = $null
		$command.removeTeams = $null
		$left = 100
		if ($left -gt 0 -and $rec_changes) {
			$toAdd = [Math]::Min($left, $rec_changes.Count)
			$command.updateRecords = $rec_changes[0..$toAdd]
			$rec_changes = $rec_changes[$toAdd..$rec_changes.Count]
			$left -= $toAdd
		}
		if ($left -gt 0 -and $user_changes) {
			$toAdd = [Math]::Min($left, $user_changes.Count)
			$command.updateUsers = $user_changes[0..$toAdd]
			$user_changes = $user_changes[$toAdd..$user_changes.Count]
			$left -= $toAdd
		}
		if ($left -gt 0 -and $team_changes) {
			$toAdd = [Math]::Min($left, $team_changes.Count)
			$command.updateTeams = $team_changes[0..$toAdd]
			$team_changes = $team_changes[$toAdd..$team_changes.Count]
			$left -= $toAdd
		}

		$t = $auth.ExecuteAuthCommand($command, [SharedFolderUpdateResponse], $true)
		$rs = $t.GetAwaiter().GetResult()
		if ($rs.updateRecords) {
			foreach($status in $rs.updateRecords) {
				if ($status.Status -eq 'success') {
					$recordsChanded++
				} else {
					Write-Information -MessageData "Shared Folder UID / Record UID  ($($command.SharedFolderUid) / $($status.RecordUid)) error: ($($status.Status))"
				}
			}
		}
		if ($rs.updateUsers) {
			foreach($status in $rs.updateUsers) {
				if ($status.Status -eq 'success') {
					$usersChanged++
				} else {
					Write-Information -MessageData "Shared Folder UID / Username  ($($command.SharedFolderUid) / $($status.Username)) error: ($($status.Status))"
				}
			}
		}
		if ($rs.updateTeams) {
			foreach($status in $rs.updateTeams) {
				if ($status.Status -eq 'success') {
					$usersChanged++
				} else {
					Write-Information -MessageData "Shared Folder UID / Team UID  ($($command.SharedFolderUid) / $($status.TeamUid)) error: ($($status.Status))"
				}
			}
		}
	}
	if ($recordsChanded -gt 0 -or $usersChanged -gt 0) {
		$info = "Shared Folder '$($sharedFolder.Name)'. Permission changed for"
		if ($recordsChanded -gt 0 ) {
			$info += " $recordsChanded record(s);"
		}
		if ($usersChanged -gt 0) {
			$info += " $usersChanged users(s);"
		}
		Write-Information -MessageData $info
	}
}