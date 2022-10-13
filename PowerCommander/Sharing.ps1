#requires -Version 5.0


function Show-KeeperRecordShares {
    <#
        .Synopsis
        Shows a record sharing information

    	.Parameter Record
	    Record UID or any object containing property Uid
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]$Records
    )
    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        [string[]]$recordUids = @() 
    
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
                if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
                    $entries = Get-KeeperChildItems -Filter $uid -ObjectType Record
                    if ($entries.Uid) {
                        $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
                    }
                }
                if ($rec) {
                    $recordUids += $rec.Uid
                } else {
                    Write-Error -Message "Cannot find a Keeper record: $r" -ErrorAction SilentlyContinue
                }
            }
        }
    }

    End {
        $vault.GetSharesForRecords($recordUids).GetAwaiter().GetResult()
    }
}
New-Alias -Name kshrsh -Value Show-KeeperRecordShares

function Grant-KeeperRecordAccess {
    <#
        .Synopsis
        Shares a record with user

    	.Parameter Record
	    Record UID or any object containing property Uid

        .Parameter User
	    User email

        .Parameter CanEdit
        Grant edit permission

        .Parameter CanShare
        Grant re-share permission

    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)]$User,
        [Parameter()][switch]$CanEdit,
        [Parameter()][switch]$CanShare
    )
    
	[KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if ($Record -is [Array]) {
        if ($Record.Count -ne 1) {
            Write-Error -Message 'Only one record is expected' -ErrorAction Stop
        }
        $Record = $Record[0]
    }
    $uid = $null
    if ($Record -is [String]) {
        $uid = $Record
    } 
    elseif ($null -ne $Record.Uid) {
        $uid = $Record.Uid
    }

    if ($uid) {
        [KeeperSecurity.Vault.KeeperRecord] $rec = $null
        if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
            $entries = Get-KeeperChildItems -Filter $uid -ObjectType Record
            if ($entries.Uid) {
                $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
            }
        }
        if ($rec) {
            try {
                $vault.ShareRecordWithUser($rec.Uid, $User, $CanShare.IsPresent, $CanEdit.IsPresent).GetAwaiter().GetResult() | Out-Null
                Write-Host "Record `"$($rec.Title)`" was shared with $($User)"
            }
            catch [KeeperSecurity.Vault.NoActiveShareWithUserException] {
                Write-Host $_
                $prompt =  "Do you want to send share invitation request to `"$($User)`"? (Yes/No)"
                $answer = Read-Host -Prompt $prompt
                if ($answer -in 'yes', 'y') {
                    $vault.SendShareInvitationRequest($User).GetAwaiter().GetResult() | Out-Null
                    Write-Host("Invitation has been sent to $($User)`nPlease repeat this command when your invitation is accepted.");
                }
            }
        } else {
            Write-Error -Message "Cannot find a Keeper record: $Record"
        }
    } 
}
New-Alias -Name kshr -Value Grant-KeeperRecordAccess

function Revoke-KeeperRecordAccess {
    <#
        .Synopsis
        Shares a record with user

    	.Parameter Record
	    Record UID or any object containg record UID

        .Parameter User
	    User email
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)]$User
    )
    
	[KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if ($Record -is [Array]) {
        if ($Record.Count -ne 1) {
            Write-Error -Message 'Only one record is expected'
            return
        }
        $Record = $Record[0]
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
        [KeeperSecurity.Vault.KeeperRecord] $rec = $null
        if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
            $entries = Get-KeeperChildItems -Filter $uid -ObjectType Record
            if ($entries.Uid) {
                $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
            }
        }
        if ($rec) {
            $found = $true
            $vault.RevokeShareFromUser($rec.Uid, $User).GetAwaiter().GetResult() | Out-Null
            Write-Host "Record `"$($rec.Title)`" share has been removed from $($username)"
        }
    } 
    if (-not $found) {
        Write-Error -Message "Cannot find a Keeper record: $Record"
    }

}
New-Alias -Name kushr -Value Revoke-KeeperRecordAccess

function Grant-KeeperSharedFolderAccess {
    <#
        .Synopsis
        Adds a user or team to a shared foler

    	.Parameter SharedFolder
	    Shared Folder UID, name or any object containing property Uid

        .Parameter User
	    User email

        .Parameter Team
	    Team Name or UID
 
        .Parameter ManageRecords
        Grant Manage Records permission

        .Parameter ManageUsers
        Grant Manage Users permission

    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]$SharedFolder,
        [Parameter(Mandatory = $true, ParameterSetName='user')]$User,
        [Parameter(Mandatory = $true, ParameterSetName='team')]$Team,
        [Parameter()][switch]$ManageRecords,
        [Parameter()][switch]$ManageUsers
    )
    
    [KeeperSecurity.Vault.VaultOnline]$private:vault = getVault

    if ($SharedFolder -is [Array]) {
        if ($SharedFolder.Count -ne 1) {
            Write-Error -Message 'Only one shared folder is expected'
            return
        }
        $SharedFolder = $SharedFolder[0]
    }
    $uid = $null
    if ($SharedFolder -is [String]) {
        $uid = $SharedFolder
    } 
    elseif ($null -ne $Record.Uid) {
        $uid = $SharedFolder.Uid
    }

    if (-not $uid) {
        Write-Error -Message "Cannot find Shared Folder: $SharedFolder" -ErrorAction Stop
    }

    [KeeperSecurity.Vault.SharedFolder] $sf = $null
    if (-not $vault.TryGetSharedFolder($uid, [ref]$sf)) {
        $sf = $vault.SharedFolders | Where-Object { $_.Name -eq $uid } | Select-Object -First 1
    }
    if (-not $sf) {
        Write-Error -Message "Cannot find Shared Folder: $SharedFolder" -ErrorAction Stop
    }

    if ($User) {
        $userType = [KeeperSecurity.Vault.UserType]::User
        $userId = ([MailAddress]$User).Address
        $userName = $userId
        if (-not $userId) {
            return
        }
    } 
    elseif ($Team) {
        $userType = [KeeperSecurity.Vault.UserType]::Team
        [KeeperSecurity.Vault.TeamInfo]$teamInfo = $null
        if ($vault.TryGetTeam($Team, [ref]$teamInfo)) {
            $userId = $teamInfo.TeamUid
            $userName = $teamInfo.Name
        } else {
            $teamInfo = $vault.Teams | Where-Object {  $_.Name -eq $Team } | Select-Object -First 1
            if ($teamInfo) {
                $userId = $teamInfo.TeamUid
                $userName = $teamInfo.Name
            }
        }
        if (-not $userId) {
            ensureAvalableLoaded
            $teamInfo = $Script:Context.AvailableTeams | Where-Object { $_.TeamUid -ceq $Team -or $_.Name -eq $Team  } | Select-Object -First 1
            if ($teamInfo) {
                $userId = $teamInfo.TeamUid
                $userName = $teamInfo.Name
            }
        }

        if (-not $userId) {
            Write-Error  -Message "Cannot find team: $Team" -ErrorAction Stop
        }
    }

    try {
        $options = New-Object KeeperSecurity.Vault.SharedFolderUserOptions
        $options.ManageRecords = $ManageRecords.IsPresent
        $options.ManageUsers = $ManageUsers.IsPresent
        $vault.PutUserToSharedFolder($sf.Uid, $userId, $userType, $options).GetAwaiter().GetResult() | Out-Null
        Write-Host "${userType} `"$($userName)`" has been added to shared folder `"$($sf.Name)`""
    }
    catch [KeeperSecurity.Vault.NoActiveShareWithUserException] {
        Write-Host $_
        $prompt =  "Do you want to send share invitation request to `"$($User)`"? (Yes/No)"
        $answer = Read-Host -Prompt $prompt
        if ($answer -in 'yes', 'y') {
            $vault.SendShareInvitationRequest($User).GetAwaiter().GetResult() | Out-Null
            Write-Host("Invitation has been sent to `"$($User)`"`nPlease repeat this command when your invitation is accepted.");
        }
    }

}

function Revoke-KeeperSharedFolderAccess {
    <#
        .Synopsis
        Removes record share from user

    	.Parameter SharedFolder
	    Shared Folder UID, name or any object containing property Uid

        .Parameter User
	    User email

        .Parameter Team
	    Team Name or UID
 
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]$SharedFolder,
        [Parameter(Mandatory = $true, ParameterSetName='user')]$User,
        [Parameter(Mandatory = $true, ParameterSetName='team')]$Team
    )
    
    [KeeperSecurity.Vault.VaultOnline]$private:vault = getVault

    if ($SharedFolder -is [Array]) {
        if ($SharedFolder.Count -ne 1) {
            Write-Error -Message 'Only one shared folder is expected'
            return
        }
        $SharedFolder = $SharedFolder[0]
    }
    $uid = $null
    if ($SharedFolder -is [String]) {
        $uid = $SharedFolder
    } 
    elseif ($null -ne $Record.Uid) {
        $uid = $SharedFolder.Uid
    }

    if (-not $uid) {
        Write-Error -Message "Cannot find Shared Folder: $SharedFolder" -ErrorAction Stop
    }

    [KeeperSecurity.Vault.SharedFolder] $sf = $null
    if (-not $vault.TryGetSharedFolder($uid, [ref]$sf)) {
        $sf = $vault.SharedFolders | Where-Object { $_.Name -eq $uid } | Select-Object -First 1
    }
    if (-not $sf) {
        Write-Error -Message "Cannot find Shared Folder: $SharedFolder" -ErrorAction Stop
    }

    if ($User) {
        $userType = [KeeperSecurity.Vault.UserType]::User
        $userId = ([MailAddress]$User).Address
        $userName = $userId
        if (-not $userId) {
            return
        }
    } 
    elseif ($Team) {
        $userType = [KeeperSecurity.Vault.UserType]::Team
        [KeeperSecurity.Vault.TeamInfo]$teamInfo = $null
        if ($vault.TryGetTeam($Team, [ref]$teamInfo)) {
            $userId = $teamInfo.TeamUid
            $userName = $teamInfo.Name
        } else {
            $teamInfo = $vault.Teams | Where-Object {  $_.Name -eq $Team } | Select-Object -First 1
            if ($teamInfo) {
                $userId = $teamInfo.TeamUid
                $userName = $teamInfo.Name
            }
        }
        if (-not $userId) {
            ensureAvalableLoaded
            $teamInfo = $Script:Context.AvailableTeams | Where-Object { $_.TeamUid -ceq $Team -or $_.Name -eq $Team  } | Select-Object -First 1
            if ($teamInfo) {
                $userId = $teamInfo.TeamUid
                $userName = $teamInfo.Name
            }
        }

        if (-not $userId) {
            Write-Error  -Message "Cannot find team: $Team" -ErrorAction Stop
        }
    }

    $vault.RemoveUserFromSharedFolder($sf.Uid, $userId, $userType).GetAwaiter().GetResult() | Out-Null
    Write-Host "${userType} `"$($userName)`" has been removed from shared folder `"$($sf.Name)`""
}

function ensureAvalableLoaded {
    $vault = $Script:Context.Vault
    if (-not $vault) {
        return
    }

    if ($null -ne $Script:Context.AvailableTeams) {
        return
    }

    $Script:Context.AvailableTeams = @()
    $Script:Context.AvailableUsers = @()

    $teamTask = $vault.GetTeamsForShare()
    $userTask = $vault.GetUsersForShare()
    [System.Threading.Tasks.Task[]]$tasks = $teamTask, $userTask
    [System.Threading.Tasks.Task]::WaitAll($tasks) | Out-Null
    $Script:Context.AvailableTeams += $teamTask.GetAwaiter().GetResult()
    $userInfo = $userTask.GetAwaiter().GetResult()
    $users = @()
    $users += $userInfo.SharesWith
    $users += $userInfo.SharesFrom
    $users += $userInfo.GroupUsers

    $Script:Context.AvailableUsers += ($users | Sort-Object | Get-Unique)
}

$Keeper_TeamCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    ensureAvalableLoaded
    if (-not $Script:Context.AvailableTeams) {
        return $null
    }

	$result = @()
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
	foreach ($team in  $Script:Context.AvailableTeams) {
		if ($team.Name -like $toComplete) {
			$name = $team.Name
			if ($name -match ' ') {
				$name = $name -replace '''', ''''''
				$name = '''' + $name + ''''
			}
			$result += $name
		}
	}
	if ($result.Count -gt 0) {
		return $result
	} else {
		return $null
	}
}

$Keeper_UserCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    ensureAvalableLoaded
    if (-not $Script:Context.AvailableUsers) {
        return $null
    }

	$result = @()
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
	foreach ($user in  $Script:Context.AvailableUsers) {
		if ($user -like $toComplete) {
			$result += $user
		}
	}
	if ($result.Count -gt 0) {
		return $result
	} else {
		return $null
	}
}

Register-ArgumentCompleter -CommandName Grant-KeeperSharedFolderAccess -ParameterName Team -ScriptBlock $Keeper_TeamCompleter
Register-ArgumentCompleter -CommandName Grant-KeeperSharedFolderAccess -ParameterName User -ScriptBlock $Keeper_UserCompleter
Register-ArgumentCompleter -CommandName Grant-KeeperSharedFolderAccess -ParameterName SharedFolder -ScriptBlock $Keeper_SharedFolderCompleter

New-Alias -Name kshf -Value Grant-KeeperSharedFolderAccess

Register-ArgumentCompleter -CommandName Revoke-KeeperSharedFolderAccess -ParameterName Team -ScriptBlock $Keeper_TeamCompleter
Register-ArgumentCompleter -CommandName Revoke-KeeperSharedFolderAccess -ParameterName User -ScriptBlock $Keeper_UserCompleter
Register-ArgumentCompleter -CommandName Revoke-KeeperSharedFolderAccess -ParameterName SharedFolder -ScriptBlock $Keeper_SharedFolderCompleter

New-Alias -Name kushf -Value Revoke-KeeperSharedFolderAccess

function Get-KeeperAvailableTeams {
	<#
		.Synopsis
		Get Keeper Available Teams
	
		.Parameter Uid
		Team UID
	
		.Parameter Filter
		Return matching teams only
	#>
		[CmdletBinding()]
		[OutputType([KeeperSecurity.Vault.TeamInfo[]])] 
		Param (
			[string] $Uid,
			[string] $Filter
		)
	
        ensureAvalableLoaded
        $teams = $Script:Context.AvailableTeams 
		if ($Uid) {
            $teams | Where-Object { $_.TeamUid -ceq $Uid } | Select-Object -First 1
		} else {
			foreach ($team in $teams) {
				if ($Filter) {
					$match = $($team.Uid, $team.Name) | Select-String $Filter | Select-Object -First 1
					if (-not $match) {
						continue
					}
				}
				$team
			}
		}
	}
	New-Alias -Name kat -Value Get-KeeperAvailableTeams
	