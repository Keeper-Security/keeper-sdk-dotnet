#requires -Version 5.1


function Show-KeeperRecordShare {
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
                    $entries = Get-KeeperChildItem -Filter $uid -ObjectType Record
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
New-Alias -Name kshrsh -Value Show-KeeperRecordShare

function Move-KeeperRecordOwnership {
    <#
        .Synopsis
        Transfers record ownership to a user

    	.Parameter Record
	    Record UID or any object containing property Uid

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
            $entries = Get-KeeperChildItem -Filter $uid -ObjectType Record
            if ($entries.Uid) {
                $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
            }
        }
        if ($rec) {
            try {
                $vault.TransferRecordToUser($rec.Uid, $User).GetAwaiter().GetResult() | Out-Null
                Write-Output "Record `"$($rec.Title)`" was transfered to $($User)`nThe new record owner can edit or remove your access to this record."
            }
            catch [KeeperSecurity.Vault.NoActiveShareWithUserException] {
                Write-Output $_
                $prompt =  "Do you want to send share invitation request to `"$($User)`"? (Yes/No)"
                $answer = Read-Host -Prompt $prompt
                if ($answer -in 'yes', 'y') {
                    $vault.SendShareInvitationRequest($User).GetAwaiter().GetResult() | Out-Null
                    Write-Output("Invitation has been sent to $($User)`nPlease repeat this command when your invitation is accepted.");
                }
            }
        } else {
            Write-Error -Message "Cannot find a Keeper record: $Record"
        }
    }
}
New-Alias -Name ktr -Value Move-KeeperRecordOwnership
function Grant-KeeperRecordAccess {
    <#
    .SYNOPSIS
        Shares a Keeper record with a specified user.

    .DESCRIPTION
        Grants access to a Keeper record to another user. 
        You can specify edit and share permissions and optionally set an expiration using either a time offset (in seconds) or an ISO 8601-formatted expiration datetime.

    .PARAMETER Record
        The UID of the Keeper record to share, or an object containing a 'Uid' property.

    .PARAMETER User
        The email address of the user to share the record with.

    .PARAMETER CanEdit
        Optional switch to grant edit permissions on the record.

    .PARAMETER CanShare
        Optional switch to grant re-share permissions on the record.

    .PARAMETER TimeOffset
        Optional. Expiration time offset in seconds from now. Mutually exclusive with ExpirationDateTimeISO.

    .PARAMETER ExpirationDateTimeISO
        Optional. An absolute expiration time in ISO 8601 or RFC 1123 format (e.g., "2025-05-23T08:59:11Z" or "Fri, 23 May 2025 08:59:11 GMT").

    .EXAMPLE
        Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "jane.doe@example.com" -CanEdit -CanShare

        Shares the record with full permissions (edit and re-share) with Jane Doe.

    .EXAMPLE
        Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "john.doe@example.com" -TimeOffset 3600

        Shares the record with John Doe for 1 hour from now.

    .EXAMPLE
        Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "alice@example.com" -ExpirationDateTimeISO "2025-05-23T08:59:11Z"

        Shares the record with Alice until the specified UTC datetime.

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)]$User,
        [Parameter()][switch]$CanEdit,
        [Parameter()][switch]$CanShare,
        [Parameter()][System.Nullable[int]]$TimeOffset,
        [Parameter()][string]$ExpirationDateTimeISO
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

    $options = [KeeperSecurity.Vault.SharedFolderRecordOptions]::new()
    try{
        $expirationDateTimeOffset = Get-ExpirationDateTimeOffset -TimeOffset $TimeOffset -ExpirationDateTime $ExpirationDateTimeISO
        $options.CanEdit = $CanEdit.IsPresent
        $options.CanShare = $CanShare.IsPresent
        $options.Expiration = $expirationDateTimeOffset
    }catch  {
        Write-Error "Error: $($_.Exception.Message)" -ErrorAction Stop
        throw
    }

    if ($uid) {
        [KeeperSecurity.Vault.KeeperRecord] $rec = $null
        if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
            $entries = Get-KeeperChildItem -Filter $uid -ObjectType Record
            if ($entries.Uid) {
                $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
            }
        }
        if ($rec) {
            try {
                $vault.ShareRecordWithUser($rec.Uid, $User, $options).GetAwaiter().GetResult() | Out-Null
                Write-Output "Record `"$($rec.Title)`" was shared with $($User)"
            }
            catch [KeeperSecurity.Vault.NoActiveShareWithUserException] {
                Write-Output $_
                $prompt = "Do you want to send share invitation request to `"$($User)`"? (Yes/No)"
                $answer = Read-Host -Prompt $prompt
                if ($answer -in 'yes', 'y') {
                    $vault.SendShareInvitationRequest($User).GetAwaiter().GetResult() | Out-Null
                    Write-Output("Invitation has been sent to $($User)`nPlease repeat this command when your invitation is accepted.");
                }
            }
        }
        else {
            Write-Error -Message "Cannot find a Keeper record: $Record"
        }
    }
}
New-Alias -Name kshr -Value Grant-KeeperRecordAccess

function Get-ExpirationDateTimeOffset {
    param(
        [System.Nullable[int]]$TimeOffset,
        [string]$ExpirationDateTime
    )
        
    if ($TimeOffset) {
        return [System.DateTimeOffset]::UtcNow.AddSeconds($TimeOffset)
    }
    elseif ($ExpirationDateTime) {
        $expirationDateTimeOffset = if ($ExpirationDateTime) {
            [DateTimeOffset]::Parse($ExpirationDateTime)
        } else {
            $null
        }
        return $expirationDateTimeOffset
    }
    else {
        return $null  # No expiration
    }
}
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
            $entries = Get-KeeperChildItem -Filter $uid -ObjectType Record
            if ($entries.Uid) {
                $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
            }
        }
        if ($rec) {
            $found = $true
            $vault.RevokeShareFromUser($rec.Uid, $User).GetAwaiter().GetResult() | Out-Null
            Write-Output "Record `"$($rec.Title)`" share has been removed from $($username)"
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
        Write-Output "${userType} `"$($userName)`" has been added to shared folder `"$($sf.Name)`""
    }
    catch [KeeperSecurity.Vault.NoActiveShareWithUserException] {
        Write-Output $_
        $prompt =  "Do you want to send share invitation request to `"$($User)`"? (Yes/No)"
        $answer = Read-Host -Prompt $prompt
        if ($answer -in 'yes', 'y') {
            $vault.SendShareInvitationRequest($User).GetAwaiter().GetResult() | Out-Null
            Write-Output("Invitation has been sent to `"$($User)`"`nPlease repeat this command when your invitation is accepted.");
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
    Write-Output "${userType} `"$($userName)`" has been removed from shared folder `"$($sf.Name)`""
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

function Get-KeeperAvailableTeam {
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
	New-Alias -Name kat -Value Get-KeeperAvailableTeam

    function New-KeeperOneTimeShare {
        <#
        .Synopsis
        New Keeper One-Time Share

        .Parameter Uid
        Shared Record UID

        .Parameter Expiration
        Expiration TimeSpan

        .Parameter ShareName
        One-Time Share Name
    #>
        [CmdletBinding()]
        [OutputType([string])]
        Param (
            [Parameter(Mandatory = $true)][string] $Uid,
            [Parameter(Mandatory=$true)][TimeSpan] $ExpireIn,
            [Parameter(Mandatory=$false)][string] $ShareName
        )

        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $oneTimeShare = [KeeperSecurity.Vault.ExternalRecordShareExtensions]::CreateExternalRecordShare($vault, $Uid, $ExpireIn, $ShareName).GetAwaiter().GetResult()
        return $oneTimeShare
    }

    New-Alias -Name kotsn -Value New-KeeperOneTimeShare

    function Get-KeeperOneTimeShare {
        <#
        .Synopsis
        Get Keeper One-Time Shares

        .Parameter Uid
        Shared Record UID

    #>
        [CmdletBinding()]
        [OutputType([string])]
        Param (
            [Parameter(Mandatory = $true, Position=0)][string] $Uid
        )

        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        [KeeperSecurity.Vault.ExternalRecordShareExtensions]::GetExernalRecordShares($vault, $Uid).GetAwaiter().GetResult()
    }
    New-Alias -Name kotsg -Value Get-KeeperOneTimeShare

    function Remove-KeeperOneTimeShare {
        <#
        .Synopsis
        Deletes Keeper One-Time Share(s)

        .Parameter Uid
        Shared Record UID

        .Parameter ShareName
        One-Time Share Name
    #>
        [CmdletBinding()]
        [OutputType([string])]
        Param (
            [Parameter(Mandatory = $true)][string] $Uid,
            [string[]] $ShareName
        )

        [KeeperSecurity.Vault.VaultOnline]$vault = getVault

        $shares = Get-KeeperOneTimeShare $Uid
        [String[]]$clientUids = @()
        foreach ($n in $ShareName) {
            $share = $shares | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            if ($share) {
                $clientUids += $share.ClientId
            } else {
                Write-Information -MessageData "One-Time Share not found: $n"
            }
        }
        [KeeperSecurity.Vault.ExternalRecordShareExtensions]::DeleteExernalRecordShares($vault, $Uid, $clientUids).GetAwaiter().GetResult() | Out-Null
    }
    New-Alias -Name kotsr -Value Remove-KeeperOneTimeShare
