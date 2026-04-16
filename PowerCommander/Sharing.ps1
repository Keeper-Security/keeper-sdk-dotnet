#requires -Version 5.1


function Show-KeeperRecordShare {
    <#
        .Synopsis
        Displays sharing information for one or more records (who the record is shared with and permissions).

        .Description
        Displays sharing information for one or more records (who the record is shared with and permissions).

        Alias: kshrsh

        .Parameter Records
        Record UID(s) or objects with a Uid property (Required, accepts pipeline)

        .Example
        Show-KeeperRecordShare -Records "record-uid"
        Display sharing info for a single record by UID

        .Example
        kshrsh "record-uid"
        Display sharing info using the alias

        .Example
        Get-KeeperChildItem -Filter "myrecord" | Show-KeeperRecordShare
        Pipe search results to display their sharing info
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]$Records
    )
    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $recordMap = [System.Collections.Generic.Dictionary[string, string]]::new()
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
                    $recordMap[$rec.Uid] = $rec.Title
                } else {
                    Write-Error -Message "Cannot find a Keeper record: $r" -ErrorAction SilentlyContinue
                }
            }
        }
    }

    End {
        if ($recordMap.Count -eq 0) { return }

        try {
            $shares = $vault.GetSharesForRecords($recordMap.Keys).GetAwaiter().GetResult()
        }
        catch {
            Write-Error "Failed to retrieve sharing information: $_"
            return
        }

        foreach ($shareInfo in $shares) {
            $title = if ($recordMap.ContainsKey($shareInfo.RecordUid)) { $recordMap[$shareInfo.RecordUid] } else { $shareInfo.RecordUid }

            Write-Host ""
            Write-Host "Record UID:  $($shareInfo.RecordUid)"
            Write-Host "Title:       $title"

            if ($shareInfo.UserPermissions -and $shareInfo.UserPermissions.Length -gt 0) {
                Write-Host ""
                Write-Host "User Shares:"
                foreach ($up in $shareInfo.UserPermissions) {
                    $status = $up.ShareStatus
                    if ($up.Expiration) {
                        $status += " (Expires: $($up.Expiration.Value.LocalDateTime.ToString('g')))"
                    }
                    Write-Host "  $($up.Username): $status"
                }
            }

            if ($shareInfo.SharedFolderPermissions -and $shareInfo.SharedFolderPermissions.Length -gt 0) {
                Write-Host ""
                Write-Host "Shared Folders:"
                foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                    $status = $sfp.ShareStatus
                    $name = if ($sfp.SharedFolderName) { $sfp.SharedFolderName } else { $sfp.SharedFolderUid }
                    if ($sfp.Expiration) {
                        $status += " (Expires: $($sfp.Expiration.Value.LocalDateTime.ToString('g')))"
                    }
                    Write-Host "  ${name}: $status"
                }
            }
        }
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
                Write-Output "Record `"$($rec.Title)`" was transferred to $($User)`nThe new record owner can edit or remove your access to this record."
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
            Shares a Keeper record with a specified user, with optional edit/share permissions and flexible expiration input.

        .DESCRIPTION
            Grants access to a Keeper record to another user. 
            You can specify edit and share permissions and optionally set an expiration using a time offset 
            (as a TimeSpan object, minutes as an integer or string, or a TimeSpan-formatted string) 
            or an ISO 8601-formatted absolute expiration datetime.

        .PARAMETER Record
            The UID of the Keeper record to share, or an object containing a 'Uid' property.

        .PARAMETER User
            The email address of the user to share the record with.

        .PARAMETER CanEdit
            Optional switch to grant edit permissions on the record.

        .PARAMETER CanShare
            Optional switch to grant re-share permissions on the record.

        .PARAMETER ExpireIn
            Optional. Expiration time offset from now. Can be a TimeSpan object, integer (minutes), or a string representing minutes or a TimeSpan.

        .PARAMETER ExpireAt
            Optional. An absolute expiration time in ISO 8601 or RFC 1123 format (e.g., "2025-05-23T08:59:11Z" or "Fri, 23 May 2025 08:59:11 GMT").

        .EXAMPLE
            Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "jane.doe@example.com" -CanEdit -CanShare

            Shares the record with full permissions (edit and re-share) with Jane Doe.

        .EXAMPLE
            Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "john.doe@example.com" -ExpireIn 60

            Shares the record with John Doe for 1 hour from now.

        .EXAMPLE
            Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "alice@example.com" -ExpireIn "00:30:00"

            Shares the record with Alice for 30 minutes.

        .EXAMPLE
            Grant-KeeperRecordAccess -Record "XP-TKMqg9kIf4RXLuW4Qwg" -User "bob@example.com" -ExpireAt "2025-05-23T08:59:11Z"

            Shares the record with Bob until the specified UTC datetime.
    #>


    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)]$User,
        [Parameter()][switch]$CanEdit,
        [Parameter()][switch]$CanShare,
        [Parameter()][System.Object]$ExpireIn,
        [Parameter()][string]$ExpireAt
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
        $expiration = Get-ExpirationDate -ExpireIn $ExpireIn -ExpireAt $ExpireAt
        $options.CanEdit = $CanEdit.IsPresent
        $options.CanShare = $CanShare.IsPresent
        $options.Expiration = $expiration
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

function Get-ExpirationDate {
    param(
        [object]$ExpireIn,
        [string]$ExpireAt
    )

    $expireOffset = $null

    if ($ExpireIn) {
        if ($ExpireIn -is [TimeSpan]) {
            $expireOffset = $ExpireIn
        }
        elseif ($ExpireIn -is [int] -or $ExpireIn -is [long] -or $ExpireIn -is [double] -or $ExpireIn -is [decimal]) {
            $expireOffset = [TimeSpan]::FromMinutes([double]$ExpireIn)
        }
        elseif ($ExpireIn -is [string]) {
            $parsedMinutes = $null
            if ([int]::TryParse($ExpireIn, [ref]$parsedMinutes)) {
                $expireOffset = [TimeSpan]::FromMinutes($parsedMinutes)
            }
            else {
                try {
                    $expireOffset = [TimeSpan]::Parse($ExpireIn)
                }
                catch {
                    throw "Cannot parse ExpireIn string value '$ExpireIn' - not a number or valid TimeSpan string."
                }
            }
        }
        else {
            throw "Unsupported type for ExpireIn: $($ExpireIn.GetType().FullName)"
        }

        return [DateTimeOffset]::UtcNow.Add($expireOffset)
    }
    elseif ($ExpireAt) {
        try {
            return [DateTimeOffset]::Parse($ExpireAt)
        }
        catch {
            throw "Cannot parse ExpireAt: '$ExpireAt'. Must be a valid ISO 8601 or RFC 1123 string."
        }
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

function Revoke-KeeperSharesWithUser {
    <#
        .SYNOPSIS
        Cancels all record shares with a user.

        .DESCRIPTION
        Removes all record shares between the current account and the specified user.
        This is equivalent to the share-record cancel action in the Commander CLI.

        .PARAMETER User
        Email address of the user with whom to cancel all shares.

        .EXAMPLE
        Revoke-KeeperSharesWithUser -User "user@example.com"
        Cancels all record shares with user@example.com (after confirmation).

        .EXAMPLE
        Revoke-KeeperSharesWithUser -User "user@example.com" -Confirm:$false
        Cancels all record shares without prompting for confirmation.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true)]$User
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if ($PSCmdlet.ShouldProcess("all record shares with user `"$User`"", "Cancel")) {
        try {
            $vault.CancelSharesWithUser($User).GetAwaiter().GetResult() | Out-Null
            Write-Output "All record shares with user `"$User`" have been cancelled."
        }
        catch {
            Write-Error -Message "Failed to cancel shares with user `"$User`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }
}
New-Alias -Name kcancelshare -Value Revoke-KeeperSharesWithUser

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
        .SYNOPSIS
            Creates a secure one-time share link for a Keeper record, with optional expiration settings and a custom name.

        .DESCRIPTION
            This command generates a one-time access link to a specified Keeper record. 
            You can choose to set the link to expire after a specific duration (ExpireIn) or at an exact date/time (ExpireAt). 
            You may also provide a custom name for easier identification. Once the link expires or is used, it can no longer be accessed.

        .PARAMETER Uid
            The UID of the record to share.

        .PARAMETER ExpireIn
            Optional. Expiration offset (TimeSpan, string, or integer in minutes).

        .PARAMETER ExpireAt
            Optional. Absolute expiration timestamp (ISO 8601 or RFC 1123).

        .PARAMETER ShareName
            Optional. Custom label for the one-time share.

        .EXAMPLE
            New-KeeperOneTimeShare -Uid "XP-TKMqg9kIf4RXLuW4Qwg" -ExpireIn 60
            Creates a one-time share link for the record that expires in 60 minutes from now.

        .EXAMPLE
            New-KeeperOneTimeShare -Uid "XP-TKMqg9kIf4RXLuW4Qwg" -ExpireIn "00:45:00" -ShareName "Temporary Share"
            Creates a one-time share that expires in 45 minutes with a custom label "Temporary Share".

        .EXAMPLE
            New-KeeperOneTimeShare -Uid "XP-TKMqg9kIf4RXLuW4Qwg" -ExpireAt "2025-05-28T12:00:00Z"
            Creates a one-time share that will expire exactly at the specified UTC time.

        .EXAMPLE
            New-KeeperOneTimeShare -Uid "XP-TKMqg9kIf4RXLuW4Qwg" -ExpireAt "Wed, 28 May 2025 12:00:00 GMT" -ShareName "Expires Noon"
            Creates a one-time share that expires at 12 PM UTC on May 28, 2025, with the name "Expires Noon".

    #>

    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory = $true)][string] $Uid,
        [Parameter()][object] $ExpireIn,
        [Parameter()][string] $ExpireAt,
        [Parameter()][string] $ShareName
    )

    try {
        $expiration = Get-ExpirationDate -ExpireIn $ExpireIn -ExpireAt $ExpireAt
        if (-not $expiration) {
            throw "You must provide either ExpireIn or ExpireAt."
        }

        $expirationTimeSpan = $expiration.ToUniversalTime() - [DateTimeOffset]::UtcNow

        [KeeperSecurity.Vault.VaultOnline]$vault = GetVault
        $oneTimeShare = [KeeperSecurity.Vault.ExternalRecordShareExtensions]::CreateExternalRecordShare(
            $vault, $Uid, $expirationTimeSpan, $ShareName
        ).GetAwaiter().GetResult()

        return $oneTimeShare
    }
    catch {
        Write-Error "Error creating one-time share: $($_.Exception.Message)" -ErrorAction Stop
    }
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

function Get-KeeperComplianceRestResponse {
    param(
        [Parameter(Mandatory = $true)]$Auth,
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter()]$Request,
        [Parameter(Mandatory = $true)][type]$ResponseType
    )

    return $Auth.ExecuteAuthRest($Endpoint, $Request, $ResponseType).GetAwaiter().GetResult()
}

function Write-KeeperComplianceStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )

    Write-Verbose -Message "[compliance] $Message"
}

function Set-KeeperComplianceLastSnapshotStatus {
    param(
        [Parameter()][bool]$FromCache = $false,
        [Parameter()][bool]$Incomplete = $false,
        [Parameter()][int]$PreliminaryUsersSkipped = 0,
        [Parameter()][int]$FullComplianceFailures = 0,
        [Parameter()][bool]$PrivilegeDeniedStoppedFullFetch = $false,
        [Parameter()][int]$RecordMetadataDecryptFailures = 0,
        [Parameter()][datetime]$BuiltAt = (Get-Date)
    )

    $script:ComplianceReportLastSnapshotStatus = [PSCustomObject][ordered]@{
        PSTypeName = 'KeeperComplianceSnapshotStatus'
        FromCache = $FromCache
        Incomplete = $Incomplete
        PreliminaryUsersSkipped = $PreliminaryUsersSkipped
        FullComplianceFailures = $FullComplianceFailures
        PrivilegeDeniedStoppedFullFetch = $PrivilegeDeniedStoppedFullFetch
        RecordMetadataDecryptFailures = $RecordMetadataDecryptFailures
        BuiltAt = $BuiltAt
    }
}

function ConvertTo-KeeperComplianceUid {
    param(
        [Parameter()]$ByteString
    )

    if (-not $ByteString -or $ByteString.IsEmpty) {
        return ''
    }

    return [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($ByteString.ToByteArray())
}

function Get-KeeperComplianceRecordData {
    param(
        [Parameter()]$EncryptedData,
        [Parameter()]$EcPrivateKey,
        [Parameter()]$Diagnostics,
        [Parameter()][string]$RecordUid,
        [Parameter()][ValidateSet('preliminary', 'full-compliance')][string]$Source = 'preliminary'
    )

    $result = [PSCustomObject]@{
        Title      = ''
        RecordType = ''
        Url        = ''
    }

    $ctx = if ($RecordUid) { "record=$RecordUid source=$Source" } else { "source=$Source" }

    if (-not $EncryptedData -or $EncryptedData.IsEmpty -or -not $EcPrivateKey) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx skipped (no ciphertext or EC key)."
        return $result
    }

    $encBytes = $EncryptedData.ToByteArray()

    $jsonBytes = $null
    try {
        $jsonBytes = [KeeperSecurity.Utils.CryptoUtils]::DecryptEc($encBytes, $EcPrivateKey)
    }
    catch {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx DecryptEc failed: $($_.Exception.Message)"
        if ($Diagnostics) {
            $Diagnostics.RecordDataFailures = [int]$Diagnostics.RecordDataFailures + 1
        }
        return $result
    }

    if ($null -eq $jsonBytes -or $jsonBytes.Length -eq 0) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx decrypt ok but plaintext length=0."
        return $result
    }

    $decodeOffset = 0
    if ($jsonBytes.Length -ge 3 -and $jsonBytes[0] -eq 0xEF -and $jsonBytes[1] -eq 0xBB -and $jsonBytes[2] -eq 0xBF) {
        $decodeOffset = 3
    }
    $jsonText = [System.Text.Encoding]::UTF8.GetString($jsonBytes, $decodeOffset, $jsonBytes.Length - $decodeOffset)
    if ($jsonText.Length -gt 0 -and [int][char]$jsonText[0] -eq 0xFEFF) {
        $jsonText = $jsonText.Substring(1)
    }
    $jsonText = $jsonText.Trim()
    if ([string]::IsNullOrWhiteSpace($jsonText)) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx decrypt ok but JSON text empty after trim."
        return $result
    }

    $auditData = $null
    try {
        $auditData = $jsonText | ConvertFrom-Json
    }
    catch {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx ConvertFrom-Json failed: $($_.Exception.Message)"
        if ($Diagnostics) {
            $Diagnostics.RecordDataFailures = [int]$Diagnostics.RecordDataFailures + 1
        }
        return $result
    }

    if ($null -eq $auditData) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx JSON root is null."
        return $result
    }
    if ($auditData -isnot [PSCustomObject]) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx JSON root is not an object (type=$($auditData.GetType().FullName))."
        return $result
    }

    foreach ($prop in $auditData.PSObject.Properties) {
        $n = [string]$prop.Name
        if ($n -ieq 'title') {
            $result.Title = [string]$prop.Value
        }
        elseif ($n -ieq 'record_type') {
            $result.RecordType = [string]$prop.Value
        }
        elseif ($n -ieq 'url') {
            $result.Url = [string]$prop.Value
        }
    }

    $titleLen = if ($result.Title) { $result.Title.Length } else { 0 }
    $urlLen = if ($result.Url) { $result.Url.Length } else { 0 }
    Write-KeeperComplianceStatus "Compliance metadata: $ctx extracted title_length=$titleLen record_type='$($result.RecordType)' url_length=$urlLen"

    return $result
}

function Merge-KeeperComplianceRecordFields {
    param(
        [Parameter(Mandatory = $true)]$RecordEntry,
        [Parameter(Mandatory = $true)]$RecordData
    )

    if ([string]::IsNullOrEmpty([string]$RecordEntry.Title) -and $RecordData.Title) {
        $RecordEntry.Title = [string]$RecordData.Title
    }
    if ([string]::IsNullOrEmpty([string]$RecordEntry.RecordType) -and $RecordData.RecordType) {
        $RecordEntry.RecordType = [string]$RecordData.RecordType
    }
    if ([string]::IsNullOrEmpty([string]$RecordEntry.Url) -and $RecordData.Url) {
        $RecordEntry.Url = [string]$RecordData.Url
    }
}

function Get-KeeperCompliancePrelimRequeueUserIds {
    param(
        [Parameter(Mandatory = $true)]$UserChunk,
        [Parameter(Mandatory = $true)]$SeenUserIds
    )

    $completeIds = [System.Collections.Generic.HashSet[long]]::new()
    if ($SeenUserIds.Count -gt 1) {
        foreach ($completedUserId in ($SeenUserIds | Select-Object -First ($SeenUserIds.Count - 1))) {
            $completeIds.Add([long]$completedUserId) | Out-Null
        }
    }
    return @($UserChunk | Where-Object { -not $completeIds.Contains([long]$_) })
}

function Add-KeeperComplianceUserQueueFront {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.Queue[long]]$Queue,
        [Parameter(Mandatory = $true)][long[]]$FrontIds
    )

    $newQ = [System.Collections.Generic.Queue[long]]::new()
    foreach ($id in $FrontIds) {
        $newQ.Enqueue($id)
    }
    while ($Queue.Count -gt 0) {
        $newQ.Enqueue($Queue.Dequeue())
    }
    return $newQ
}

$script:KeeperCompliancePermissionMasks = @(
    [PSCustomObject]@{ Mask = 1;  Name = 'owner' }
    [PSCustomObject]@{ Mask = 2;  Name = 'mask' }
    [PSCustomObject]@{ Mask = 4;  Name = 'edit' }
    [PSCustomObject]@{ Mask = 8;  Name = 'share' }
    [PSCustomObject]@{ Mask = 16; Name = 'share_admin' }
)
$script:KeeperCompliancePermissionShareAdmin = 16

function Get-KeeperCompliancePermissionText {
    param(
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    $permissions = @()
    foreach ($permissionMask in $script:KeeperCompliancePermissionMasks) {
        if (($PermissionBits -band [int]$permissionMask.Mask) -ne 0) {
            $permissions += [string]$permissionMask.Name
        }
    }

    if ($permissions.Count -eq 0) {
        $permissions += 'read-only'
    }

    return ($permissions -join ',')
}

function Add-KeeperCompliancePermissionBits {
    param(
        [Parameter(Mandatory = $true)]$PermissionLookup,
        [Parameter(Mandatory = $true)][long]$UserUid,
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    $currentBits = 0
    if ($PermissionLookup.ContainsKey($UserUid)) {
        $currentBits = [int]$PermissionLookup[$UserUid]
    }
    $PermissionLookup[$UserUid] = ($currentBits -bor $PermissionBits)
}

function Ensure-KeeperComplianceRecordEntry {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$RecordUid,
        [Parameter()][bool]$Shared = $false
    )

    if (-not $Snapshot.Records.ContainsKey($RecordUid)) {
        $Snapshot.Records[$RecordUid] = [PSCustomObject]@{
            Uid              = $RecordUid
            Title            = ''
            RecordType       = ''
            Url              = ''
            Shared           = $Shared
            InTrash          = $false
            UserPermissions  = @{}
            SharedFolderUids = [System.Collections.Generic.HashSet[string]]::new()
        }
    }
    elseif ($Shared -and -not $Snapshot.Records[$RecordUid].Shared) {
        $Snapshot.Records[$RecordUid].Shared = $true
    }

    return $Snapshot.Records[$RecordUid]
}

function Ensure-KeeperComplianceSharedFolderEntry {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$SharedFolderUid
    )

    if (-not $Snapshot.SharedFolders.ContainsKey($SharedFolderUid)) {
        $Snapshot.SharedFolders[$SharedFolderUid] = [PSCustomObject]@{
            Uid               = $SharedFolderUid
            Users             = [System.Collections.Generic.HashSet[long]]::new()
            Teams             = [System.Collections.Generic.HashSet[string]]::new()
            RecordPermissions = @{}
        }
    }

    return $Snapshot.SharedFolders[$SharedFolderUid]
}

function Add-KeeperCompliancePermissionByEmail {
    param(
        [Parameter(Mandatory = $true)]$PermissionLookup,
        [Parameter()][string]$Email,
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    if (-not $Email) {
        return
    }

    $existingBits = 0
    if ($PermissionLookup.ContainsKey($Email)) {
        $existingBits = [int]$PermissionLookup[$Email]
    }
    $PermissionLookup[$Email] = ($existingBits -bor $PermissionBits)
}

function Add-KeeperCompliancePermissionByUserUid {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)]$PermissionLookup,
        [Parameter(Mandatory = $true)][long]$TargetUid,
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    if (-not $Snapshot.Users.ContainsKey($TargetUid)) {
        return
    }

    Add-KeeperCompliancePermissionByEmail -PermissionLookup $PermissionLookup `
        -Email ([string]$Snapshot.Users[$TargetUid].Email) -PermissionBits $PermissionBits
}

function Write-KeeperReportOutput {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter()]$DisplayRows,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][int]$JsonDepth = 6,
        [Parameter()][string[]]$TableColumns
    )

    if ($null -eq $DisplayRows) {
        $DisplayRows = $Rows
    }

    if ($Output -and $Format -ne 'table') {
        $outPath = $Output
        switch ($Format) {
            'json' { Set-Content -Path $outPath -Value ($DisplayRows | ConvertTo-Json -Depth $JsonDepth) -Encoding utf8 }
            'csv'  { $DisplayRows | Export-Csv -Path $outPath -NoTypeInformation -Encoding utf8 }
        }
        Write-Host "Report exported to $outPath ($($Rows.Count) row(s) found)"
        return
    }

    switch ($Format) {
        'json' { $DisplayRows | ConvertTo-Json -Depth $JsonDepth }
        'csv'  { $DisplayRows | ConvertTo-Csv -NoTypeInformation }
        default {
            Write-Host ""
            $resolvedTableColumns = @(
                @($TableColumns) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            )
            if ($resolvedTableColumns.Count -eq 0 -and $DisplayRows.Count -gt 0) {
                $resolvedTableColumns = @($DisplayRows[0].PSObject.Properties.Name)
            }
            if ($resolvedTableColumns.Count -gt 0) {
                $DisplayRows | Format-Table -Property $resolvedTableColumns -AutoSize
            }
            else {
                $DisplayRows | Format-Table -AutoSize
            }
        }
    }
}

function Resolve-KeeperComplianceNode {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter()][string]$Context = 'compliance report'
    )

    try {
        return (resolveSingleNode $Node)
    }
    catch {
        $message = [string]$_.Exception.Message
        if ($message.IndexOf('not found', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Write-Error -Message "Cannot resolve node `"$Node`" for $Context. Use Get-KeeperEnterpriseNode or kein to list valid node IDs and names." -ErrorAction Stop
        }
        if ($message.IndexOf('not unique', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Write-Error -Message "Node name `"$Node`" is ambiguous for $Context. Use the numeric node ID instead. Run Get-KeeperEnterpriseNode or kein to find the exact ID." -ErrorAction Stop
        }
        throw
    }
}

function Update-KeeperComplianceAnonymousUsers {
    param(
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][long]$AnonymousSeed
    )

    $anonymousUserIds = @{}
    $nextSeed = $AnonymousSeed

    foreach ($userProfile in $Response.UserProfiles) {
        $userId = [long]$userProfile.EnterpriseUserId
        if (($userId -shr 32) -ne 0) {
            continue
        }

        $newUserId = $userId + $nextSeed
        $anonymousUserIds[$userId] = $newUserId
        $userProfile.EnterpriseUserId = $newUserId
        $nextSeed = $newUserId
    }

    foreach ($userRecord in $Response.UserRecords) {
        $userId = [long]$userRecord.EnterpriseUserId
        if ($anonymousUserIds.ContainsKey($userId)) {
            $userRecord.EnterpriseUserId = [long]$anonymousUserIds[$userId]
        }
    }

    foreach ($sharedFolderUser in $Response.SharedFolderUsers) {
        for ($i = 0; $i -lt $sharedFolderUser.EnterpriseUserIds.Count; $i++) {
            $userId = [long]$sharedFolderUser.EnterpriseUserIds[$i]
            if ($anonymousUserIds.ContainsKey($userId)) {
                $sharedFolderUser.EnterpriseUserIds[$i] = [long]$anonymousUserIds[$userId]
            }
        }
    }

    return $nextSeed
}

function Merge-KeeperComplianceResponse {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)]$Response
    )

    foreach ($userProfile in $Response.UserProfiles) {
        $userUid = [long]$userProfile.EnterpriseUserId
        if (-not $Snapshot.Users.ContainsKey($userUid)) {
            $Snapshot.Users[$userUid] = [PSCustomObject]@{
                UserUid  = $userUid
                Email    = [string]$userProfile.Email
                FullName = [string]$userProfile.FullName
                JobTitle = [string]$userProfile.JobTitle
                NodeId   = 0L
            }
            continue
        }

        if ([string]::IsNullOrEmpty([string]$Snapshot.Users[$userUid].Email) -and $userProfile.Email) {
            $Snapshot.Users[$userUid].Email = [string]$userProfile.Email
        }
        if ([string]::IsNullOrEmpty([string]$Snapshot.Users[$userUid].FullName) -and $userProfile.FullName) {
            $Snapshot.Users[$userUid].FullName = [string]$userProfile.FullName
        }
        if ($userProfile.JobTitle) {
            $Snapshot.Users[$userUid].JobTitle = [string]$userProfile.JobTitle
        }
    }

    foreach ($auditRecord in $Response.AuditRecords) {
        $recordUid = ConvertTo-KeeperComplianceUid -ByteString $auditRecord.RecordUid
        if (-not $recordUid) {
            continue
        }

        $recordEntry = Ensure-KeeperComplianceRecordEntry -Snapshot $Snapshot -RecordUid $recordUid

        $recordData = Get-KeeperComplianceRecordData -EncryptedData $auditRecord.AuditData -EcPrivateKey $Snapshot.EcPrivateKey `
            -Diagnostics $Snapshot.Diagnostics -RecordUid $recordUid -Source 'full-compliance'
        Merge-KeeperComplianceRecordFields -RecordEntry $recordEntry -RecordData $recordData

        $recordEntry.InTrash = [bool]$auditRecord.InTrash
    }

    foreach ($auditTeamUser in $Response.AuditTeamUsers) {
        $teamUid = ConvertTo-KeeperComplianceUid -ByteString $auditTeamUser.TeamUid
        if (-not $teamUid) {
            continue
        }

        if (-not $Snapshot.Teams.ContainsKey($teamUid)) {
            $Snapshot.Teams[$teamUid] = [PSCustomObject]@{
                Uid   = $teamUid
                Users = [System.Collections.Generic.HashSet[long]]::new()
            }
        }

        foreach ($userUid in $auditTeamUser.EnterpriseUserIds) {
            $Snapshot.Teams[$teamUid].Users.Add([long]$userUid) | Out-Null
        }
    }

    foreach ($sharedFolderRecord in $Response.SharedFolderRecords) {
        $sharedFolderUid = ConvertTo-KeeperComplianceUid -ByteString $sharedFolderRecord.SharedFolderUid
        if (-not $sharedFolderUid) {
            continue
        }

        $sharedFolderEntry = Ensure-KeeperComplianceSharedFolderEntry -Snapshot $Snapshot -SharedFolderUid $sharedFolderUid

        foreach ($recordPermission in $sharedFolderRecord.RecordPermissions) {
            $recordUid = ConvertTo-KeeperComplianceUid -ByteString $recordPermission.RecordUid
            if (-not $recordUid) {
                continue
            }

            $existingBits = 0
            if ($sharedFolderEntry.RecordPermissions.ContainsKey($recordUid)) {
                $existingBits = [int]$sharedFolderEntry.RecordPermissions[$recordUid]
            }
            $sharedFolderEntry.RecordPermissions[$recordUid] = ($existingBits -bor [int]$recordPermission.PermissionBits)

            $recordEntry = Ensure-KeeperComplianceRecordEntry -Snapshot $Snapshot -RecordUid $recordUid -Shared:$true
            $recordEntry.SharedFolderUids.Add($sharedFolderUid) | Out-Null
        }

        foreach ($shareAdminRecord in $sharedFolderRecord.ShareAdminRecords) {
            foreach ($recordPermissionIndex in $shareAdminRecord.RecordPermissionIndexes) {
                if ($recordPermissionIndex -lt 0 -or $recordPermissionIndex -ge $sharedFolderRecord.RecordPermissions.Count) {
                    continue
                }

                $recordPermission = $sharedFolderRecord.RecordPermissions[$recordPermissionIndex]
                $recordUid = ConvertTo-KeeperComplianceUid -ByteString $recordPermission.RecordUid
                if (-not $recordUid -or -not $Snapshot.Records.ContainsKey($recordUid)) {
                    continue
                }

                Add-KeeperCompliancePermissionBits -PermissionLookup $Snapshot.Records[$recordUid].UserPermissions `
                    -UserUid ([long]$shareAdminRecord.EnterpriseUserId) -PermissionBits $script:KeeperCompliancePermissionShareAdmin
            }
        }
    }

    foreach ($userRecord in $Response.UserRecords) {
        $userUid = [long]$userRecord.EnterpriseUserId
        foreach ($recordPermission in $userRecord.RecordPermissions) {
            $recordUid = ConvertTo-KeeperComplianceUid -ByteString $recordPermission.RecordUid
            if (-not $recordUid -or -not $Snapshot.Records.ContainsKey($recordUid)) {
                continue
            }

            Add-KeeperCompliancePermissionBits -PermissionLookup $Snapshot.Records[$recordUid].UserPermissions `
                -UserUid $userUid -PermissionBits ([int]$recordPermission.PermissionBits)
        }
    }

    foreach ($sharedFolderUser in $Response.SharedFolderUsers) {
        $sharedFolderUid = ConvertTo-KeeperComplianceUid -ByteString $sharedFolderUser.SharedFolderUid
        if (-not $sharedFolderUid) {
            continue
        }

        $sharedFolderEntry = Ensure-KeeperComplianceSharedFolderEntry -Snapshot $Snapshot -SharedFolderUid $sharedFolderUid

        foreach ($userUid in $sharedFolderUser.EnterpriseUserIds) {
            $sharedFolderEntry.Users.Add([long]$userUid) | Out-Null
        }
    }

    foreach ($sharedFolderTeam in $Response.SharedFolderTeams) {
        $sharedFolderUid = ConvertTo-KeeperComplianceUid -ByteString $sharedFolderTeam.SharedFolderUid
        if (-not $sharedFolderUid) {
            continue
        }

        $sharedFolderEntry = Ensure-KeeperComplianceSharedFolderEntry -Snapshot $Snapshot -SharedFolderUid $sharedFolderUid

        foreach ($teamUidBytes in $sharedFolderTeam.TeamUids) {
            $teamUid = ConvertTo-KeeperComplianceUid -ByteString $teamUidBytes
            if ($teamUid) {
                $sharedFolderEntry.Teams.Add([string]$teamUid) | Out-Null
            }
        }
    }
}

function Get-KeeperComplianceEnterpriseNodeSubtreeIds {
    param(
        [Parameter(Mandatory = $true)]$EnterpriseData,
        [Parameter(Mandatory = $true)][long]$RootNodeId
    )

    if ($RootNodeId -le 0) {
        return $null
    }

    $subnodes = @{}
    foreach ($n in $EnterpriseData.Nodes) {
        $parentId = [long]$n.ParentNodeId
        $childId = [long]$n.Id
        if ($parentId -gt 0) {
            if (-not $subnodes.ContainsKey($parentId)) {
                $subnodes[$parentId] = [System.Collections.Generic.List[long]]::new()
            }
            $subnodes[$parentId].Add($childId) | Out-Null
        }
    }

    $set = [System.Collections.Generic.HashSet[long]]::new()
    $queue = [System.Collections.Generic.Queue[long]]::new()
    $queue.Enqueue($RootNodeId) | Out-Null
    while ($queue.Count -gt 0) {
        $nid = $queue.Dequeue()
        [void]$set.Add($nid)
        if ($subnodes.ContainsKey($nid)) {
            foreach ($c in $subnodes[$nid]) {
                $queue.Enqueue($c) | Out-Null
            }
        }
    }

    $lookup = @{}
    foreach ($nid in $set) {
        $lookup["$([long]$nid)"] = $true
    }
    return $lookup
}

function Test-KeeperComplianceHasNonEmptyStringList {
    param(
        [Parameter()][AllowNull()][string[]]$Strings
    )

    if ($null -eq $Strings) {
        return $false
    }
    foreach ($s in $Strings) {
        if (-not [string]::IsNullOrWhiteSpace([string]$s)) {
            return $true
        }
    }
    return $false
}

function Test-KeeperComplianceHasNodeFilter {
    param(
        [Parameter()][AllowNull()][string]$Node
    )

    return -not [string]::IsNullOrWhiteSpace($Node)
}

function Resolve-KeeperComplianceFetchOwnerIds {
    param(
        [Parameter()][string[]]$Username,
        [Parameter()][string[]]$Team,
        [Parameter()][string]$Node
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $candidateUserIds = [System.Collections.Generic.HashSet[long]]::new()
    $hasPrefilter = $false
    $hasUsernameFilter = Test-KeeperComplianceHasNonEmptyStringList -Strings $Username
    $hasTeamFilter = Test-KeeperComplianceHasNonEmptyStringList -Strings $Team

    if ($hasUsernameFilter) {
        $hasPrefilter = $true
        $lookup = @{}
        foreach ($value in $Username) {
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $lookup[$value.ToLowerInvariant()] = $true
            }
        }
        foreach ($enterpriseUser in $enterpriseData.Users) {
            if ($enterpriseUser.Email -and $lookup.ContainsKey(([string]$enterpriseUser.Email).ToLowerInvariant())) {
                $candidateUserIds.Add([long]$enterpriseUser.Id) | Out-Null
            }
        }
    }

    if ($hasTeamFilter) {
        $hasPrefilter = $true
        foreach ($teamRef in $Team) {
            if ([string]::IsNullOrWhiteSpace([string]$teamRef)) {
                continue
            }
            $resolvedTeam = Get-KeeperTeamByNameOrUid -EnterpriseData $enterpriseData -TeamInput $teamRef
            if (-not $resolvedTeam) {
                Write-Warning "No enterprise team matched '$teamRef' for compliance owner pre-filter."
                continue
            }
            foreach ($userUid in $enterpriseData.GetUsersForTeam($resolvedTeam.Uid)) {
                $candidateUserIds.Add([long]$userUid) | Out-Null
            }
        }
    }

    if (Test-KeeperComplianceHasNodeFilter -Node $Node) {
        $hasPrefilter = $true
        $nodeInput = $Node.Trim()
        $resolvedNode = Resolve-KeeperComplianceNode -Node $nodeInput -Context 'compliance owner pre-filter'
        $targetNodeId = [long]$resolvedNode.Id
        $rootNodeId = [long]$enterpriseData.RootNode.Id
        if ($targetNodeId -eq $rootNodeId) {
            if ($candidateUserIds.Count -eq 0 -and -not $hasUsernameFilter -and -not $hasTeamFilter) {
                foreach ($enterpriseUser in $enterpriseData.Users) {
                    $candidateUserIds.Add([long]$enterpriseUser.Id) | Out-Null
                }
            }
        }
        else {
            $nodeMatchedUserIds = [System.Collections.Generic.HashSet[long]]::new()
            foreach ($enterpriseUser in $enterpriseData.Users) {
                $userNodeId = [long]$enterpriseUser.ParentNodeId
                if ($userNodeId -le 0) {
                    $userNodeId = $rootNodeId
                }
                if ($userNodeId -eq $targetNodeId) {
                    $nodeMatchedUserIds.Add([long]$enterpriseUser.Id) | Out-Null
                }
            }

            if ($candidateUserIds.Count -eq 0 -and -not $hasUsernameFilter -and -not $hasTeamFilter) {
                foreach ($userUid in $nodeMatchedUserIds) {
                    $candidateUserIds.Add([long]$userUid) | Out-Null
                }
            }
            else {
                $filteredUserIds = [System.Collections.Generic.HashSet[long]]::new()
                foreach ($userUid in $candidateUserIds) {
                    if ($nodeMatchedUserIds.Contains([long]$userUid)) {
                        $filteredUserIds.Add([long]$userUid) | Out-Null
                    }
                }
                $candidateUserIds = $filteredUserIds
            }
        }
    }

    if (-not $hasPrefilter) {
        return $null
    }

    return @(
        $candidateUserIds |
            Where-Object {
                $enterpriseUser = $null
                [bool]($enterpriseData.TryGetUserById([long]$_, [ref]$enterpriseUser) -and $enterpriseUser)
            } |
            Sort-Object
    )
}

function Get-KeeperComplianceDiskCacheRoot {
    return [System.IO.Path]::Combine(
        [Environment]::GetFolderPath('UserProfile'),
        '.keeper',
        'powercommander',
        'compliance_cache'
    )
}

function Get-KeeperComplianceSqliteDbPath {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    $server = [string]$Auth.Endpoint.Server
    if ([string]::IsNullOrWhiteSpace($server)) {
        $server = 'keepersecurity.com'
    }
    $safeServer = [System.Text.RegularExpressions.Regex]::Replace($server, '[^\w\-\.]', '_')
    $entId = 0L
    if ($Enterprise.enterpriseData -and $Enterprise.enterpriseData.EnterpriseLicense) {
        $entId = [long]$Enterprise.enterpriseData.EnterpriseLicense.EnterpriseLicenseId
    }
    $mc = 0
    if ($Script:Context.ManagedCompanyId) {
        $mc = [int]$Script:Context.ManagedCompanyId
    }
    $suffix = if ($mc -gt 0) { "_mc$mc" } else { '' }
    $cacheRoot = Get-KeeperComplianceDiskCacheRoot
    $serverDir = [System.IO.Path]::Combine($cacheRoot, $safeServer)
    if (-not (Test-Path -LiteralPath $serverDir)) {
        [void][System.IO.Directory]::CreateDirectory($serverDir)
    }
    return [System.IO.Path]::Combine($serverDir, "compliance_${entId}${suffix}.db")
}

function Get-KeeperComplianceSqliteStorage {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    $dbPath = Get-KeeperComplianceSqliteDbPath -Enterprise $Enterprise -Auth $Auth
    if ($script:ComplianceSqliteStorage -and $script:ComplianceSqliteDbPath -eq $dbPath) {
        return $script:ComplianceSqliteStorage
    }

    $script:ComplianceSqliteStorage = $null
    $script:ComplianceSqliteDbPath = $null

    $connectionString = "Data Source=$dbPath;Pooling=True;"
    try {
        $storage = Get-SqliteComplianceStorageFromHelper -ConnectionString $connectionString
        $script:ComplianceSqliteStorage = $storage
        $script:ComplianceSqliteDbPath = $dbPath
        return $storage
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to initialize SQLite compliance storage: $($_.Exception.Message)"
        return $null
    }
}

function Save-KeeperComplianceSnapshotToSqlite {
    param(
        [Parameter(Mandatory = $true)][string]$CacheKey,
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][bool]$Incomplete,
        [Parameter()][bool]$SharedOnly = $false,
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        $storage.ClearNonAgingData()

        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        $existingMeta = $null
        try { $existingMeta = @($storage.Metadata.GetAll()) | Select-Object -First 1 } catch { }

        $meta = New-Object KeeperSecurity.Compliance.ComplianceMetadata
        $meta.AccountUid = $CacheKey
        $meta.PrelimDataLastUpdate = $nowEpoch
        $meta.ComplianceDataLastUpdate = $nowEpoch
        $meta.SharedRecordsOnly = $SharedOnly
        if ($existingMeta) {
            $meta.RecordsDated = $existingMeta.RecordsDated
            $meta.LastPwAudit = $existingMeta.LastPwAudit
        }
        $storage.Metadata.Store($meta)

        $userEntities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceUser]]::new()
        foreach ($userUid in $Snapshot.Users.Keys) {
            $u = $Snapshot.Users[$userUid]
            $cu = New-Object KeeperSecurity.Compliance.ComplianceUser
            $cu.UserUid = [long]$userUid
            $cu.Email = [System.Text.Encoding]::UTF8.GetBytes([string]$u.Email)
            $cu.Status = 0
            $cu.JobTitle = if ($u.JobTitle) { [System.Text.Encoding]::UTF8.GetBytes([string]$u.JobTitle) } else { [byte[]]@() }
            $cu.FullName = if ($u.FullName) { [System.Text.Encoding]::UTF8.GetBytes([string]$u.FullName) } else { [byte[]]@() }
            $cu.NodeId = if ($u.NodeId) { [long]$u.NodeId } else { 0L }
            $cu.LastRefreshed = $nowEpoch
            $cu.LastComplianceRefreshed = $nowEpoch
            $cu.LastAgingRefreshed = 0L
            $userEntities.Add($cu)
        }
        if ($userEntities.Count -gt 0) {
            $storage.Users.PutEntities($userEntities)
        }

        $recordEntities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceRecord]]::new()
        foreach ($recUid in $Snapshot.Records.Keys) {
            $r = $Snapshot.Records[$recUid]
            $cr = New-Object KeeperSecurity.Compliance.ComplianceRecord
            $cr.RecordUid = [string]$recUid
            $cr.RecordUidBytes = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode([string]$recUid)
            $titleJson = @{ title = [string]$r.Title; type = [string]$r.RecordType; url = [string]$r.Url } | ConvertTo-Json -Compress
            $cr.EncryptedData = [System.Text.Encoding]::UTF8.GetBytes($titleJson)
            $cr.Shared = [bool]$r.Shared
            $cr.InTrash = [bool]$r.InTrash
            $cr.HasAttachments = $false
            $cr.LastComplianceRefreshed = $nowEpoch
            $recordEntities.Add($cr)
        }
        if ($recordEntities.Count -gt 0) {
            $storage.Records.PutEntities($recordEntities)
        }

        $userRecordLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceUserRecordLink]]::new()
        foreach ($ownerUid in $Snapshot.OwnedRecordsByUser.Keys) {
            foreach ($recUid in $Snapshot.OwnedRecordsByUser[$ownerUid]) {
                $link = New-Object KeeperSecurity.Compliance.ComplianceUserRecordLink
                $link.RecordUid = [string]$recUid
                $link.UserUid = [long]$ownerUid
                $userRecordLinks.Add($link)
            }
        }
        if ($userRecordLinks.Count -gt 0) {
            $storage.UserRecordLinks.PutLinks($userRecordLinks)
        }

        $teamEntities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceTeam]]::new()
        $teamUserLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceTeamUserLink]]::new()
        foreach ($teamUid in $Snapshot.Teams.Keys) {
            $t = $Snapshot.Teams[$teamUid]
            $ct = New-Object KeeperSecurity.Compliance.ComplianceTeam
            $ct.TeamUid = [string]$teamUid
            $ct.TeamName = ''
            $ct.RestrictEdit = $false
            $ct.RestrictShare = $false
            $teamEntities.Add($ct)
            foreach ($memberUid in $t.Users) {
                $tl = New-Object KeeperSecurity.Compliance.ComplianceTeamUserLink
                $tl.TeamUid = [string]$teamUid
                $tl.UserUid = [long]$memberUid
                $teamUserLinks.Add($tl)
            }
        }
        if ($teamEntities.Count -gt 0) {
            $storage.Teams.PutEntities($teamEntities)
        }
        if ($teamUserLinks.Count -gt 0) {
            $storage.TeamUserLinks.PutLinks($teamUserLinks)
        }

        $sfRecordLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceSfRecordLink]]::new()
        $sfUserLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceSfUserLink]]::new()
        $sfTeamLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceSfTeamLink]]::new()
        $recPermLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceRecordPermissions]]::new()
        foreach ($sfUid in $Snapshot.SharedFolders.Keys) {
            $sf = $Snapshot.SharedFolders[$sfUid]
            foreach ($recUid in $sf.RecordPermissions.Keys) {
                $srl = New-Object KeeperSecurity.Compliance.ComplianceSfRecordLink
                $srl.FolderUid = [string]$sfUid
                $srl.RecordUid = [string]$recUid
                $srl.Permissions = [int]$sf.RecordPermissions[$recUid]
                $sfRecordLinks.Add($srl)
            }
            foreach ($userUid in $sf.Users) {
                $sul = New-Object KeeperSecurity.Compliance.ComplianceSfUserLink
                $sul.FolderUid = [string]$sfUid
                $sul.UserUid = [long]$userUid
                $sfUserLinks.Add($sul)
            }
            foreach ($teamUid in $sf.Teams) {
                $stl = New-Object KeeperSecurity.Compliance.ComplianceSfTeamLink
                $stl.FolderUid = [string]$sfUid
                $stl.TeamUid = [string]$teamUid
                $sfTeamLinks.Add($stl)
            }
        }
        if ($sfRecordLinks.Count -gt 0) {
            $storage.SfRecordLinks.PutLinks($sfRecordLinks)
        }
        if ($sfUserLinks.Count -gt 0) {
            $storage.SfUserLinks.PutLinks($sfUserLinks)
        }
        if ($sfTeamLinks.Count -gt 0) {
            $storage.SfTeamLinks.PutLinks($sfTeamLinks)
        }

        foreach ($recUid in $Snapshot.Records.Keys) {
            $r = $Snapshot.Records[$recUid]
            if ($r.UserPermissions -and $r.UserPermissions.Count -gt 0) {
                foreach ($userUid in $r.UserPermissions.Keys) {
                    $rp = New-Object KeeperSecurity.Compliance.ComplianceRecordPermissions
                    $rp.RecordUid = [string]$recUid
                    $rp.UserUid = [long]$userUid
                    $rp.Permissions = [int]$r.UserPermissions[$userUid]
                    $recPermLinks.Add($rp)
                }
            }
        }
        if ($recPermLinks.Count -gt 0) {
            $storage.RecordPermissions.PutLinks($recPermLinks)
        }

        Write-KeeperComplianceStatus "Saved compliance snapshot to SQLite."
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to save SQLite cache: $($_.Exception.Message)"
    }
}

function Import-KeeperComplianceSnapshotFromSqlite {
    param(
        [Parameter(Mandatory = $true)][string]$CacheKey,
        [Parameter(Mandatory = $true)][TimeSpan]$CacheTtl,
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return $null }

        $meta = $storage.Metadata.Load()
        if (-not $meta) { return $null }
        if ($meta.AccountUid -ne $CacheKey) { return $null }

        $loadedEpoch = $meta.ComplianceDataLastUpdate
        if ($loadedEpoch -le 0) { return $null }
        $loadedAt = [DateTimeOffset]::FromUnixTimeSeconds($loadedEpoch).LocalDateTime
        if (((Get-Date) - $loadedAt) -ge $CacheTtl) { return $null }

        $snapshot = [PSCustomObject]@{
            Users              = @{}
            Records            = @{}
            SharedFolders      = @{}
            Teams              = @{}
            OwnedRecordsByUser = @{}
        }

        foreach ($cu in $storage.Users.GetAll()) {
            $email = if ($cu.Email) { [System.Text.Encoding]::UTF8.GetString($cu.Email) } else { '' }
            $fullName = if ($cu.FullName -and $cu.FullName.Length -gt 0) { [System.Text.Encoding]::UTF8.GetString($cu.FullName) } else { '' }
            $jobTitle = if ($cu.JobTitle -and $cu.JobTitle.Length -gt 0) { [System.Text.Encoding]::UTF8.GetString($cu.JobTitle) } else { '' }
            $snapshot.Users[[long]$cu.UserUid] = [PSCustomObject]@{
                UserUid  = [long]$cu.UserUid
                Email    = $email
                FullName = $fullName
                JobTitle = $jobTitle
                NodeId   = [long]$cu.NodeId
            }
        }

        foreach ($cr in $storage.Records.GetAll()) {
            $recData = @{ Title = ''; RecordType = ''; Url = '' }
            if ($cr.EncryptedData -and $cr.EncryptedData.Length -gt 0) {
                try {
                    $json = [System.Text.Encoding]::UTF8.GetString($cr.EncryptedData) | ConvertFrom-Json
                    $recData.Title = [string]$json.title
                    $recData.RecordType = [string]$json.type
                    $recData.Url = [string]$json.url
                } catch {
                    Write-Verbose -Message "[compliance] Could not parse record data for $($cr.RecordUid): $($_.Exception.Message)"
                }
            }
            $snapshot.Records[[string]$cr.RecordUid] = [PSCustomObject]@{
                Uid              = [string]$cr.RecordUid
                Title            = $recData.Title
                RecordType       = $recData.RecordType
                Url              = $recData.Url
                Shared           = [bool]$cr.Shared
                InTrash          = [bool]$cr.InTrash
                UserPermissions  = @{}
                SharedFolderUids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            }
        }

        foreach ($rp in $storage.RecordPermissions.GetAllLinks()) {
            $recUid = [string]$rp.RecordUid
            if ($snapshot.Records.ContainsKey($recUid)) {
                $snapshot.Records[$recUid].UserPermissions[[long]$rp.UserUid] = [int]$rp.Permissions
            }
        }

        foreach ($link in $storage.UserRecordLinks.GetAllLinks()) {
            $userUid = [long]$link.UserUid
            $recUid = [string]$link.RecordUid
            if (-not $snapshot.OwnedRecordsByUser.ContainsKey($userUid)) {
                $snapshot.OwnedRecordsByUser[$userUid] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            }
            $snapshot.OwnedRecordsByUser[$userUid].Add($recUid) | Out-Null
        }

        foreach ($ct in $storage.Teams.GetAll()) {
            $teamUid = [string]$ct.TeamUid
            $teamUsers = [System.Collections.Generic.HashSet[long]]::new()
            foreach ($tl in $storage.TeamUserLinks.GetLinksForSubject($teamUid)) {
                $teamUsers.Add([long]$tl.UserUid) | Out-Null
            }
            $snapshot.Teams[$teamUid] = [PSCustomObject]@{
                Uid   = $teamUid
                Users = $teamUsers
            }
        }

        $sfMap = @{}
        foreach ($srl in $storage.SfRecordLinks.GetAllLinks()) {
            $sfUid = [string]$srl.FolderUid
            if (-not $sfMap.ContainsKey($sfUid)) {
                $sfMap[$sfUid] = [PSCustomObject]@{
                    Uid               = $sfUid
                    Users             = [System.Collections.Generic.HashSet[long]]::new()
                    Teams             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    RecordPermissions = @{}
                }
            }
            $sfMap[$sfUid].RecordPermissions[[string]$srl.RecordUid] = [int]$srl.Permissions
            if ($snapshot.Records.ContainsKey([string]$srl.RecordUid)) {
                $snapshot.Records[[string]$srl.RecordUid].SharedFolderUids.Add($sfUid) | Out-Null
            }
        }
        foreach ($sul in $storage.SfUserLinks.GetAllLinks()) {
            $sfUid = [string]$sul.FolderUid
            if (-not $sfMap.ContainsKey($sfUid)) {
                $sfMap[$sfUid] = [PSCustomObject]@{
                    Uid               = $sfUid
                    Users             = [System.Collections.Generic.HashSet[long]]::new()
                    Teams             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    RecordPermissions = @{}
                }
            }
            $sfMap[$sfUid].Users.Add([long]$sul.UserUid) | Out-Null
        }
        foreach ($stl in $storage.SfTeamLinks.GetAllLinks()) {
            $sfUid = [string]$stl.FolderUid
            if (-not $sfMap.ContainsKey($sfUid)) {
                $sfMap[$sfUid] = [PSCustomObject]@{
                    Uid               = $sfUid
                    Users             = [System.Collections.Generic.HashSet[long]]::new()
                    Teams             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    RecordPermissions = @{}
                }
            }
            $sfMap[$sfUid].Teams.Add([string]$stl.TeamUid) | Out-Null
        }
        $snapshot.SharedFolders = $sfMap

        return @{
            Snapshot        = $snapshot
            LoadedAt        = $loadedAt
            Incomplete      = $false
            SharedRecordsOnly = [bool]$meta.SharedRecordsOnly
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to load SQLite cache: $($_.Exception.Message)"
        return $null
    }
}

function Import-KeeperComplianceAgingCacheFromSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        if (-not $script:ComplianceAgingCache) {
            $script:ComplianceAgingCache = @{ Entries = @{} }
        }
        if (-not $script:ComplianceAgingCache.Entries) {
            $script:ComplianceAgingCache.Entries = @{}
        }
        $cacheTtl = [TimeSpan]::FromDays(1)
        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        foreach ($aging in $storage.RecordAging.GetAll()) {
            $recUid = [string]$aging.RecordUid
            if ($script:ComplianceAgingCache.Entries.ContainsKey($recUid)) {
                continue
            }
            if ($aging.LastCached -le 0) { continue }
            if (($nowEpoch - $aging.LastCached) -ge $cacheTtl.TotalSeconds) { continue }

            $lcDt = [DateTimeOffset]::FromUnixTimeSeconds($aging.LastCached).LocalDateTime
            $script:ComplianceAgingCache.Entries[$recUid] = @{
                Created      = if ($aging.Created -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.Created).LocalDateTime } else { $null }
                LastPwChange = if ($aging.LastPwChange -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.LastPwChange).LocalDateTime } else { $null }
                LastModified = if ($aging.LastModified -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.LastModified).LocalDateTime } else { $null }
                LastRotation = if ($aging.LastRotation -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.LastRotation).LocalDateTime } else { $null }
                LastCached   = $lcDt
            }
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to import aging from SQLite: $($_.Exception.Message)"
    }
}

function Save-KeeperComplianceAgingCacheToSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    if (-not $script:ComplianceAgingCache -or -not $script:ComplianceAgingCache.Entries) {
        return
    }
    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        $entities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceRecordAging]]::new()
        foreach ($k in $script:ComplianceAgingCache.Entries.Keys) {
            $e = $script:ComplianceAgingCache.Entries[$k]
            $ra = New-Object KeeperSecurity.Compliance.ComplianceRecordAging
            $ra.RecordUid = [string]$k
            $ra.Created = if ($e.Created) { [int64][DateTimeOffset]::new([datetime]$e.Created).ToUnixTimeSeconds() } else { 0L }
            $ra.LastPwChange = if ($e.LastPwChange) { [int64][DateTimeOffset]::new([datetime]$e.LastPwChange).ToUnixTimeSeconds() } else { 0L }
            $ra.LastModified = if ($e.LastModified) { [int64][DateTimeOffset]::new([datetime]$e.LastModified).ToUnixTimeSeconds() } else { 0L }
            $ra.LastRotation = if ($e.LastRotation) { [int64][DateTimeOffset]::new([datetime]$e.LastRotation).ToUnixTimeSeconds() } else { 0L }
            $ra.LastCached = if ($e.LastCached) { [int64][DateTimeOffset]::new([datetime]$e.LastCached).ToUnixTimeSeconds() } else { 0L }
            $entities.Add($ra)
        }
        if ($entities.Count -gt 0) {
            $storage.RecordAging.PutEntities($entities)
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to save aging to SQLite: $($_.Exception.Message)"
    }
}

function Remove-KeeperComplianceSqliteCache {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    $script:ComplianceSqliteStorage = $null
    $script:ComplianceSqliteDbPath = $null
    $dbPath = Get-KeeperComplianceSqliteDbPath -Enterprise $Enterprise -Auth $Auth
    if (Test-Path -LiteralPath $dbPath) {
        try {
            [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        catch {
            Write-Verbose -Message "[compliance] Could not clear SQLite connection pools: $($_.Exception.Message)"
        }
        Remove-Item -LiteralPath $dbPath -Force -ErrorAction SilentlyContinue
        foreach ($sidecar in @("$dbPath-wal", "$dbPath-shm")) {
            if (Test-Path -LiteralPath $sidecar) {
                Remove-Item -LiteralPath $sidecar -Force -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $dbPath) {
            Write-Warning "[compliance] SQLite cache file could not be deleted (may be locked): $dbPath"
        }
        else {
            Write-Verbose -Message "[compliance] Removed SQLite cache: $dbPath"
        }
    }
}

function Assert-KeeperComplianceReportAccess {
    $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader -or -not $enterprise.roleData) {
        Write-Error "Enterprise connection is required for compliance reports." -ErrorAction Stop
    }
    $auth = $enterprise.loader.Auth
    # Login identity is on IAuthentication (AuthCommon.Username), not IAuthContext.
    $username = [string]$auth.Username
    if ([string]::IsNullOrWhiteSpace($username)) {
        Write-Error "Could not determine login username for compliance access validation." -ErrorAction Stop
    }
    $enterpriseUser = $null
    if (-not $enterprise.enterpriseData.TryGetUserByEmail($username, [ref]$enterpriseUser) -or -not $enterpriseUser) {
        foreach ($u in $enterprise.enterpriseData.Users) {
            if ($u.Email -and [string]::Compare([string]$u.Email, $username, $true) -eq 0) {
                $enterpriseUser = $u
                break
            }
        }
    }
    if (-not $enterpriseUser) {
        Write-Error "Could not resolve your enterprise user for compliance access validation. Your login ($username) was not found among enterprise users." -ErrorAction Stop
    }
    $uid = [long]$enterpriseUser.Id
    $hasPrivilege = $false
    foreach ($roleId in @($enterprise.roleData.GetRolesForUser($uid))) {
        foreach ($rp in @($enterprise.roleData.GetRolePermissions($roleId))) {
            if ($rp.RunComplianceReports) {
                $hasPrivilege = $true
                break
            }
        }
        if ($hasPrivilege) {
            break
        }
    }
    if (-not $hasPrivilege) {
        Write-Error "You do not have the required privilege to run a Compliance Report (RUN_COMPLIANCE_REPORTS)." -ErrorAction Stop
    }
    $license = $enterprise.enterpriseData.EnterpriseLicense
    $addonOk = $false
    if ($license -and $license.AddOns) {
        foreach ($a in $license.AddOns) {
            if ([string]$a.Name -eq 'compliance_report' -and $a.Enabled) {
                $addonOk = $true
                break
            }
        }
    }
    if (-not $addonOk) {
        Write-Error "Compliance reports add-on is required to perform this action. Ask your administrator to enable the compliance_report add-on." -ErrorAction Stop
    }
}

function Import-KeeperComplianceAgingUserRefreshFromSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return @{} }

        $h = @{}
        foreach ($cu in $storage.Users.GetAll()) {
            if ($cu.LastAgingRefreshed -gt 0) {
                $h[[string]$cu.UserUid] = [long]$cu.LastAgingRefreshed
            }
        }
        return $h
    }
    catch {
        return @{}
    }
}

function Save-KeeperComplianceAgingUserRefreshToSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth,
        [Parameter(Mandatory = $true)][long[]]$UserIds
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $updates = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceUser]]::new()
        foreach ($id in $UserIds) {
            $existing = $storage.Users.GetEntity([string]$id)
            if ($existing) {
                $cu = New-Object KeeperSecurity.Compliance.ComplianceUser
                $cu.UserUid = $existing.UserUid
                $cu.Email = $existing.Email
                $cu.Status = $existing.Status
                $cu.JobTitle = $existing.JobTitle
                $cu.FullName = $existing.FullName
                $cu.NodeId = $existing.NodeId
                $cu.LastRefreshed = $existing.LastRefreshed
                $cu.LastComplianceRefreshed = $existing.LastComplianceRefreshed
                $cu.LastAgingRefreshed = $nowTs
                $updates.Add($cu)
            }
        }
        if ($updates.Count -gt 0) {
            $storage.Users.PutEntities($updates)
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to save aging user refresh to SQLite: $($_.Exception.Message)"
    }
}

function ConvertTo-KeeperComplianceRowPlainText {
    param([Parameter(Mandatory = $true)]$Row)

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Row.PSObject.Properties) {
        if ($p.Name -eq 'permission_bits') {
            continue
        }
        $v = $p.Value
        if ($null -eq $v) {
            continue
        }
        if (($v -is [System.Array]) -or (($v -is [System.Collections.IEnumerable]) -and -not ($v -is [string]))) {
            $parts.Add(($v | ForEach-Object { [string]$_ }) -join ' ') | Out-Null
        }
        else {
            $parts.Add([string]$v) | Out-Null
        }
    }
    return (($parts | ForEach-Object { $_ }) -join ' ').ToLowerInvariant()
}

function Invoke-KeeperCompliancePatternFilterRows {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter()][string[]]$Patterns,
        [Parameter()][switch]$UseRegex,
        [Parameter()][switch]$MatchAll
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $Rows
    }

    function Test-PatternOne {
        param([string]$PatternStr, [string]$Plain)

        $s = $PatternStr.Trim()
        if ($s.StartsWith('regex:')) {
            $rx = $s.Substring(6)
            try {
                return [regex]::IsMatch($Plain, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            catch {
                return $Plain.Contains($rx.ToLowerInvariant())
            }
        }
        if ($s.StartsWith('exact:')) {
            $ex = $s.Substring(6)
            return $Plain -ceq $ex.ToLowerInvariant()
        }
        if ($s.StartsWith('not:')) {
            $rest = $s.Substring(4).Trim()
            if ($rest.StartsWith('regex:')) {
                $rx = $rest.Substring(6)
                try {
                    return -not [regex]::IsMatch($Plain, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                }
                catch {
                    return $Plain -notlike "*$($rx.ToLowerInvariant())*"
                }
            }
            if ($rest.StartsWith('exact:')) {
                $ex = $rest.Substring(6)
                return $Plain -cne $ex.ToLowerInvariant()
            }
            return $Plain -notlike "*$($rest.ToLowerInvariant())*"
        }
        if ($UseRegex) {
            try {
                return [regex]::IsMatch($Plain, $s, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            catch {
                return $Plain.Contains($s.ToLowerInvariant())
            }
        }
        return $Plain.Contains($s.ToLowerInvariant())
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $plain = ConvertTo-KeeperComplianceRowPlainText -Row $row
        $results = foreach ($p in $Patterns) {
            Test-PatternOne -PatternStr ([string]$p) -Plain $plain
        }
        $ok = if ($MatchAll) { @($results) -notcontains $false } else { @($results) -contains $true }
        if ($ok) {
            $out.Add($row) | Out-Null
        }
    }
    return @($out)
}

function Get-KeeperComplianceSnapshot {
    [CmdletBinding()]
    param(
        [Parameter()][switch]$Rebuild,
        [Parameter()][switch]$NoRebuild,
        [Parameter()][long[]]$OwnerUserIds,
        [Parameter()][switch]$SharedOnly
    )

    if ($Rebuild -and $NoRebuild) {
        Write-Error "-Rebuild and -NoRebuild cannot be used together." -ErrorAction Stop
    }

    Assert-KeeperComplianceReportAccess

    if (-not $script:ComplianceReportCache) {
        $script:ComplianceReportCache = @{
            Entries = @{}
        }
    }

    if (-not $script:ComplianceReportCache.Entries) {
        $script:ComplianceReportCache.Entries = @{}
    }

    $cacheTtl = [TimeSpan]::FromDays(1)
    $scopeKey = if ($null -eq $OwnerUserIds) {
        'all'
    }
    else {
        'users:' + ((@($OwnerUserIds | Sort-Object) | ForEach-Object { [string]$_ }) -join ',')
    }
    $cacheKey = if ($SharedOnly) {
        "shared-only:$scopeKey"
    }
    else {
        $scopeKey
    }
    $allCacheEntry = $script:ComplianceReportCache.Entries['all']
    $cacheEntry = $script:ComplianceReportCache.Entries[$cacheKey]
    if ($cacheEntry) {
        $loadedAt = [datetime]$cacheEntry.LoadedAt
        $cacheIsFresh = ((Get-Date) - $loadedAt) -lt $cacheTtl
        if ($NoRebuild -or (-not $Rebuild -and $cacheIsFresh)) {
            Write-KeeperComplianceStatus "Using in-session cache '$cacheKey' loaded at $($loadedAt.ToString('u'))."
            Set-KeeperComplianceLastSnapshotStatus -FromCache $true -Incomplete $false -BuiltAt $loadedAt
            return $cacheEntry.Snapshot
        }
    }
    # Do not substitute the full snapshot for owner-scoped requests (e.g. -Node): filtered compliance data must be built.
    if ($null -eq $OwnerUserIds -and $SharedOnly -and $allCacheEntry) {
        $allLoadedAt = [datetime]$allCacheEntry.LoadedAt
        $allCacheIsFresh = ((Get-Date) - $allLoadedAt) -lt $cacheTtl
        if ($NoRebuild -or (-not $Rebuild -and $allCacheIsFresh)) {
            Write-KeeperComplianceStatus "Using in-session cache 'all' for compatible shared-only request '$cacheKey', loaded at $($allLoadedAt.ToString('u'))."
            Set-KeeperComplianceLastSnapshotStatus -FromCache $true -Incomplete $false -BuiltAt $allLoadedAt
            return $allCacheEntry.Snapshot
        }
    }

    if (-not $Rebuild) {
        try {
            $entForCache = getEnterprise
            if ($entForCache -and $entForCache.loader -and $entForCache.loader.Auth) {
                $sqliteLoaded = Import-KeeperComplianceSnapshotFromSqlite -CacheKey $cacheKey -CacheTtl $cacheTtl `
                    -Enterprise $entForCache -Auth $entForCache.loader.Auth
                if ($sqliteLoaded) {
                    $script:ComplianceReportCache.Entries[$cacheKey] = @{
                        Snapshot = $sqliteLoaded.Snapshot
                        LoadedAt = $sqliteLoaded.LoadedAt
                    }
                    Write-KeeperComplianceStatus "Using SQLite cache '$cacheKey' loaded at $($sqliteLoaded.LoadedAt.ToString('u'))."
                    Set-KeeperComplianceLastSnapshotStatus -FromCache $true -Incomplete $sqliteLoaded.Incomplete -BuiltAt $sqliteLoaded.LoadedAt
                    return $sqliteLoaded.Snapshot
                }
                if ($null -eq $OwnerUserIds -and $SharedOnly) {
                    $sqliteAll = Import-KeeperComplianceSnapshotFromSqlite -CacheKey 'all' -CacheTtl $cacheTtl `
                        -Enterprise $entForCache -Auth $entForCache.loader.Auth
                    if ($sqliteAll) {
                        $script:ComplianceReportCache.Entries['all'] = @{
                            Snapshot = $sqliteAll.Snapshot
                            LoadedAt = $sqliteAll.LoadedAt
                        }
                        Write-KeeperComplianceStatus "Using SQLite cache 'all' for compatible shared-only request '$cacheKey', loaded at $($sqliteAll.LoadedAt.ToString('u'))."
                        Set-KeeperComplianceLastSnapshotStatus -FromCache $true -Incomplete $sqliteAll.Incomplete -BuiltAt $sqliteAll.LoadedAt
                        return $sqliteAll.Snapshot
                    }
                }
            }
        }
        catch {
            Write-Verbose -Message "[compliance] SQLite cache read skipped: $($_.Exception.Message)"
        }
    }

    if ($null -eq $OwnerUserIds -and $NoRebuild) {
        Write-Warning "No local compliance cache is available for this request. Building it now."
    }

    $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader) {
        Write-Error "Enterprise data is required to build the compliance report." -ErrorAction Stop
    }

    $auth = $enterprise.loader.Auth
    $ecPrivateKey = $null
    if ($enterprise.loader.EcPrivateKey) {
        $ecPrivateKey = [KeeperSecurity.Utils.CryptoUtils]::LoadEcPrivateKey($enterprise.loader.EcPrivateKey)
    }

    $snapshot = [PSCustomObject]@{
        Users              = @{}
        Records            = @{}
        SharedFolders      = @{}
        Teams              = @{}
        OwnedRecordsByUser = @{}
        EcPrivateKey       = $ecPrivateKey
        Diagnostics        = [PSCustomObject]@{
            RecordDataFailures = 0
        }
    }

    $ownerIdLookup = $null
    if ($null -ne $OwnerUserIds) {
        $ownerIdLookup = [System.Collections.Generic.HashSet[long]]::new()
        foreach ($ownerUserId in $OwnerUserIds) {
            $ownerIdLookup.Add([long]$ownerUserId) | Out-Null
        }
    }

    $enterpriseUserIds = [System.Collections.Generic.List[long]]::new()
    foreach ($enterpriseUser in $enterprise.enterpriseData.Users) {
        $userUid = [long]$enterpriseUser.Id
        $userEmail = [string]$enterpriseUser.Email
        $snapshot.Users[$userUid] = [PSCustomObject]@{
            UserUid  = $userUid
            Email    = $userEmail
            FullName = [string]$enterpriseUser.DisplayName
            JobTitle = ''
            NodeId   = [long]$enterpriseUser.ParentNodeId
        }
        if ($null -eq $ownerIdLookup -or $ownerIdLookup.Contains($userUid)) {
            $snapshot.OwnedRecordsByUser[$userUid] = [System.Collections.Generic.HashSet[string]]::new()
            $enterpriseUserIds.Add($userUid) | Out-Null
        }
    }

    if ($null -ne $OwnerUserIds -and $enterpriseUserIds.Count -eq 0) {
        Write-KeeperComplianceStatus "Owner pre-filter resolved to zero enterprise users."
        Set-KeeperComplianceLastSnapshotStatus -FromCache $false -Incomplete $false
        $snapshot.PSObject.Properties.Remove('EcPrivateKey')
        $snapshot.PSObject.Properties.Remove('Diagnostics')
        return $snapshot
    }

    Write-KeeperComplianceStatus "Building compliance snapshot for $($enterpriseUserIds.Count) owner user(s). Cache key: $cacheKey. SharedOnly=$SharedOnly."
    $prelimPageLimit = 10000
    $prelimFixedChunkSize = 5
    $problemUserIds = [System.Collections.Generic.HashSet[long]]::new()
    $prelimSingleUserIds = [System.Collections.Generic.HashSet[long]]::new()
    $userQueue = [System.Collections.Generic.Queue[long]]::new()
    foreach ($uid in $enterpriseUserIds) {
        $userQueue.Enqueue($uid)
    }
    $prelimBatchNumber = 0
    while ($userQueue.Count -gt 0) {
        $prelimChunkSize = [Math]::Min($prelimFixedChunkSize, [Math]::Max(1, $userQueue.Count))
        if ($userQueue.Count -gt 0 -and $prelimSingleUserIds.Contains([long]$userQueue.Peek())) {
            $prelimChunkSize = 1
        }
        $prelimBatchNumber++
        $takeCount = [Math]::Min($prelimChunkSize, $userQueue.Count)
        $userChunkList = [System.Collections.Generic.List[long]]::new()
        for ($qi = 0; $qi -lt $takeCount; $qi++) {
            $userChunkList.Add($userQueue.Dequeue()) | Out-Null
        }
        $userChunk = @($userChunkList)
        if ($userChunk.Count -eq 0) {
            continue
        }
        Write-KeeperComplianceStatus "Preliminary batch ${prelimBatchNumber}: requesting $($userChunk.Count) user(s); queue remaining=$($userQueue.Count); chunk size=$prelimChunkSize."

        $prelimRequest = [Enterprise.PreliminaryComplianceDataRequest]::new()
        foreach ($userUid in $userChunk) {
            $prelimRequest.EnterpriseUserIds.Add([long]$userUid) | Out-Null
        }
        $prelimRequest.IncludeNonShared = (-not $SharedOnly)
        $prelimRequest.IncludeTotalMatchingRecordsInFirstResponse = $true
        $prelimRequest.ContinuationToken = [Google.Protobuf.ByteString]::Empty

        $hasMore = $true
        $chunkCompleted = $true
        $chunkTotal = 0
        $currentBatchLoaded = 0
        $seenUserIds = [System.Collections.Generic.List[long]]::new()
        $prelimPageNumber = 0
        while ($hasMore) {
            $prelimPageNumber++
            Write-KeeperComplianceStatus "Preliminary batch ${prelimBatchNumber} page ${prelimPageNumber}: calling enterprise/get_preliminary_compliance_data."
            try {
                $prelimResponse = [Enterprise.PreliminaryComplianceDataResponse](
                    Get-KeeperComplianceRestResponse -Auth $auth -Endpoint 'enterprise/get_preliminary_compliance_data' `
                        -Request $prelimRequest -ResponseType ([Enterprise.PreliminaryComplianceDataResponse])
                )
            }
            catch {
                $message = [string]$_.Exception.Message
                $exceptionText = [string]$_
                $isTimeout = (
                    $message.IndexOf('GatewayTimeout', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $message.IndexOf('gateway_timeout', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $message.IndexOf('HttpClient.Timeout', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $message.IndexOf('The request was canceled', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $exceptionText.IndexOf('TaskCanceledException', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $exceptionText.IndexOf('OperationCanceledException', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
                )
                if ($isTimeout) {
                    $requeueIds = Get-KeeperCompliancePrelimRequeueUserIds -UserChunk $userChunk -SeenUserIds $seenUserIds
                    if ($requeueIds.Count -gt 1 -or $prelimChunkSize -gt 1) {
                        if ($prelimChunkSize -gt 1) {
                            foreach ($requeueUserId in $requeueIds) {
                                $prelimSingleUserIds.Add([long]$requeueUserId) | Out-Null
                            }
                            Write-Warning "Preliminary compliance request timed out for $($requeueIds.Count) user(s). Retrying the affected users one-by-one."
                        }
                        else {
                            Write-Warning "Preliminary compliance request timed out for user $($requeueIds[0]). Skipping after single-user retry."
                        }
                        $userQueue = Add-KeeperComplianceUserQueueFront -Queue $userQueue -FrontIds $requeueIds
                    }
                    else {
                        Write-Warning "Preliminary compliance request timed out for user $($requeueIds[0]). Skipping after single-user retry."
                        foreach ($problemUserId in $requeueIds) {
                            $prelimSingleUserIds.Remove([long]$problemUserId) | Out-Null
                            $problemUserIds.Add([long]$problemUserId) | Out-Null
                        }
                    }

                    $chunkCompleted = $false
                    break
                }
                throw
            }

            if ($prelimResponse.PSObject.Properties['TotalMatchingRecords'] -and $prelimResponse.TotalMatchingRecords) {
                $currentBatchLoaded = 0
                $chunkTotal = [int]$prelimResponse.TotalMatchingRecords
            }
            Write-KeeperComplianceStatus "Preliminary batch ${prelimBatchNumber} page ${prelimPageNumber}: received $(@($prelimResponse.AuditUserData).Count) user result(s); total matching records=$chunkTotal."

            foreach ($auditUserData in $prelimResponse.AuditUserData) {
                $ownerUid = [long]$auditUserData.EnterpriseUserId
                if (-not $snapshot.OwnedRecordsByUser.ContainsKey($ownerUid)) {
                    $snapshot.OwnedRecordsByUser[$ownerUid] = [System.Collections.Generic.HashSet[string]]::new()
                }
                if (-not $seenUserIds.Contains($ownerUid)) {
                    $seenUserIds.Add($ownerUid) | Out-Null
                }

                foreach ($auditUserRecord in $auditUserData.AuditUserRecords) {
                    $recordUid = ConvertTo-KeeperComplianceUid -ByteString $auditUserRecord.RecordUid
                    if (-not $recordUid) {
                        continue
                    }

                    $recordData = Get-KeeperComplianceRecordData -EncryptedData $auditUserRecord.EncryptedData -EcPrivateKey $ecPrivateKey `
                        -Diagnostics $snapshot.Diagnostics -RecordUid $recordUid -Source 'preliminary'
                    if (-not $snapshot.Records.ContainsKey($recordUid)) {
                        $snapshot.Records[$recordUid] = [PSCustomObject]@{
                            Uid             = $recordUid
                            Title           = [string]$recordData.Title
                            RecordType      = [string]$recordData.RecordType
                            Url             = [string]$recordData.Url
                            Shared          = [bool]$auditUserRecord.Shared
                            InTrash         = $false
                            UserPermissions = @{}
                            SharedFolderUids = [System.Collections.Generic.HashSet[string]]::new()
                        }
                    }
                    else {
                        if (-not $snapshot.Records[$recordUid].Shared -and $auditUserRecord.Shared) {
                            $snapshot.Records[$recordUid].Shared = $true
                        }
                        Merge-KeeperComplianceRecordFields -RecordEntry $snapshot.Records[$recordUid] -RecordData $recordData
                    }

                    $snapshot.OwnedRecordsByUser[$ownerUid].Add($recordUid) | Out-Null
                    $currentBatchLoaded++
                }
            }

            $hasMore = [bool]$prelimResponse.HasMore
            if ($chunkTotal -gt $prelimPageLimit -and $userChunk.Count -gt 1 -and $hasMore) {
                foreach ($requeueUserId in $userChunk) {
                    $prelimSingleUserIds.Add([long]$requeueUserId) | Out-Null
                }
                Write-Warning "Preliminary compliance response reported $chunkTotal matching records for $($userChunk.Count) user(s). Retrying the affected users one-by-one."

                $requeueIds = Get-KeeperCompliancePrelimRequeueUserIds -UserChunk $userChunk -SeenUserIds $seenUserIds
                $userQueue = Add-KeeperComplianceUserQueueFront -Queue $userQueue -FrontIds $requeueIds
                $chunkCompleted = $false
                break
            }

            if ($hasMore) {
                $prelimRequest.ContinuationToken = $prelimResponse.ContinuationToken
            }
        }

        if ($chunkCompleted) {
            foreach ($completedUserId in $userChunk) {
                $prelimSingleUserIds.Remove([long]$completedUserId) | Out-Null
            }
            Write-KeeperComplianceStatus "Preliminary batch $prelimBatchNumber completed: users seen=$($seenUserIds.Count); records loaded=$currentBatchLoaded; next chunk size=$prelimFixedChunkSize."
        }
    }

    if ($problemUserIds.Count -gt 0) {
        $problemEmails = @()
        foreach ($problemUserId in $problemUserIds) {
            $problemUser = $null
            if ($enterprise.enterpriseData.TryGetUserById([long]$problemUserId, [ref]$problemUser) -and $problemUser) {
                $problemEmails += [string]$problemUser.Email
            }
            else {
                $problemEmails += [string]$problemUserId
            }
        }
        Write-Warning "Preliminary compliance data could not be fetched for: $($problemEmails -join ', ')"
    }
    Write-KeeperComplianceStatus "Preliminary compliance phase complete. Owners with records tracked=$($snapshot.OwnedRecordsByUser.Count); records tracked=$($snapshot.Records.Count)."

    $rootNodeId = [long]$enterprise.enterpriseData.RootNode.Id
    $anonymousSeed = 0L
    $maxUsersPerRequest = 5000
    $maxRecordsPerRequest = 1000
    $userIdList = @(
        $snapshot.OwnedRecordsByUser.GetEnumerator() |
            Where-Object { $_.Value -and $_.Value.Count -gt 0 } |
            ForEach-Object { [long]$_.Key } |
            Sort-Object
    )
    $fullComplianceFailures = 0
    $stopFullCompliance = $false

    for ($userIndex = 0; $userIndex -lt $userIdList.Count; $userIndex += $maxUsersPerRequest) {
        if ($stopFullCompliance) {
            break
        }
        $userChunk = @($userIdList | Select-Object -Skip $userIndex -First $maxUsersPerRequest)
        if ($userChunk.Count -eq 0) {
            continue
        }

        $chunkRecordSet = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($userUid in $userChunk) {
            foreach ($recordUid in $snapshot.OwnedRecordsByUser[[long]$userUid]) {
                $chunkRecordSet.Add($recordUid) | Out-Null
            }
        }

        $chunkRecordList = @($chunkRecordSet)
        for ($recordIndex = 0; $recordIndex -lt $chunkRecordList.Count; $recordIndex += $maxRecordsPerRequest) {
            if ($stopFullCompliance) {
                break
            }
            $recordChunk = @($chunkRecordList | Select-Object -Skip $recordIndex -First $maxRecordsPerRequest)
            if ($recordChunk.Count -eq 0) {
                continue
            }

            $request = [Enterprise.ComplianceReportRequest]::new()
            $request.ReportName = "Compliance Report on $(Get-Date -Format o)"
            $request.SaveReport = $false
            $request.ComplianceReportRun = [Enterprise.ComplianceReportRun]::new()
            $request.ComplianceReportRun.ReportCriteriaAndFilter = [Enterprise.ComplianceReportCriteriaAndFilter]::new()
            $request.ComplianceReportRun.ReportCriteriaAndFilter.Criteria = [Enterprise.ComplianceReportCriteria]::new()
            $request.ComplianceReportRun.ReportCriteriaAndFilter.NodeId = $rootNodeId
            $request.ComplianceReportRun.ReportCriteriaAndFilter.Criteria.IncludeNonShared = (-not $SharedOnly)

            foreach ($userUid in $userChunk) {
                $request.ComplianceReportRun.Users.Add([long]$userUid) | Out-Null
            }
            foreach ($recordUid in $recordChunk) {
                $request.ComplianceReportRun.Records.Add(
                    [Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode([string]$recordUid))
                ) | Out-Null
            }

            try {
                $response = [Enterprise.ComplianceReportResponse](
                    Get-KeeperComplianceRestResponse -Auth $auth -Endpoint 'enterprise/run_compliance_report' `
                        -Request $request -ResponseType ([Enterprise.ComplianceReportResponse])
                )
            }
            catch {
                $fullComplianceFailures++
                $message = [string]$_.Exception.Message
                if ($message.IndexOf('required privilege', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $message.IndexOf('access_denied', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    Write-Warning "Full compliance request was denied by Keeper. Continuing with the preliminary snapshot only."
                    $stopFullCompliance = $true
                    break
                }

                Write-Warning "Full compliance request failed for users=$($userChunk.Count), records=$($recordChunk.Count): $message"
                continue
            }

            $anonymousSeed = Update-KeeperComplianceAnonymousUsers -Response $response -AnonymousSeed $anonymousSeed
            Merge-KeeperComplianceResponse -Snapshot $snapshot -Response $response
        }
    }

    if ($snapshot.Diagnostics.RecordDataFailures -gt 0) {
        Write-Warning "Failed to decrypt or parse compliance metadata for $($snapshot.Diagnostics.RecordDataFailures) record payload(s). Some title/type/url fields may be blank."
    }
    if ($fullComplianceFailures -gt 0) {
        Write-Warning "$fullComplianceFailures full compliance request batch(es) failed. Results may be incomplete."
    }

    $recordDecryptFails = [int]$snapshot.Diagnostics.RecordDataFailures
    $incomplete = ($problemUserIds.Count -gt 0) -or ($fullComplianceFailures -gt 0) -or $stopFullCompliance -or ($recordDecryptFails -gt 0)
    Set-KeeperComplianceLastSnapshotStatus -FromCache $false -Incomplete $incomplete `
        -PreliminaryUsersSkipped $problemUserIds.Count -FullComplianceFailures $fullComplianceFailures `
        -PrivilegeDeniedStoppedFullFetch $stopFullCompliance -RecordMetadataDecryptFailures $recordDecryptFails

    $snapshot.PSObject.Properties.Remove('EcPrivateKey')
    $snapshot.PSObject.Properties.Remove('Diagnostics')

    $script:ComplianceReportCache.Entries[$cacheKey] = @{
        Snapshot = $snapshot
        LoadedAt = Get-Date
    }
    Write-KeeperComplianceStatus "Compliance snapshot cached under '$cacheKey'. Final records=$($snapshot.Records.Count); shared folders=$($snapshot.SharedFolders.Count); teams=$($snapshot.Teams.Count)."
    Save-KeeperComplianceSnapshotToSqlite -CacheKey $cacheKey -Snapshot $snapshot -Incomplete $incomplete `
        -SharedOnly ([bool]$SharedOnly) -Enterprise $enterprise -Auth $auth

    return $snapshot
}

function Get-KeeperComplianceAuditEventValue {
    param(
        [Parameter()]$Event,
        [Parameter(Mandatory = $true)][string]$Key
    )

    if ($null -eq $Event) {
        return $null
    }

    $property = $Event.PSObject.Properties[$Key]
    if ($property -and $null -ne $property.Value) {
        return $property.Value
    }

    $keysProperty = $Event.PSObject.Properties['Keys']
    if ($keysProperty -and $null -ne $keysProperty.Value) {
        try {
            if (@($keysProperty.Value) -contains $Key) {
                $value = $Event[$Key]
                if ($null -ne $value) {
                    return $value
                }
            }
        }
        catch {
        }
    }

    $containsKeyMethod = $Event.PSObject.Methods['ContainsKey']
    if ($containsKeyMethod) {
        try {
            if ($Event.ContainsKey($Key)) {
                $value = $Event[$Key]
                if ($null -ne $value) {
                    return $value
                }
            }
        }
        catch {
        }
    }

    try {
        foreach ($p in $Event.PSObject.Properties) {
            if ($p.Name -ieq $Key -and $null -ne $p.Value) {
                return $p.Value
            }
        }
    }
    catch {
    }
    if ($Event -is [System.Collections.IDictionary]) {
        foreach ($k in @($Event.Keys)) {
            if ($null -eq $k) {
                continue
            }
            if ([string]$k -ieq $Key) {
                $v = $Event[$k]
                if ($null -ne $v) {
                    return $v
                }
            }
        }
    }

    return $null
}

function ConvertTo-KeeperComplianceDateTime {
    param(
        [Parameter()]$EpochValue
    )

    if ($null -eq $EpochValue) {
        return $null
    }

    $epoch = 0L
    if ([long]::TryParse($EpochValue.ToString(), [ref]$epoch)) {
        try {
            return [DateTimeOffset]::FromUnixTimeSeconds($epoch).LocalDateTime
        }
        catch {
        }
    }

    return $null
}

function Get-KeeperComplianceAgingData {
    param(
        [Parameter(Mandatory = $true)][string[]]$RecordUids,
        [Parameter()]$Snapshot,
        [Parameter()][long[]]$OwnerUserIdsForAging
    )

    $recordIds = @($RecordUids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($recordIds.Count -eq 0) {
        return @{}
    }

    $enterprise = $null
    $auth = $null
    try {
        $enterprise = getEnterprise
        if ($enterprise -and $enterprise.loader -and $enterprise.loader.Auth) {
            $auth = $enterprise.loader.Auth
            Import-KeeperComplianceAgingCacheFromSqlite -Enterprise $enterprise -Auth $auth
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Aging SQLite preload skipped: $($_.Exception.Message)"
    }

    if (-not $script:ComplianceAgingCache) {
        $script:ComplianceAgingCache = @{
            Entries = @{}
        }
    }
    if (-not $script:ComplianceAgingCache.Entries) {
        $script:ComplianceAgingCache.Entries = @{}
    }

    $cacheTtl = [TimeSpan]::FromDays(1)
    $now = Get-Date
    $agingData = @{}
    $staleRecordIds = [System.Collections.Generic.List[string]]::new()

    foreach ($recordUid in $recordIds) {
        $cachedEntry = $script:ComplianceAgingCache.Entries[$recordUid]
        if ($cachedEntry -and (((Get-Date) - [datetime]$cachedEntry.LastCached) -lt $cacheTtl)) {
            $agingData[$recordUid] = @{
                created        = $cachedEntry.Created
                last_pw_change = $cachedEntry.LastPwChange
                last_modified  = $cachedEntry.LastModified
                last_rotation  = $cachedEntry.LastRotation
            }
        }
        else {
            $agingData[$recordUid] = @{
                created        = $null
                last_pw_change = $null
                last_modified  = $null
                last_rotation  = $null
            }
            $staleRecordIds.Add($recordUid) | Out-Null
        }
    }

    if ($null -ne $Snapshot -and $OwnerUserIdsForAging -and $OwnerUserIdsForAging.Count -gt 0 -and $enterprise -and $auth) {
        $refreshMap = Import-KeeperComplianceAgingUserRefreshFromSqlite -Enterprise $enterprise -Auth $auth
        $minTs = [DateTimeOffset]::UtcNow.AddDays(-1).ToUnixTimeSeconds()
        $skipIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($ou in $OwnerUserIdsForAging) {
            $last = $refreshMap[[string]$ou]
            if ($null -eq $last -or [long]$last -lt $minTs) {
                continue
            }
            if ($Snapshot.OwnedRecordsByUser.ContainsKey([long]$ou)) {
                foreach ($r in $Snapshot.OwnedRecordsByUser[[long]$ou]) {
                    $rs = [string]$r
                    if ($recordIds -contains $rs) {
                        $skipIds.Add($rs) | Out-Null
                    }
                }
            }
        }
        if ($skipIds.Count -gt 0) {
            $newStale = [System.Collections.Generic.List[string]]::new()
            foreach ($x in $staleRecordIds) {
                if (-not $skipIds.Contains($x)) {
                    $newStale.Add($x) | Out-Null
                }
            }
            $staleRecordIds = $newStale
        }
    }

    if ($staleRecordIds.Count -eq 0) {
        Write-KeeperComplianceStatus "Aging phase: all $($recordIds.Count) record(s) satisfied from cache."
        if ($null -ne $OwnerUserIdsForAging -and $OwnerUserIdsForAging.Count -gt 0) {
            try {
                if ($enterprise -and $auth) {
                    Save-KeeperComplianceAgingUserRefreshToSqlite -Enterprise $enterprise -Auth $auth -UserIds $OwnerUserIdsForAging
                }
            }
            catch {
                Write-Verbose -Message "[compliance] Aging user refresh save skipped: $($_.Exception.Message)"
            }
        }
        return $agingData
    }
    Write-KeeperComplianceStatus "Aging phase: fetching audit events for $($staleRecordIds.Count) stale record(s); cache hits=$($recordIds.Count - $staleRecordIds.Count)."

    if (-not $auth) {
        Write-Warning "Cannot fetch compliance aging data: enterprise authentication is not available."
        return $agingData
    }
    $typesByAgingEvent = [ordered]@{
        created        = @()
        last_modified  = @('record_update')
        last_rotation  = @('record_rotation_scheduled_ok', 'record_rotation_on_demand_ok')
        last_pw_change = @('record_password_change')
    }
    $requestChunkSize = 2000

    function Invoke-KeeperComplianceAgingRequests {
        param(
            [Parameter(Mandatory = $true)][string[]]$RequestRecordUids,
            [Parameter()][string[]]$EventTypes,
            [Parameter(Mandatory = $true)][string]$Aggregate,
            [Parameter(Mandatory = $true)][string]$Order
        )

        $responses = [System.Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $RequestRecordUids.Count; $index += $requestChunkSize) {
            $chunk = @($RequestRecordUids | Select-Object -Skip $index -First $requestChunkSize)
            if ($chunk.Count -eq 0) {
                continue
            }
            Write-KeeperComplianceStatus "Aging request: aggregate=$Aggregate order=$Order events=$(@($EventTypes) -join ',') records=$($chunk.Count) offset=$index."

            $filter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter
            $filter.RecordUid = $chunk
            if ($EventTypes -and $EventTypes.Count -gt 0) {
                $filter.EventTypes = $EventTypes
            }

            $request = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
            $request.Filter = $filter
            $request.ReportType = 'span'
            $request.Aggregate = @($Aggregate)
            $request.Columns = @('record_uid')
            $request.Order = $Order
            $request.Limit = 2000

            $response = $auth.ExecuteAuthCommand(
                $request,
                [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse],
                $true
            ).GetAwaiter().GetResult()

            if ($response -and $response.Events) {
                foreach ($auditRow in $response.Events) {
                    $responses.Add($auditRow) | Out-Null
                }
                Write-KeeperComplianceStatus "Aging response: aggregate=$Aggregate returned $($response.Events.Count) event row(s)."
            }
            else {
                Write-KeeperComplianceStatus "Aging response: aggregate=$Aggregate returned 0 event row(s)."
            }
        }

        return @($responses)
    }

    $recordEventsByStat = @{}
    foreach ($stat in $typesByAgingEvent.Keys) {
        $aggregate = if ($stat -eq 'created') { 'first_created' } else { 'last_created' }
        $order = if ($stat -eq 'created') { 'ascending' } else { 'descending' }
        $events = Invoke-KeeperComplianceAgingRequests -RequestRecordUids @($staleRecordIds) `
            -EventTypes $typesByAgingEvent[$stat] -Aggregate $aggregate -Order $order
        $recordEventsByStat[$stat] = @{}
        foreach ($auditRow in $events) {
            $recordUid = Get-KeeperComplianceAuditEventValue -Event $auditRow -Key 'record_uid'
            if (-not $recordUid) {
                continue
            }
            $recordEventsByStat[$stat][[string]$recordUid] = ConvertTo-KeeperComplianceDateTime `
                -EpochValue (Get-KeeperComplianceAuditEventValue -Event $auditRow -Key $aggregate)
        }
    }

    $pwCountEvents = Invoke-KeeperComplianceAgingRequests -RequestRecordUids @($staleRecordIds) `
        -EventTypes @('record_password_change') -Aggregate 'occurrences' -Order 'descending'
    $pwOccurrences = @{}
    foreach ($auditRow in $pwCountEvents) {
        $recordUid = Get-KeeperComplianceAuditEventValue -Event $auditRow -Key 'record_uid'
        if (-not $recordUid) {
            continue
        }

        $occurrences = 0
        $occurrenceValue = Get-KeeperComplianceAuditEventValue -Event $auditRow -Key 'occurrences'
        if ($null -ne $occurrenceValue) {
            [void][int]::TryParse($occurrenceValue.ToString(), [ref]$occurrences)
        }
        $pwOccurrences[[string]$recordUid] = $occurrences
    }

    foreach ($stat in $recordEventsByStat.Keys) {
        foreach ($recordUid in $recordEventsByStat[$stat].Keys) {
            $agingData[$recordUid][$stat] = $recordEventsByStat[$stat][$recordUid]
            if ($stat -eq 'created' -and -not $agingData[$recordUid]['last_modified']) {
                $agingData[$recordUid]['last_modified'] = $recordEventsByStat[$stat][$recordUid]
            }
        }
    }

    foreach ($recordUid in $pwOccurrences.Keys) {
        if ($pwOccurrences[$recordUid] -le 1 -and $agingData[$recordUid]['last_pw_change']) {
            $agingData[$recordUid]['last_pw_change'] = $null
        }
    }

    foreach ($recordUid in $staleRecordIds) {
        $pwChange = $agingData[$recordUid]['last_pw_change']
        $rotation = $agingData[$recordUid]['last_rotation']
        if ($rotation -and (-not $pwChange -or $rotation -gt $pwChange)) {
            $agingData[$recordUid]['last_pw_change'] = $rotation
        }

        $script:ComplianceAgingCache.Entries[$recordUid] = @{
            Created       = $agingData[$recordUid]['created']
            LastPwChange  = $agingData[$recordUid]['last_pw_change']
            LastModified  = $agingData[$recordUid]['last_modified']
            LastRotation  = $agingData[$recordUid]['last_rotation']
            LastCached    = $now
        }
    }

    try {
        if ($enterprise -and $auth) {
            Save-KeeperComplianceAgingCacheToSqlite -Enterprise $enterprise -Auth $auth
            if ($null -ne $OwnerUserIdsForAging -and $OwnerUserIdsForAging.Count -gt 0) {
                Save-KeeperComplianceAgingUserRefreshToSqlite -Enterprise $enterprise -Auth $auth -UserIds $OwnerUserIdsForAging
            }
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Aging SQLite save skipped: $($_.Exception.Message)"
    }

    return $agingData
}

function Get-KeeperComplianceOwners {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][string[]]$Username,
        [Parameter()][string[]]$Team,
        [Parameter()][string[]]$JobTitle,
        [Parameter()]$Node
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $candidateUserIds = [System.Collections.Generic.HashSet[long]]::new()
    $hasUsernameFilter = Test-KeeperComplianceHasNonEmptyStringList -Strings $Username
    $hasTeamFilter = Test-KeeperComplianceHasNonEmptyStringList -Strings $Team

    if ($hasUsernameFilter) {
        $lookup = @{}
        foreach ($value in $Username) {
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $lookup[$value.ToLowerInvariant()] = $true
            }
        }
        foreach ($user in $Snapshot.Users.Values) {
            if ($user.Email -and $lookup.ContainsKey($user.Email.ToLowerInvariant())) {
                $candidateUserIds.Add([long]$user.UserUid) | Out-Null
            }
        }
    }

    if ($hasTeamFilter) {
        foreach ($teamRef in $Team) {
            if ([string]::IsNullOrWhiteSpace([string]$teamRef)) {
                continue
            }
            $resolvedTeam = Get-KeeperTeamByNameOrUid -EnterpriseData $enterpriseData -TeamInput $teamRef
            if (-not $resolvedTeam) {
                Write-Warning "No enterprise team matched '$teamRef' for compliance report owners."
                continue
            }
            foreach ($userUid in $enterpriseData.GetUsersForTeam($resolvedTeam.Uid)) {
                $candidateUserIds.Add([long]$userUid) | Out-Null
            }
        }
    }

    if ($candidateUserIds.Count -eq 0 -and -not $hasUsernameFilter -and -not $hasTeamFilter) {
        foreach ($userUid in $Snapshot.OwnedRecordsByUser.Keys) {
            $candidateUserIds.Add([long]$userUid) | Out-Null
        }
    }

    $owners = @()
    foreach ($userUid in $candidateUserIds) {
        if ($Snapshot.Users.ContainsKey([long]$userUid)) {
            $owners += $Snapshot.Users[[long]$userUid]
        }
    }

    if ($JobTitle) {
        $jobTitleLookup = @{}
        foreach ($title in $JobTitle) {
            if ($title) {
                $jobTitleLookup[$title.ToLowerInvariant()] = $true
            }
        }
        $owners = @($owners | Where-Object {
            $_.JobTitle -and $jobTitleLookup.ContainsKey(([string]$_.JobTitle).ToLowerInvariant())
        })
    }

    if (Test-KeeperComplianceHasNodeFilter -Node $Node) {
        $resolvedNode = Resolve-KeeperComplianceNode -Node $Node.Trim() -Context 'compliance report node filter'
        $targetNodeId = [long]$resolvedNode.Id
        $rootNodeId = [long]$enterpriseData.RootNode.Id
        if ($targetNodeId -ne $rootNodeId) {
            # Commander parity: exact home node match only (not subtree).
            $owners = @($owners | Where-Object {
                $nid = [long]$_.NodeId
                if ($nid -le 0) {
                    $nid = $rootNodeId
                }
                return ($nid -eq $targetNodeId)
            })
        }
    }

    return @($owners)
}

function Test-KeeperComplianceRecordMatch {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter()][string[]]$RecordFilter,
        [Parameter()][string[]]$Url,
        [Parameter()][switch]$Shared,
        [Parameter()][switch]$DeletedItems,
        [Parameter()][switch]$ActiveItems
    )

    if ($Shared -and -not $Record.Shared) {
        return $false
    }

    if ($DeletedItems -and -not $Record.InTrash) {
        return $false
    }

    if ($ActiveItems -and $Record.InTrash) {
        return $false
    }

    if ($Url) {
        $matchedUrl = $false
        foreach ($urlValue in $Url) {
            if ($Record.Url -and $Record.Url.IndexOf($urlValue, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $matchedUrl = $true
                break
            }
        }
        if (-not $matchedUrl) {
            return $false
        }
    }

    if ($RecordFilter) {
        $matchedRecord = $false
        foreach ($recordRef in $RecordFilter) {
            if ($Record.Uid -eq $recordRef) {
                $matchedRecord = $true
                break
            }
            if ($Record.Title -and $Record.Title -like $recordRef) {
                $matchedRecord = $true
                break
            }
        }
        if (-not $matchedRecord) {
            return $false
        }
    }

    return $true
}

function Get-KeeperComplianceReportRows {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][string[]]$Username,
        [Parameter()][string[]]$Team,
        [Parameter()][string[]]$JobTitle,
        [Parameter()]$Node,
        [Parameter()][string[]]$Record,
        [Parameter()][string[]]$Url,
        [Parameter()][switch]$Shared,
        [Parameter()][switch]$DeletedItems,
        [Parameter()][switch]$ActiveItems,
        [Parameter()][switch]$Aging,
        [Parameter()][long[]]$OwnerUserIdsForAging
    )

    if ($DeletedItems -and $ActiveItems) {
        Write-Error "-DeletedItems and -ActiveItems cannot be used together." -ErrorAction Stop
    }

    $owners = Get-KeeperComplianceOwners -Snapshot $Snapshot -Username $Username -Team $Team -JobTitle $JobTitle -Node $Node
    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $agingData = @{}
    Write-KeeperComplianceStatus "Building report rows for $($owners.Count) owner(s)."

    foreach ($owner in $owners) {
        if (-not $Snapshot.OwnedRecordsByUser.ContainsKey([long]$owner.UserUid)) {
            continue
        }

        foreach ($recordUid in $Snapshot.OwnedRecordsByUser[[long]$owner.UserUid]) {
            if (-not $Snapshot.Records.ContainsKey($recordUid)) {
                continue
            }

            $recordEntry = $Snapshot.Records[$recordUid]
            if (-not (Test-KeeperComplianceRecordMatch -Record $recordEntry -RecordFilter $Record -Url $Url `
                    -Shared:$Shared -DeletedItems:$DeletedItems -ActiveItems:$ActiveItems)) {
                continue
            }

            $permissionsLookup = @{}
            foreach ($userUid in $recordEntry.UserPermissions.Keys) {
                Add-KeeperCompliancePermissionByUserUid -Snapshot $Snapshot -PermissionLookup $permissionsLookup `
                    -TargetUid ([long]$userUid) -PermissionBits ([int]$recordEntry.UserPermissions[$userUid])
            }

            foreach ($sharedFolderUid in $recordEntry.SharedFolderUids) {
                if (-not $Snapshot.SharedFolders.ContainsKey([string]$sharedFolderUid)) {
                    continue
                }

                $folderEntry = $Snapshot.SharedFolders[[string]$sharedFolderUid]
                if (-not $folderEntry.RecordPermissions.ContainsKey($recordUid)) {
                    continue
                }

                $folderBits = [int]$folderEntry.RecordPermissions[$recordUid]
                foreach ($folderUserUid in $folderEntry.Users) {
                    Add-KeeperCompliancePermissionByUserUid -Snapshot $Snapshot -PermissionLookup $permissionsLookup `
                        -TargetUid ([long]$folderUserUid) -PermissionBits $folderBits
                }

                foreach ($teamUid in $folderEntry.Teams) {
                    if (-not $Snapshot.Teams.ContainsKey([string]$teamUid)) {
                        continue
                    }

                    foreach ($teamUserUid in $Snapshot.Teams[[string]$teamUid].Users) {
                        Add-KeeperCompliancePermissionByUserUid -Snapshot $Snapshot -PermissionLookup $permissionsLookup `
                            -TargetUid ([long]$teamUserUid) -PermissionBits $folderBits
                    }
                }
            }

            if ($permissionsLookup.Count -eq 0 -and $owner.Email) {
                Add-KeeperCompliancePermissionByEmail -PermissionLookup $permissionsLookup -Email ([string]$owner.Email) -PermissionBits 1
            }

            $sharedFolderIds = @($recordEntry.SharedFolderUids | Sort-Object)
            foreach ($email in ($permissionsLookup.Keys | Sort-Object)) {
                $bits = [int]$permissionsLookup[$email]
                $row = [ordered]@{
                    record_uid        = $recordEntry.Uid
                    title             = [string]$recordEntry.Title
                    type              = [string]$recordEntry.RecordType
                    username          = [string]$email
                    permissions       = Get-KeeperCompliancePermissionText -PermissionBits $bits
                    permission_bits   = $bits
                    url               = if ($recordEntry.Url) { ([string]$recordEntry.Url).TrimEnd('/') } else { '' }
                    in_trash          = [bool]$recordEntry.InTrash
                    shared_folder_uid = $sharedFolderIds
                }

                $rows.Add([PSCustomObject]$row) | Out-Null
            }
        }
    }

    # Commander: stable sort — primary record_uid ASC, then (bits & 1) DESC, then permission bits DESC.
    $rows = @(
        $rows |
            Sort-Object record_uid,
            @{ Expression = { $_.permission_bits -band 1 }; Descending = $true },
            @{ Expression = { $_.permission_bits }; Descending = $true }
    )

    if ($Aging -and $rows.Count -gt 0) {
        Write-KeeperComplianceStatus "Applying aging data to $($rows.Count) row(s)."
        $agingData = Get-KeeperComplianceAgingData -RecordUids @($rows | Select-Object -ExpandProperty record_uid -Unique) `
            -Snapshot $Snapshot -OwnerUserIdsForAging $OwnerUserIdsForAging
        foreach ($row in $rows) {
            $rowAging = $agingData[$row.record_uid]
            Add-Member -InputObject $row -NotePropertyName created -NotePropertyValue $rowAging['created'] -Force
            Add-Member -InputObject $row -NotePropertyName last_pw_change -NotePropertyValue $rowAging['last_pw_change'] -Force
            Add-Member -InputObject $row -NotePropertyName last_modified -NotePropertyValue $rowAging['last_modified'] -Force
            Add-Member -InputObject $row -NotePropertyName last_rotation -NotePropertyValue $rowAging['last_rotation'] -Force
        }
    }
    Write-KeeperComplianceStatus "Report row generation complete. Rows=$($rows.Count)."

    return @($rows)
}

function ConvertTo-KeeperComplianceDisplayRows {
    param(
        [Parameter(Mandatory = $true)]$Rows
    )

    return @(
        $Rows | ForEach-Object {
            $row = [ordered]@{}
            foreach ($property in $_.PSObject.Properties) {
                if ($property.Name -eq 'permission_bits') {
                    continue
                }
                if ($property.Name -eq 'shared_folder_uid') {
                    $row[$property.Name] = @($property.Value) -join ', '
                }
                else {
                    $row[$property.Name] = $property.Value
                }
            }
            [PSCustomObject]$row
        }
    )
}

<#
    .SYNOPSIS
        Clear compliance report cache
    .DESCRIPTION
        Clears in-session compliance data and removes the local SQLite cache file.
#>
function Clear-KeeperComplianceCache {
    $script:ComplianceReportCache = @{
        Entries = @{}
    }
    $script:ComplianceAgingCache = @{
        Entries = @{}
    }
    $script:ComplianceReportLastSnapshotStatus = $null
    try {
        $entClear = getEnterprise
        if ($entClear -and $entClear.loader -and $entClear.loader.Auth) {
            Remove-KeeperComplianceSqliteCache -Enterprise $entClear -Auth $entClear.loader.Auth
        }
    }
    catch {
        Write-Verbose -Message "[compliance] SQLite cache clear skipped: $($_.Exception.Message)"
    }
}

function Invoke-KeeperComplianceReportSession {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter()][switch]$NoCache,
        [Parameter()][object[]]$ArgumentList
    )

    try {
        if ($null -ne $ArgumentList -and $ArgumentList.Length -gt 0) {
            return & $ScriptBlock @ArgumentList
        }
        return & $ScriptBlock
    }
    finally {
        if ($NoCache) {
            Clear-KeeperComplianceCache
        }
    }
}

function Get-KeeperComplianceReport {
    <#
        .SYNOPSIS
            Run enterprise compliance report

        .DESCRIPTION
            Report of records owned by enterprise users and their sharing relationships.
            Data is cached locally for up to one day. Use -Rebuild to force a fresh pull, -NoCache to discard caches after the report.

        .PARAMETER Format
            Output format: table (default), json, or csv.

        .PARAMETER Output
            Output file path. Ignored when Format is 'table'.

        .PARAMETER Username
            Filter by enterprise username(s).

        .PARAMETER Node
            Filter by node name or UID.

        .PARAMETER Pattern
            Filter rows by pattern. Supports regex:, exact:, not: prefixes.

        .PARAMETER Regex
            Treat plain patterns as regular expressions.

        .PARAMETER PatternMatchAll
            Require all patterns to match (AND). Default is OR.

        .PARAMETER JobTitle
            Filter by job title.

        .PARAMETER Record
            Filter by record UID(s) or title.

        .PARAMETER Team
            Filter by team name or UID.

        .PARAMETER Url
            Filter by URL substring.

        .PARAMETER Shared
            Show only shared records.

        .PARAMETER DeletedItems
            Show only deleted records.

        .PARAMETER ActiveItems
            Show only active records.

        .PARAMETER Rebuild
            Rebuild the in-session compliance cache from Keeper.

        .PARAMETER NoRebuild
            Use the in-session compliance cache if it exists; if not, build it once.

        .PARAMETER NoCache
            Clear the in-session compliance cache after the report finishes.

        .PARAMETER Aging
            Include aging data columns: Created, Last Password Change, Last Modified, and Last Rotation.

        .EXAMPLE
            Get-KeeperComplianceReport -Rebuild
            Return a fresh batch of records for all users in the enterprise and their sharing relationship.

        .EXAMPLE
            compliance-report -Username user@company.com
            Return the records owned by the specified user and their sharing relationship.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][string[]]$Username,
        [Parameter()][string]$Node,
        [Parameter()][string[]]$JobTitle,
        [Parameter()][string[]]$Record,
        [Parameter()][string[]]$Team,
        [Parameter()][string[]]$Url,
        [Parameter()][string[]]$Pattern,
        [Parameter()][switch]$Regex,
        [Parameter()][switch]$PatternMatchAll,
        [Parameter()][switch]$Shared,
        [Parameter()][switch]$DeletedItems,
        [Parameter()][switch]$ActiveItems,
        [Parameter()][switch]$Rebuild,
        [Parameter()][switch]$NoRebuild,
        [Parameter()][switch]$NoCache,
        [Parameter()][switch]$Aging
    )

    $reportRows = Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ScriptBlock {
        Write-KeeperComplianceStatus "Starting compliance-report. Format=$Format Rebuild=$Rebuild NoRebuild=$NoRebuild NoCache=$NoCache Aging=$Aging."
        $fetchOwnerIds = Resolve-KeeperComplianceFetchOwnerIds -Username $Username -Team $Team -Node $Node
        if ($null -ne $fetchOwnerIds -and $fetchOwnerIds.Count -eq 0) {
            Write-Warning "No enterprise users matched the provided owner filters."
        }
        elseif ($null -eq $fetchOwnerIds) {
            Write-KeeperComplianceStatus "Owner pre-filter: all enterprise users."
        }
        else {
            Write-KeeperComplianceStatus "Owner pre-filter matched $($fetchOwnerIds.Count) user(s)."
        }

        $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$Rebuild -NoRebuild:$NoRebuild -OwnerUserIds $fetchOwnerIds
        $ownerIdsForAging = if ($null -ne $fetchOwnerIds) { $fetchOwnerIds } else { $null }
        $reportRows = Get-KeeperComplianceReportRows -Snapshot $snapshot -Username $Username -Team $Team `
            -JobTitle $JobTitle -Node $Node -Record $Record -Url $Url -Shared:$Shared `
            -DeletedItems:$DeletedItems -ActiveItems:$ActiveItems -Aging:$Aging `
            -OwnerUserIdsForAging $ownerIdsForAging

        if ($Pattern -and $Pattern.Count -gt 0) {
            $reportRows = Invoke-KeeperCompliancePatternFilterRows -Rows $reportRows -Patterns $Pattern `
                -UseRegex:$Regex -MatchAll:$PatternMatchAll
        }
        return ,@($reportRows)
    }

    if ($reportRows.Count -eq 0) {
        Write-KeeperComplianceStatus "No compliance report rows matched the current filters."
        Write-Host "No compliance report rows found."
        return
    }

    $displayRows = ConvertTo-KeeperComplianceDisplayRows -Rows $reportRows
    if ($Format -eq 'table' -and -not ($Pattern -and $Pattern.Count -gt 0)) {
        $lastRecUid = ''
        $displayRows = @($displayRows | ForEach-Object {
            $curUid = [string]$_.record_uid
            $dr = [ordered]@{}
            foreach ($p in $_.PSObject.Properties) {
                if ($p.Name -eq 'record_uid' -and $curUid -and $curUid -eq $lastRecUid) {
                    $dr[$p.Name] = ''
                }
                else {
                    $dr[$p.Name] = $p.Value
                }
            }
            if ($curUid) {
                $lastRecUid = $curUid
            }
            [PSCustomObject]$dr
        })
    }
    Write-KeeperComplianceStatus "Rendering $($reportRows.Count) row(s) as $Format."
    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $displayRows -Format $Format -Output $Output -JsonDepth 6
}
New-Alias -Name compliance-report -Value Get-KeeperComplianceReport

function ConvertTo-KeeperUnixSecondsOptional {
    param(
        [Parameter()]$DateTimeValue
    )
    if ($null -eq $DateTimeValue) {
        return $null
    }
    try {
        $dt = [datetime]$DateTimeValue
        return [int64][DateTimeOffset]::new($dt).ToUnixTimeSeconds()
    }
    catch {
        return $null
    }
}

function Resolve-KeeperAgingCutoffDateTime {
    param(
        [Parameter()][string]$Period,
        [Parameter()][string]$CutoffDate
    )

    if ($Period -and $CutoffDate) {
        Write-Error "-Period and -CutoffDate cannot be used together (same as Keeper Commander aging-report)." -ErrorAction Stop
    }

    if ($CutoffDate) {
        $fmts = @(
            'yyyy-MM-dd', 'yyyy.MM.dd', 'yyyy/MM/dd',
            'MM-dd-yyyy', 'MM.dd.yyyy', 'MM/dd/yyyy'
        )
        $trimmed = $CutoffDate.Trim()
        foreach ($fmt in $fmts) {
            try {
                return [datetime]::ParseExact($trimmed, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None)
            }
            catch [System.FormatException] {
                continue
            }
        }
        try {
            return [datetime]::Parse($trimmed, [System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::None)
        }
        catch {
        }
        Write-Error "Unrecognized -CutoffDate format. Use yyyy-MM-dd, yyyy.MM.dd, yyyy/MM/dd, MM-dd-yyyy, MM.dd.yyyy, or MM/dd/yyyy." -ErrorAction Stop
    }

    $duration = $Period
    if ([string]::IsNullOrWhiteSpace($duration)) {
        Write-Host ""
        Write-Host "The default password aging period is 3 months."
        Write-Host "To change this value pass -Period (e.g. 10d for 10 days; 3m for 3 months; 1y for 1 year)."
        Write-Host ""
        $duration = '3m'
    }

    $co = $duration.Substring($duration.Length - 1).ToLowerInvariant()
    $numPart = $duration.Substring(0, [Math]::Max(0, $duration.Length - 1))
    $va = 0
    if (-not [int]::TryParse($numPart, [ref]$va)) {
        Write-Error "Invalid -Period value: $duration" -ErrorAction Stop
    }
    $va = [Math]::Abs($va)
    $days = $va
    if ($co -eq 'd') {
    }
    elseif ($co -eq 'm') {
        $days = $va * 30
    }
    elseif ($co -eq 'y') {
        $days = $va * 365
    }
    else {
        Write-Error "Invalid -Period suffix: use d, m, or y (e.g. 3m)." -ErrorAction Stop
    }

    return (Get-Date).AddDays(-$days)
}

function Get-KeeperAgingReport {
    <#
        .SYNOPSIS
            Run password aging report

        .DESCRIPTION
            Lists records whose password has not been changed since a cutoff date (default: 3 months).

        .PARAMETER Format
            table (default), json, or csv.

        .PARAMETER Output
            File path when Format is json or csv.

        .PARAMETER Period
            Cutoff period, e.g. 10d, 3m, 1y. Ignored if -CutoffDate is set.

        .PARAMETER CutoffDate
            Fixed cutoff date. Mutually exclusive with -Period.

        .PARAMETER Username
            Filter by enterprise user email.

        .PARAMETER ExcludeDeleted
            Exclude records in trash.

        .PARAMETER InSharedFolder
            Only include records in shared folders.

        .PARAMETER Sort
            Sort by: owner, title, last_changed, or shared.

        .PARAMETER Rebuild, NoRebuild, NoCache, Delete
            Cache control flags. -Delete clears cache without running a report.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][string]$Period,
        [Parameter()][string]$CutoffDate,
        [Parameter()][string]$Username,
        [Parameter()][switch]$ExcludeDeleted,
        [Parameter()][switch]$InSharedFolder,
        [Parameter()][ValidateSet('owner', 'title', 'last_changed', 'shared')][string]$Sort = 'last_changed',
        [Parameter()][switch]$Rebuild,
        [Parameter()][switch]$NoRebuild,
        [Parameter()][switch]$NoCache,
        [Parameter()][switch]$Delete
    )

    if ($Delete) {
        $ent = getEnterprise
        if (-not $ent -or -not $ent.loader -or -not $ent.loader.Auth) {
            Write-Error "Enterprise authentication is required for -Delete." -ErrorAction Stop
        }
        Remove-KeeperComplianceSqliteCache -Enterprise $ent -Auth $ent.loader.Auth
        Clear-KeeperComplianceCache
        Write-Host "Local compliance cache has been deleted."
        return
    }

    $cutoffDt = Resolve-KeeperAgingCutoffDateTime -Period $Period -CutoffDate $CutoffDate
    $reportRows = Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ArgumentList @($cutoffDt) -ScriptBlock {
        param([datetime]$CutoffDt)
        Write-KeeperComplianceStatus "Starting aging-report. Format=$Format Rebuild=$Rebuild NoRebuild=$NoRebuild NoCache=$NoCache."
        $cutoffEpoch = [int64][DateTimeOffset]::new($CutoffDt).ToUnixTimeSeconds()

        $fetchOwnerIds = Resolve-KeeperComplianceFetchOwnerIds -Username $(if ($Username) { @($Username) } else { $null }) -Team $null -Node $null
        if ($Username -and $null -ne $fetchOwnerIds -and $fetchOwnerIds.Count -eq 0) {
            Write-Warning "No enterprise user matched -Username '$Username'."
            return ,@()
        }

        if ($Rebuild) {
            $script:ComplianceAgingCache = @{
                Entries = @{}
            }
        }

        $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$Rebuild -NoRebuild:$NoRebuild -OwnerUserIds $fetchOwnerIds
        $ownerIdsForAging = if ($null -ne $fetchOwnerIds) { $fetchOwnerIds } else { $null }

        $owners = Get-KeeperComplianceOwners -Snapshot $snapshot -Username $(if ($Username) { @($Username) } else { $null }) -Team $null -Node $null
        $enterprise = getEnterprise
        $owners = @(
            $owners | Where-Object {
                $eu = $null
                if (-not ($enterprise.enterpriseData.TryGetUserById([long]$_.UserUid, [ref]$eu)) -or -not $eu) {
                    return $false
                }
                return ($eu.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Active)
            }
        )

        if ($Username) {
            $emailOk = $false
            foreach ($o in $owners) {
                if ($o.Email -and [string]::Compare([string]$o.Email, $Username, $true) -eq 0) {
                    $emailOk = $true
                    break
                }
            }
            if (-not $emailOk) {
                Write-Warning "User $Username is not a valid enterprise user for this report scope."
                return ,@()
            }
        }

        $allRecordUids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($o in $owners) {
            $ou = [long]$o.UserUid
            if (-not $snapshot.OwnedRecordsByUser.ContainsKey($ou)) {
                continue
            }
            foreach ($r in $snapshot.OwnedRecordsByUser[$ou]) {
                if ($r) {
                    $allRecordUids.Add([string]$r) | Out-Null
                }
            }
        }

        $agingData = @{}
        if ($allRecordUids.Count -gt 0) {
            $agingData = Get-KeeperComplianceAgingData -RecordUids @($allRecordUids) -Snapshot $snapshot `
                -OwnerUserIdsForAging $ownerIdsForAging
        }

        $auth = $enterprise.loader.Auth
        $server = [string]$auth.Endpoint.Server
        if ([string]::IsNullOrWhiteSpace($server)) {
            $server = 'keepersecurity.com'
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($o in $owners) {
            $ou = [long]$o.UserUid
            if (-not $snapshot.OwnedRecordsByUser.ContainsKey($ou)) {
                continue
            }
            $ownerEmail = [string]$o.Email
            foreach ($recordUid in $snapshot.OwnedRecordsByUser[$ou]) {
                if (-not $snapshot.Records.ContainsKey([string]$recordUid)) {
                    continue
                }
                $rec = $snapshot.Records[[string]$recordUid]
                $ag = $agingData[[string]$recordUid]
                if (-not $ag) {
                    $ag = @{
                        created        = $null
                        last_pw_change = $null
                    }
                }

                $createdTs = ConvertTo-KeeperUnixSecondsOptional -DateTimeValue $ag['created']
                $changeTs = ConvertTo-KeeperUnixSecondsOptional -DateTimeValue $ag['last_pw_change']

                $createdAfter = $null -ne $createdTs -and $createdTs -ge $cutoffEpoch
                $pwChangedAfter = $null -ne $changeTs -and $changeTs -ge $cutoffEpoch
                if ($createdAfter -or $pwChangedAfter) {
                    continue
                }
                if ($ExcludeDeleted -and $rec.InTrash) {
                    continue
                }
                if ($InSharedFolder -and ($null -eq $rec.SharedFolderUids -or $rec.SharedFolderUids.Count -eq 0)) {
                    continue
                }

                $ts = $changeTs
                if ($null -eq $ts) {
                    $ts = $createdTs
                }
                $pwDt = $null
                if ($null -ne $ts) {
                    try {
                        $pwDt = [DateTimeOffset]::FromUnixTimeSeconds([long]$ts).LocalDateTime
                    }
                    catch {
                        $pwDt = $null
                    }
                }

                $sfIds = @()
                if ($rec.SharedFolderUids) {
                    $sfIds = @($rec.SharedFolderUids | Sort-Object)
                }
                $row = [ordered]@{
                    owner            = $ownerEmail
                    title            = [string]$rec.Title
                    password_changed = $pwDt
                    shared           = [bool]$rec.Shared
                    record_url       = "https://$server/value/#detail/$recordUid"
                }
                if ($InSharedFolder) {
                    $row['shared_folder_uid'] = ($sfIds -join ', ')
                }
                $rows.Add([PSCustomObject]$row) | Out-Null
            }
        }

        $list = @($rows)
        if ($Sort -eq 'owner') {
            $list = $list | Sort-Object owner, title
        }
        elseif ($Sort -eq 'title') {
            $list = $list | Sort-Object title, owner
        }
        elseif ($Sort -eq 'last_changed') {
            $list = $list | Sort-Object @{ Expression = { $_.password_changed }; Descending = $true }, owner, title
        }
        else {
            $list = $list | Sort-Object @{ Expression = { $_.shared }; Descending = $true }, owner, title
        }

        return ,@($list)
    }

    if ($reportRows.Count -eq 0) {
        Write-KeeperComplianceStatus "No aging report rows matched the current filters."
        Write-Host "No aging report rows found."
        return
    }

    $titleLine = "Aging Report: Records With Passwords Last Modified Before $($cutoffDt.ToString('yyyy/MM/dd HH:mm:ss'))"
    $displayRows = foreach ($r in $reportRows) {
        $d = [ordered]@{
            Owner              = $r.owner
            Title              = $r.title
            'Password Changed' = $r.password_changed
            Shared             = $r.shared
        }
        if ($InSharedFolder -and ($r.PSObject.Properties.Name -contains 'shared_folder_uid')) {
            $d['Shared Folder Uid'] = $r.shared_folder_uid
        }
        $d['Record URL'] = $r.record_url
        [PSCustomObject]$d
    }

    $tableCols = @('Owner', 'Title', 'Password Changed', 'Shared')
    if ($InSharedFolder) {
        $tableCols += 'Shared Folder Uid'
    }
    $tableCols += 'Record URL'

    Write-KeeperComplianceStatus "Rendering $($reportRows.Count) aging row(s) as $Format."
    if ($Format -eq 'table') {
        Write-Host ""
        Write-Host $titleLine
    }
    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $displayRows -Format $Format -Output $Output -JsonDepth 6 -TableColumns $tableCols
}
New-Alias -Name aging-report -Value Get-KeeperAgingReport

# record access report
function Get-KeeperComplianceManagedUserEmailSet {
    $enterprise = getEnterprise
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($eu in $enterprise.enterpriseData.Users) {
        if ($eu.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Inactive) {
            continue
        }
        if ($eu.Email) {
            $set.Add([string]$eu.Email) | Out-Null
        }
    }
    return $set
}

function Get-KeeperComplianceVaultRecordUidsForUser {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][long]$UserUid
    )

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    if ($Snapshot.OwnedRecordsByUser.ContainsKey($UserUid)) {
        foreach ($r in $Snapshot.OwnedRecordsByUser[$UserUid]) {
            if ($r) {
                $set.Add([string]$r) | Out-Null
            }
        }
    }

    foreach ($recordUid in $Snapshot.Records.Keys) {
        $rec = $Snapshot.Records[$recordUid]
        if ($rec.UserPermissions.ContainsKey($UserUid)) {
            $set.Add([string]$recordUid) | Out-Null
            continue
        }

        foreach ($sfUid in $rec.SharedFolderUids) {
            $sfKey = [string]$sfUid
            if (-not $Snapshot.SharedFolders.ContainsKey($sfKey)) {
                continue
            }
            $sf = $Snapshot.SharedFolders[$sfKey]
            $allFolderUids = Get-KeeperComplianceSharedFolderAllUserUids -Snapshot $Snapshot -SharedFolder $sf
            if ($allFolderUids -contains $UserUid) {
                $set.Add([string]$recordUid) | Out-Null
                break
            }
        }
    }

    return $set
}

function Get-KeeperComplianceRecordOwnerEmailFromSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$RecordUid
    )

    foreach ($ownerUid in $Snapshot.OwnedRecordsByUser.Keys) {
        $owned = $Snapshot.OwnedRecordsByUser[$ownerUid]
        if ($owned -and $owned.Contains($RecordUid) -and $Snapshot.Users.ContainsKey([long]$ownerUid)) {
            return [string]$Snapshot.Users[[long]$ownerUid].Email
        }
    }

    return ''
}

function Get-KeeperVaultRecordMetadataFallback {
    <#
        When compliance/SOX snapshot has no decrypted title, type, or URL for a record UID, try the
        current session vault (admin's vault). Fills gaps when the same record exists there.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RecordUid
    )

    try {
        $vault = getVault
        $rec = $null
        if (-not $vault.TryGetKeeperRecord($RecordUid, [ref]$rec)) {
            return $null
        }

        $title = [string]$rec.Title
        $url = ''
        $rtype = ''

        if ($rec -is [KeeperSecurity.Vault.PasswordRecord]) {
            $pr = [KeeperSecurity.Vault.PasswordRecord]$rec
            $rtype = 'login'
            if ($pr.Link) {
                $url = ([string]$pr.Link).TrimEnd('/')
            }
        }
        else {
            $tn = $rec.GetType().Name
            if ($tn -and $tn -ne 'KeeperRecord') {
                $rtype = $tn -replace 'Record$', ''
            }
        }

        return [PSCustomObject]@{
            Title      = $title
            RecordType = $rtype
            Url        = $url
        }
    }
    catch {
        return $null
    }
}

function Get-KeeperRecordAccessAuditEventsForUser {
    param(
        [Parameter(Mandatory = $true)]$Auth,
        [Parameter(Mandatory = $true)][string]$UserEmail,
        [Parameter()][string[]]$VaultRecordUids,
        [Parameter()][switch]$VaultMode,
        [Parameter(Mandatory = $true)][int]$Limit
    )

    $result = @{}
    if ($VaultMode -and (-not $VaultRecordUids -or $VaultRecordUids.Count -eq 0)) {
        return $result
    }

    $createdMax = $null
    $remaining = $null
    if ($VaultMode) {
        $remaining = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($r in $VaultRecordUids) {
            if ($r) {
                $remaining.Add([string]$r) | Out-Null
            }
        }
    }

    while ($true) {
        $filter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter
        $filter.Username = @($UserEmail)
        if ($VaultMode) {
            if ($remaining.Count -eq 0) {
                break
            }
            $filter.RecordUid = @($remaining | Sort-Object)
        }

        if ($null -ne $createdMax) {
            $cf = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
            $cf.Max = $createdMax
            $cf.ExcludeMax = $true
            $filter.Created = $cf
        }

        $rq = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
        $rq.Filter = $filter
        $rq.ReportType = 'span'
        $rq.Aggregate = @('last_created')
        $rq.Columns = @('record_uid', 'ip_address', 'keeper_version')
        $rq.Order = 'descending'
        $rq.Limit = $Limit

        try {
            $rs = $Auth.ExecuteAuthCommand(
                $rq,
                [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse],
                $true
            ).GetAwaiter().GetResult()
        }
        catch {
            Write-Warning "Record-access audit request failed for ${UserEmail}: $($_.Exception.Message)"
            break
        }

        $events = if ($rs -and $rs.Events) {
            @($rs.Events | Where-Object { $null -ne $_ })
        }
        else {
            @()
        }
        if ($events.Count -eq 0) {
            break
        }

        foreach ($evt in $events) {
            $rUid = Get-KeeperComplianceAuditEventValue -Event $evt -Key 'record_uid'
            if (-not $rUid) {
                continue
            }
            $rUidStr = [string]$rUid
            if (-not $result.ContainsKey($rUidStr)) {
                $result[$rUidStr] = $evt
            }
            if ($null -ne $remaining) {
                $remaining.Remove($rUidStr) | Out-Null
            }
        }

        $lastEvt = $events[$events.Count - 1]
        if ($null -eq $lastEvt) {
            break
        }
        $lc = Get-KeeperComplianceAuditEventValue -Event $lastEvt -Key 'last_created'
        $lastCreatedEpoch = 0L
        if ($null -ne $lc) {
            [void][long]::TryParse($lc.ToString(), [ref]$lastCreatedEpoch)
        }

        $queriesDone = $false
        if ($events.Count -lt $Limit) {
            $queriesDone = $true
        }
        if ($VaultMode -and $remaining.Count -eq 0) {
            $queriesDone = $true
        }
        if ($queriesDone) {
            break
        }

        if ($lastCreatedEpoch -le 0) {
            break
        }
        $createdMax = $lastCreatedEpoch
    }

    return $result
}

function Test-KeeperRecordAccessRowPattern {
    param(
        [Parameter(Mandatory = $true)]$Row,
        [Parameter(Mandatory = $true)][string[]]$Patterns,
        [Parameter()][switch]$UseRegex
    )

    $text = ($Row.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join "`t"
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) {
            continue
        }
        if ($UseRegex) {
            try {
                if ($text -match $p) {
                    return $true
                }
            }
            catch {
            }
        }
        else {
            foreach ($prop in $Row.PSObject.Properties) {
                $v = $prop.Value
                if ($null -eq $v) {
                    continue
                }
                $s = [string]$v
                if ($s -like $p) {
                    return $true
                }
            }
        }
    }

    return $false
}

function ConvertTo-KeeperRecordAccessDisplayRows {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table'
    )

    if ($Format -ne 'table' -or $Rows.Count -eq 0) {
        return $Rows
    }

    $lastOwner = [string]::Empty
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Rows) {
        $vo = [string]$r.vault_owner
        $showVo = $vo
        if ($vo -eq $lastOwner) {
            $showVo = ''
        }
        else {
            $lastOwner = $vo
        }

        $copy = [ordered]@{}
        foreach ($prop in $r.PSObject.Properties) {
            if ($prop.Name -eq 'vault_owner') {
                $copy[$prop.Name] = $showVo
            }
            else {
                $copy[$prop.Name] = $prop.Value
            }
        }
        $out.Add([PSCustomObject]$copy) | Out-Null
    }

    return @($out)
}

function Get-KeeperComplianceRecordAccessReport {
    <#
        .SYNOPSIS
            Run record-access report

        .DESCRIPTION
            Lists records a user has accessed or can access, with IP, client version, and last-access time from audit data.

        .PARAMETER Email
            User email(s), enterprise user ID, or '@all'.

        .PARAMETER ReportType
            'history' (default) or 'vault'.

        .PARAMETER Format
            Output format: table (default), json, or csv.

        .PARAMETER Output
            Output file path for json/csv.

        .PARAMETER Node, Username, Team
            Filter by node, username, or team.

        .PARAMETER Pattern
            Wildcard filter strings.

        .PARAMETER PatternRegex
            Regex filter strings. Mutually exclusive with -Pattern.

        .PARAMETER Rebuild, NoRebuild, NoCache, Aging
            Cache control flags.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [string[]]$Email,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [ValidateSet('history', 'vault')][string]$ReportType = 'history',
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [string]$Output,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [string]$Node,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [string[]]$Username,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [string[]]$Team,
        [Parameter(ParameterSetName = 'Default')][string[]]$Pattern,
        [Parameter(ParameterSetName = 'RegexPatterns')][string[]]$PatternRegex,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [switch]$Rebuild,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [switch]$NoRebuild,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [switch]$NoCache,
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'RegexPatterns')]
        [switch]$Aging
    )

    $apiRowLimit = 2000

    Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ScriptBlock {
        Write-KeeperComplianceStatus "Starting compliance record-access-report. ReportType=$ReportType Format=$Format Rebuild=$Rebuild NoRebuild=$NoRebuild NoCache=$NoCache Aging=$Aging."

        $enterprise = getEnterprise
        $auth = $enterprise.loader.Auth
        $managedSet = Get-KeeperComplianceManagedUserEmailSet

        $allowedUserIds = $null
        $fetchIds = Resolve-KeeperComplianceFetchOwnerIds -Username $Username -Team $Team -Node $Node
        if ($null -ne $fetchIds) {
            $allowedUserIds = [System.Collections.Generic.HashSet[long]]::new()
            foreach ($id in $fetchIds) {
                $allowedUserIds.Add([long]$id) | Out-Null
            }
        }
        if ($null -eq $fetchIds) {
            Write-KeeperComplianceStatus "Record-access owner pre-filter: all enterprise users (no Node/Username/Team filter)."
        }
        elseif ($fetchIds.Count -eq 0) {
            Write-KeeperComplianceStatus "Record-access owner pre-filter: 0 user(s) matched (Node/Username/Team exclude everyone)."
        }
        else {
            Write-KeeperComplianceStatus "Record-access owner pre-filter matched $($fetchIds.Count) user(s)."
        }

        $emailArgs = $Email
        if (-not $emailArgs -or $emailArgs.Count -eq 0) {
            $emailArgs = @('@all')
        }

        $resolvedEmails = [System.Collections.Generic.List[string]]::new()
        foreach ($ref in $emailArgs) {
            if ($ref -ieq '@all') {
                $sortedUsers = @($enterprise.enterpriseData.Users | Sort-Object Email)
                foreach ($eu in $sortedUsers) {
                    if ($eu.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Inactive) {
                        continue
                    }
                    if (-not $eu.Email) {
                        continue
                    }
                    if ($null -ne $allowedUserIds -and -not $allowedUserIds.Contains([long]$eu.Id)) {
                        continue
                    }
                    $resolvedEmails.Add([string]$eu.Email) | Out-Null
                }
                continue
            }

            $trim = $ref.Trim()
            if ($trim -match '^\d+$') {
                $eu = $null
                if ($enterprise.enterpriseData.TryGetUserById([long]$trim, [ref]$eu) -and $eu -and $eu.Email) {
                    if ($null -ne $allowedUserIds -and -not $allowedUserIds.Contains([long]$eu.Id)) {
                        continue
                    }
                    $resolvedEmails.Add([string]$eu.Email) | Out-Null
                }
                continue
            }

            if (-not $managedSet.Contains($trim)) {
                continue
            }
            $eu = $null
            if (-not $enterprise.enterpriseData.TryGetUserByEmail($trim, [ref]$eu) -or -not $eu) {
                continue
            }
            if ($null -ne $allowedUserIds -and -not $allowedUserIds.Contains([long]$eu.Id)) {
                continue
            }
            $resolvedEmails.Add($trim) | Out-Null
        }

        $seen = @{}
        $targetEmails = [System.Collections.Generic.List[string]]::new()
        foreach ($e in $resolvedEmails) {
            $k = $e.ToLowerInvariant()
            if ($seen[$k]) {
                continue
            }
            $seen[$k] = $true
            $targetEmails.Add($e) | Out-Null
        }

        if ($targetEmails.Count -eq 0) {
            Write-Host "No users selected for record-access report."
            return
        }

        # Full snapshot (not SharedOnly): audit can reference any accessed record; shared-only preliminary
        # data omits many owned/non-shared UIDs, leaving title, record_type, record_url, and record_owner blank.
        $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$Rebuild -NoRebuild:$NoRebuild -OwnerUserIds $null

        $rows = [System.Collections.Generic.List[object]]::new()
        $vaultMode = ($ReportType -eq 'vault')

        foreach ($userEmail in $targetEmails) {
            $eu = $null
            if (-not $enterprise.enterpriseData.TryGetUserByEmail($userEmail, [ref]$eu) -or -not $eu) {
                continue
            }
            $userUid = [long]$eu.Id

            $vaultUids = $null
            if ($vaultMode) {
                $vaultSet = Get-KeeperComplianceVaultRecordUidsForUser -Snapshot $snapshot -UserUid $userUid
                $vaultUids = @($vaultSet)
            }

            $auditMap = Get-KeeperRecordAccessAuditEventsForUser -Auth $auth -UserEmail $userEmail -VaultRecordUids $vaultUids `
                -VaultMode:$vaultMode -Limit $apiRowLimit

            $recordUids = [System.Collections.Generic.List[string]]::new()
            if ($vaultMode) {
                foreach ($u in $vaultUids) {
                    $recordUids.Add([string]$u) | Out-Null
                }
            }
            else {
                foreach ($k in $auditMap.Keys) {
                    $recordUids.Add([string]$k) | Out-Null
                }
            }

            foreach ($recUid in $recordUids) {
                $evt = $null
                if ($auditMap.ContainsKey([string]$recUid)) {
                    $evt = $auditMap[[string]$recUid]
                }

                $rec = $null
                if ($snapshot.Records.ContainsKey([string]$recUid)) {
                    $rec = $snapshot.Records[[string]$recUid]
                }

                $title = if ($rec) { [string]$rec.Title } else { '' }
                $rtype = if ($rec) { [string]$rec.RecordType } else { '' }
                $url = if ($rec -and $rec.Url) { ([string]$rec.Url).TrimEnd('/') } else { '' }
                if ([string]::IsNullOrWhiteSpace($title) -or [string]::IsNullOrWhiteSpace($rtype) -or [string]::IsNullOrWhiteSpace($url)) {
                    $vaultMeta = Get-KeeperVaultRecordMetadataFallback -RecordUid $recUid
                    if ($vaultMeta) {
                        if ([string]::IsNullOrWhiteSpace($title) -and $vaultMeta.Title) {
                            $title = [string]$vaultMeta.Title
                        }
                        if ([string]::IsNullOrWhiteSpace($rtype) -and $vaultMeta.RecordType) {
                            $rtype = [string]$vaultMeta.RecordType
                        }
                        if ([string]::IsNullOrWhiteSpace($url) -and $vaultMeta.Url) {
                            $url = [string]$vaultMeta.Url
                        }
                    }
                }
                $inTrash = if ($rec) { [bool]$rec.InTrash } else { $false }

                $ip = ''
                $device = ''
                $lastAccess = $null
                if ($evt) {
                    $ip = [string](Get-KeeperComplianceAuditEventValue -Event $evt -Key 'ip_address')
                    $device = [string](Get-KeeperComplianceAuditEventValue -Event $evt -Key 'keeper_version')
                    $lc = Get-KeeperComplianceAuditEventValue -Event $evt -Key 'last_created'
                    $lastAccess = ConvertTo-KeeperComplianceDateTime -EpochValue $lc
                }

                $ownerEmail = Get-KeeperComplianceRecordOwnerEmailFromSnapshot -Snapshot $snapshot -RecordUid $recUid

                $row = [ordered]@{
                    vault_owner     = $userEmail
                    record_uid      = $recUid
                    record_title    = $title
                    record_type     = $rtype
                    record_url      = $url
                    has_attachments = $false
                    in_trash        = $inTrash
                    record_owner    = $ownerEmail
                    ip_address      = $ip
                    device          = $device
                    last_access     = $lastAccess
                }

                $rows.Add([PSCustomObject]$row) | Out-Null
            }
        }

        $reportRows = @($rows)
        if ($Pattern -and $Pattern.Count -gt 0) {
            $reportRows = @(
                $reportRows | Where-Object {
                    Test-KeeperRecordAccessRowPattern -Row $_ -Patterns $Pattern -UseRegex:$false
                }
            )
        }
        elseif ($PatternRegex -and $PatternRegex.Count -gt 0) {
            $reportRows = @(
                $reportRows | Where-Object {
                    Test-KeeperRecordAccessRowPattern -Row $_ -Patterns $PatternRegex -UseRegex:$true
                }
            )
        }

        if ($Aging -and $reportRows.Count -gt 0) {
            $agingUids = @($reportRows | ForEach-Object { [string]$_.record_uid } | Where-Object { $_ } | Sort-Object -Unique)
            Write-KeeperComplianceStatus "Applying aging to $($agingUids.Count) unique record(s)."
            $agingData = Get-KeeperComplianceAgingData -RecordUids $agingUids
            $newRows = [System.Collections.Generic.List[object]]::new()
            foreach ($r in $reportRows) {
                $uidKey = [string]$r.record_uid
                $ag = $null
                if ($agingData -and $agingData.ContainsKey($uidKey)) {
                    $ag = $agingData[$uidKey]
                }
                $nr = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) {
                    $nr[$p.Name] = $p.Value
                }
                if ($ag) {
                    $nr['created'] = $ag['created']
                    $nr['last_pw_change'] = $ag['last_pw_change']
                    $nr['last_modified'] = $ag['last_modified']
                    $nr['last_rotation'] = $ag['last_rotation']
                }
                else {
                    $nr['created'] = $null
                    $nr['last_pw_change'] = $null
                    $nr['last_modified'] = $null
                    $nr['last_rotation'] = $null
                }
                $newRows.Add([PSCustomObject]$nr) | Out-Null
            }
            $reportRows = @($newRows)
        }

        if ($reportRows.Count -eq 0) {
            Write-KeeperComplianceStatus "No record-access rows matched."
            Write-Host "No compliance record-access report rows found."
            return
        }

        $displayRows = ConvertTo-KeeperRecordAccessDisplayRows -Rows $reportRows -Format $Format
        Write-KeeperComplianceStatus "Rendering $($reportRows.Count) row(s) as $Format."
        $tableCols = [System.Collections.Generic.List[string]]::new()
        foreach ($c in @(
                'vault_owner', 'record_uid', 'record_title', 'record_type', 'record_url', 'has_attachments',
                'in_trash', 'record_owner', 'ip_address', 'device', 'last_access'
            )) {
            $tableCols.Add($c) | Out-Null
        }
        if ($Aging) {
            foreach ($c in @('created', 'last_pw_change', 'last_modified', 'last_rotation')) {
                $tableCols.Add($c) | Out-Null
            }
        }
        Write-KeeperReportOutput -Rows $reportRows -DisplayRows $displayRows -Format $Format -Output $Output -JsonDepth 8 `
            -TableColumns @($tableCols)
    }
}
New-Alias -Name record-access-report -Value Get-KeeperComplianceRecordAccessReport
# Record access report ends.

function Get-KeeperComplianceTeamReportFilters {
    param(
        [Parameter()][string[]]$Team
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData

    $teamUids = [System.Collections.Generic.HashSet[string]]::new()
    if (Test-KeeperComplianceHasNonEmptyStringList -Strings $Team) {
        foreach ($teamRef in $Team) {
            if ([string]::IsNullOrWhiteSpace([string]$teamRef)) {
                continue
            }
            $resolvedTeam = Get-KeeperTeamByNameOrUid -EnterpriseData $enterpriseData -TeamInput $teamRef
            if (-not $resolvedTeam) {
                Write-Warning "No enterprise team matched '$teamRef' for compliance team filter."
                continue
            }
            $teamUids.Add([string]$resolvedTeam.Uid) | Out-Null
        }
    }

    return [PSCustomObject]@{
        TeamUids = if ($teamUids.Count -gt 0) { @($teamUids | Sort-Object) } else { $null }
    }
}

function Get-KeeperComplianceSharedFolderAllUserUids {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)]$SharedFolder
    )

    $allUserUids = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($userUid in $SharedFolder.Users) {
        $allUserUids.Add([long]$userUid) | Out-Null
    }

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    foreach ($teamUid in $SharedFolder.Teams) {
        if ($Snapshot.Teams.ContainsKey([string]$teamUid)) {
            foreach ($teamUserUid in $Snapshot.Teams[[string]$teamUid].Users) {
                $allUserUids.Add([long]$teamUserUid) | Out-Null
            }
        }
        else {
            foreach ($teamUserUid in $enterpriseData.GetUsersForTeam([string]$teamUid)) {
                $allUserUids.Add([long]$teamUserUid) | Out-Null
            }
        }
    }

    return @($allUserUids | Sort-Object)
}

function Get-KeeperComplianceSharedFolderUserEmails {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$TeamUid
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $emails = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $teamUserIds = @()
    if ($Snapshot.Teams.ContainsKey([string]$TeamUid)) {
        $teamUserIds = @($Snapshot.Teams[[string]$TeamUid].Users)
    }
    else {
        $teamUserIds = @($enterpriseData.GetUsersForTeam([string]$TeamUid))
    }

    foreach ($userUid in $teamUserIds) {
        $email = $null
        if ($Snapshot.Users.ContainsKey([long]$userUid)) {
            $email = [string]$Snapshot.Users[[long]$userUid].Email
        }
        else {
            $enterpriseUser = $null
            if ($enterpriseData.TryGetUserById([long]$userUid, [ref]$enterpriseUser) -and $enterpriseUser) {
                $email = [string]$enterpriseUser.Email
            }
        }

        if ($email) {
            $emails.Add($email) | Out-Null
        }
    }

    return @($emails | Sort-Object)
}

function Get-KeeperComplianceSharedFolderNameLookup {
    $lookup = @{}
    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        foreach ($sharedFolder in $vault.SharedFolders) {
            if ($sharedFolder.Uid) {
                $lookup[[string]$sharedFolder.Uid] = [string]$sharedFolder.Name
            }
        }
    }
    catch {
    }
    return $lookup
}

function Get-KeeperComplianceTeamPermissionText {
    param(
        [Parameter(Mandatory = $true)]$Team
    )

    $permissions = @()
    if (-not $Team.RestrictShare) {
        $permissions += 'Can Share'
    }
    if (-not $Team.RestrictEdit) {
        $permissions += 'Can Edit'
    }

    if ($permissions.Count -eq 0) {
        return 'Read Only'
    }

    # Semicolons read clearly in narrow tables; commas wrap awkwardly with Format-Table.
    return ($permissions -join '; ')
}

function Get-KeeperComplianceTeamReportRows {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][string[]]$Team,
        [Parameter()]$Node,
        [Parameter()][switch]$ShowTeamUsers
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $filterInfo = Get-KeeperComplianceTeamReportFilters -Team $Team

    $teamLookup = $null
    if ($null -ne $filterInfo.TeamUids) {
        $teamLookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($teamUid in $filterInfo.TeamUids) {
            $teamLookup.Add([string]$teamUid) | Out-Null
        }
    }

    # -Node: include a team row only if the team's enterprise home node (ParentNodeId) is the filter node or a
    # descendant. Folder-level gates (records owned in node / members in node) wrongly dropped sibling teams on
    # the same shared folder and missed teams when no member lived in the node despite the team's ParentNodeId.
    $filterTeamNodeSubtreeIds = $null
    $filterTeamNodeSkip = $false
    if (Test-KeeperComplianceHasNodeFilter -Node $Node) {
        $resolvedFilterNode = Resolve-KeeperComplianceNode -Node $Node.Trim() -Context 'compliance team report node filter'
        $filterTargetNodeId = [long]$resolvedFilterNode.Id
        $rootNodeId = [long]$enterpriseData.RootNode.Id
        if ($filterTargetNodeId -eq $rootNodeId) {
            $filterTeamNodeSkip = $true
        }
        else {
            $filterTeamNodeSubtreeIds = Get-KeeperComplianceEnterpriseNodeSubtreeIds -EnterpriseData $enterpriseData -RootNodeId $filterTargetNodeId
        }
    }

    $sharedFolderNames = Get-KeeperComplianceSharedFolderNameLookup
    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($folderEntry in ($Snapshot.SharedFolders.Values | Sort-Object Uid)) {
        $folderRecordUids = @($folderEntry.RecordPermissions.Keys)
        if ($folderRecordUids.Count -le 0) {
            continue
        }

        $recordCount = @($folderRecordUids).Count

        if ($teamLookup) {
            $matchesTeam = $false
            foreach ($tUid in $folderEntry.Teams) {
                if ($teamLookup.Contains([string]$tUid)) {
                    $matchesTeam = $true
                    break
                }
            }
            if (-not $matchesTeam) {
                continue
            }
        }

        foreach ($teamUid in (@($folderEntry.Teams) | Sort-Object)) {
            if ($teamLookup -and -not $teamLookup.Contains([string]$teamUid)) {
                continue
            }

            $teamObject = $null
            if (-not $enterpriseData.TryGetTeam([string]$teamUid, [ref]$teamObject) -or -not $teamObject) {
                continue
            }

            $teamNodeId = [long]$teamObject.ParentNodeId
            if ($teamNodeId -le 0) {
                $teamNodeId = [long]$enterpriseData.RootNode.Id
            }
            if ($Node -and -not $filterTeamNodeSkip) {
                if ($null -eq $filterTeamNodeSubtreeIds -or $filterTeamNodeSubtreeIds.Count -eq 0 -or
                    -not $filterTeamNodeSubtreeIds.ContainsKey("$([long]$teamNodeId)")) {
                    continue
                }
            }

            $teamNodePath = Get-KeeperNodePath -NodeId $teamNodeId -OmitRoot

            $row = [ordered]@{
                team_name          = [string]$teamObject.Name
                team_uid           = [string]$teamUid
                node               = [string]$teamNodePath
                shared_folder_name = if ($sharedFolderNames.ContainsKey([string]$folderEntry.Uid)) { [string]$sharedFolderNames[[string]$folderEntry.Uid] } else { '' }
                shared_folder_uid  = [string]$folderEntry.Uid
                permissions        = Get-KeeperComplianceTeamPermissionText -Team $teamObject
                records            = [int]$recordCount
            }

            if ($ShowTeamUsers) {
                $row['team_users'] = Get-KeeperComplianceSharedFolderUserEmails -Snapshot $Snapshot -TeamUid ([string]$teamUid)
            }

            $rows.Add([PSCustomObject]$row) | Out-Null
        }
    }

    return @($rows | Sort-Object shared_folder_uid, team_name)
}

function Get-KeeperComplianceTeamReport {
    <#
        .SYNOPSIS
            Run compliance team report

        .DESCRIPTION
            Lists teams with access to shared folders containing records, including node path, edit/share permissions, and optionally team members.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][string]$Node,
        [Parameter()][string[]]$Team,
        [Parameter()][switch]$ShowTeamUsers,
        [Parameter()][switch]$Rebuild,
        [Parameter()][switch]$NoRebuild,
        [Parameter()][switch]$NoCache
    )

    $reportRows = Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ScriptBlock {
        Write-KeeperComplianceStatus "Starting compliance-team-report. Format=$Format Rebuild=$Rebuild NoRebuild=$NoRebuild NoCache=$NoCache ShowTeamUsers=$ShowTeamUsers."
        $fetchOwnerIds = Resolve-KeeperComplianceFetchOwnerIds -Node $Node
        if ((Test-KeeperComplianceHasNodeFilter -Node $Node) -and $null -ne $fetchOwnerIds -and $fetchOwnerIds.Count -eq 0) {
            Write-Warning "No enterprise users matched the provided node filter."
        }

        # With -Node, use a full shared snapshot so shared folders still appear when record owners are outside
        # the node; rows are filtered by each team's enterprise ParentNodeId.
        $ownerIdsForSnapshot = if (Test-KeeperComplianceHasNodeFilter -Node $Node) { $null } else { $fetchOwnerIds }
        $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$Rebuild -NoRebuild:$NoRebuild -OwnerUserIds $ownerIdsForSnapshot -SharedOnly
        $reportRows = Get-KeeperComplianceTeamReportRows -Snapshot $snapshot -Team $Team `
            -Node $Node -ShowTeamUsers:$ShowTeamUsers
        return ,@($reportRows)
    }

    if ($reportRows.Count -eq 0) {
        Write-Host "No compliance team report rows found."
        return
    }

    $displayRows = @(
        $reportRows | ForEach-Object {
            $row = [ordered]@{}
            foreach ($property in $_.PSObject.Properties) {
                if ($property.Name -eq 'team_users') {
                    $row[$property.Name] = @($property.Value) -join ', '
                }
                else {
                    $row[$property.Name] = $property.Value
                }
            }
            [PSCustomObject]$row
        }
    )

    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $displayRows -Format $Format -Output $Output -JsonDepth 5
}
New-Alias -Name compliance-team-report -Value Get-KeeperComplianceTeamReport

# Compliance summary stats for user.
function Get-KeeperComplianceSummaryStatsForUser {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][long]$UserUid,
        [Parameter(Mandatory = $true)][string]$Email
    )

    $vaultSet = Get-KeeperComplianceVaultRecordUidsForUser -Snapshot $Snapshot -UserUid $UserUid
    $totalItems = $vaultSet.Count

    $numOwned = 0
    $activeOwned = 0
    $deletedOwned = 0
    if ($Snapshot.OwnedRecordsByUser.ContainsKey($UserUid)) {
        $ownedSet = $Snapshot.OwnedRecordsByUser[$UserUid]
        $numOwned = $ownedSet.Count
        foreach ($r in $ownedSet) {
            $rk = [string]$r
            $inTrash = $false
            if ($Snapshot.Records.ContainsKey($rk)) {
                $inTrash = [bool]$Snapshot.Records[$rk].InTrash
            }
            if ($inTrash) {
                $deletedOwned++
            }
            else {
                $activeOwned++
            }
        }
    }

    return [PSCustomObject]@{
        email         = $Email
        total_items   = [int]$totalItems
        total_owned   = [int]$numOwned
        active_owned  = [int]$activeOwned
        deleted_owned = [int]$deletedOwned
    }
}

function Get-KeeperComplianceSummaryReportRows {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][string[]]$Team,
        [Parameter()]$Node
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $fetchIds = Resolve-KeeperComplianceFetchOwnerIds -Team $Team -Node $Node

    if ((Test-KeeperComplianceHasNodeFilter -Node $Node) -and $null -ne $fetchIds -and @($fetchIds).Count -eq 0) {
        Write-Warning "No enterprise users matched the provided node (and team) filter."
    }

    $fetchIdSet = $null
    if ($null -ne $fetchIds) {
        $fetchIdSet = [System.Collections.Generic.HashSet[long]]::new()
        foreach ($id in @($fetchIds)) {
            $fetchIdSet.Add([long]$id) | Out-Null
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $soxUserIds = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($k in $Snapshot.Users.Keys) {
        $soxUserIds.Add([long]$k) | Out-Null
    }

    foreach ($eu in $enterpriseData.Users) {
        if ($eu.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Inactive) {
            continue
        }
        if (-not $eu.Email) {
            continue
        }
        if ($null -ne $fetchIdSet -and -not $fetchIdSet.Contains([long]$eu.Id)) {
            continue
        }

        $uid = [long]$eu.Id
        $email = [string]$eu.Email
        if ($soxUserIds.Contains($uid)) {
            $rows.Add((Get-KeeperComplianceSummaryStatsForUser -Snapshot $Snapshot -UserUid $uid -Email $email)) | Out-Null
        }
        else {
            $rows.Add([PSCustomObject]@{
                email         = $email
                total_items   = 0
                total_owned   = 0
                active_owned  = 0
                deleted_owned = 0
            }) | Out-Null
        }
    }

    $sortedRows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (@($rows) | Sort-Object email)) {
        $sortedRows.Add($r) | Out-Null
    }

    $sumOwned = 0L
    $sumActive = 0L
    $sumDeleted = 0L
    foreach ($dr in $sortedRows) {
        $sumOwned += [long]$dr.total_owned
        $sumActive += [long]$dr.active_owned
        $sumDeleted += [long]$dr.deleted_owned
    }

    $sortedRows.Add([PSCustomObject]@{
        email         = 'TOTAL'
        total_items   = $null
        total_owned   = [long]$sumOwned
        active_owned  = [long]$sumActive
        deleted_owned = [long]$sumDeleted
    }) | Out-Null

    return @($sortedRows)
}

function Get-KeeperComplianceSummaryReport {
    <#
        .SYNOPSIS
            Run compliance summary report

        .DESCRIPTION
            Per-user record counts: total accessible, owned, active, and deleted. Appends a TOTAL row.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][string]$Node,
        [Parameter()][string[]]$Team,
        [Parameter()][switch]$Rebuild,
        [Parameter()][switch]$NoRebuild,
        [Parameter()][switch]$NoCache
    )

    $reportRows = Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ScriptBlock {
        Write-KeeperComplianceStatus "Starting compliance summary-report. Format=$Format Rebuild=$Rebuild NoRebuild=$NoRebuild NoCache=$NoCache."
        $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$Rebuild -NoRebuild:$NoRebuild -OwnerUserIds $null
        $reportRows = Get-KeeperComplianceSummaryReportRows -Snapshot $snapshot -Team $Team -Node $Node
        return ,@($reportRows)
    }

    if ($reportRows.Count -eq 0) {
        Write-Host "No compliance summary report rows found."
        return
    }

    $displayRows = @(
        $reportRows | ForEach-Object {
            $row = [ordered]@{}
            foreach ($property in $_.PSObject.Properties) {
                $row[$property.Name] = $property.Value
            }
            [PSCustomObject]$row
        }
    )

    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $displayRows -Format $Format -Output $Output -JsonDepth 5 `
        -TableColumns @('email', 'total_items', 'total_owned', 'active_owned', 'deleted_owned')
}
New-Alias -Name compliance-summary-report -Value Get-KeeperComplianceSummaryReport

function Get-KeeperComplianceSharedFolderReportRows {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][string[]]$Team,
        [Parameter()][switch]$ShowTeamUsers,
        [Parameter()]$Node,
        [Parameter()][long[]]$NodeScopeUserIds
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $filterInfo = Get-KeeperComplianceTeamReportFilters -Team $Team

    $teamLookup = $null
    if ($null -ne $filterInfo.TeamUids) {
        $teamLookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($teamUid in $filterInfo.TeamUids) {
            $teamLookup.Add([string]$teamUid) | Out-Null
        }
    }

    $nodeUserIdSet = $null
    $recordsOwnedByNodeUsers = $null
    $filterTeamNodeSubtreeIds = $null
    $rootNodeIdSf = [long]$enterpriseData.RootNode.Id
    if (Test-KeeperComplianceHasNodeFilter -Node $Node) {
        if ($null -ne $NodeScopeUserIds -and @($NodeScopeUserIds).Count -gt 0) {
            $nodeUserIdSet = [System.Collections.Generic.HashSet[long]]::new()
            foreach ($id in @($NodeScopeUserIds)) {
                $nodeUserIdSet.Add([long]$id) | Out-Null
            }
            $recordsOwnedByNodeUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($uid in $nodeUserIdSet) {
                if (-not $Snapshot.OwnedRecordsByUser.ContainsKey([long]$uid)) {
                    continue
                }
                foreach ($r in $Snapshot.OwnedRecordsByUser[[long]$uid]) {
                    $recordsOwnedByNodeUsers.Add([string]$r) | Out-Null
                }
            }
        }
        $resolvedFilterNode = Resolve-KeeperComplianceNode -Node $Node.Trim() -Context 'compliance shared-folder report node filter'
        $filterTargetNodeId = [long]$resolvedFilterNode.Id
        $subtreeRootId = if ($filterTargetNodeId -eq $rootNodeIdSf) { $rootNodeIdSf } else { $filterTargetNodeId }
        $filterTeamNodeSubtreeIds = Get-KeeperComplianceEnterpriseNodeSubtreeIds -EnterpriseData $enterpriseData -RootNodeId $subtreeRootId
    }

    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($folderEntry in ($Snapshot.SharedFolders.Values | Sort-Object { $_.Uid })) {
        $recordUids = @($folderEntry.RecordPermissions.Keys | Sort-Object)
        if ($recordUids.Count -eq 0) {
            continue
        }

        if (Test-KeeperComplianceHasNodeFilter -Node $Node) {
            $folderRelevantToNode = $false
            if ($null -ne $recordsOwnedByNodeUsers -and $recordsOwnedByNodeUsers.Count -gt 0) {
                foreach ($ru in $recordUids) {
                    if ($recordsOwnedByNodeUsers.Contains([string]$ru)) {
                        $folderRelevantToNode = $true
                        break
                    }
                }
            }
            if (-not $folderRelevantToNode -and $null -ne $nodeUserIdSet) {
                foreach ($userUid in $folderEntry.Users) {
                    if ($nodeUserIdSet.Contains([long]$userUid)) {
                        $folderRelevantToNode = $true
                        break
                    }
                }
            }
            if (-not $folderRelevantToNode) {
                foreach ($tuid in $folderEntry.Teams) {
                    $teamObj = $null
                    if ($enterpriseData.TryGetTeam([string]$tuid, [ref]$teamObj) -and $teamObj) {
                        $teamHomeId = [long]$teamObj.ParentNodeId
                        if ($teamHomeId -le 0) {
                            $teamHomeId = $rootNodeIdSf
                        }
                        if ($null -ne $filterTeamNodeSubtreeIds -and $filterTeamNodeSubtreeIds.Count -gt 0 -and
                            $filterTeamNodeSubtreeIds.ContainsKey("$([long]$teamHomeId)")) {
                            $folderRelevantToNode = $true
                            break
                        }
                    }
                    if (-not $folderRelevantToNode -and $null -ne $nodeUserIdSet) {
                        $teamUserIds = @()
                        if ($Snapshot.Teams.ContainsKey([string]$tuid)) {
                            $teamUserIds = @($Snapshot.Teams[[string]$tuid].Users)
                        }
                        else {
                            $teamUserIds = @($enterpriseData.GetUsersForTeam([string]$tuid))
                        }
                        foreach ($tu in $teamUserIds) {
                            if ($nodeUserIdSet.Contains([long]$tu)) {
                                $folderRelevantToNode = $true
                                break
                            }
                        }
                    }
                    if ($folderRelevantToNode) {
                        break
                    }
                }
            }
            if (-not $folderRelevantToNode) {
                continue
            }
        }

        if ($teamLookup) {
            $matchesTeam = $false
            foreach ($t in $folderEntry.Teams) {
                if ($teamLookup.Contains([string]$t)) {
                    $matchesTeam = $true
                    break
                }
            }
            if (-not $matchesTeam) {
                continue
            }
        }

        $teamUids = @($folderEntry.Teams | Sort-Object)
        $teamNames = [System.Collections.Generic.List[string]]::new()
        $teamNodePaths = [System.Collections.Generic.List[string]]::new()
        $rootNodeIdForTeams = [long]$enterpriseData.RootNode.Id
        foreach ($tid in $teamUids) {
            $teamObj = $null
            if ($enterpriseData.TryGetTeam([string]$tid, [ref]$teamObj) -and $teamObj) {
                $teamNames.Add([string]$teamObj.Name) | Out-Null
                $teamNodeId = [long]$teamObj.ParentNodeId
                if ($teamNodeId -le 0) {
                    $teamNodeId = $rootNodeIdForTeams
                }
                $teamNodePaths.Add([string](Get-KeeperNodePath -NodeId $teamNodeId -OmitRoot)) | Out-Null
            }
            else {
                $teamNames.Add('') | Out-Null
                $teamNodePaths.Add('') | Out-Null
            }
        }

        $emailParts = [System.Collections.Generic.List[string]]::new()
        if ($ShowTeamUsers) {
            foreach ($tid in $teamUids) {
                foreach ($em in Get-KeeperComplianceSharedFolderUserEmails -Snapshot $Snapshot -TeamUid ([string]$tid)) {
                    $emailParts.Add("(TU)$em") | Out-Null
                }
            }
        }
        foreach ($userUid in ($folderEntry.Users | Sort-Object)) {
            if ($Snapshot.Users.ContainsKey([long]$userUid)) {
                $emailParts.Add([string]$Snapshot.Users[[long]$userUid].Email) | Out-Null
            }
        }

        $recordTitles = [System.Collections.Generic.List[string]]::new()
        foreach ($ru in $recordUids) {
            $rt = ''
            if ($Snapshot.Records.ContainsKey([string]$ru)) {
                $rt = [string]$Snapshot.Records[[string]$ru].Title
            }
            $recordTitles.Add($rt) | Out-Null
        }

        $rows.Add([PSCustomObject][ordered]@{
            shared_folder_uid = [string]$folderEntry.Uid
            team_uid          = @($teamUids) -join ', '
            team_name         = @($teamNames) -join ', '
            node              = @($teamNodePaths) -join ', '
            record_uid        = @($recordUids) -join ', '
            record_title      = @($recordTitles) -join ', '
            email             = @($emailParts) -join ', '
        }) | Out-Null
    }

    return @($rows | Sort-Object shared_folder_uid)
}

function Get-KeeperComplianceSharedFolderReport {
    <#
        .SYNOPSIS
            Run compliance shared-folder report

        .DESCRIPTION
            Lists shared folders with their teams, records, and participant emails.

        .PARAMETER ShowTeamUsers
            Include team members (prefixed with TU) in the email column.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][string]$Node,
        [Parameter()][string[]]$Team,
        [Parameter()][switch]$ShowTeamUsers,
        [Parameter()][switch]$Rebuild,
        [Parameter()][switch]$NoRebuild,
        [Parameter()][switch]$NoCache
    )

    $reportRows = Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ScriptBlock {
        Write-KeeperComplianceStatus "Starting compliance shared-folder-report. Format=$Format Rebuild=$Rebuild NoRebuild=$NoRebuild NoCache=$NoCache ShowTeamUsers=$ShowTeamUsers."
        $fetchOwnerIds = Resolve-KeeperComplianceFetchOwnerIds -Node $Node
        if ((Test-KeeperComplianceHasNodeFilter -Node $Node) -and $null -ne $fetchOwnerIds -and @($fetchOwnerIds).Count -eq 0) {
            Write-Warning "No enterprise users in the node subtree for user/record checks; folders may still match via team home node."
        }

        $ownerIdsForSnapshot = if (Test-KeeperComplianceHasNodeFilter -Node $Node) { $null } else { $fetchOwnerIds }
        $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$Rebuild -NoRebuild:$NoRebuild -OwnerUserIds $ownerIdsForSnapshot -SharedOnly
        $reportRows = Get-KeeperComplianceSharedFolderReportRows -Snapshot $snapshot -Team $Team `
            -ShowTeamUsers:$ShowTeamUsers -Node $Node -NodeScopeUserIds $fetchOwnerIds
        return ,@($reportRows)
    }

    if ($ShowTeamUsers) {
        Write-Host "(TU) denotes a user whose membership in a team grants them access to the shared folder." -ForegroundColor DarkGray
    }

    if ($reportRows.Count -eq 0) {
        Write-Host "No compliance shared-folder report rows found."
        return
    }

    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $reportRows -Format $Format -Output $Output -JsonDepth 6 `
        -TableColumns @('shared_folder_uid', 'team_uid', 'team_name', 'node', 'record_uid', 'record_title', 'email')
}
New-Alias -Name compliance-shared-folder-report -Value Get-KeeperComplianceSharedFolderReport

function Get-KeeperExternalSharesData {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all'
    )

    $externalUsers = @{}
    foreach ($userEntry in $Snapshot.Users.Values) {
        $userUid = [long]$userEntry.UserUid
        $userEmail = [string]$userEntry.Email
        if (($userUid -shr 32) -eq 0 -and
            -not [string]::IsNullOrWhiteSpace($userEmail)) {
            $externalUsers[$userUid] = $userEntry
        }
    }

    $shareEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($ShareType -in @('direct', 'all')) {
        foreach ($recordEntry in $Snapshot.Records.Values) {
            if (-not $recordEntry.Shared) {
                continue
            }

            foreach ($userUid in ($recordEntry.UserPermissions.Keys | Sort-Object)) {
                $targetUid = [long]$userUid
                if (-not $externalUsers.ContainsKey($targetUid)) {
                    continue
                }

                $permissionBits = 0
                if ($recordEntry.UserPermissions.ContainsKey($targetUid)) {
                    $permissionBits = [int]$recordEntry.UserPermissions[$targetUid]
                }

                $shareEntries.Add([PSCustomObject][ordered]@{
                    kind         = 'direct'
                    uid          = [string]$recordEntry.Uid
                    name         = [string]$recordEntry.Title
                    type         = 'Direct'
                    shared_to    = [string]$externalUsers[$targetUid].Email
                    permissions  = Get-KeeperCompliancePermissionText -PermissionBits $permissionBits
                    target_email = [string]$externalUsers[$targetUid].Email
                }) | Out-Null
            }
        }
    }

    if ($ShareType -in @('shared-folder', 'all')) {
        foreach ($folderEntry in $Snapshot.SharedFolders.Values) {
            foreach ($userUid in ($folderEntry.Users | Sort-Object)) {
                $targetUid = [long]$userUid
                if (-not $externalUsers.ContainsKey($targetUid)) {
                    continue
                }

                $shareEntries.Add([PSCustomObject][ordered]@{
                    kind         = 'shared-folder'
                    uid          = [string]$folderEntry.Uid
                    name         = ''
                    type         = 'Shared Folder'
                    shared_to    = [string]$externalUsers[$targetUid].Email
                    permissions  = ''
                    target_email = [string]$externalUsers[$targetUid].Email
                }) | Out-Null
            }
        }
    }

    return [PSCustomObject]@{
        ExternalUsers = $externalUsers
        ShareEntries  = @($shareEntries | Sort-Object type, uid, shared_to)
    }
}

function Get-KeeperExternalShareRows {
    param(
        [Parameter(Mandatory = $true)]$ExternalShareData
    )

    return @(
        $ExternalShareData.ShareEntries | ForEach-Object {
            [PSCustomObject][ordered]@{
                uid         = [string]$_.uid
                name        = [string]$_.name
                type        = [string]$_.type
                shared_to   = [string]$_.shared_to
                permissions = [string]$_.permissions
            }
        }
    )
}

function Remove-KeeperExternalShareEntries {
    param(
        [Parameter(Mandatory = $true)]$ExternalShareData,
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all'
    )

    $result = [PSCustomObject]@{
        Removed = 0
        Failed  = 0
        Errors  = [System.Collections.Generic.List[string]]::new()
    }

    foreach ($shareEntry in $ExternalShareData.ShareEntries) {
        if ($ShareType -ne 'all' -and $shareEntry.kind -ne $ShareType) {
            continue
        }

        $targetEmail = [string]$shareEntry.target_email
        if (-not $targetEmail) {
            continue
        }

        try {
            if ($shareEntry.kind -eq 'direct') {
                Revoke-KeeperRecordAccess -Record ([string]$shareEntry.uid) -User $targetEmail -ErrorAction Stop | Out-Null
            }
            else {
                Revoke-KeeperSharedFolderAccess -SharedFolder ([string]$shareEntry.uid) -User $targetEmail -ErrorAction Stop | Out-Null
            }
            $result.Removed++
        }
        catch {
            $result.Failed++
            $result.Errors.Add("$($shareEntry.kind):$($shareEntry.uid)->${targetEmail}: $($_.Exception.Message)") | Out-Null
        }
    }

    return $result
}

function Confirm-KeeperExternalShareRemoval {
    param(
        [Parameter(Mandatory = $true)]$PreviewRows,
        [Parameter(Mandatory = $true)]$ExternalShareData,
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all'
    )

    Write-Host ""
    Write-Host "ALERT!"
    Write-Host "You are about to delete the following shares:"
    Write-Host ""

    if ($PreviewRows.Count -gt 0) {
        $PreviewRows | Format-Table -Property uid, name, type, shared_to, permissions -Wrap
    }
    else {
        Write-Host "No external shares found."
        return
    }

    $answer = Read-Host "Do you wish to proceed? (y/n)"
    if ($answer -in @('y', 'Y', 'yes', 'YES', 'Yes')) {
        $removalResult = Remove-KeeperExternalShareEntries -ExternalShareData $ExternalShareData -ShareType $ShareType
        Write-Host "Removed $($removalResult.Removed) external share(s)."
        if ($removalResult.Failed -gt 0) {
            $errorPreview = @($removalResult.Errors | Select-Object -First 5) -join '; '
            Write-Warning "Failed to remove $($removalResult.Failed) external share(s). $errorPreview"
        }
    }
    else {
        Write-Host "Action aborted."
    }
}

function Get-KeeperExternalSharesReport {
    <#
        .SYNOPSIS
            Run external shares report

        .DESCRIPTION
            Lists records and shared folders shared with external (non-enterprise) users. Optionally revoke matching shares.

        .PARAMETER Format
            Output format: table (default), json, csv.

        .PARAMETER Output
            Output file path. Ignored when Format is 'table'.

        .PARAMETER Action
            Action to perform on external shares: remove or none.

        .PARAMETER ShareType
            Filter the report/action by share type: direct, shared-folder, or all.

        .PARAMETER Force
            Apply remove without confirmation.

        .PARAMETER RefreshData
            Rebuild the compliance snapshot before running the report.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][ValidateSet('remove', 'none')][string]$Action = 'none',
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all',
        [Parameter()][switch]$Force,
        [Parameter()][switch]$RefreshData
    )

    Write-KeeperComplianceStatus "Starting external-shares-report. Format=$Format RefreshData=$RefreshData ShareType=$ShareType Action=$Action."
    $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$RefreshData -NoRebuild:([bool](-not $RefreshData)) -SharedOnly
    $externalShareData = Get-KeeperExternalSharesData -Snapshot $snapshot -ShareType $ShareType

    if ($Action -eq 'remove') {
        $previewRows = Get-KeeperExternalShareRows -ExternalShareData $externalShareData
        if ($Force) {
            $removalResult = Remove-KeeperExternalShareEntries -ExternalShareData $externalShareData -ShareType $ShareType
            Write-Host "Removed $($removalResult.Removed) external share(s)."
            if ($removalResult.Failed -gt 0) {
                $errorPreview = @($removalResult.Errors | Select-Object -First 5) -join '; '
                Write-Warning "Failed to remove $($removalResult.Failed) external share(s). $errorPreview"
            }
        }
        else {
            Confirm-KeeperExternalShareRemoval -PreviewRows $previewRows -ExternalShareData $externalShareData -ShareType $ShareType
        }
        return
    }

    $reportRows = Get-KeeperExternalShareRows -ExternalShareData $externalShareData
    if ($reportRows.Count -eq 0) {
        Write-Host "No external shares found."
        return
    }

    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $reportRows -Format $Format -Output $Output -JsonDepth 4 `
        -TableColumns @('uid', 'name', 'type', 'shared_to', 'permissions')
}
New-Alias -Name external-shares-report -Value Get-KeeperExternalSharesReport