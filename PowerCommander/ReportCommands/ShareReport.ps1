#requires -Version 5.1

function Script:Get-ShareReportFolderPath {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,

        [Parameter()]
        [string] $FolderUid
    )

    if ([string]::IsNullOrEmpty($FolderUid)) {
        return ''
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $current = $FolderUid

    while (-not [string]::IsNullOrEmpty($current) -and $visited.Add($current)) {
        [KeeperSecurity.Vault.FolderNode] $folder = $null
        if (-not $Vault.TryGetFolder($current, [ref]$folder)) { break }
        $parts.Add($folder.Name)
        $current = $folder.ParentUid
    }

    $parts.Reverse()
    return ($parts -join '\')
}

function Script:Get-ShareReportRecordShares {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,

        [Parameter(Mandatory = $true)]
        [string[]] $RecordUids
    )

    $batchSize = 100
    $allShares = [System.Collections.Generic.List[KeeperSecurity.Vault.RecordSharePermissions]]::new()

    for ($i = 0; $i -lt $RecordUids.Count; $i += $batchSize) {
        $end = [Math]::Min($i + $batchSize, $RecordUids.Count)
        $batch = [System.Collections.Generic.List[string]]::new()
        for ($j = $i; $j -lt $end; $j++) {
            $batch.Add($RecordUids[$j])
        }
        try {
            $shares = $Vault.GetSharesForRecords([System.Collections.Generic.IEnumerable[string]]$batch).GetAwaiter().GetResult()
            foreach ($s in $shares) {
                $allShares.Add($s)
            }
        }
        catch {
            Write-Warning "Failed to retrieve record shares: $($_.Exception.Message)"
        }
    }

    return $allShares
}

function Script:Get-ShareReportTeamMembers {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault
    )

    $teamMembers = @{}

    $enterprise = $Script:Context.Enterprise
    if ($null -eq $enterprise -or $null -eq $enterprise.enterpriseData) {
        Write-Warning "Enterprise data is not available. login as enterprise admin."
        return $teamMembers
    }

    $enterpriseData = $enterprise.enterpriseData
    foreach ($team in $Vault.Teams) {
        $teamUid = $team.TeamUid
        $members = [System.Collections.Generic.List[string]]::new()
        foreach ($userId in $enterpriseData.GetUsersForTeam($teamUid)) {
            $user = $null
            if ($enterpriseData.TryGetUserById($userId, [ref]$user)) {
                $members.Add($user.Email)
            }
        }
        $teamMembers[$teamUid] = $members
    }

    return $teamMembers
}

function Script:Get-ShareReportAuditEvents {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,

        [Parameter(Mandatory = $true)]
        [string] $RecordUid,

        [Parameter(Mandatory = $true)]
        [ref] $AramEnabled
    )

    $rq = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
    $rq.ReportType = 'raw'
    $rq.Limit = 1000
    $rq.Order = 'descending'

    $filter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter
    $filter.EventTypes = @('share', 'record_share_outside_user', 'remove_share',
        'folder_add_team', 'folder_remove_team', 'folder_add_record', 'folder_remove_record')
    $filter.RecordUid = @($RecordUid)
    $rq.Filter = $filter

    try {
        $response = $Auth.ExecuteAuthCommand(
            $rq,
            [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse],
            $true
        ).GetAwaiter().GetResult()
        $rs = [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse]$response
    }
    catch [KeeperSecurity.Authentication.KeeperApiException] {
        $apiEx = $_.Exception
        if ($apiEx.Code -eq 'not_an_enterprise_user' -or $apiEx.Code -eq 'access_denied') {
            $AramEnabled.Value = $false
        }
        return @()
    }
    catch {
        return @()
    }

    if (-not $rs.Events -or $rs.Events.Count -eq 0) {
        return @()
    }

    $latestRecordEvents = [ordered]@{}
    $latestFolderEvents = [ordered]@{}

    foreach ($evt in $rs.Events) {
        $eventType = if ($evt.ContainsKey('audit_event_type')) { $evt['audit_event_type'].ToString() } else { '' }
        $recUid = if ($evt.ContainsKey('record_uid')) { $evt['record_uid'].ToString() } else { '' }
        $created = Get-ShareReportCreatedUnixSeconds -Event $evt

        if ($evt.ContainsKey('to_username')) {
            $toUser = $evt['to_username'].ToString()
            $key = "${recUid}-${toUser}"
            if ([string]::IsNullOrEmpty($recUid) -or [string]::IsNullOrEmpty($toUser)) { continue }

            $existing = $latestRecordEvents[$key]
            if ($null -eq $existing -or $created -gt $existing.Created) {
                $latestRecordEvents[$key] = [PSCustomObject]@{
                    Created = $created
                    Event   = $evt
                }
            }
        }
        elseif ($evt.ContainsKey('shared_folder_uid')) {
            $sfUid = $evt['shared_folder_uid'].ToString()
            $key = "${recUid}-${sfUid}"
            if ([string]::IsNullOrEmpty($recUid) -or [string]::IsNullOrEmpty($sfUid)) { continue }

            $existing = $latestFolderEvents[$key]
            if ($null -eq $existing -or $created -gt $existing.Created) {
                $latestFolderEvents[$key] = [PSCustomObject]@{
                    Created = $created
                    Event   = $evt
                }
            }
        }
    }

    $activeEvents = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $latestRecordEvents.Values) {
        $eventType = if ($entry.Event.ContainsKey('audit_event_type')) { $entry.Event['audit_event_type'].ToString() } else { '' }
        if ($eventType -in 'share', 'record_share_outside_user') {
            $activeEvents.Add($entry.Event) | Out-Null
        }
    }
    foreach ($entry in $latestFolderEvents.Values) {
        $eventType = if ($entry.Event.ContainsKey('audit_event_type')) { $entry.Event['audit_event_type'].ToString() } else { '' }
        if ($eventType -eq 'folder_add_record') {
            $activeEvents.Add($entry.Event) | Out-Null
        }
    }

    return $activeEvents
}

function Script:Get-ShareReportCreatedUnixSeconds {
    param($AuditEvent)

    if ($null -eq $AuditEvent -or -not $AuditEvent.ContainsKey('created') -or $null -eq $AuditEvent['created']) { return 0L }

    $raw = $AuditEvent['created'].ToString()
    $epoch = 0L
    if (-not [long]::TryParse($raw, [ref]$epoch)) { return 0L }

    $maxReasonableSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + (10 * 365 * 24 * 60 * 60)
    if ($epoch -le $maxReasonableSeconds) {
        return $epoch
    }

    if ($epoch -le ($maxReasonableSeconds * 100)) {
        return [long]($epoch / 100)
    }

    return [long]($epoch / 1000)
}

function Script:Get-ShareDateForUser {
    param($ActivityList, [string] $Username)

    if (-not $ActivityList -or $ActivityList.Count -eq 0) { return '' }

    $matchesUserName = $ActivityList | Where-Object {
        $_.ContainsKey('to_username') -and $_['to_username'].ToString() -eq $Username
    }

    if (-not $matchesUserName -or $matchesUserName.Count -eq 0) { return '' }

    $activity = $null
    $createdSec = 0L
    foreach ($m in $matchesUserName) {
        $sec = Get-ShareReportCreatedUnixSeconds -AuditEvent $m
        if ($sec -gt $createdSec) {
            $createdSec = $sec
            $activity = $m
        }
    }

    if ($createdSec -le 0) { return '' }
    if ($createdSec -lt 946684800) { return '' }
    $dt = [DateTimeOffset]::FromUnixTimeSeconds($createdSec).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
    $eventType = if ($activity.ContainsKey('audit_event_type')) { $activity['audit_event_type'].ToString() } else { '' }

    if ($eventType -eq 'record_share_outside_user') {
        return "(externally shared on $dt)"
    }
    return "(shared on $dt)"
}

function Script:Get-ShareDateForFolder {
    param($ActivityList, [string] $SharedFolderUid)

    if (-not $ActivityList -or $ActivityList.Count -eq 0) { return '' }

    $matchesFolder = $ActivityList | Where-Object {
        $_.ContainsKey('audit_event_type') -and $_['audit_event_type'].ToString() -match 'folder' -and
        $_.ContainsKey('shared_folder_uid') -and $_['shared_folder_uid'].ToString() -eq $SharedFolderUid
    }

    if (-not $matchesFolder -or $matchesFolder.Count -eq 0) { return '' }

    $createdSec = 0L
    foreach ($m in $matchesFolder) {
        $sec = Get-ShareReportCreatedUnixSeconds -AuditEvent $m
        if ($sec -gt $createdSec) {
            $createdSec = $sec
        }
    }
    if ($createdSec -le 0) { return '' }
    if ($createdSec -lt 946684800) { return '' }
    $dt = [DateTimeOffset]::FromUnixTimeSeconds($createdSec).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
    return "(shared on $dt)"
}

function Script:Get-PermissionsText {
    param([bool] $CanEdit, [bool] $CanShare)

    if (-not $CanEdit -and -not $CanShare) {
        return 'Read Only'
    }

    $parts = @()
    if ($CanShare) { $parts += 'Share' }
    if ($CanEdit) { $parts += 'Edit' }
    return 'Can ' + ($parts -join ' & ')
}

function Script:Get-SharedFolderPermissionsText {
    param([bool] $ManageRecords, [bool] $ManageUsers)

    if (-not $ManageRecords -and -not $ManageUsers) {
        return 'No User Permissions'
    }

    $parts = @()
    if ($ManageUsers) { $parts += 'Manage Users' }
    if ($ManageRecords) { $parts += 'Manage Records' }
    return 'Can ' + ($parts -join ' & ')
}

function Script:Write-ShareReportOutput {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Rows,

        [Parameter()]
        [string] $Title,

        [Parameter(Mandatory = $true)]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format,

        [Parameter()]
        [string] $Output
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Warning 'No data to display.'
        return
    }

    switch ($Format) {
        'json' {
            $jsonText = $Rows | ConvertTo-Json -Depth 5
            if ($Output) {
                Set-Content -Path $Output -Value $jsonText -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }
            return $jsonText
        }
        'csv' {
            $csvText = $Rows | ConvertTo-Csv -NoTypeInformation
            if ($Output) {
                Set-Content -Path $Output -Value $csvText -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }
            return $csvText
        }
        default {
            if ($Output) {
                $tableText = @($Rows | Format-Table -Property * -AutoSize | Out-String -Width 8192)
                $content = @()
                if ($Title) { $content += $Title; $content += '' }
                $content += $tableText
                Set-Content -Path $Output -Value $content -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }

            if ($Title) {
                Write-Host ''
                Write-Host $Title
            }
            $Rows | Format-Table -Property * -AutoSize | Out-String -Width 8192
        }
    }
}

function Script:Build-RecordToFolderIndex {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault
    )

    $index = @{}
    foreach ($fn in $Vault.Folders) {
        foreach ($recUid in $fn.Records) {
            if (-not $index.ContainsKey($recUid)) {
                $index[$recUid] = [System.Collections.Generic.List[string]]::new()
            }
            $index[$recUid].Add($fn.FolderUid)
        }
    }
    return $index
}

function Script:Write-ShareReportFolders {
    param(
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [hashtable] $TeamMembers,
        [bool] $ShowTeamUsers,
        [string] $Format,
        [string] $Output
    )

    $table = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($sf in $Vault.SharedFolders) {
        $folderPath = Get-ShareReportFolderPath -Vault $Vault -FolderUid $sf.Uid
        if (-not $folderPath) { $folderPath = $sf.Name }

        foreach ($perm in $sf.UsersPermissions) {
            $permText = Get-SharedFolderPermissionsText -ManageRecords $perm.ManageRecords -ManageUsers $perm.ManageUsers
            $isTeam = $perm.UserType -eq [KeeperSecurity.Vault.UserType]::Team

            if ($isTeam -and $ShowTeamUsers) {
                $table.Add([PSCustomObject][ordered]@{
                    'Folder UID'  = $sf.Uid
                    'Folder Name' = $sf.Name
                    'Shared To'   = "(Team) $($perm.Name)"
                    'Permissions' = $permText
                    'Folder Path' = $folderPath
                })

                $members = $TeamMembers[$perm.Uid]
                if ($members) {
                    foreach ($member in $members) {
                        $table.Add([PSCustomObject][ordered]@{
                            'Folder UID'  = $sf.Uid
                            'Folder Name' = $sf.Name
                            'Shared To'   = "(Team User) $member"
                            'Permissions' = $permText
                            'Folder Path' = $folderPath
                        })
                    }
                }
            }
            else {
                $displayName = if ($isTeam) { "(Team) $($perm.Name)" } else { $perm.Name }
                $table.Add([PSCustomObject][ordered]@{
                    'Folder UID'  = $sf.Uid
                    'Folder Name' = $sf.Name
                    'Shared To'   = $displayName
                    'Permissions' = $permText
                    'Folder Path' = $folderPath
                })
            }
        }
    }

    Write-ShareReportOutput -Rows $table -Title 'Shared Folders' -Format $Format -Output $Output
}

function Script:Write-ShareReportRecordDetail {
    param(
        [string[]] $RecordUids,
        [hashtable] $SharesMap,
        [hashtable] $RecordTitleMap,
        [hashtable] $SfMembershipCache
    )

    foreach ($uid in $RecordUids) {
        $shareInfo = $SharesMap[$uid]
        $title = $RecordTitleMap[$uid]

        Write-Host ''
        Write-Host ('{0,20}   {1}' -f 'Record UID:', $uid)
        Write-Host ('{0,20}   {1}' -f 'Title:', $title)

        $i = 0
        if ($shareInfo -and $shareInfo.UserPermissions) {
            foreach ($up in $shareInfo.UserPermissions) {
                if ($up.Owner) { continue }
                $label = if ($i -eq 0) { 'Shared with:' } else { '' }
                $permText = Get-PermissionsText -CanEdit $up.CanEdit -CanShare $up.CanShare
                $target = $up.Username
                if ($up.AwaitingApproval) { $target += ' (pending)' }
                Write-Host ('{0,20}   {1} => {2}' -f $label, $target, $permText)
                $i++
            }
        }

        if ($shareInfo -and $shareInfo.SharedFolderPermissions) {
            foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                $sf = $SfMembershipCache[$sfp.SharedFolderUid]
                $sfName = if ($sf) { $sf.Name } else { $sfp.SharedFolderUid }
                $label = if ($i -eq 0) { 'Shared with:' } else { '' }
                Write-Host ('{0,20}   via Shared Folder: {1}' -f $label, $sfName)
                $i++
            }
        }
        Write-Host ''
    }
}

function Script:Write-ShareReportUserSharedFolders {
    param(
        [hashtable] $SfShares,
        [hashtable] $SfMembershipCache,
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [System.Collections.Generic.HashSet[string]] $UserFilter,
        [string] $Format,
        [string] $Output
    )

    $table = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($user in $SfShares.Keys) {
        if (-not $UserFilter.Contains($user)) { continue }
        foreach ($sfUid in $SfShares[$user]) {
            $sf = $SfMembershipCache[$sfUid]
            if (-not $sf) {
                [KeeperSecurity.Vault.SharedFolder] $sfObj = $null
                if ($Vault.TryGetSharedFolder($sfUid, [ref]$sfObj)) { $sf = $sfObj }
            }
            $sfName = if ($sf) { $sf.Name } else { '' }
            $table.Add([PSCustomObject][ordered]@{
                'Username'          = $user
                'Shared Folder UID' = $sfUid
                'Name'              = $sfName
            })
        }
    }

    Write-ShareReportOutput -Rows $table -Title 'Shared Folders by User' -Format $Format -Output $Output
}

function Script:Build-ShareReportFolderShares {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter()]
        [hashtable] $TeamMembers,
        [Parameter()]
        [bool] $ShowTeamUsers
    )

    $sfShares = @{}
    foreach ($sf in $Vault.SharedFolders) {
        foreach ($perm in $sf.UsersPermissions) {
            $target = $perm.Name
            if (-not $sfShares.ContainsKey($target)) {
                $sfShares[$target] = [System.Collections.Generic.HashSet[string]]::new()
            }
            [void]$sfShares[$target].Add($sf.Uid)

            $isTeam = $perm.UserType -eq [KeeperSecurity.Vault.UserType]::Team
            if ($isTeam -and $ShowTeamUsers) {
                $members = $TeamMembers[$perm.Uid]
                if ($members) {
                    foreach ($member in $members) {
                        if (-not $sfShares.ContainsKey($member)) {
                            $sfShares[$member] = [System.Collections.Generic.HashSet[string]]::new()
                        }
                        [void]$sfShares[$member].Add($sf.Uid)
                    }
                }
            }
        }
    }
    return $sfShares
}

function Script:Write-ShareReportUserRecords {
    param(
        [hashtable] $RecordShares,
        [hashtable] $RecordOwnerMap,
        [hashtable] $RecordTitleMap,
        [System.Collections.Generic.HashSet[string]] $UserFilter,
        [string] $Format,
        [string] $Output
    )

    $table = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($user in $RecordShares.Keys) {
        if (-not $UserFilter.Contains($user)) { continue }
        foreach ($uid in $RecordShares[$user]) {
            $table.Add([PSCustomObject][ordered]@{
                'Username'     = $user
                'Record Owner' = $RecordOwnerMap[$uid]
                'Record UID'   = $uid
                'Record Title' = $RecordTitleMap[$uid]
            })
        }
    }

    Write-ShareReportOutput -Rows $table -Title 'Shared Records by User' -Format $Format -Output $Output
}

function Script:Write-ShareReportOwner {
    param(
        [System.Collections.Generic.List[string]] $RecordUids,
        [hashtable] $SharesMap,
        [hashtable] $RecordOwnerMap,
        [hashtable] $RecordTitleMap,
        [hashtable] $SfMembershipCache,
        [hashtable] $RecordToFolderIndex,
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [hashtable] $TeamMembers,
        [bool] $ShowTeamUsers,
        [bool] $IncludeShareDate,
        [bool] $DetailedView,
        $UserFilter,
        [string] $Format,
        [string] $Output
    )

    $aramEnabled = $true
    $table = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($uid in $RecordUids) {
        $shareInfo = $SharesMap[$uid]
        if (-not $shareInfo) { continue }

        $recOwner = $RecordOwnerMap[$uid]
        $title = $RecordTitleMap[$uid]

        $folderPaths = [System.Collections.Generic.List[string]]::new()
        $folderUids = $RecordToFolderIndex[$uid]
        if ($folderUids) {
            foreach ($fUid in $folderUids) {
                $folderPaths.Add((Get-ShareReportFolderPath -Vault $Vault -FolderUid $fUid))
            }
        }
        $folderPathStr = $folderPaths -join "`n"

        $shareEvents = @()
        if ($IncludeShareDate -and $aramEnabled) {
            $shareEvents = Get-ShareReportAuditEvents -Auth $Vault.Auth -RecordUid $uid -AramEnabled ([ref]$aramEnabled)
        }

        $shareTargets = [System.Collections.Generic.List[string]]::new()
        $permissionsList = [System.Collections.Generic.List[object]]::new()

        if ($shareInfo.UserPermissions) {
            foreach ($up in $shareInfo.UserPermissions) {
                if (-not $up.Owner) { $permissionsList.Add($up) }
            }
        }

        if ($UserFilter) {
            $filtered = [System.Collections.Generic.List[object]]::new()
            foreach ($p in $permissionsList) {
                if ($UserFilter.Contains($p.Username)) { $filtered.Add($p) }
            }
            $permissionsList = $filtered
        }

        if (-not $DetailedView) {
            $shareWith = $permissionsList.Count
            if ($shareInfo.SharedFolderPermissions) {
                foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                    $sf = $SfMembershipCache[$sfp.SharedFolderUid]
                    if ($sf) { $shareWith += $sf.UsersPermissions.Count }
                }
            }
            $shareInfoText = $shareWith.ToString()
        }
        else {
            if ($ShowTeamUsers -and $recOwner) {
                $shareTargets.Add("$recOwner => Owner")
            }

            foreach ($up in $permissionsList) {
                $permText = Get-PermissionsText -CanEdit $up.CanEdit -CanShare $up.CanShare
                $dateSuffix = ''

                if ($IncludeShareDate) {
                    $dateStr = ''
                    if ($shareEvents.Count -gt 0) {
                        $dateStr = Get-ShareDateForUser -ActivityList $shareEvents -Username $up.Username
                    }
                    if ($dateStr) {
                        $dateSuffix = $dateStr
                    }
                    else {
                        $dateSuffix = '(share date unavailable)'
                    }
                }
                $shareTargets.Add("$($up.Username) => $permText$(if ($dateSuffix) { " $dateSuffix" } else { '' })")

                if ($up.Expiration) {
                    $expDt = $up.Expiration.Value.LocalDateTime
                    $shareTargets.Add("`t(expires on $expDt)")
                }
            }

            if ($shareInfo.SharedFolderPermissions) {
                foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                    $sf = $SfMembershipCache[$sfp.SharedFolderUid]
                    if (-not $sf) { continue }
                    foreach ($sfUser in $sf.UsersPermissions) {
                        if ($sfUser.Name -eq $recOwner) { continue }
                        if ($UserFilter -and -not $UserFilter.Contains($sfUser.Name)) { continue }

                        $isTeam = $sfUser.UserType -eq [KeeperSecurity.Vault.UserType]::Team
                        $displayName = if ($isTeam -and $ShowTeamUsers) { "(Team) $($sfUser.Name)" } else { $sfUser.Name }
                        $permText = Get-PermissionsText -CanEdit $sfUser.ManageRecords -CanShare $sfUser.ManageUsers

                        $dateSuffix = ''

                        if ($IncludeShareDate) {
                            $dateStr = ''
                            if ($shareEvents.Count -gt 0) {
                                if (-not $isTeam) {
                                    $dateStr = Get-ShareDateForUser -ActivityList $shareEvents -Username $sfUser.Name
                                }
                                else {
                                    $dateStr = Get-ShareDateForFolder -ActivityList $shareEvents -SharedFolderUid $sfp.SharedFolderUid
                                }
                            }
                            if ($dateStr) {
                                $dateSuffix = $dateStr
                            }
                            else {
                                $dateSuffix = '(share date unavailable)'
                            }
                        }
                        $shareTargets.Add("$displayName => $permText$(if ($dateSuffix) { " $dateSuffix" } else { '' })")

                        if ($isTeam -and $ShowTeamUsers) {
                            $members = $TeamMembers[$sfUser.Uid]
                            if ($members) {
                                foreach ($member in $members) {
                                    $shareTargets.Add("(Team User) $member => $permText")
                                }
                            }
                        }
                    }
                }
            }

            $shareInfoText = $shareTargets -join "`n"
        }

        $table.Add([PSCustomObject][ordered]@{
            'Record Owner' = $recOwner
            'Record UID'   = $uid
            'Record Title' = $title
            'Shared With'  = $shareInfoText
            'Folder Path'  = $folderPathStr
        })
    }

    Write-ShareReportOutput -Rows $table -Title 'Record Share Report (Owner)' -Format $Format -Output $Output
}

function Script:Write-ShareReportSummary {
    param(
        [hashtable] $RecordShares,
        [hashtable] $SfShares,
        [string] $CurrentUser,
        $UserFilter,
        [string] $Format,
        [string] $Output
    )

    $RecordShares.Remove($CurrentUser)
    $SfShares.Remove($CurrentUser)

    $allTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $RecordShares.Keys) { [void]$allTargets.Add($key) }
    foreach ($key in $SfShares.Keys) { [void]$allTargets.Add($key) }

    if ($UserFilter) {
        $allTargets = [System.Collections.Generic.HashSet[string]]::new(
            ($allTargets | Where-Object { $UserFilter.Contains($_) }),
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    $table = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($target in ($allTargets | Sort-Object)) {
        $recCount = if ($RecordShares.ContainsKey($target)) { $RecordShares[$target].Count } else { $null }
        $sfCount = if ($SfShares.ContainsKey($target)) { $SfShares[$target].Count } else { $null }
        $table.Add([PSCustomObject][ordered]@{
            'Shared To'      = $target
            'Records'        = $recCount
            'Shared Folders' = $sfCount
        })
    }

    Write-ShareReportOutput -Rows $table -Title 'Share Report Summary' -Format $Format -Output $Output
}

function Get-KeeperShareReport {
    <#
    .SYNOPSIS
    Show a report of shared records and shared folders.

    .DESCRIPTION
    Generates a report of records and folders shared both with and by the current user.
    Supports multiple modes: summary, per-record detail, per-user filter, shared folders listing,
    and owner report with optional share-date information.
    Use -Verbose or -ShowTeamUsers to show detailed share permissions per target.

    .PARAMETER Format
    Output format: table, json, or csv. Default is table.

    .PARAMETER Output
    Path to write the report to a file.

    .PARAMETER Record
    Record name(s) or UID(s) to show share information for.

    .PARAMETER Email
    User email(s) or team name(s) to filter the report by.

    .PARAMETER Owner
    Show record ownership information in the report.

    .PARAMETER ShareDate
    Include the date when each record was shared. Requires enterprise admin with report permissions.
    Only applies to the owner report (-Owner).

    .PARAMETER SharedFolders
    Display shared folder detail instead of records. Used with -Email.

    .PARAMETER Folders
    Limit the report to shared folders only (excludes shared records).

    .PARAMETER ShowTeamUsers
    Expand team shares to show individual team members. Requires enterprise admin.

    .EXAMPLE
    Get-KeeperShareReport
    Display a summary of all shares grouped by share target.

    .EXAMPLE
    Get-KeeperShareReport -Record "5R7Ued8#JctulYbBLwM$"
    Display share info for a specific record.

    .EXAMPLE
    Get-KeeperShareReport -Format csv -Output share_report.csv
    Export share report as CSV.

    .EXAMPLE
    Get-KeeperShareReport -Email "john.doe@gmail.com" -Owner -ShareDate -Verbose
    Show records shared with a user including owner and share dates.

    .EXAMPLE
    Get-KeeperShareReport -Folders
    Display a list of shared folders with their access permissions.

    .EXAMPLE
    Get-KeeperShareReport -Folders -ShowTeamUsers
    Display shared folders with team memberships expanded to individual users.
    #>

    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output,

        [Parameter()]
        [string[]] $Record,

        [Parameter()]
        [string[]] $Email,

        [Parameter()]
        [switch] $Owner,

        [Parameter()]
        [switch] $ShareDate,

        [Parameter()]
        [switch] $SharedFolders,

        [Parameter()]
        [switch] $Folders,

        [Parameter()]
        [switch] $ShowTeamUsers
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Unable to load Keeper vault context. Run Connect-Keeper and Sync-Keeper first. Details: $($_.Exception.Message)" -ErrorAction Stop
    }

    $currentUser = $vault.Auth.Username
    $verbose = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose') -or $ShowTeamUsers.IsPresent

    $teamMembers = @{}
    if ($ShowTeamUsers.IsPresent) {
        $teamMembers = Get-ShareReportTeamMembers -Vault $vault
    }

    if ($Folders.IsPresent) {
        Write-ShareReportFolders -Vault $vault -TeamMembers $teamMembers -ShowTeamUsers $ShowTeamUsers.IsPresent `
            -Format $Format -Output $Output
        return
    }

    $sharedRecordUids = [System.Collections.Generic.List[string]]::new()
    $recordTitleMap = @{}

    if ($Record) {
        foreach ($r in $Record) {
            [KeeperSecurity.Vault.KeeperRecord] $rec = $null
            if ($vault.TryGetKeeperRecord($r, [ref]$rec)) {
                $sharedRecordUids.Add($rec.Uid)
                $recordTitleMap[$rec.Uid] = $rec.Title
            }
            else {
                $found = $false
                foreach ($kr in $vault.KeeperRecords) {
                    if ($kr.Title -eq $r) {
                        $sharedRecordUids.Add($kr.Uid)
                        $recordTitleMap[$kr.Uid] = $kr.Title
                        $found = $true
                        break
                    }
                }
                if (-not $found) {
                    Write-Warning "Cannot find a Keeper record: $r"
                }
            }
        }
    }
    else {
        foreach ($kr in $vault.KeeperRecords) {
            if ($kr.Shared) {
                $sharedRecordUids.Add($kr.Uid)
                $recordTitleMap[$kr.Uid] = $kr.Title
            }
        }
    }

    if ($sharedRecordUids.Count -eq 0 -and -not ($Email -and $SharedFolders.IsPresent)) {
        Write-Warning 'No shared records found.'
        return
    }

    $allShares = Get-ShareReportRecordShares -Vault $vault -RecordUids $sharedRecordUids.ToArray()
    $sharesMap = @{}
    foreach ($s in $allShares) {
        $sharesMap[$s.RecordUid] = $s
    }

    $sfMembershipCache = @{}
    foreach ($shareInfo in $allShares) {
        if ($shareInfo.SharedFolderPermissions) {
            foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                if (-not $sfMembershipCache.ContainsKey($sfp.SharedFolderUid)) {
                    [KeeperSecurity.Vault.SharedFolder] $sf = $null
                    if ($vault.TryGetSharedFolder($sfp.SharedFolderUid, [ref]$sf)) {
                        $sfMembershipCache[$sfp.SharedFolderUid] = $sf
                    }
                }
            }
        }
    }

    $recordOwnerMap = @{}
    foreach ($uid in $sharedRecordUids) {
        $shareInfo = $sharesMap[$uid]
        $ownerName = ''
        if ($shareInfo -and $shareInfo.UserPermissions) {
            foreach ($up in $shareInfo.UserPermissions) {
                if ($up.Owner) { $ownerName = $up.Username; break }
            }
        }
        [KeeperSecurity.Vault.KeeperRecord] $rec = $null
        if (-not $ownerName -and $vault.TryGetKeeperRecord($uid, [ref]$rec) -and $rec.Owner) {
            $ownerName = $currentUser
        }
        $recordOwnerMap[$uid] = $ownerName
    }

    if ($Record) {
        Write-ShareReportRecordDetail -RecordUids $sharedRecordUids.ToArray() -SharesMap $sharesMap `
            -RecordTitleMap $recordTitleMap -SfMembershipCache $sfMembershipCache
        return
    }

    $userFilter = $null
    if ($Email) {
        $userFilter = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($e in $Email) { [void]$userFilter.Add($e) }
    }

    if ($Owner.IsPresent) {
        $recordToFolderIndex = Build-RecordToFolderIndex -Vault $vault

        Write-ShareReportOwner -RecordUids $sharedRecordUids -SharesMap $sharesMap `
            -RecordOwnerMap $recordOwnerMap -RecordTitleMap $recordTitleMap `
            -SfMembershipCache $sfMembershipCache -RecordToFolderIndex $recordToFolderIndex `
            -Vault $vault -TeamMembers $teamMembers -ShowTeamUsers $ShowTeamUsers.IsPresent `
            -IncludeShareDate $ShareDate.IsPresent -DetailedView $verbose `
            -UserFilter $userFilter -Format $Format -Output $Output
        return
    }

    $recordShares = @{}
    $sfShares = @{}

    foreach ($uid in $sharedRecordUids) {
        $shareInfo = $sharesMap[$uid]
        if (-not $shareInfo) { continue }

        if ($shareInfo.UserPermissions) {
            foreach ($up in $shareInfo.UserPermissions) {
                if ($up.Owner) { continue }
                $target = $up.Username
                if (-not $recordShares.ContainsKey($target)) {
                    $recordShares[$target] = [System.Collections.Generic.HashSet[string]]::new()
                }
                [void]$recordShares[$target].Add($uid)
            }
        }

        if ($shareInfo.SharedFolderPermissions) {
            foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                $sf = $sfMembershipCache[$sfp.SharedFolderUid]
                if (-not $sf) { continue }

                foreach ($perm in $sf.UsersPermissions) {
                    $target = $perm.Name
                    $isTeam = $perm.UserType -eq [KeeperSecurity.Vault.UserType]::Team

                    if (-not $sfShares.ContainsKey($target)) {
                        $sfShares[$target] = [System.Collections.Generic.HashSet[string]]::new()
                    }
                    [void]$sfShares[$target].Add($sfp.SharedFolderUid)

                    if (-not $recordShares.ContainsKey($target)) {
                        $recordShares[$target] = [System.Collections.Generic.HashSet[string]]::new()
                    }
                    [void]$recordShares[$target].Add($uid)

                    if ($isTeam -and $ShowTeamUsers.IsPresent) {
                        $members = $teamMembers[$perm.Uid]
                        if ($members) {
                            foreach ($member in $members) {
                                if (-not $sfShares.ContainsKey($member)) {
                                    $sfShares[$member] = [System.Collections.Generic.HashSet[string]]::new()
                                }
                                [void]$sfShares[$member].Add($sfp.SharedFolderUid)

                                if (-not $recordShares.ContainsKey($member)) {
                                    $recordShares[$member] = [System.Collections.Generic.HashSet[string]]::new()
                                }
                                [void]$recordShares[$member].Add($uid)
                            }
                        }
                    }
                }
            }
        }
    }

    if ($Email -and $SharedFolders.IsPresent) {
        $folderSfShares = Build-ShareReportFolderShares -Vault $vault -TeamMembers $teamMembers -ShowTeamUsers $ShowTeamUsers.IsPresent
        Write-ShareReportUserSharedFolders -SfShares $folderSfShares -SfMembershipCache $sfMembershipCache `
            -Vault $vault -UserFilter $userFilter -Format $Format -Output $Output
        return
    }

    if ($Email) {
        Write-ShareReportUserRecords -RecordShares $recordShares -RecordOwnerMap $recordOwnerMap `
            -RecordTitleMap $recordTitleMap -UserFilter $userFilter -Format $Format -Output $Output
        return
    }

        Write-ShareReportSummary -RecordShares $recordShares -SfShares $sfShares `
        -CurrentUser $currentUser -UserFilter $userFilter -Format $Format -Output $Output
}

New-Alias -Name share-report -Value Get-KeeperShareReport

function Get-KeeperSharedRecordsReport {
    <#
    .SYNOPSIS
    Report shared records for the logged-in user.

    .DESCRIPTION
    Generates a report of all shared records showing the share type, recipient, and permissions per row.
    the share type (Direct Share, Share Folder, Share Team Folder), permissions, and folder path.
    By default only owned shared records are included. Use -AllRecords to include non-owned records.
    Mirrors the Python Commander 'shared-records-report' command.

    Alias: shared-records-report, ksrr

    .PARAMETER ShowTeamUsers
    Expand team shares to show individual team members. Requires enterprise admin.

    .PARAMETER AllRecords
    Include all shared records in the vault, not just records owned by the current user.

    .PARAMETER Folder
    Optional folder path(s) or UID(s) to scope the report to records within those folders.

    .PARAMETER Format
    Output format: table (default), json, or csv.

    .PARAMETER Output
    Path to write the report to a file.

    .EXAMPLE
    Get-KeeperSharedRecordsReport
    Report all owned shared records in table format.

    .EXAMPLE
    Get-KeeperSharedRecordsReport -AllRecords
    Report all shared records in the vault (including non-owned).

    .EXAMPLE
    Get-KeeperSharedRecordsReport -ShowTeamUsers
    Report with team shares expanded to individual team members.

    .EXAMPLE
    Get-KeeperSharedRecordsReport -Format csv -Output "shared_records.csv"
    Export the shared records report to a CSV file.

    .EXAMPLE
    Get-KeeperSharedRecordsReport -Folder "Shared\Projects"
    Report shared records within a specific folder.
    #>

    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('tu')]
        [switch] $ShowTeamUsers,

        [Parameter()]
        [switch] $AllRecords,

        [Parameter()]
        [string[]] $Folder,

        [Parameter()]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Unable to load Keeper vault context. Run Connect-Keeper and Sync-Keeper first. Details: $($_.Exception.Message)" -ErrorAction Stop
    }

    $currentUser = $vault.Auth.Username

    $allowedVersions = if ($AllRecords.IsPresent) { @(0, 1, 2, 3, 5, 6) } else { @(2, 3) }

    $teamMembers = @{}
    if ($ShowTeamUsers.IsPresent) {
        $teamMembers = Get-ShareReportTeamMembers -Vault $vault
    }

    $records = @{}
    $filterFolderUids = $null

    if ($Folder -and $Folder.Count -gt 0) {
        $filterFolderUids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($folderName in $Folder) {
            $folderFound = $false
            foreach ($fn in $vault.Folders) {
                $folderPath = Get-ShareReportFolderPath -Vault $vault -FolderUid $fn.FolderUid
                if ($fn.FolderUid -eq $folderName -or $fn.Name -eq $folderName -or $folderPath -eq $folderName) {
                    [void]$filterFolderUids.Add($fn.FolderUid)
                    $folderFound = $true
                    foreach ($recUid in $fn.Records) {
                        [KeeperSecurity.Vault.KeeperRecord] $rec = $null
                        if (-not $vault.TryGetKeeperRecord($recUid, [ref]$rec)) { continue }
                        if (-not $rec.Shared) { continue }
                        if ($rec.Version -notin $allowedVersions) { continue }
                        $records[$rec.Uid] = $rec
                    }
                }
            }
            if (-not $folderFound) {
                Write-Warning "Folder '$folderName' could not be found."
            }
        }
    }
    else {
        foreach ($kr in $vault.KeeperRecords) {
            if (-not $kr.Shared) { continue }
            if ($kr.Version -notin $allowedVersions) { continue }
            $records[$kr.Uid] = $kr
        }
    }

    if (-not $AllRecords.IsPresent) {
        $ownedOnly = @{}
        foreach ($entry in $records.GetEnumerator()) {
            if ($entry.Value.Owner) {
                $ownedOnly[$entry.Key] = $entry.Value
            }
        }
        $records = $ownedOnly
    }

    if ($records.Count -eq 0) {
        Write-Warning 'No shared records found.'
        return
    }

    $recordUids = [string[]]@($records.Keys)
    $allShares = Get-ShareReportRecordShares -Vault $vault -RecordUids $recordUids

    $sharesMap = @{}
    foreach ($s in $allShares) {
        $sharesMap[$s.RecordUid] = $s
    }

    $sfMembershipCache = @{}
    foreach ($shareInfo in $allShares) {
        if ($shareInfo.SharedFolderPermissions) {
            foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                if (-not $sfMembershipCache.ContainsKey($sfp.SharedFolderUid)) {
                    [KeeperSecurity.Vault.SharedFolder] $sf = $null
                    if ($vault.TryGetSharedFolder($sfp.SharedFolderUid, [ref]$sf)) {
                        $sfMembershipCache[$sfp.SharedFolderUid] = $sf
                    }
                }
            }
        }
    }

    $recordToFolderIndex = Build-RecordToFolderIndex -Vault $vault

    $table = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($recordUid in $recordUids) {
        $rec = $records[$recordUid]
        $shareInfo = $sharesMap[$recordUid]
        if (-not $shareInfo) { continue }

        $recTitle = $rec.Title
        if ($Format -eq 'table' -and $recTitle.Length -gt 40) {
            $recTitle = $recTitle.Substring(0, 38) + '...'
        }

        $owner = $null
        if ($shareInfo.UserPermissions) {
            foreach ($up in $shareInfo.UserPermissions) {
                if ($up.Owner) { $owner = $up.Username; break }
            }
        }
        if (-not $owner -and $rec.Owner) {
            $owner = $currentUser
        }

        $folderPaths = [System.Collections.Generic.List[string]]::new()
        $folderUids = $recordToFolderIndex[$recordUid]
        if ($folderUids) {
            if ($null -ne $filterFolderUids) {
                $folderUids = $folderUids | Where-Object { $filterFolderUids.Contains($_) }
            }
            foreach ($fUid in $folderUids) {
                $folderPaths.Add((Get-ShareReportFolderPath -Vault $vault -FolderUid $fUid))
            }
        }
        $folderPathStr = $folderPaths -join "`n"

        if ($shareInfo.UserPermissions) {
            foreach ($up in $shareInfo.UserPermissions) {
                if ($up.Owner) { continue }
                if (-not $AllRecords.IsPresent -and $up.Username -eq $currentUser) { continue }
                $permText = Get-PermissionsText -CanEdit $up.CanEdit -CanShare $up.CanShare
                $row = [ordered]@{
                    'Record UID'  = $recordUid
                    'Title'       = $recTitle
                    'Share Type'  = 'Direct Share'
                    'Shared To'   = $up.Username
                    'Permissions' = $permText
                    'Folder Path' = $folderPathStr
                }
                if ($AllRecords.IsPresent) {
                    $row.Insert(0, 'Owner', $owner)
                }
                $table.Add([PSCustomObject]$row)
            }
        }

        if ($shareInfo.SharedFolderPermissions) {
            foreach ($sfp in $shareInfo.SharedFolderPermissions) {
                $sf = $sfMembershipCache[$sfp.SharedFolderUid]
                if (-not $sf) {
                    $permText = Get-PermissionsText -CanEdit $sfp.CanEdit -CanShare $sfp.CanShare
                    $row = [ordered]@{
                        'Record UID'  = $recordUid
                        'Title'       = $recTitle
                        'Share Type'  = 'Share Folder'
                        'Shared To'   = '***'
                        'Permissions' = $permText
                        'Folder Path' = $sfp.SharedFolderUid
                    }
                    if ($AllRecords.IsPresent) {
                        $row.Insert(0, 'Owner', $owner)
                    }
                    $table.Add([PSCustomObject]$row)
                    continue
                }

                $sfFolderPath = Get-ShareReportFolderPath -Vault $vault -FolderUid $sf.Uid
                if (-not $sfFolderPath) { $sfFolderPath = $sf.Name }

                foreach ($sfUser in $sf.UsersPermissions) {
                    $isTeam = $sfUser.UserType -eq [KeeperSecurity.Vault.UserType]::Team
                    $permText = Get-PermissionsText -CanEdit $sfp.CanEdit -CanShare $sfp.CanShare

                    if ($isTeam) {
                        if ($ShowTeamUsers.IsPresent -and $teamMembers.ContainsKey($sfUser.Uid)) {
                            foreach ($member in $teamMembers[$sfUser.Uid]) {
                                $row = [ordered]@{
                                    'Record UID'  = $recordUid
                                    'Title'       = $recTitle
                                    'Share Type'  = 'Share Team Folder'
                                    'Shared To'   = "($($sfUser.Name)) $member"
                                    'Permissions' = $permText
                                    'Folder Path' = $sfFolderPath
                                }
                                if ($AllRecords.IsPresent) {
                                    $row.Insert(0, 'Owner', $owner)
                                }
                                $table.Add([PSCustomObject]$row)
                            }
                        }
                        else {
                            $row = [ordered]@{
                                'Record UID'  = $recordUid
                                'Title'       = $recTitle
                                'Share Type'  = 'Share Team Folder'
                                'Shared To'   = $sfUser.Name
                                'Permissions' = $permText
                                'Folder Path' = $sfFolderPath
                            }
                            if ($AllRecords.IsPresent) {
                                $row.Insert(0, 'Owner', $owner)
                            }
                            $table.Add([PSCustomObject]$row)
                        }
                    }
                    else {
                        if (-not $AllRecords.IsPresent -and $sfUser.Name -eq $currentUser) { continue }
                        $row = [ordered]@{
                            'Record UID'  = $recordUid
                            'Title'       = $recTitle
                            'Share Type'  = 'Share Folder'
                            'Shared To'   = $sfUser.Name
                            'Permissions' = $permText
                            'Folder Path' = $sfFolderPath
                        }
                        if ($AllRecords.IsPresent) {
                            $row.Insert(0, 'Owner', $owner)
                        }
                        $table.Add([PSCustomObject]$row)
                    }
                }
            }
        }
    }

    Write-ShareReportOutput -Rows $table -Title 'Shared Records Report' -Format $Format -Output $Output
}

New-Alias -Name shared-records-report -Value Get-KeeperSharedRecordsReport
