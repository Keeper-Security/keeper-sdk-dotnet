#requires -Version 5.1
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
        elseif ($rec -is [KeeperSecurity.Vault.TypedRecord]) {
            $tr = [KeeperSecurity.Vault.TypedRecord]$rec
            if ($tr.TypeName) {
                $rtype = $tr.TypeName
            }
            $urlField = $null
            if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($tr, 'url', $null, [ref]$urlField)) {
                $urlVal = [KeeperSecurity.Vault.VaultDataExtensions]::GetExternalValue($urlField)
                if ($urlVal) {
                    $url = ([string]$urlVal).TrimEnd('/')
                }
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

        if (($events.Count -lt $Limit) -or ($VaultMode -and $remaining.Count -eq 0) -or ($lastCreatedEpoch -le 0)) {
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
        .Synopsis
        Run record-access report

        .Parameter Email
        User email(s), enterprise user ID, or '@all'

        .Parameter ReportType
        'history' (default) or 'vault'

        .Parameter Format
        table (default), json, or csv

        .Parameter Output
        File path for json/csv output

        .Parameter Node
        Filter by node

        .Parameter Username
        Filter by username

        .Parameter Team
        Filter by team

        .Parameter Pattern
        Wildcard filter strings

        .Parameter PatternRegex
        Regex filter (mutually exclusive with -Pattern)
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
        .Synopsis
        Run compliance team report
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
        .Synopsis
        Run compliance summary report
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
        .Synopsis
        Run compliance shared-folder report

        .Parameter ShowTeamUsers
        Include team members in the email column
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

