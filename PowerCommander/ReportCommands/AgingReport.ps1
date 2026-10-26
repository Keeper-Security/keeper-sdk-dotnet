#requires -Version 5.1

function Get-KeeperAgingReport {
    <#
        .Synopsis
        Run password aging report

        .Parameter Format
        table (default), json, or csv

        .Parameter Output
        File path for json/csv output

        .Parameter Period
        Cutoff period, e.g. 10d, 3m, 1y

        .Parameter CutoffDate
        Fixed cutoff date (mutually exclusive with -Period)

        .Parameter Username
        Filter by user email

        .Parameter ExcludeDeleted
        Exclude trashed records

        .Parameter InSharedFolder
        Only records in shared folders

        .Parameter Sort
        Sort by: owner, title, last_changed, or shared

        .Parameter Delete
        Clear cache without running a report
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

