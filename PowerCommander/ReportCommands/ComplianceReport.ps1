#requires -Version 5.1

<#
    .Synopsis
    Fetch compliance report data using SDK's ReportingPlugin
    Replaces direct API calls for duplicate elimination
#>
function Get-KeeperComplianceReportViaSdk {
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

    try {

        $enterprise = getEnterprise
        if (-not $enterprise -or -not $enterprise.loader) {
            Write-Error "Enterprise data is required to build the compliance report." -ErrorAction Stop
        }

        $auth = $enterprise.loader.Auth
        if (-not $auth) {
            Write-Error "Cannot fetch compliance report: enterprise authentication is not available." -ErrorAction Stop
        }

        # Create ReportingPlugin with SQLite storage

        $storage = $null
        try {
            # Use SQLite storage for persistent caching (like existing PowerCommander auth storage)
            $dbPath = Get-KeeperComplianceSqliteDbPath -Enterprise $enterprise -Auth $auth
            $connectionString = "Data Source=$dbPath;Pooling=True;"

            $sqlComplianceStorage = Get-SqliteComplianceStorageFromHelper -ConnectionString $connectionString

            $storage = New-Object KeeperSecurity.Enterprise.ReportingPlugin.SqliteReportingStorage($sqlComplianceStorage)
        }
        catch {
            $storageType = [KeeperSecurity.Enterprise.ReportingPlugin.InMemoryReportingStorage]
            $storage = New-Object $storageType
        }

        $enterpriseEcKey = $null
        if ($enterprise.loader.EcPrivateKey -and $enterprise.loader.EcPrivateKey.Length -gt 0) {
            $enterpriseEcKey = [KeeperSecurity.Utils.CryptoUtils]::LoadEcPrivateKey($enterprise.loader.EcPrivateKey)
        }
        $pluginType = [KeeperSecurity.Enterprise.ReportingPlugin.ReportingPlugin]
        $plugin = New-Object $pluginType($enterprise.enterpriseData, $storage, $enterpriseEcKey)

        # Create compliance report config (use ComplianceReportConfig)
        $config = New-Object KeeperSecurity.Enterprise.ReportingPlugin.ComplianceReportConfig
        $config.NoRebuild = $NoRebuild
        $config.Rebuild = $Rebuild
        $config.CacheMaxAgeDays = 1
        $config.IncludeAging = $false # Aging is fetched by the report's aggregate-query path below.
        $config.SharedRecordsOnly = $SharedOnly
        if ($OwnerUserIds -and $OwnerUserIds.Count -gt 0) {
            $ownerIds = [System.Collections.Generic.List[long]]::new()
            $ownerIds.AddRange([long[]]$OwnerUserIds)
            $config.OwnerUserIds = $ownerIds
        }

        $reportResult = $plugin.GenerateComplianceReportAsync($auth, $config).GetAwaiter().GetResult()

        if ($reportResult.ErrorMessage) {
            Write-Error "Compliance report error: $($reportResult.ErrorMessage)" -ErrorAction Stop
        }


        # Transform SDK results to match expected output structure
        $result = @{
            Entries = $reportResult.Entries
            TotalCount = $reportResult.TotalCount
            GeneratedAt = $reportResult.GeneratedAt
        }

        return $result
    }
    catch {
        Write-Error "Failed to fetch compliance report via SDK: $($_.Exception.Message)" -ErrorAction Stop
    }
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
    .Synopsis
    Clear compliance report cache
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
        .Synopsis
        Run enterprise compliance report

        .Parameter Format
        table (default), json, or csv

        .Parameter Output
        File path for json/csv output

        .Parameter Username
        Filter by enterprise username(s)

        .Parameter Node
        Filter by node name or ID

        .Parameter Pattern
        Filter rows by pattern (supports regex:, exact:, not: prefixes)

        .Parameter Regex
        Treat patterns as regular expressions

        .Parameter PatternMatchAll
        Require all patterns to match (AND); default is OR

        .Parameter JobTitle
        Filter by job title

        .Parameter Record
        Filter by record UID or title

        .Parameter Team
        Filter by team name or UID

        .Parameter Url
        Filter by URL substring

        .Parameter Shared
        Show only shared records

        .Parameter DeletedItems
        Show only deleted (trashed) records

        .Parameter ActiveItems
        Show only active records

        .Parameter Rebuild
        Force rebuild compliance cache

        .Parameter NoRebuild
        Use existing cache if available

        .Parameter NoCache
        Discard cache after the report

        .Parameter Aging
        Include password aging columns
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

    if ($DeletedItems -and $ActiveItems) {
        Write-Error "-DeletedItems and -ActiveItems cannot be used together." -ErrorAction Stop
    }

    $reportRows = Invoke-KeeperComplianceReportSession -NoCache:$NoCache -ScriptBlock {
        Write-Host ""
        Write-Host "================================ COMPLIANCE REPORT ================================" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "Starting compliance-report" -ForegroundColor White
        Write-Host "  Format: $Format, Rebuild: $Rebuild, NoRebuild: $NoRebuild, NoCache: $NoCache, Aging: $Aging" -ForegroundColor White

        # Use SDK-based approach (eliminates duplicate API calls)
        Write-Host ""
        $fetchOwnerIds = Resolve-KeeperComplianceFetchOwnerIds -Username $Username -Team $Team -Node $Node -JobTitle $JobTitle
        if ($null -ne $fetchOwnerIds -and $fetchOwnerIds.Count -eq 0) {
            Write-Warning "No enterprise users matched the provided owner filters."
            return @()
        }
        elseif ($null -eq $fetchOwnerIds) {
            Write-Host "  ✓ No filters applied - will fetch data for ALL enterprise users" -ForegroundColor Green
        }
        else {
            Write-Host "  ✓ Owner pre-filter matched $($fetchOwnerIds.Count) user(s)" -ForegroundColor Green
        }

        Write-Host ""
        $sdkReport = Get-KeeperComplianceReportViaSdk -Rebuild:$Rebuild -NoRebuild:$NoRebuild `
            -OwnerUserIds $fetchOwnerIds -SharedOnly:$Shared

        if ($sdkReport -and $sdkReport.Entries) {
            Write-Host ""
            Write-Host "  ✓ SDK returned $($sdkReport.Entries.Count) compliance record(s)" -ForegroundColor Green

            # Convert SDK compliance entries to display rows
            $reportRows = @()
            foreach ($entry in $sdkReport.Entries) {
                if ($Url) {
                    $urlMatches = @($Url | Where-Object {
                        $entry.Url -and $entry.Url.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
                    })
                    if ($urlMatches.Count -eq 0) { continue }
                }
                $row = [ordered]@{
                    record_uid        = $entry.RecordUid
                    title             = $entry.Title
                    type              = $entry.RecordType
                    username          = $entry.Owner
                    permissions       = if ($entry.Permissions) { $entry.Permissions } elseif ($entry.Shared) { 'Shared' } else { 'Owner' }
                    permission_bits   = $entry.PermissionBits
                    url               = $entry.Url
                    in_trash          = $entry.InTrash
                    shared_folder_uid = @($entry.SharedFolderUids)
                }
                if ($Username -and -not ($Username | Where-Object { [string]::Equals($_, $row.username, [System.StringComparison]::OrdinalIgnoreCase) })) {
                    continue
                }
                $reportRows += [PSCustomObject]$row
            }

            # Apply post-SDK filters
            $filterCount = 0
            if ($Username -or $Team -or $JobTitle -or $Node) { $filterCount++ }
            if ($Url) { $filterCount++ }
            if ($Shared) { $filterCount++ }
            if ($Record -and $Record.Count -gt 0) {
                $filterCount++
                $recordsBefore = $reportRows.Count
                $recordFilter = @($Record | ForEach-Object { ([string]$_).ToLowerInvariant() })
                $reportRows = @($reportRows | Where-Object {
                    $recordFilter -contains ([string]$_.record_uid).ToLowerInvariant() -or
                    $recordFilter -contains ([string]$_.title).ToLowerInvariant()
                })
                Write-Host "  Filtered by Record: $recordsBefore → $($reportRows.Count) records" -ForegroundColor Yellow
            }

            if ($DeletedItems) {
                $filterCount++
                $recordsBefore = $reportRows.Count
                $reportRows = @($reportRows | Where-Object { $_.in_trash -eq $true })
                Write-Host "  Filtered by DeletedItems: $recordsBefore → $($reportRows.Count) records" -ForegroundColor Yellow
            }
            elseif ($ActiveItems) {
                $filterCount++
                $recordsBefore = $reportRows.Count
                $reportRows = @($reportRows | Where-Object { $_.in_trash -eq $false })
                Write-Host "  Filtered by ActiveItems: $recordsBefore → $($reportRows.Count) records" -ForegroundColor Yellow
            }

            if ($Pattern -and $Pattern.Count -gt 0) {
                $filterCount++
                $recordsBefore = $reportRows.Count
                $reportRows = Invoke-KeeperCompliancePatternFilterRows -Rows $reportRows -Patterns $Pattern `
                    -UseRegex:$Regex -MatchAll:$PatternMatchAll
                Write-Host "  Filtered by Pattern: $recordsBefore → $($reportRows.Count) records" -ForegroundColor Yellow
            }

            if ($Aging -and $reportRows.Count -gt 0) {
                $agingData = Get-KeeperComplianceAgingData -RecordUids @($reportRows | Select-Object -ExpandProperty record_uid -Unique)
                foreach ($row in $reportRows) {
                    $aging = $agingData[[string]$row.record_uid]
                    if ($aging) {
                        Add-Member -InputObject $row -NotePropertyName created -NotePropertyValue $aging.created -Force
                        Add-Member -InputObject $row -NotePropertyName last_pw_change -NotePropertyValue $aging.last_pw_change -Force
                        Add-Member -InputObject $row -NotePropertyName last_modified -NotePropertyValue $aging.last_modified -Force
                        Add-Member -InputObject $row -NotePropertyName last_rotation -NotePropertyValue $aging.last_rotation -Force
                    }
                }
            }

            if ($filterCount -eq 0) {
                Write-Host "  No additional filters applied - using all $($reportRows.Count) records" -ForegroundColor Green
            } else {
                Write-Host "  ✓ Applied $filterCount filter(s) → Final: $($reportRows.Count) records" -ForegroundColor Green
            }

            return ,@($reportRows)
        }
        else {
            return @()
        }
    }

    if ($reportRows.Count -eq 0) {
        Write-Host ""
        Write-Host "No compliance report rows matched the current filters." -ForegroundColor Yellow
        Write-Host "Compliance Report: 0 rows" -ForegroundColor White
        return
    }

    Write-Host ""
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

    Write-Host "  ✓ Rendering $($reportRows.Count) row(s) as $Format format" -ForegroundColor Green
    Write-Host ""
    Write-Host "================================ END REPORT ================================" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host ""

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
        Write-Error "-Period and -CutoffDate cannot be used together." -ErrorAction Stop
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

