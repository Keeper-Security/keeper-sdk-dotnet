#requires -Version 5.1

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
    
    if ($null -eq $OwnerUserIds -and $SharedOnly -and $allCacheEntry) {
        $allLoadedAt = [datetime]$allCacheEntry.LoadedAt
        $allCacheIsFresh = ((Get-Date) - $allLoadedAt) -lt $cacheTtl
        if ($NoRebuild -or (-not $Rebuild -and $allCacheIsFresh)) {
            Write-KeeperComplianceStatus "Using in-session cache 'all' for compatible shared-only request '$cacheKey', loaded at $($allLoadedAt.ToString('u'))."
            Set-KeeperComplianceLastSnapshotStatus -FromCache $true -Incomplete $false -BuiltAt $allLoadedAt
            return $allCacheEntry.Snapshot
        }
    }

    $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader) {
        Write-Error "Enterprise data is required to build the compliance report." -ErrorAction Stop
    }

    $auth = $enterprise.loader.Auth
    if (-not $auth) {
        Write-Warning "Cannot fetch compliance aging data: enterprise authentication is not available."
        return
    }

    if (-not $Rebuild) {
        try {
            if ($enterprise.loader.Auth) {
                $sqliteLoaded = Import-KeeperComplianceSnapshotFromSqlite -CacheKey $cacheKey -CacheTtl $cacheTtl `
                    -Enterprise $enterprise -Auth $enterprise.loader.Auth
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
                        -Enterprise $enterprise -Auth $enterprise.loader.Auth
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

