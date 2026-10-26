using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise.AuditLogCommands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise.ReportingPlugin
{
    /// <summary>
    /// Main reporting plugin - orchestrates audit and compliance reports
    /// Handles:
    /// 1. Fetching SOX compliance data from API (if needed)
    /// 2. Fetching audit events from API (if needed)
    /// 3. Storing to SQLite cache
    /// 4. Extracting aging data from audit
    /// 5. Linking audit + SOX + aging together
    /// </summary>
    public class ReportingPlugin : IReportingPlugin
    {
        private readonly IReportingStorage _storage;
        private readonly IEnterpriseData _enterpriseData;
        private readonly EcPrivateKey _enterpriseEcPrivateKey;
        private const int ApiRawEventRowLimit = 1000;

        public ReportingPlugin(
            IEnterpriseData enterpriseData,
            IReportingStorage storage = null,
            EcPrivateKey enterpriseEcPrivateKey = null)
        {
            _enterpriseData = enterpriseData ?? throw new ArgumentNullException(nameof(enterpriseData));
            _storage = storage ?? new InMemoryReportingStorage();
            _enterpriseEcPrivateKey = enterpriseEcPrivateKey;
        }

        /// <summary>
        /// Generate audit report WITH SOX compliance context
        ///
        /// Flow:
        /// 1. Check if SOX data is cached and fresh
        /// 2. If stale/missing, fetch from API
        /// 3. Check if audit events are cached and fresh
        /// 4. If stale/missing, fetch from API
        /// 5. Extract aging data from audit events
        /// 6. Link: Audit + SOX (compliance context) + Aging
        /// 7. Return enriched report
        /// </summary>
        public async Task<AuditReportResult> GenerateAuditReportAsync(
            IAuthentication auth,
            AuditReportConfig config)
        {
            var result = new AuditReportResult();

            try
            {
                if (config == null) throw new ArgumentNullException(nameof(config));
                if (config.CacheMaxAgeDays < 0)
                    throw new ArgumentOutOfRangeException(nameof(config.CacheMaxAgeDays), "Cache age cannot be negative.");
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                Dictionary<string, ComplianceContextInfo> soxData = null;

                if (config.IncludeComplianceContext)
                {
                    var isStale = _storage.IsComplianceDataStale(config.CacheMaxAgeDays);

                    if (!isStale)
                    {
                        // Use cached SOX data
                        Trace.TraceInformation("Using cached compliance data");
                        soxData = _storage.GetComplianceData(config.RecordUids);
                    }
                    else
                    {
                        Trace.TraceInformation("Fetching fresh compliance data from API");
                        soxData = await FetchComplianceDataAsync(auth, config.RecordUids, config.OwnerUserIds);

                        var scopedFetch = (config.RecordUids?.Count > 0) || (config.OwnerUserIds?.Count > 0);
                        if (!scopedFetch && soxData.Count > 0)
                        {
                            _storage.SaveComplianceData(soxData, now);
                            _storage.UpdateComplianceRefreshTimestamp(now);
                            Trace.TraceInformation($"Cached {soxData.Count} compliance records");
                        }
                    }
                }

                List<AuditReportEntry> auditEvents = null;


                if (!_storage.IsAuditEventStale(config.CacheMaxAgeDays))
                {
                    Trace.TraceInformation("Using cached audit events");
                    auditEvents = _storage.GetAuditEvents(config.RecordUids);
                }
                else
                {
                    Trace.TraceInformation("Fetching fresh audit events from API");
                    auditEvents = await FetchAuditEventsAsync(auth, config);

                    if (auditEvents != null && auditEvents.Count > 0)
                    {
                        _storage.UpdateAuditRefreshTimestamp(now);
                        Trace.TraceInformation($"Cached {auditEvents.Count} audit events");
                    }
                }

                Dictionary<string, RecordAgingInfo> agingData = null;

                if (config.IncludeAging && auditEvents != null && auditEvents.Count > 0)
                {
                    Trace.TraceInformation("Fetching aggregate aging data for audit report records");
                    var recordUids = auditEvents.Select(e => e.RecordUid)
                        .Where(uid => !string.IsNullOrWhiteSpace(uid))
                        .Distinct(StringComparer.Ordinal)
                        .ToList();
                    agingData = await FetchAgingDataAsync(auth, recordUids);
                    _storage.SaveAgingData(agingData, now);
                    Trace.TraceInformation($"Extracted aging data for {agingData?.Count ?? 0} records");
                }

                result.Entries = auditEvents ?? new List<AuditReportEntry>();
                result.AgingData = agingData ?? new Dictionary<string, RecordAgingInfo>();
                result.ComplianceContext = soxData ?? new Dictionary<string, ComplianceContextInfo>();
                result.TotalCount = result.Entries.Count;
                result.GeneratedAt = DateTime.UtcNow;

                Trace.TraceInformation($"Generated audit report with {result.TotalCount} entries");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error generating audit report: {ex.Message}");
                result.ErrorMessage = $"Error generating audit report: {ex.Message}";
            }

            return result;
        }

        /// <summary>
        /// Generate compliance report with optional aging data from audit
        /// </summary>
        public async Task<ComplianceReportResult> GenerateComplianceReportAsync(
            IAuthentication auth,
            ComplianceReportConfig config,
            List<string> vaultRecordUids = null)
        {
            var result = new ComplianceReportResult();

            try
            {
                if (config == null) throw new ArgumentNullException(nameof(config));
                if (config.Rebuild && config.NoRebuild)
                    throw new ArgumentException("Rebuild and NoRebuild cannot both be enabled.", nameof(config));
                if (config.CacheMaxAgeDays < 0)
                    throw new ArgumentOutOfRangeException(nameof(config.CacheMaxAgeDays), "Cache age cannot be negative.");

                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                var ownerFilterSpecified = (config.OwnerUserIds != null && config.OwnerUserIds.Count > 0) ||
                    (config.Teams != null && config.Teams.Count > 0);
                var effectiveOwnerIds = ResolveOwnerUserIds(config.OwnerUserIds, config.Teams);
                var recordFilterSpecified = vaultRecordUids != null && vaultRecordUids.Count > 0;
                var canUseSharedCache = !ownerFilterSpecified && !recordFilterSpecified;
                var isStale = _storage.IsComplianceDataStale(config.CacheMaxAgeDays);
                var cachedData = _storage.GetComplianceData(null);
                var cacheEmpty = cachedData == null || cachedData.Count == 0;
                Dictionary<string, ComplianceContextInfo> soxData;

                if ((config.NoRebuild && !cacheEmpty) ||
                    (canUseSharedCache && !config.Rebuild && !isStale && !cacheEmpty))
                {
                    Trace.TraceInformation("Using cached compliance data");
                    soxData = cachedData ?? new Dictionary<string, ComplianceContextInfo>();
                }
                else
                {
                    Trace.TraceInformation("Fetching fresh compliance data from API");
                    soxData = ownerFilterSpecified && effectiveOwnerIds.Count == 0
                        ? new Dictionary<string, ComplianceContextInfo>()
                        : await FetchComplianceDataAsync(auth, vaultRecordUids,
                            ownerFilterSpecified ? effectiveOwnerIds : null);

                    if (canUseSharedCache && soxData.Count > 0)
                    {
                        _storage.SaveComplianceData(soxData, now);
                        _storage.UpdateComplianceRefreshTimestamp(now);
                    }
                }

                // Build compliance entries from SOX data
                result.Entries = soxData.Values
                    .Where(sox => !config.SharedRecordsOnly || sox.Shared)
                    .SelectMany(sox =>
                    {
                        var owners = sox.Owners != null && sox.Owners.Count > 0
                            ? sox.Owners
                            : new List<string> { sox.Owner ?? string.Empty };
                        return owners.Select(owner => new ComplianceReportEntry
                        {
                            RecordUid = sox.RecordUid,
                            Title = sox.Title,
                            RecordType = sox.RecordType,
                            Url = sox.Url,
                            Owner = owner,
                            SharedFolderUids = sox.SharedFolderUids?.ToList() ?? new List<string>(),
                            Shared = sox.Shared,
                            InTrash = sox.InTrash,
                            Permissions = sox.Permissions ?? (sox.PermissionBits != 0
                                ? FormatPermissionBits(sox.PermissionBits)
                                : sox.Shared ? "Shared" : "Owner"),
                            PermissionBits = sox.PermissionBits != 0 ? sox.PermissionBits : (sox.Shared ? 2 : 1)
                        });
                    })
                    .ToList();

                if (config.Usernames != null && config.Usernames.Count > 0)
                {
                    var usernameSet = new HashSet<string>(config.Usernames, StringComparer.OrdinalIgnoreCase);
                    result.Entries = result.Entries.Where(e => usernameSet.Contains(e.Owner ?? string.Empty)).ToList();
                }
                if (ownerFilterSpecified)
                {
                    var ownerEmails = new HashSet<string>(
                        effectiveOwnerIds
                            .Where(id => _enterpriseData.TryGetUserById(id, out _))
                            .Select(id =>
                            {
                                _enterpriseData.TryGetUserById(id, out var user);
                                return user.Email;
                            })
                            .Where(email => !string.IsNullOrWhiteSpace(email)),
                        StringComparer.OrdinalIgnoreCase);
                    result.Entries = result.Entries.Where(e => ownerEmails.Contains(e.Owner ?? string.Empty)).ToList();
                }

                if (config.IncludeAging)
                {
                    result.AgingData = await FetchAgingDataAsync(auth, soxData.Keys.ToList());
                    _storage.SaveAgingData(result.AgingData, now);
                    Trace.TraceInformation($"Retrieved aging data for {result.AgingData.Count} records");

                    LinkAgingToComplianceEntries(result.Entries, result.AgingData);
                }

                result.TotalCount = result.Entries.Count;
                result.GeneratedAt = DateTime.UtcNow;

                Trace.TraceInformation($"Generated compliance report with {result.TotalCount} entries");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error generating compliance report: {ex.Message}");
                result.ErrorMessage = $"Error generating compliance report: {ex.Message}";
            }

            return result;
        }

        private List<long> ResolveOwnerUserIds(List<long> ownerUserIds, List<string> teams)
        {
            var resolvedIds = ownerUserIds == null
                ? new HashSet<long>()
                : new HashSet<long>(ownerUserIds);
            var hasOwnerFilter = ownerUserIds != null && ownerUserIds.Count > 0;
            var invalidUserIds = resolvedIds.Where(id => !_enterpriseData.TryGetUserById(id, out _)).ToList();
            if (invalidUserIds.Count > 0)
                throw new ArgumentException($"Unknown enterprise user ID(s): {string.Join(", ", invalidUserIds)}.", nameof(ownerUserIds));

            if (teams != null && teams.Count > 0)
            {
                if (!(_enterpriseData is EnterpriseData enterpriseData))
                    throw new NotSupportedException("Team filters require a concrete EnterpriseData instance.");
                var teamUserIds = new HashSet<long>();
                var teamFilters = teams.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                if (teamFilters.Count == 0)
                    throw new ArgumentException("Team filters cannot be empty.", nameof(teams));
                foreach (var teamNameOrUid in teamFilters)
                {
                    var matches = _enterpriseData.Teams.Where(team =>
                        string.Equals(team.Uid, teamNameOrUid, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(team.Name, teamNameOrUid, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (matches.Count != 1)
                        throw new ArgumentException(matches.Count == 0
                            ? $"Team '{teamNameOrUid}' was not found."
                            : $"Team name '{teamNameOrUid}' is ambiguous; use its UID.", nameof(teams));
                    teamUserIds.UnionWith(enterpriseData.GetUsersForTeam(matches[0].Uid));
                }

                resolvedIds = hasOwnerFilter
                    ? new HashSet<long>(resolvedIds.Where(teamUserIds.Contains))
                    : teamUserIds;
            }

            return resolvedIds.ToList();
        }

        private static string FormatPermissionBits(int permissionBits)
        {
            var permissions = new List<string>();
            if ((permissionBits & 1) != 0) permissions.Add("owner");
            if ((permissionBits & 2) != 0) permissions.Add("mask");
            if ((permissionBits & 4) != 0) permissions.Add("edit");
            if ((permissionBits & 8) != 0) permissions.Add("share");
            if ((permissionBits & 16) != 0) permissions.Add("share_admin");
            return permissions.Count > 0 ? string.Join(",", permissions) : "read-only";
        }

        /// <summary>
        /// Fetch compliance/SOX data from Server 
        /// </summary>
        private async Task<Dictionary<string, ComplianceContextInfo>> FetchComplianceDataAsync(
            IAuthentication auth,
            List<string> recordUids,
            List<long> ownerUserIds)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            if (_enterpriseData?.Users == null)
                throw new InvalidOperationException("Enterprise users must be loaded before generating a compliance report.");

            var requestedUsers = ownerUserIds != null && ownerUserIds.Count > 0
                ? ownerUserIds.Distinct().ToList()
                : _enterpriseData.Users.Select(u => u.Id).Distinct().ToList();
            var invalidUserIds = requestedUsers
                .Where(id => !_enterpriseData.TryGetUserById(id, out _))
                .ToList();
            if (invalidUserIds.Count > 0)
                throw new ArgumentException($"Unknown enterprise user ID(s): {string.Join(", ", invalidUserIds)}.", nameof(ownerUserIds));
            var soxData = await FetchPreliminaryComplianceDataAsync(auth, requestedUsers);
            if (soxData.Count == 0)
            {
                return soxData;
            }

            var selectedRecordUids = recordUids != null && recordUids.Count > 0
                ? soxData.Keys.Intersect(recordUids, StringComparer.Ordinal).ToList()
                : soxData.Keys.ToList();
            const int apiMaxRecordsPerRequest = 1000;
            const int apiMaxUsersPerRequest = 5000;
            var nodeId = _enterpriseData.RootNode?.Id ?? 0;

            for (var offset = 0; offset < selectedRecordUids.Count; offset += apiMaxRecordsPerRequest)
            {
                var batch = selectedRecordUids.Skip(offset).Take(apiMaxRecordsPerRequest).ToList();
                var batchUsers = batch
                    .Where(soxData.ContainsKey)
                    .SelectMany(uid => soxData[uid].Owners ?? new List<string>())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(email => _enterpriseData.TryGetUserByEmail(email, out var user) ? user.Id : 0)
                    .Where(id => id > 0)
                    .Distinct()
                    .ToList();
                if (batchUsers.Count == 0)
                    batchUsers = requestedUsers;

                for (var userOffset = 0; userOffset < batchUsers.Count; userOffset += apiMaxUsersPerRequest)
                {
                    var userBatch = batchUsers.Skip(userOffset).Take(apiMaxUsersPerRequest).ToList();
                    var reportRun = new ComplianceReportRun
                    {
                        ReportCriteriaAndFilter = new ComplianceReportCriteriaAndFilter
                        {
                            Criteria = new ComplianceReportCriteria { IncludeNonShared = true },
                            NodeId = nodeId
                        }
                    };
                    reportRun.Users.AddRange(userBatch);

                    foreach (var uid in batch)
                    {
                        var uidBytes = CryptoUtils.Base64UrlDecode(uid);
                        reportRun.Records.Add(Google.Protobuf.ByteString.CopyFrom(uidBytes));
                    }

                    var request = new ComplianceReportRequest
                    {
                        SaveReport = false,
                        ReportName = $"Compliance Report on {DateTime.UtcNow:O}",
                        ComplianceReportRun = reportRun
                    };
                    var response = await auth.ExecuteAuthRest<ComplianceReportRequest, ComplianceReportResponse>(
                        "enterprise/run_compliance_report", request);
                    if (response == null)
                        throw new InvalidOperationException("Compliance report endpoint returned an empty response.");

                    foreach (var auditRecord in response.AuditRecords)
                    {
                        var uid = CryptoUtils.Base64UrlEncode(auditRecord.RecordUid.ToByteArray());
                        if (!soxData.TryGetValue(uid, out var info))
                        {
                            info = new ComplianceContextInfo { RecordUid = uid };
                            soxData[uid] = info;
                        }
                        info.InTrash = auditRecord.InTrash;
                    }

                    foreach (var sfRecord in response.SharedFolderRecords)
                    {
                    var folderUid = CryptoUtils.Base64UrlEncode(sfRecord.SharedFolderUid.ToByteArray());
                        foreach (var recPerm in sfRecord.RecordPermissions)
                        {
                        if (recPerm.RecordUid == null || recPerm.RecordUid.IsEmpty)
                            continue;
                            var uid = CryptoUtils.Base64UrlEncode(recPerm.RecordUid.ToByteArray());
                            if (!soxData.TryGetValue(uid, out var info))
                            {
                                info = new ComplianceContextInfo { RecordUid = uid };
                                soxData[uid] = info;
                            }
                            info.Shared = true;
                        if (!string.IsNullOrWhiteSpace(folderUid) &&
                            !info.SharedFolderUids.Contains(folderUid, StringComparer.Ordinal))
                            info.SharedFolderUids.Add(folderUid);
                        if (recPerm.HasPermissionBits)
                            info.PermissionBits |= recPerm.PermissionBits;
                        }
                    }
                }
            }
            return soxData;
        }

        /// <summary>
        /// Fetch preliminary compliance data from API (all enterprise records)
        /// Returns list of record UIDs (in bytes format) to pass to compliance report
        /// </summary>
        private async Task<Dictionary<string, ComplianceContextInfo>> FetchPreliminaryComplianceDataAsync(
            IAuthentication auth,
            List<long> userIds)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            var records = new Dictionary<string, ComplianceContextInfo>(StringComparer.Ordinal);
            if (userIds == null || userIds.Count == 0)
            {
                return records;
            }

            const int userBatchSize = 5;
            for (var userOffset = 0; userOffset < userIds.Count; userOffset += userBatchSize)
            {
                var userBatch = userIds.Skip(userOffset).Take(userBatchSize).ToList();
                var continuationToken = Google.Protobuf.ByteString.Empty;
                var seenTokens = new HashSet<string>(StringComparer.Ordinal);

                while (true)
                {
                    var request = new PreliminaryComplianceDataRequest
                    {
                        IncludeNonShared = true,
                        IncludeTotalMatchingRecordsInFirstResponse = continuationToken.IsEmpty,
                        ContinuationToken = continuationToken
                    };
                    request.EnterpriseUserIds.AddRange(userBatch);
                    var response = await auth.ExecuteAuthRest<PreliminaryComplianceDataRequest, PreliminaryComplianceDataResponse>(
                        "enterprise/get_preliminary_compliance_data", request);
                    if (response == null)
                        throw new InvalidOperationException("Preliminary compliance endpoint returned an empty response.");

                    foreach (var userData in response.AuditUserData)
                    {
                        var owner = _enterpriseData.TryGetUserById(userData.EnterpriseUserId, out var enterpriseUser)
                            ? enterpriseUser.Email
                            : null;

                        foreach (var record in userData.AuditUserRecords)
                        {
                            if (record.RecordUid == null || record.RecordUid.IsEmpty)
                                continue;
                            var uid = CryptoUtils.Base64UrlEncode(record.RecordUid.ToByteArray());
                            if (!records.TryGetValue(uid, out var info))
                            {
                                info = new ComplianceContextInfo { RecordUid = uid };
                                records.Add(uid, info);
                            }

                            info.Shared |= record.Shared;
                            if (!string.IsNullOrWhiteSpace(owner))
                            {
                                if (!info.Owners.Contains(owner, StringComparer.OrdinalIgnoreCase))
                                    info.Owners.Add(owner);
                                info.Owner ??= owner;
                            }

                            if (record.EncryptedData != null && !record.EncryptedData.IsEmpty && _enterpriseEcPrivateKey != null)
                            {
                                try
                                {
                                    var json = CryptoUtils.DecryptEc(record.EncryptedData.ToByteArray(), _enterpriseEcPrivateKey);
                                    var fields = JsonUtils.ParseJson<Dictionary<string, object>>(json);
                                    info.Title ??= GetMetadataString(fields, "title");
                                    info.RecordType ??= GetMetadataString(fields, "record_type");
                                    info.Url ??= GetMetadataString(fields, "url");
                                }
                                catch (Exception ex)
                                {
                                    Trace.TraceWarning($"Could not decrypt compliance metadata for record {uid}: {ex.Message}");
                                }
                            }
                        }
                    }

                    if (!response.HasMore)
                        break;

                    if (response.ContinuationToken == null || response.ContinuationToken.IsEmpty)
                        throw new InvalidOperationException("Preliminary compliance response indicated more data without a continuation token.");
                    var nextToken = Convert.ToBase64String(response.ContinuationToken.ToByteArray());
                    if (!seenTokens.Add(nextToken))
                        throw new InvalidOperationException("Preliminary compliance API repeated a continuation token.");
                    continuationToken = response.ContinuationToken;
                }
            }

            return records;
        }

        private static string GetMetadataString(Dictionary<string, object> fields, string name)
        {
            if (fields == null) return null;
            var pair = fields.FirstOrDefault(x => string.Equals(x.Key, name, StringComparison.OrdinalIgnoreCase));
            return pair.Value?.ToString();
        }

        /// <summary>
        /// Fetch audit events from API
        /// Handles pagination if result set exceeds limit
        /// Applies all filters from config
        /// </summary>
        private async Task<List<AuditReportEntry>> FetchAuditEventsAsync(
            IAuthentication auth,
            AuditReportConfig config)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            if (config == null) throw new ArgumentNullException(nameof(config));
            var events = new List<AuditReportEntry>();
            if (config.Limit <= 0) throw new ArgumentOutOfRangeException(nameof(config.Limit), "Limit must be greater than zero.");
            if (!string.Equals(config.ReportType ?? "raw", "raw", StringComparison.OrdinalIgnoreCase))
                throw new NotSupportedException("The reporting plugin currently supports raw audit event reports only.");
            if ((config.Columns?.Count > 0) || (config.Aggregate?.Count > 0))
                throw new NotSupportedException("Custom audit columns and aggregates are not supported by the enriched raw report path.");
            if (string.Equals(config.Order, "asc", StringComparison.OrdinalIgnoreCase) && config.Limit > ApiRawEventRowLimit)
                throw new NotSupportedException("Ascending audit reports are limited to one API page.");

            var usernameFilter = config.Usernames?.Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (config.UserIds != null && config.UserIds.Count > 0)
            {
                var usersById = config.UserIds.Distinct().Select(id =>
                {
                    if (!_enterpriseData.TryGetUserById(id, out var user))
                        throw new ArgumentException($"Unknown enterprise user ID: {id}.", nameof(config.UserIds));
                    return user.Email;
                }).Where(email => !string.IsNullOrWhiteSpace(email)).ToList();
                usernameFilter = usernameFilter == null
                    ? usersById
                    : usernameFilter.Where(name => usersById.Contains(name, StringComparer.OrdinalIgnoreCase))
                        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (usernameFilter.Count == 0)
                    return events;
            }

            var initialCreatedFilter = config.CreatedFilter as CreatedFilter;
            var startTime = initialCreatedFilter?.Min ??
                (config.StartDate.HasValue ? new DateTimeOffset(config.StartDate.Value).ToUnixTimeSeconds() : (long?)null);
            var currentEndTime = initialCreatedFilter?.Max ??
                (config.EndDate.HasValue ? new DateTimeOffset(config.EndDate.Value).ToUnixTimeSeconds() : (long?)null);
            if (startTime.HasValue && currentEndTime.HasValue && startTime.Value > currentEndTime.Value)
                throw new ArgumentException("The audit report start time must not be later than its end time.", nameof(config));
            if (initialCreatedFilter?.Min.HasValue == true && initialCreatedFilter.Max.HasValue &&
                initialCreatedFilter.Min.Value > initialCreatedFilter.Max.Value)
                throw new ArgumentException("The audit report created filter has an invalid time range.", nameof(config));
            var predefinedCreatedFilter = config.CreatedFilter != null && initialCreatedFilter == null;

            while (events.Count < config.Limit)
            {
                var filter = new ReportFilter
                {
                    RecordUid = config.RecordUids?.Count > 0 ? config.RecordUids.ToArray() : null,
                    EventTypes = config.EventTypes?.Count > 0 ? config.EventTypes.ToArray() : null,
                    Username = usernameFilter?.Count > 0 ? usernameFilter.ToArray() : null,
                    ToUsername = !string.IsNullOrEmpty(config.ToUsername) ? new[] { config.ToUsername } : null,
                    IpAddress = config.IpAddresses?.Count > 0 ? config.IpAddresses.ToArray() : null,
                    SharedFolderUid = config.SharedFolderUids?.Count > 0 ? config.SharedFolderUids.ToArray() : null,
                    NodeId = config.NodeIds?.Count > 0 ? config.NodeIds.ToArray() : null
                };

                if (predefinedCreatedFilter)
                {
                    filter.Created = config.CreatedFilter;
                }
                else if (startTime.HasValue || currentEndTime.HasValue)
                {
                    var created = initialCreatedFilter == null ? new CreatedFilter() : new CreatedFilter
                    {
                        ExcludeMin = initialCreatedFilter.ExcludeMin,
                        ExcludeMax = initialCreatedFilter.ExcludeMax
                    };
                    created.Min = startTime;
                    created.Max = currentEndTime;
                    filter.Created = created;
                }

                var requestLimit = Math.Min(ApiRawEventRowLimit, config.Limit - events.Count);
                var command = new GetAuditEventReportsCommand
                {
                    Filter = filter,
                    Limit = requestLimit,
                    Order = string.Equals(config.Order, "asc", StringComparison.OrdinalIgnoreCase) ? "ascending" : "descending",
                    ReportType = config.ReportType ?? "raw",
                    Columns = config.Columns?.Count > 0 ? config.Columns.ToArray() : null,
                    Aggregate = config.Aggregate?.Count > 0 ? config.Aggregate.ToArray() : null
                };
                var response = await auth.ExecuteAuthCommand<GetAuditEventReportsCommand, GetAuditEventReportsResponse>(command);
                var rows = response?.Events ?? new List<Dictionary<string, object>>();

                // If the endpoint filled a page, defer its oldest timestamp group to the
                // following page. This prevents splitting events with the same second.
                var rowsToProcess = rows;
                long? nextEndTime = null;
                if (!predefinedCreatedFilter && rows.Count >= requestLimit &&
                    config.Limit - events.Count > requestLimit)
                {
                    var oldest = TryGetUnixTime(rows.LastOrDefault(), "created");
                    if (oldest.HasValue)
                    {
                        var boundaryIndex = rows.Count - 1;
                        while (boundaryIndex > 0 &&
                               TryGetUnixTime(rows[boundaryIndex - 1], "created") == oldest)
                            boundaryIndex--;

                        if (boundaryIndex == 0)
                            throw new InvalidOperationException("Audit report pagination cannot continue because the entire page has the same event timestamp.");

                        rowsToProcess = rows.Take(boundaryIndex).ToList();
                        nextEndTime = oldest.Value + 1;
                    }
                }

                foreach (var row in rowsToProcess)
                {
                    if (events.Count >= config.Limit) break;
                    if (!row.ContainsKey("created"))
                        throw new InvalidOperationException("Audit report row is missing the required 'created' timestamp.");
                    events.Add(new AuditReportEntry
                    {
                        EventType = ExtractString(row, "audit_event_type"),
                        EventTime = ExtractDateTime(row, "created"),
                        Username = ExtractString(row, "username"),
                        UserId = ExtractLong(row, "user_id"),
                        IpAddress = ExtractString(row, "ip_address"),
                        GeoLocation = ExtractString(row, "geo_location"),
                        ClientType = ExtractString(row, "client_type"),
                        RecordUid = ExtractString(row, "record_uid"),
                        RecordTitle = ExtractString(row, "record_title"),
                        Details = row.ToDictionary(x => x.Key, x => x.Value)
                    });
                }

                if (predefinedCreatedFilter && rows.Count >= requestLimit && events.Count < config.Limit)
                    throw new InvalidOperationException("The requested predefined date filter returned a full API page; use a bounded time range to page results.");
                if (rows.Count < requestLimit || events.Count >= config.Limit || predefinedCreatedFilter || !nextEndTime.HasValue)
                    break;
                if (currentEndTime.HasValue && nextEndTime.Value >= currentEndTime.Value)
                    throw new InvalidOperationException("Audit report pagination did not advance its time cursor.");
                currentEndTime = nextEndTime;
            }

            return events;
        }

        private static string ExtractString(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value) && value != null)
                return value.ToString();
            return "";
        }

        private static long ExtractLong(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value) && value != null &&
                long.TryParse(value.ToString(), System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out var result))
            {
                return result;
            }
            return 0;
        }

        private static DateTime ExtractDateTime(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var value) && value != null)
            {
                if (long.TryParse(value.ToString(), System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out var unixTime))
                {
                    return DateTimeOffset.FromUnixTimeSeconds(unixTime).UtcDateTime;
                }
                if (DateTimeOffset.TryParse(value.ToString(), System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var dateTime))
                    return dateTime.UtcDateTime;
            }
            throw new FormatException($"Audit report row contains an invalid '{key}' timestamp.");
        }

        private static long? TryGetUnixTime(Dictionary<string, object> row, string key)
        {
            if (row != null && row.TryGetValue(key, out var value) &&
                long.TryParse(value?.ToString(), System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out var unixTime))
                return unixTime;
            return null;
        }

        /// <summary>
        /// Link aging data to compliance report entries
        /// </summary>
        private void LinkAgingToComplianceEntries(
            List<ComplianceReportEntry> entries,
            Dictionary<string, RecordAgingInfo> agingData)
        {
            foreach (var entry in entries)
            {
                if (agingData.TryGetValue(entry.RecordUid, out var aging))
                {
                    if (aging.CreatedDate.HasValue)
                        entry.Created = aging.CreatedDate.Value;
                    if (aging.LastPasswordChangeDate.HasValue)
                        entry.LastPasswordChange = aging.LastPasswordChangeDate.Value;
                    if (aging.LastModifiedDate.HasValue)
                        entry.LastModified = aging.LastModifiedDate.Value;
                    if (aging.LastRotationDate.HasValue)
                        entry.LastRotation = aging.LastRotationDate.Value;
                }
            }
        }

        private async Task<Dictionary<string, RecordAgingInfo>> FetchAgingDataAsync(
            IAuthentication auth,
            List<string> recordUids)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            var result = new Dictionary<string, RecordAgingInfo>(StringComparer.Ordinal);
            if (recordUids == null || recordUids.Count == 0) return result;

            const int recordBatchSize = 1000;
            foreach (var batch in recordUids.Distinct(StringComparer.Ordinal)
                         .Select((uid, index) => new { uid, index })
                         .GroupBy(x => x.index / recordBatchSize)
                         .Select(g => g.Select(x => x.uid).ToArray()))
            {
                var created = await FetchAuditAggregateAsync(auth, batch, "first_created", null);
                var modified = await FetchAuditAggregateAsync(auth, batch, "last_created", new[] { "record_update" });
                var passwordChanges = await FetchAuditAggregateAsync(auth, batch, "last_created", new[] { "record_password_change" });
                var passwordCounts = await FetchAuditAggregateAsync(auth, batch, "occurrences", new[] { "record_password_change" });
                var rotations = await FetchAuditAggregateAsync(auth, batch,
                    "last_created", new[] { "record_rotation_scheduled_ok", "record_rotation_on_demand_ok" });

                foreach (var uid in batch)
                {
                    var aging = new RecordAgingInfo { RecordUid = uid };
                    aging.CreatedDate = GetAggregateDate(created, uid, "first_created");
                    aging.LastModifiedDate = GetAggregateDate(modified, uid, "last_created");
                    aging.LastRotationDate = GetAggregateDate(rotations, uid, "last_created");
                    var passwordCount = GetAggregateLong(passwordCounts, uid, "occurrences");
                    aging.PasswordChangeCount = (int)Math.Max(0, passwordCount - 1);
                    if (passwordCount > 1)
                        aging.LastPasswordChangeDate = GetAggregateDate(passwordChanges, uid, "last_created");
                    if (aging.LastRotationDate.HasValue &&
                        (!aging.LastPasswordChangeDate.HasValue || aging.LastRotationDate > aging.LastPasswordChangeDate))
                        aging.LastPasswordChangeDate = aging.LastRotationDate;
                    result[uid] = aging;
                }
            }

            return result;
        }

        private static async Task<Dictionary<string, Dictionary<string, object>>> FetchAuditAggregateAsync(
            IAuthentication auth,
            string[] recordUids,
            string aggregate,
            string[] eventTypes)
        {
            var result = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
            var filter = new ReportFilter { RecordUid = recordUids };
            if (eventTypes != null && eventTypes.Length > 0)
                filter.EventTypes = eventTypes;
            var command = new GetAuditEventReportsCommand
            {
                Filter = filter,
                ReportType = "span",
                Columns = new[] { "record_uid" },
                Aggregate = new[] { aggregate },
                Order = "descending",
                Limit = 2000
            };
            var response = await auth.ExecuteAuthCommand<GetAuditEventReportsCommand, GetAuditEventReportsResponse>(command);
            if (response == null)
                throw new InvalidOperationException("Audit aging endpoint returned an empty response.");
            foreach (var row in response.Events ?? new List<Dictionary<string, object>>())
            {
                var uid = ExtractString(row, "record_uid");
                if (!string.IsNullOrWhiteSpace(uid))
                    result[uid] = row;
            }
            return result;
        }

        private static DateTime? GetAggregateDate(
            Dictionary<string, Dictionary<string, object>> data,
            string recordUid,
            string field)
        {
            if (data != null && data.TryGetValue(recordUid, out var row) &&
                long.TryParse(ExtractString(row, field), out var value) && value > 0)
                return DateTimeOffset.FromUnixTimeSeconds(value).UtcDateTime;
            return null;
        }

        private static long GetAggregateLong(
            Dictionary<string, Dictionary<string, object>> data,
            string recordUid,
            string field)
        {
            if (data != null && data.TryGetValue(recordUid, out var row))
                return ExtractLong(row, field);
            return 0;
        }
    }
}
