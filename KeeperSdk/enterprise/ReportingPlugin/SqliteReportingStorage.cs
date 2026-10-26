using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using KeeperSecurity.Compliance;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise.ReportingPlugin
{
    /// <summary>
    /// SQLite implementation of reporting storage
    /// Persists compliance data, audit events, and aging information for offline access
    /// </summary>
    public class SqliteReportingStorage : IReportingStorage
    {
        private readonly SqlComplianceStorage _sqlStorage;

        public SqliteReportingStorage(SqlComplianceStorage sqlStorage)
        {
            _sqlStorage = sqlStorage ?? throw new ArgumentNullException(nameof(sqlStorage));
        }

        public static void VerifyDatabase(DbConnection connection, ISqlDialect dialect)
        {
            SqlComplianceStorage.VerifyDatabase(connection, dialect);
        }

        public void SaveComplianceData(Dictionary<string, ComplianceContextInfo> data, long timestamp)
        {
            if (data == null)
            {
                return;
            }

            try
            {
                var existingRecords = _sqlStorage.Records.GetAll()
                    .Where(record => !string.IsNullOrWhiteSpace(record.RecordUid))
                    .ToDictionary(record => record.RecordUid, StringComparer.Ordinal);
               
                var complianceRecords = data.Values
                    .Where(sox => !string.IsNullOrWhiteSpace(sox.RecordUid))
                    .Select(sox =>
                    {
                        existingRecords.TryGetValue(sox.RecordUid, out var existing);
                        var metadata = new Dictionary<string, object>
                        {
                            ["title"] = sox.Title ?? string.Empty,
                            ["record_type"] = sox.RecordType ?? string.Empty,
                            ["url"] = sox.Url ?? string.Empty,
                            ["owners"] = sox.Owners ?? new List<string>(),
                            ["shared_folder_uids"] = sox.SharedFolderUids ?? new List<string>(),
                            ["permissions"] = sox.Permissions ?? string.Empty,
                            ["permission_bits"] = sox.PermissionBits
                        };
                        return new ComplianceRecord
                        {
                            RecordUid = sox.RecordUid,
                            RecordUidBytes = CryptoUtils.Base64UrlDecode(sox.RecordUid),
                            EncryptedData = JsonUtils.DumpJson(metadata, true),
                            Shared = sox.Shared,
                            InTrash = sox.InTrash,
                            HasAttachments = existing?.HasAttachments ?? false,
                            LastComplianceRefreshed = timestamp
                        };
                    })
                    .ToList();

                if (complianceRecords.Count > 0)
                {
                    var incomingUids = new HashSet<string>(complianceRecords.Select(x => x.RecordUid), StringComparer.Ordinal);
                    var staleUids = existingRecords.Keys
                        .Where(uid => !incomingUids.Contains(uid))
                        .ToList();
                    _sqlStorage.Records.PutEntities(complianceRecords);
                    if (staleUids.Count > 0)
                        _sqlStorage.Records.DeleteUids(staleUids);
                    Trace.TraceInformation($"Saved {complianceRecords.Count} compliance records to SQLite");
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error saving compliance data: {ex.Message}");
                throw;
            }
        }

        public void SaveAgingData(Dictionary<string, RecordAgingInfo> agingData, long timestamp)
        {
            if (agingData == null || agingData.Count == 0)
                return;

            try
            {
                var agingRecords = agingData.Values
                    .Select(aging => new ComplianceRecordAging
                    {
                        RecordUid = aging.RecordUid,
                        Created = aging.CreatedDate.HasValue
                            ? (long)(aging.CreatedDate.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                            : 0,
                        LastPwChange = aging.LastPasswordChangeDate.HasValue
                            ? (long)(aging.LastPasswordChangeDate.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                            : 0,
                        LastModified = aging.LastModifiedDate.HasValue
                            ? (long)(aging.LastModifiedDate.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                            : 0,
                        LastRotation = aging.LastRotationDate.HasValue
                            ? (long)(aging.LastRotationDate.Value - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
                            : 0,
                        LastCached = timestamp
                    })
                    .ToList();

                if (agingRecords.Count > 0)
                {
                    _sqlStorage.RecordAging.PutEntities(agingRecords);
                    Trace.TraceInformation($"Saved {agingRecords.Count} aging records to SQLite");
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error saving aging data: {ex.Message}");
                throw;
            }
        }

        public Dictionary<string, ComplianceContextInfo> GetComplianceData(List<string> recordUids)
        {
            var result = new Dictionary<string, ComplianceContextInfo>();

            try
            {
                var uidsSet = recordUids != null && recordUids.Count > 0
                    ? new HashSet<string>(recordUids)
                    : null;

                var records = _sqlStorage.Records.GetAll().ToList();
                foreach (var record in records)
                {
                    if (uidsSet != null && !uidsSet.Contains(record.RecordUid))
                        continue;

                    result[record.RecordUid] = new ComplianceContextInfo
                    {
                        RecordUid = record.RecordUid,
                        Shared = record.Shared,
                        InTrash = record.InTrash
                    };
                    if (record.EncryptedData != null && record.EncryptedData.Length > 0)
                    {
                        var metadata = JsonUtils.ParseJson<Dictionary<string, object>>(record.EncryptedData);
                        result[record.RecordUid].Title = GetMetadataString(metadata, "title");
                        result[record.RecordUid].RecordType =
                            GetMetadataString(metadata, "record_type") ?? GetMetadataString(metadata, "type");
                        result[record.RecordUid].Url = GetMetadataString(metadata, "url");
                        result[record.RecordUid].Owner = GetMetadataString(metadata, "owner");
                        result[record.RecordUid].Permissions = GetMetadataString(metadata, "permissions");
                        result[record.RecordUid].PermissionBits = GetMetadataInt(metadata, "permission_bits");
                        var owners = metadata?.FirstOrDefault(x =>
                            string.Equals(x.Key, "owners", StringComparison.OrdinalIgnoreCase)).Value as IEnumerable<object>;
                        if (owners != null)
                            result[record.RecordUid].Owners = owners.Select(x => x?.ToString()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                        else if (!string.IsNullOrWhiteSpace(result[record.RecordUid].Owner))
                            result[record.RecordUid].Owners.Add(result[record.RecordUid].Owner);
                        var sharedFolders = metadata?.FirstOrDefault(x =>
                            string.Equals(x.Key, "shared_folder_uids", StringComparison.OrdinalIgnoreCase)).Value as IEnumerable<object>;
                        if (sharedFolders != null)
                            result[record.RecordUid].SharedFolderUids = sharedFolders.Select(x => x?.ToString())
                                .Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                    }
                }

                Trace.TraceInformation($"Retrieved {result.Count} compliance records from SQLite");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error retrieving compliance data: {ex.Message}");
                throw;
            }

            return result;
        }

        private static string GetMetadataString(Dictionary<string, object> metadata, string name)
        {
            if (metadata == null) return null;
            var pair = metadata.FirstOrDefault(x => string.Equals(x.Key, name, StringComparison.OrdinalIgnoreCase));
            return pair.Value?.ToString();
        }

        private static int GetMetadataInt(Dictionary<string, object> metadata, string name)
        {
            if (metadata == null) return 0;
            var pair = metadata.FirstOrDefault(x => string.Equals(x.Key, name, StringComparison.OrdinalIgnoreCase));
            return int.TryParse(pair.Value?.ToString(), out var value) ? value : 0;
        }

        public Dictionary<string, RecordAgingInfo> GetAgingData(List<string> recordUids)
        {
            var result = new Dictionary<string, RecordAgingInfo>();

            try
            {
                var uidsSet = recordUids != null && recordUids.Count > 0
                    ? new HashSet<string>(recordUids)
                    : null;

                var agingRecords = _sqlStorage.RecordAging.GetAll().ToList();

                foreach (var record in agingRecords)
                {
                    if (uidsSet != null && !uidsSet.Contains(record.RecordUid))
                        continue;

                    var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

                    result[record.RecordUid] = new RecordAgingInfo
                    {
                        RecordUid = record.RecordUid,
                        CreatedDate = record.Created > 0
                            ? epoch.AddSeconds(record.Created)
                            : (DateTime?)null,
                        LastPasswordChangeDate = record.LastPwChange > 0
                            ? epoch.AddSeconds(record.LastPwChange)
                            : (DateTime?)null,
                        LastModifiedDate = record.LastModified > 0
                            ? epoch.AddSeconds(record.LastModified)
                            : (DateTime?)null,
                        LastRotationDate = record.LastRotation > 0
                            ? epoch.AddSeconds(record.LastRotation)
                            : (DateTime?)null
                    };
                }

                Trace.TraceInformation($"Retrieved {result.Count} aging records from SQLite");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error retrieving aging data: {ex.Message}");
                throw;
            }

            return result;
        }

        public bool IsComplianceDataStale(int maxAgeDays = 1)
        {
            try
            {
                var metadata = _sqlStorage.Metadata.Load();
                if (metadata == null || metadata.ComplianceDataLastUpdate == 0)
                {
                    return true;
                }

                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var maxAge = maxAgeDays * 24 * 3600;
                var age = now - metadata.ComplianceDataLastUpdate;
                var isStale = age > maxAge;

                return isStale;
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error checking compliance data staleness: {ex.Message}");
                return true;
            }
        }

        public long? GetLastComplianceRefresh()
        {
            try
            {
                var metadata = _sqlStorage.Metadata.Load();
                return metadata?.ComplianceDataLastUpdate > 0 ? metadata.ComplianceDataLastUpdate : (long?)null;
            }
            catch
            {
                return null;
            }
        }

        public void UpdateComplianceRefreshTimestamp(long timestamp)
        {
            try
            {
                var metadata = _sqlStorage.Metadata.Load() ?? new ComplianceMetadata();
                metadata.ComplianceDataLastUpdate = timestamp;
                _sqlStorage.Metadata.Store(metadata);
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error updating compliance refresh timestamp: {ex.Message}");
                throw;
            }
        }

        public void ClearComplianceData()
        {
            try
            {
                _sqlStorage.ClearNonAgingData();
                Trace.TraceInformation("Cleared compliance data from SQLite");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error clearing compliance data: {ex.Message}");
            }
        }

        public void ClearAgingData()
        {
            try
            {
                _sqlStorage.ClearAgingData();
                Trace.TraceInformation("Cleared aging data from SQLite");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error clearing aging data: {ex.Message}");
            }
        }

        public void ClearAll()
        {
            try
            {
                ClearComplianceData();
                ClearAgingData();
                Trace.TraceInformation("Cleared all data from SQLite");
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error clearing all data: {ex.Message}");
            }
        }
    }
}
