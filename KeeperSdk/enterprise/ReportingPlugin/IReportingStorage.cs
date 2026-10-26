using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace KeeperSecurity.Enterprise.ReportingPlugin
{
    /// <summary>
    /// Storage interface for caching report data (SOX, audit events, etc.)
    /// Abstracts SQLite persistence - allows memory/disk interchangeability
    /// </summary>
    public interface IReportingStorage
    {
        /// <summary>
        /// Save compliance/SOX data to storage
        /// </summary>
        void SaveComplianceData(Dictionary<string, ComplianceContextInfo> data, long timestamp);

        /// <summary>
        /// Save aging data to storage
        /// </summary>
        void SaveAgingData(Dictionary<string, RecordAgingInfo> agingData, long timestamp);

        /// <summary>
        /// Get cached SOX compliance data for specific records
        /// </summary>
        Dictionary<string, ComplianceContextInfo> GetComplianceData(List<string> recordUids);

        /// <summary>
        /// Get cached audit events for specific records
        /// </summary>
        List<AuditReportEntry> GetAuditEvents(List<string> recordUids);

        /// <summary>
        /// Get cached aging data for specific records
        /// </summary>
        Dictionary<string, RecordAgingInfo> GetAgingData(List<string> recordUids);

        /// <summary>
        /// Check if compliance data is stale and needs refresh
        /// </summary>
        bool IsComplianceDataStale(int maxAgeDays = 1);

        /// <summary>
        /// Check if audit events are stale and need refresh
        /// </summary>
        bool IsAuditEventStale(int maxAgeDays = 1);

        /// <summary>
        /// Get the last time compliance data was refreshed
        /// </summary>
        long? GetLastComplianceRefresh();

        /// <summary>
        /// Get the last time audit events were refreshed
        /// </summary>
        long? GetLastAuditRefresh();

        /// <summary>
        /// Update metadata timestamp for compliance data
        /// </summary>
        void UpdateComplianceRefreshTimestamp(long timestamp);

        /// <summary>
        /// Update metadata timestamp for audit events
        /// </summary>
        void UpdateAuditRefreshTimestamp(long timestamp);

        /// <summary>
        /// Clear cached compliance data (but keep aging)
        /// </summary>
        void ClearComplianceData();

        /// <summary>
        /// Clear cached aging data
        /// </summary>
        void ClearAgingData();

        /// <summary>
        /// Clear all cached data
        /// </summary>
        void ClearAll();
    }

    /// <summary>
    /// In-memory implementation of reporting storage (for testing)
    /// </summary>
    public class InMemoryReportingStorage : IReportingStorage
    {
        private Dictionary<string, ComplianceContextInfo> _complianceData = new();
        private List<AuditReportEntry> _auditEvents = new();
        private Dictionary<string, RecordAgingInfo> _agingData = new();
        private long? _lastComplianceRefresh;
        private long? _lastAuditRefresh;

        public void SaveComplianceData(Dictionary<string, ComplianceContextInfo> data, long timestamp)
        {
            _complianceData = data ?? new();
            _lastComplianceRefresh = timestamp;
        }

        public void SaveAgingData(Dictionary<string, RecordAgingInfo> agingData, long timestamp)
        {
            _agingData = agingData ?? new();
        }

        public Dictionary<string, ComplianceContextInfo> GetComplianceData(List<string> recordUids)
        {
            if (recordUids == null || recordUids.Count == 0)
                return _complianceData;

            var result = new Dictionary<string, ComplianceContextInfo>();
            foreach (var uid in recordUids)
            {
                if (_complianceData.TryGetValue(uid, out var data))
                    result[uid] = data;
            }
            return result;
        }

        public List<AuditReportEntry> GetAuditEvents(List<string> recordUids)
        {
            if (recordUids == null || recordUids.Count == 0)
                return _auditEvents;

            var uidsSet = new HashSet<string>(recordUids);
            return _auditEvents.FindAll(e => uidsSet.Contains(e.RecordUid));
        }

        public Dictionary<string, RecordAgingInfo> GetAgingData(List<string> recordUids)
        {
            if (recordUids == null || recordUids.Count == 0)
                return _agingData;

            var result = new Dictionary<string, RecordAgingInfo>();
            foreach (var uid in recordUids)
            {
                if (_agingData.TryGetValue(uid, out var data))
                    result[uid] = data;
            }
            return result;
        }

        public bool IsComplianceDataStale(int maxAgeDays = 1)
        {
            if (!_lastComplianceRefresh.HasValue)
                return true;

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var maxAge = maxAgeDays * 24 * 3600;
            return (now - _lastComplianceRefresh.Value) > maxAge;
        }

        public bool IsAuditEventStale(int maxAgeDays = 1)
        {
            if (!_lastAuditRefresh.HasValue)
                return true;

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var maxAge = maxAgeDays * 24 * 3600;
            return (now - _lastAuditRefresh.Value) > maxAge;
        }

        public long? GetLastComplianceRefresh() => _lastComplianceRefresh;
        public long? GetLastAuditRefresh() => _lastAuditRefresh;

        public void UpdateComplianceRefreshTimestamp(long timestamp)
        {
            _lastComplianceRefresh = timestamp;
        }

        public void UpdateAuditRefreshTimestamp(long timestamp)
        {
            _lastAuditRefresh = timestamp;
        }

        public void ClearComplianceData() => _complianceData.Clear();
        public void ClearAgingData() => _agingData.Clear();

        public void ClearAll()
        {
            ClearComplianceData();
            ClearAgingData();
            _lastComplianceRefresh = null;
            _lastAuditRefresh = null;
        }
    }
}
