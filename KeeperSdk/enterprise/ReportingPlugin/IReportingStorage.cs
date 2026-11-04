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
        /// Get cached aging data for specific records
        /// </summary>
        Dictionary<string, RecordAgingInfo> GetAgingData(List<string> recordUids);

        /// <summary>
        /// Check if compliance data is stale and needs refresh
        /// </summary>
        bool IsComplianceDataStale(int maxAgeDays = 1);

        /// <summary>
        /// Get the last time compliance data was refreshed
        /// </summary>
        long? GetLastComplianceRefresh();

        /// <summary>
        /// Update metadata timestamp for compliance data
        /// </summary>
        void UpdateComplianceRefreshTimestamp(long timestamp);

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
        private Dictionary<string, RecordAgingInfo> _agingData = new();
        private long? _lastComplianceRefresh;

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

        public long? GetLastComplianceRefresh() => _lastComplianceRefresh;

        public void UpdateComplianceRefreshTimestamp(long timestamp)
        {
            _lastComplianceRefresh = timestamp;
        }

        public void ClearComplianceData() => _complianceData.Clear();
        public void ClearAgingData() => _agingData.Clear();

        public void ClearAll()
        {
            ClearComplianceData();
            ClearAgingData();
            _lastComplianceRefresh = null;
        }
    }
}
