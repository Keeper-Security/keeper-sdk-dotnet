using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Enterprise.ReportingPlugin
{
    /// <summary>
    /// Main reporting plugin interface - orchestrates report generation
    /// Handles API calls, storage, and data transformation
    /// </summary>
    public interface IReportingPlugin
    {
        /// <summary>
        /// Generate audit report with SOX compliance context
        /// </summary>
        Task<AuditReportResult> GenerateAuditReportAsync(
            IAuthentication auth,
            AuditReportConfig config);

        /// <summary>
        /// Generate compliance report with audit aging data
        /// </summary>
        Task<ComplianceReportResult> GenerateComplianceReportAsync(
            IAuthentication auth,
            ComplianceReportConfig config,
            List<string> vaultRecordUids = null);
    }

    /// <summary>
    /// Configuration for audit report generation
    /// </summary>
    public class AuditReportConfig
    {
        /// <summary>
        /// Record UIDs to filter by
        /// </summary>
        public List<string> RecordUids { get; set; } = new();

        /// <summary>
        /// User IDs to filter by
        /// </summary>
        public List<long> UserIds { get; set; } = new();

        /// <summary>
        /// Event types to filter by
        /// </summary>
        public List<string> EventTypes { get; set; } = new();

        /// <summary>
        /// Usernames to filter by
        /// </summary>
        public List<string> Usernames { get; set; } = new();

        /// <summary>
        /// Target username to filter by
        /// </summary>
        public string ToUsername { get; set; }

        /// <summary>
        /// IP addresses to filter by
        /// </summary>
        public List<string> IpAddresses { get; set; } = new();

        /// <summary>
        /// Shared folder UIDs to filter by
        /// </summary>
        public List<string> SharedFolderUids { get; set; } = new();

        /// <summary>
        /// Node IDs to filter by
        /// </summary>
        public List<long> NodeIds { get; set; } = new();

        /// <summary>
        /// Enterprise user IDs whose records should be included
        /// </summary>
        public List<long> OwnerUserIds { get; set; } = new();

        /// <summary>
        /// Raw audit created filter (a CreatedFilter or a predefined API filter string)
        /// </summary>
        public object CreatedFilter { get; set; }

        /// <summary>
        /// Start date for audit range
        /// </summary>
        public DateTime? StartDate { get; set; }

        /// <summary>
        /// End date for audit range
        /// </summary>
        public DateTime? EndDate { get; set; }

        /// <summary>
        /// Include aging data (from audit events)
        /// </summary>
        public bool IncludeAging { get; set; }

        /// <summary>
        /// Include SOX compliance context (ownership, permissions)
        /// </summary>
        public bool IncludeComplianceContext { get; set; }

        /// <summary>
        /// Output format: table, csv, json
        /// </summary>
        public string Format { get; set; } = "table";

        /// <summary>
        /// Report type. The enrichment plugin currently supports raw audit events;
        /// other report types should use the standard audit report command path.
        /// </summary>
        public string ReportType { get; set; } = "raw";

        /// <summary>
        /// Columns to include in report
        /// </summary>
        public List<string> Columns { get; set; } = new();

        /// <summary>
        /// Aggregate columns
        /// </summary>
        public List<string> Aggregate { get; set; } = new();

        /// <summary>
        /// Sort order: asc, desc
        /// </summary>
        public string Order { get; set; }

        /// <summary>
        /// Maximum results to return
        /// </summary>
        public int Limit { get; set; } = 2000;

        /// <summary>
        /// Max cache age in days before refresh
        /// </summary>
        public int CacheMaxAgeDays { get; set; } = 1;
    }

    /// <summary>
    /// Result of audit report generation
    /// </summary>
    public class AuditReportResult
    {
        /// <summary>
        /// Audit entries with optional aging and SOX context
        /// </summary>
        public List<AuditReportEntry> Entries { get; set; } = new();

        /// <summary>
        /// Aging data (created, last_pw_change, last_modified, etc.)
        /// </summary>
        public Dictionary<string, RecordAgingInfo> AgingData { get; set; } = new();

        /// <summary>
        /// SOX compliance context (ownership, permissions, shared status)
        /// </summary>
        public Dictionary<string, ComplianceContextInfo> ComplianceContext { get; set; } = new();

        /// <summary>
        /// When report was generated
        /// </summary>
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Total entries found
        /// </summary>
        public int TotalCount { get; set; }

        /// <summary>
        /// Any errors during generation
        /// </summary>
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Single audit report entry
    /// </summary>
    public class AuditReportEntry
    {
        public DateTime EventTime { get; set; }
        public string EventType { get; set; }
        public string RecordUid { get; set; }
        public string RecordTitle { get; set; }
        public long UserId { get; set; }
        public string Username { get; set; }
        public string IpAddress { get; set; }
        public string GeoLocation { get; set; }
        public string ClientType { get; set; }
        public Dictionary<string, object> Details { get; set; } = new();
    }

    /// <summary>
    /// SOX compliance context for a record
    /// </summary>
    public class ComplianceContextInfo
    {
        public string RecordUid { get; set; }
        public string Title { get; set; }
        public string RecordType { get; set; }
        public string Url { get; set; }
        public string Owner { get; set; }
        public List<string> Owners { get; set; } = new();
        public List<string> SharedFolderUids { get; set; } = new();
        public bool Shared { get; set; }
        public bool InTrash { get; set; }
        public string Permissions { get; set; }
        public int PermissionBits { get; set; }
        public List<string> SharedWith { get; set; } = new();
    }

    /// <summary>
    /// Record aging information
    /// </summary>
    public class RecordAgingInfo
    {
        public string RecordUid { get; set; }
        public DateTime? CreatedDate { get; set; }
        public DateTime? LastPasswordChangeDate { get; set; }
        public DateTime? LastModifiedDate { get; set; }
        public DateTime? LastRotationDate { get; set; }
        public int PasswordChangeCount { get; set; }
    }

    /// <summary>
    /// Configuration for compliance report generation
    /// </summary>
    public class ComplianceReportConfig
    {
        public List<string> Usernames { get; set; } = new();
        public List<string> Teams { get; set; } = new();
        public List<long> OwnerUserIds { get; set; } = new();
        public bool IncludeAging { get; set; }
        public bool SharedRecordsOnly { get; set; }
        public bool Rebuild { get; set; }
        public bool NoRebuild { get; set; }
        public int CacheMaxAgeDays { get; set; } = 1;
        public string Format { get; set; } = "table";
    }

    /// <summary>
    /// Result of compliance report generation
    /// </summary>
    public class ComplianceReportResult
    {
        public List<ComplianceReportEntry> Entries { get; set; } = new();
        public Dictionary<string, RecordAgingInfo> AgingData { get; set; } = new();
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
        public int TotalCount { get; set; }
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// Single compliance report entry
    /// </summary>
    public class ComplianceReportEntry
    {
        public string RecordUid { get; set; }
        public string Title { get; set; }
        public string RecordType { get; set; }
        public string Url { get; set; }
        public string Owner { get; set; }
        public List<string> SharedFolderUids { get; set; } = new();
        public bool Shared { get; set; }
        public bool InTrash { get; set; }
        public string Permissions { get; set; }
        public int PermissionBits { get; set; }
        public DateTime? Created { get; set; }
        public DateTime? LastPasswordChange { get; set; }
        public DateTime? LastModified { get; set; }
        public DateTime? LastRotation { get; set; }
    }
}
