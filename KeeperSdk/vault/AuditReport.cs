using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
    public enum ReportOrder
    {
        Asc,
        Desc
    }

    public class AuditReportFilter
    {
        public object Created { get; set; }
        public object EventType { get; set; }
        public object KeeperVersion { get; set; }
        public object Username { get; set; }
        public object ToUsername { get; set; }
        public object IpAddress { get; set; }
        public object RecordUid { get; set; }
        public object SharedFolderUid { get; set; }
        public object ParentId { get; set; }
    }

    public class AuditReportCommon
    {
        protected IAuthentication Auth { get; }
        public AuditReportFilter Filter { get; set; }
        public ReportOrder? Order { get; set; }
        public int? Limit { get; set; }
        public string Timezone { get; set; }

        public AuditReportCommon(IAuthentication auth)
        {
            Auth = auth;
        }


        protected string GetTimezone()
        {
            if (!string.IsNullOrEmpty(Timezone))
                return Timezone;

            var hours = (int)DateTimeOffset.Now.Offset.TotalHours;
            return $"Etc/GMT{(hours >= 0 ? "+" : "")}{hours}";
        }

        private static readonly string[] ValidDatePresets = { "today", "yesterday", "last_7_days", "last_30_days", "month_to_date", "last_month", "year_to_date", "last_year" };

        private static object BuildCreatedFilter(object created)
        {
            switch (created)
            {
                case CreatedFilterCriteria criteria:
                    var dict = new[]
                    {
                        (key: "min", value: (object)criteria.FromDate, condition: criteria.FromDate.HasValue),
                        (key: "exclude_min", value: (object)true, condition: criteria.FromDate.HasValue && criteria.ExcludeFrom == true),
                        (key: "max", value: (object)criteria.ToDate, condition: criteria.ToDate.HasValue),
                        (key: "exclude_max", value: (object)true, condition: criteria.ToDate.HasValue && criteria.ExcludeTo == true)
                    }
                    .Where(x => x.condition)
                    .ToDictionary(x => x.key, x => x.value);
                    return dict.Count > 0 ? dict : null;

                case string preset when ValidDatePresets.Contains(preset):
                    return preset;

                default:
                    return null;
            }
        }

        protected Dictionary<string, object> GetFilterDictionary()
        {
            if (Filter == null)
                return null;

            var reportFilter = new Dictionary<string, object>();

            var createdFilter = BuildCreatedFilter(Filter.Created);
            if (createdFilter != null)
                reportFilter["created"] = createdFilter;

            var filterMappings = new (string key, object value)[]
            {
                ("event_type", Filter.EventType),
                ("keeper_version", Filter.KeeperVersion),
                ("username", Filter.Username),
                ("to_username", Filter.ToUsername),
                ("ip_address", Filter.IpAddress),
                ("record_uid", Filter.RecordUid),
                ("shared_folder_uid", Filter.SharedFolderUid),
                ("parent_id", Filter.ParentId)
            };

            foreach (var (key, value) in filterMappings)
            {
                if (value != null)
                {
                    reportFilter[key] = value;
                }
            }

            return reportFilter.Count > 0 ? reportFilter : null;
        }

        protected static CreatedFilterCriteria ExpandCreatedPreset(string preset)
        {
            var today = DateTime.Today;
            DateTime fromDate;
            DateTime toDate;

            switch (preset)
            {
                case "today":
                    fromDate = today;
                    toDate = today.AddDays(1);
                    break;
                case "yesterday":
                    fromDate = today.AddDays(-1);
                    toDate = today;
                    break;
                case "last_7_days":
                    fromDate = today.AddDays(-7);
                    toDate = today;
                    break;
                case "last_30_days":
                    fromDate = today.AddDays(-30);
                    toDate = today;
                    break;
                case "month_to_date":
                    fromDate = new DateTime(today.Year, today.Month, 1);
                    toDate = today;
                    break;
                case "last_month":
                    toDate = new DateTime(today.Year, today.Month, 1);
                    fromDate = toDate.AddMonths(-1);
                    break;
                case "last_year":
                    fromDate = new DateTime(today.Year - 1, 1, 1);
                    toDate = new DateTime(today.Year, 1, 1);
                    break;
                case "year_to_date":
                    fromDate = new DateTime(today.Year, 1, 1);
                    toDate = today;
                    break;
                default:
                    throw new ArgumentException($"Unknown preset: {preset}");
            }

            return new CreatedFilterCriteria
            {
                FromDate = new DateTimeOffset(fromDate, TimeSpan.Zero).ToUnixTimeSeconds(),
                ExcludeFrom = false,
                ToDate = new DateTimeOffset(toDate, TimeSpan.Zero).ToUnixTimeSeconds(),
                ExcludeTo = true
            };
        }
    }

    public class RawAuditReport : AuditReportCommon
    {
        public RawAuditReport(IAuthentication auth) : base(auth)
        {
        }

        public async Task<List<Dictionary<string, object>>> ExecuteAuditReport()
        {
            var events = new List<Dictionary<string, object>>();
            var limit = Limit ?? 50;

            if (limit == 0)
                return events;

            var isPaginated = limit < 0 || limit > 1000;
            var currentFilter = Filter;
            var order = Order ?? ReportOrder.Desc;

            if (isPaginated && currentFilter?.Created is string createdPreset)
            {
                currentFilter = new AuditReportFilter
                {
                    Created = ExpandCreatedPreset(createdPreset),
                    EventType = Filter.EventType,
                    KeeperVersion = Filter.KeeperVersion,
                    Username = Filter.Username,
                    ToUsername = Filter.ToUsername,
                    IpAddress = Filter.IpAddress,
                    RecordUid = Filter.RecordUid,
                    SharedFolderUid = Filter.SharedFolderUid,
                    ParentId = Filter.ParentId
                };
            }

            var timezone = GetTimezone();
            var eventsReturned = 0;
            var done = false;

            while (!done)
            {
                done = true;
                int queryLimit;

                queryLimit = isPaginated
                    ? (limit <= 0 ? 1000 : Math.Min(1000, limit - eventsReturned))
                    : limit;

                var originalFilter = Filter;
                Filter = currentFilter;
                var jsonFilter = GetFilterDictionary();
                Filter = originalFilter;

                var command = new AuditReportCommand
                {
                    ReportType = "raw",
                    Scope = "enterprise",
                    Timezone = timezone,
                    Limit = queryLimit,
                    Order = order == ReportOrder.Asc ? "ascending" : "descending",
                    Filter = jsonFilter
                };

                var response = await Auth.ExecuteAuthCommand<AuditReportCommand, AuditReportResponse>(command);
                
                if (response?.Rows == null)
                    break;

                var currentBatch = response.Rows;

                if (isPaginated && currentBatch.Count == 1000)
                {
                    done = false;
                    var ts = Convert.ToInt64(currentBatch.Last()["created"]);
                    var pos = currentBatch.FindLastIndex(e => Convert.ToInt64(e["created"]) != ts);

                    (currentBatch, ts) = pos > 900 
                        ? (currentBatch.Take(pos + 1).ToList(), Convert.ToInt64(currentBatch[pos]["created"]))
                        : (currentBatch, ts + 1);

                    currentFilter ??= new AuditReportFilter();
                    var createdFilter = currentFilter.Created as CreatedFilterCriteria ?? new CreatedFilterCriteria();
                    currentFilter.Created = createdFilter;

                    _ = order == ReportOrder.Asc
                        ? (createdFilter.FromDate, createdFilter.ExcludeFrom) = (ts, false)
                        : (createdFilter.ToDate, createdFilter.ExcludeTo) = (ts, false);
                }

                eventsReturned += currentBatch.Count;
                events.AddRange(currentBatch);
            }

            return events;
        }
    }

    public class SummaryAuditReport : AuditReportCommon
    {
        private string _summaryType;

        public SummaryAuditReport(IAuthentication auth) : base(auth)
        {
            Aggregates = new List<string>();
            Columns = new List<string>();
        }

        public string SummaryType
        {
            get => _summaryType;
            set => _summaryType = new[] { "hour", "day", "week", "month", "span" }.Contains(value)
                ? value
                : throw new ArgumentException($"\"{value}\" is not a valid summary report type");
        }

        public List<string> Aggregates { get; set; }
        public List<string> Columns { get; set; }

        public async Task<List<Dictionary<string, object>>> ExecuteSummaryReport()
        {
            var limit = Math.Max(1, Math.Min(Limit ?? 100, 2000));
            var timezone = GetTimezone();

            var jsonFilter = GetFilterDictionary();

            var command = new AuditReportCommand
            {
                ReportType = _summaryType,
                Scope = "enterprise",
                Timezone = timezone,
                Limit = limit,
                Columns = Columns?.Count > 0 ? Columns : null,
                Aggregate = Aggregates?.Count > 0 ? Aggregates : null,
                Order = Order.HasValue ? (Order.Value == ReportOrder.Asc ? "ascending" : "descending") : null,
                Filter = jsonFilter
            };

            var response = await Auth.ExecuteAuthCommand<AuditReportCommand, AuditReportResponse>(command);
            return response?.Rows ?? new List<Dictionary<string, object>>();
        }
    }

    public class DimAuditReport : AuditReportCommon
    {
        public DimAuditReport(IAuthentication auth) : base(auth)
        {
        }

        public async Task<List<Dictionary<string, object>>> ExecuteDimensionReport(string dimension)
        {
            var command = new DimensionReportCommand
            {
                ReportType = "dim",
                Columns = new List<string> { dimension },
                Limit = 2000,
                Scope = "enterprise"
            };

            var response = await Auth.ExecuteAuthCommand<DimensionReportCommand, DimensionReportResponse>(command);

            if (response?.Dimensions?.TryGetValue(dimension, out var dimensions) != true)
                return new List<Dictionary<string, object>>();

            if (dimension == "ip_address")
            {
                foreach (var row in dimensions)
                {
                    var parts = new[] { "city", "region", "country_code" }
                        .Select(k => row.TryGetValue(k, out var v) ? v?.ToString() : "")
                        .Where(s => !string.IsNullOrEmpty(s));

                    if (parts.Any())
                        row["geo_location"] = string.Join(", ", parts);
                }
            }

            return dimensions;
        }
    }

    public static class AuditReportExtensions
    {
        public static RawAuditReport CreateRawAuditReport(this VaultOnline vault)
        {
            return new RawAuditReport(vault.Auth);
        }

        public static SummaryAuditReport CreateSummaryAuditReport(this VaultOnline vault)
        {
            return new SummaryAuditReport(vault.Auth);
        }

        public static DimAuditReport CreateDimAuditReport(this VaultOnline vault)
        {
            return new DimAuditReport(vault.Auth);
        }
    }

    #region Data Contracts

    [DataContract]
    public class CreatedFilterCriteria
    {
        [DataMember(Name = "min", EmitDefaultValue = false)]
        public long? FromDate { get; set; }

        [DataMember(Name = "exclude_min", EmitDefaultValue = false)]
        public bool? ExcludeFrom { get; set; }

        [DataMember(Name = "max", EmitDefaultValue = false)]
        public long? ToDate { get; set; }

        [DataMember(Name = "exclude_max", EmitDefaultValue = false)]
        public bool? ExcludeTo { get; set; }
    }

    #endregion

    #region Internal API Contracts

    [DataContract]
    internal class AuditReportCommand : AuthenticatedCommand
    {
        public AuditReportCommand() : base("get_audit_event_reports") { }

        [DataMember(Name = "report_type", EmitDefaultValue = false)]
        public string ReportType { get; set; }

        [DataMember(Name = "scope", EmitDefaultValue = false)]
        public string Scope { get; set; }

        [DataMember(Name = "filter", EmitDefaultValue = false)]
        public Dictionary<string, object> Filter { get; set; }

        [DataMember(Name = "timezone", EmitDefaultValue = false)]
        public string Timezone { get; set; }

        [DataMember(Name = "limit", EmitDefaultValue = false)]
        public int? Limit { get; set; }

        [DataMember(Name = "order", EmitDefaultValue = false)]
        public string Order { get; set; }

        [DataMember(Name = "columns", EmitDefaultValue = false)]
        public List<string> Columns { get; set; }

        [DataMember(Name = "aggregate", EmitDefaultValue = false)]
        public List<string> Aggregate { get; set; }
    }

    [DataContract]
    internal class DimensionReportCommand : AuthenticatedCommand
    {
        public DimensionReportCommand() : base("get_audit_event_dimensions") { }

        [DataMember(Name = "report_type", EmitDefaultValue = false)]
        public string ReportType { get; set; }

        [DataMember(Name = "scope", EmitDefaultValue = false)]
        public string Scope { get; set; }

        [DataMember(Name = "columns", EmitDefaultValue = false)]
        public List<string> Columns { get; set; }

        [DataMember(Name = "limit", EmitDefaultValue = false)]
        public int? Limit { get; set; }
    }

    [DataContract]
    internal class AuditReportResponse : KeeperApiResponse
    {
        [DataMember(Name = "audit_event_overview_report_rows", EmitDefaultValue = false)]
        public List<Dictionary<string, object>> Rows { get; set; }
    }

    [DataContract]
    internal class DimensionReportResponse : KeeperApiResponse
    {
        [DataMember(Name = "dimensions", EmitDefaultValue = false)]
        public Dictionary<string, List<Dictionary<string, object>>> Dimensions { get; set; }
    }

    #endregion
}

