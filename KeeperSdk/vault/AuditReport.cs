using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
    using System.Runtime.Serialization.Json;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
    [DataContract]
    internal class AuditReportCommand : AuthenticatedCommand
    {
        public AuditReportCommand() : base("get_audit_event_reports")
        {
        }

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
        public DimensionReportCommand() : base("get_audit_event_dimensions")
        {
        }

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

    public enum ReportOrder
    {
        Asc,
        Desc
    }

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
            {
                return Timezone;
            }

            var now = DateTimeOffset.Now;
            var offset = now.Offset;
            var hours = (int)offset.TotalHours;
            return $"Etc/GMT{(hours >= 0 ? "+" : "")}{hours}";
        }

        protected Dictionary<string, object> GetFilterDictionary()
        {
            if (Filter == null)
            {
                return null;
            }

            var reportFilter = new Dictionary<string, object>();

            if (Filter.Created != null)
            {
                if (Filter.Created is CreatedFilterCriteria criteria)
                {
                    var created = new Dictionary<string, object>();
                    if (criteria.FromDate.HasValue)
                    {
                        created["min"] = criteria.FromDate.Value;
                        if (criteria.ExcludeFrom == true)
                        {
                            created["exclude_min"] = true;
                        }
                    }
                    if (criteria.ToDate.HasValue)
                    {
                        created["max"] = criteria.ToDate.Value;
                        if (criteria.ExcludeTo == true)
                        {
                            created["exclude_max"] = true;
                        }
                    }
                    if (created.Count > 0)
                    {
                        reportFilter["created"] = created;
                    }
                }
                else if (Filter.Created is string createdStr)
                {
                    var validPresets = new[] { "today", "yesterday", "last_7_days", "last_30_days", "month_to_date", "last_month", "year_to_date", "last_year" };
                    if (validPresets.Contains(createdStr))
                    {
                        reportFilter["created"] = createdStr;
                    }
                }
            }

            if (Filter.EventType != null)
            {
                reportFilter["event_type"] = Filter.EventType;
            }

            if (Filter.KeeperVersion != null)
            {
                reportFilter["keeper_version"] = Filter.KeeperVersion;
            }

            if (Filter.Username != null)
            {
                reportFilter["username"] = Filter.Username;
            }

            if (Filter.ToUsername != null)
            {
                reportFilter["to_username"] = Filter.ToUsername;
            }

            if (Filter.IpAddress != null)
            {
                reportFilter["ip_address"] = Filter.IpAddress;
            }

            if (Filter.RecordUid != null)
            {
                reportFilter["record_uid"] = Filter.RecordUid;
            }

            if (Filter.SharedFolderUid != null)
            {
                reportFilter["shared_folder_uid"] = Filter.SharedFolderUid;
            }

            if (Filter.ParentId != null)
            {
                reportFilter["parent_id"] = Filter.ParentId;
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
                    var year = today.Year;
                    var month = today.Month;
                    toDate = new DateTime(year, month, 1);
                    if (month == 1)
                    {
                        month = 12;
                        year -= 1;
                    }
                    else
                    {
                        month -= 1;
                    }
                    fromDate = new DateTime(year, month, 1);
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
            {
                return events;
            }

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

                if (isPaginated)
                {
                    if (limit <= 0)
                    {
                        queryLimit = 1000;
                    }
                    else
                    {
                        var left = limit - eventsReturned;
                        queryLimit = Math.Min(1000, left);
                    }
                }
                else
                {
                    queryLimit = limit;
                }

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
                
                if (response != null && response.Rows != null)
                {
                    var currentBatch = response.Rows;

                    if (isPaginated && currentBatch.Count == 1000)
                    {
                        done = false;
                        var lastEvent = currentBatch.Last();
                        var ts = Convert.ToInt64(lastEvent["created"]);
                        var pos = currentBatch.Count - 1;

                        while (pos > 900)
                        {
                            var eTs = Convert.ToInt64(currentBatch[pos]["created"]);
                            if (eTs == ts)
                            {
                                pos--;
                            }
                            else
                            {
                                break;
                            }
                        }

                        if (pos > 900)
                        {
                            currentBatch = currentBatch.Take(pos).ToList();
                        }
                        else
                        {
                            ts += 1;
                        }

                        if (currentFilter == null)
                        {
                            currentFilter = new AuditReportFilter();
                        }
                        if (currentFilter.Created == null || currentFilter.Created is string)
                        {
                            currentFilter.Created = new CreatedFilterCriteria();
                        }

                        var createdFilter = currentFilter.Created as CreatedFilterCriteria;
                        if (order == ReportOrder.Asc)
                        {
                            createdFilter.FromDate = ts;
                            createdFilter.ExcludeFrom = false;
                        }
                        else
                        {
                            createdFilter.ToDate = ts;
                            createdFilter.ExcludeTo = false;
                        }
                    }

                    eventsReturned += currentBatch.Count;
                    events.AddRange(currentBatch);
                }
                else
                {
                    break;
                }
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
            set
            {
                var validTypes = new[] { "hour", "day", "week", "month", "span" };
                if (!validTypes.Contains(value))
                {
                    throw new ArgumentException($"\"{value}\" is not a valid summary report type");
                }
                _summaryType = value;
            }
        }

        public List<string> Aggregates { get; set; }
        public List<string> Columns { get; set; }

        public async Task<List<Dictionary<string, object>>> ExecuteSummaryReport()
        {
            var limit = Limit ?? 100;
            if (limit <= 0)
            {
                limit = 100;
            }
            else if (limit > 2000)
            {
                limit = 2000;
            }

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

            if (response != null && response.Rows != null)
            {
                return response.Rows;
            }

            return new List<Dictionary<string, object>>();
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

            if (response != null && response.Dimensions != null &&
                response.Dimensions.TryGetValue(dimension, out var dimensionsList))
            {
                var dimensions = dimensionsList;

                if (dimension == "ip_address")
                {
                    foreach (var row in dimensions)
                    {
                        var city = row.ContainsKey("city") ? row["city"]?.ToString() : "";
                        var region = row.ContainsKey("region") ? row["region"]?.ToString() : "";
                        var country = row.ContainsKey("country_code") ? row["country_code"]?.ToString() : "";

                        if (!string.IsNullOrEmpty(city) || !string.IsNullOrEmpty(region) || !string.IsNullOrEmpty(country))
                        {
                            row["geo_location"] = string.Join(", ", new[] { city, region, country }.Where(s => !string.IsNullOrEmpty(s)));
                        }
                    }
                }

                return dimensions;
            }

            return new List<Dictionary<string, object>>();
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
}

