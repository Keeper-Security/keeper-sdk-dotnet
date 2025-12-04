using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Commander
{
    internal static class AuditReportCommandExtensions
    {
        private static Dictionary<string, string> _syslogTemplates;
        private static Dictionary<string, List<Dictionary<string, object>>> _dimensionCache = new Dictionary<string, List<Dictionary<string, object>>>();

        public static async Task AuditReportCommand(this VaultContext context, AuditReportCommandOptions options)
        {
            if (options.SyntaxHelp)
            {
                DisplaySyntaxHelp();
                
                var dimReport = context.Vault.CreateDimAuditReport();
                var events = await dimReport.ExecuteDimensionReport("audit_event_type");
                
                System.Diagnostics.Debug.WriteLine($"Loaded {events?.Count ?? 0} event types from dimension report");
                
                Console.WriteLine("\nThe following are possible event type id and event type name values:\n");
                
                var table = new Tabulate(2)
                {
                    DumpRowNo = true,
                    LeftPadding = 4,
                    MaxColumnWidth = int.MaxValue
                };
                table.AddHeader("Event ID", "Event Name");
                
                foreach (var evt in events.OrderBy(e => Convert.ToInt32(e.GetValueOrDefault("id", 0))))
                {
                    table.AddRow(
                        evt.GetValueOrDefault("id", ""),
                        evt.GetValueOrDefault("name", "")
                    );
                }
                
                table.Dump();
                return;
            }

            var reportType = string.IsNullOrEmpty(options.ReportType) ? "raw" : options.ReportType.ToLower();

            switch (reportType)
            {
                case "dim":
                    await ExecuteDimensionReport(context, options);
                    break;
                case "raw":
                    await ExecuteRawReport(context, options);
                    break;
                case "hour":
                case "day":
                case "week":
                case "month":
                case "span":
                    await ExecuteSummaryReport(context, options);
                    break;
                default:
                    Console.WriteLine($"Invalid report type: {reportType}");
                    break;
            }
        }

        private static async Task ExecuteDimensionReport(VaultContext context, AuditReportCommandOptions options)
        {
            var columns = options.Columns?.ToList();
            if (columns == null || columns.Count != 1)
            {
                Console.WriteLine("Error: 'dim' reports expect exactly one 'column' parameter");
                return;
            }

            var column = columns[0];
            var dimensions = await LoadAuditDimension(context, column);

            if (dimensions == null || dimensions.Count == 0)
            {
                Console.WriteLine($"No dimensions found for: {column}");
                return;
            }

            var fields = column switch
            {
                "audit_event_type" => new List<string> { "id", "name", "category", "syslog" },
                "keeper_version" => new List<string> { "version_id", "type_name", "version", "type_category" },
                "ip_address" => new List<string> { "ip_address", "city", "region", "country_code" },
                "geo_location" => new List<string> { "geo_location", "city", "region", "country_code", "ip_count" },
                "device_type" => new List<string> { "type_name", "type_category" },
                _ => new List<string> { column }
            };

            var table = new Tabulate(fields.Count)
            {
                DumpRowNo = true,
                LeftPadding = 4,
                MaxColumnWidth = int.MaxValue
            };

            table.AddHeader(fields.ToArray());

            foreach (var dim in dimensions)
            {
                var row = fields.Select(f => dim.GetValueOrDefault(f, "")).ToArray();
                table.AddRow(row);
            }

            table.Dump();
        }

        private static async Task ExecuteRawReport(VaultContext context, AuditReportCommandOptions options)
        {
            var rawReport = context.Vault.CreateRawAuditReport();
            rawReport.Filter = GetReportFilter(context, options);
            rawReport.Limit = options.Limit ?? 50;
            rawReport.Order = options.Order?.ToLower() == "asc" ? ReportOrder.Asc : ReportOrder.Desc;
            rawReport.Timezone = options.Timezone;

            var reportFormat = options.ReportFormat ?? "message";
            var fields = new List<string> { "created", "audit_event_type", "username", "ip_address", "keeper_version", "geo_location" };

            if (reportFormat == "message")
            {
                fields.Add("message");
                await LoadSyslogTemplates(context);
            }

            var events = await rawReport.ExecuteAuditReport();
            var table = new List<List<object>>();

            foreach (var evt in events)
            {
                var row = fields.Select(field => 
                    field == "message" 
                        ? GetEventMessage(evt) 
                        : FormatFieldValue(field, evt.TryGetValue(field, out var v) ? v : null, "raw")
                ).ToList();
                table.Add(row);
            }

            var tabulate = new Tabulate(fields.Count)
            {
                DumpRowNo = false,
                MaxColumnWidth = int.MaxValue
            };

            tabulate.AddHeader(fields.ToArray());

            foreach (var row in table)
            {
                tabulate.AddRow(row.ToArray());
            }

            tabulate.Dump();
        }

        private static async Task ExecuteSummaryReport(VaultContext context, AuditReportCommandOptions options)
        {
            var summaryReport = context.Vault.CreateSummaryAuditReport();
            summaryReport.SummaryType = options.ReportType.ToLower();
            summaryReport.Filter = GetReportFilter(context, options);
            
            var limit = options.Limit ?? 100;
            if (limit < 0 || limit > 2000)
            {
                Console.WriteLine($"Invalid 'limit' value: {limit}. Must be between 0 and 2000.");
                return;
            }
            summaryReport.Limit = limit;
            summaryReport.Order = options.Order?.ToLower() == "asc" ? ReportOrder.Asc : ReportOrder.Desc;
            summaryReport.Timezone = options.Timezone;

            var columns = options.Columns?.ToList() ?? new List<string>();
            if (columns.Count == 0)
            {
                Console.WriteLine("Error: 'columns' parameter cannot be empty for summary reports");
                return;
            }
            summaryReport.Columns = columns;

            var aggregates = (options.Aggregates?.ToList()) ?? new List<string> { "occurrences" };
            summaryReport.Aggregates = aggregates;

            var fields = new List<string>();
            fields.AddRange(aggregates);
            if (summaryReport.SummaryType != "span")
            {
                fields.Add("created");
            }
            fields.AddRange(columns);

            var events = await summaryReport.ExecuteSummaryReport();
            var table = new Tabulate(fields.Count)
            {
                DumpRowNo = true,
                LeftPadding = 4,
                MaxColumnWidth = int.MaxValue
            };

            table.AddHeader(fields.ToArray());

            foreach (var evt in events)
            {
                var row = fields.Select(f => FormatFieldValue(f, evt.GetValueOrDefault(f, ""), summaryReport.SummaryType)).ToArray();
                table.AddRow(row);
            }

            table.Dump();
        }

        private static AuditReportFilter GetReportFilter(VaultContext context, AuditReportCommandOptions options)
        {
            var filter = new AuditReportFilter();

            if (!string.IsNullOrEmpty(options.Created))
            {
                var validPresets = new[] { "today", "yesterday", "last_7_days", "last_30_days", "month_to_date", "last_month", "year_to_date", "last_year" };
                filter.Created = validPresets.Contains(options.Created) ? options.Created : (object)ParseCreatedFilter(options.Created);
            }

            var eventTypeList = options.EventType?.ToList();
            if (eventTypeList?.Count > 0)
            {
                var parsed = eventTypeList.Select(v => int.TryParse(v, out var i) ? (object)i : v).ToList();
                filter.EventType = parsed.Count == 1 ? parsed[0] : parsed;
            }

            // Helper to convert list to single item or list
            object ToFilterValue(List<string> list) => list?.Count > 0 ? (list.Count == 1 ? (object)list[0] : list) : null;

            filter.Username = ToFilterValue(options.Username?.ToList());
            filter.ToUsername = ToFilterValue(options.ToUsername?.ToList());
            filter.RecordUid = ToFilterValue(options.RecordUid?.ToList());
            filter.SharedFolderUid = ToFilterValue(options.SharedFolderUid?.ToList());

            var ipFilter = new HashSet<string>();
            
            if (!string.IsNullOrEmpty(options.GeoLocation))
            {
                var geoComps = options.GeoLocation.Split(',');
                var country = (geoComps.Length > 0 ? geoComps[geoComps.Length - 1] : "").Trim().ToLower();
                var region = (geoComps.Length > 1 ? geoComps[geoComps.Length - 2] : "").Trim().ToLower();
                var city = (geoComps.Length > 2 ? geoComps[geoComps.Length - 3] : "").Trim().ToLower();

                var geoDimensions = LoadAuditDimension(context, "geo_location").Result;
                if (geoDimensions != null)
                {
                    foreach (var geo in geoDimensions)
                    {
                        if (!string.IsNullOrEmpty(country) && geo.GetValueOrDefault("country_code", "").ToString().ToLower() != country)
                            continue;
                        if (!string.IsNullOrEmpty(region) && geo.GetValueOrDefault("region", "").ToString().ToLower() != region)
                            continue;
                        if (!string.IsNullOrEmpty(city) && geo.GetValueOrDefault("city", "").ToString().ToLower() != city)
                            continue;

                        if (geo.TryGetValue("ip_addresses", out var ips) && ips is List<object> ipList)
                            ipFilter.UnionWith(ipList.Select(ip => ip.ToString()));
                    }
                }
            }

            if (options.IpAddress != null)
                ipFilter.UnionWith(options.IpAddress);

            if (ipFilter.Count > 0)
                filter.IpAddress = ipFilter.ToList();

            if (!string.IsNullOrEmpty(options.DeviceType))
            {
                var deviceComps = options.DeviceType.Split(',');
                var deviceType = deviceComps.ElementAtOrDefault(0)?.Trim().ToLower() ?? "";
                var version = deviceComps.ElementAtOrDefault(1)?.Trim().ToLower() ?? "";
                if (!string.IsNullOrEmpty(version) && !version.Contains("."))
                    version += ".";

                var deviceTypes = LoadAuditDimension(context, "device_type").Result ?? new List<Dictionary<string, object>>();

                var versionFilter = deviceTypes
                    .Where(dev => string.IsNullOrEmpty(deviceType) ||
                        dev.GetValueOrDefault("type_name", "")?.ToString().ToLower() == deviceType ||
                        dev.GetValueOrDefault("type_category", "")?.ToString().ToLower() == deviceType)
                    .Where(dev => string.IsNullOrEmpty(version) ||
                        dev.GetValueOrDefault("version", "")?.ToString().StartsWith(version, StringComparison.OrdinalIgnoreCase) == true)
                    .Where(dev => dev.TryGetValue("version_ids", out _))
                    .SelectMany(dev => (dev["version_ids"] as List<object>)?.OfType<int>() ?? Enumerable.Empty<int>())
                    .ToList();

                if (versionFilter.Count > 0)
                    filter.KeeperVersion = versionFilter;
            }

            return filter;
        }

        private static CreatedFilterCriteria ParseCreatedFilter(string filterValue)
        {
            filterValue = filterValue.Trim();

            var betweenMatch = Regex.Match(filterValue, @"\s*between\s+(\S+)\s+and\s+(.+)", RegexOptions.IgnoreCase);
            if (betweenMatch.Success)
            {
                var dt1 = ParseDateValue(betweenMatch.Groups[1].Value);
                var dt2 = ParseDateValue(betweenMatch.Groups[2].Value);
                return new CreatedFilterCriteria { FromDate = dt1, ToDate = dt2 };
            }

            var prefixes = new[] { ">=", "<=", ">", "<", "=" };
            foreach (var prefix in prefixes)
            {
                if (filterValue.StartsWith(prefix))
                {
                    var value = ParseDateValue(filterValue.Substring(prefix.Length).Trim());
                    return prefix switch
                    {
                        ">=" => new CreatedFilterCriteria { FromDate = value },
                        "<=" => new CreatedFilterCriteria { ToDate = value },
                        ">" => new CreatedFilterCriteria { FromDate = value, ExcludeFrom = true },
                        "<" => new CreatedFilterCriteria { ToDate = value, ExcludeTo = true },
                        "=" => new CreatedFilterCriteria { FromDate = value, ToDate = value },
                        _ => throw new ArgumentException($"Invalid created filter prefix: {prefix}")
                    };
                }
            }

            throw new ArgumentException($"Invalid created filter value: {filterValue}");
        }

        private static long ParseDateValue(string value)
        {
            value = value.Trim();
            if (long.TryParse(value, out var timestamp))
                return timestamp;

            var format = value.Length <= 10 ? "yyyy-MM-dd" : "yyyy-MM-ddTHH:mm:ssZ";
            var dt = DateTime.ParseExact(value, format, CultureInfo.InvariantCulture);
            return new DateTimeOffset(dt, TimeSpan.Zero).ToUnixTimeSeconds();
        }

        private static async Task LoadSyslogTemplates(VaultContext context)
        {
            if (_syslogTemplates != null)
                return;

            var dimReport = context.Vault.CreateDimAuditReport();
            var eventTypes = await dimReport.ExecuteDimensionReport("audit_event_type");

            _syslogTemplates = eventTypes
                .Select(et => (name: et.GetValueOrDefault("name", "")?.ToString(), syslog: et.GetValueOrDefault("syslog", "")?.ToString()))
                .Where(x => !string.IsNullOrEmpty(x.name) && !string.IsNullOrEmpty(x.syslog))
                .ToDictionary(x => x.name, x => x.syslog);
        }

        private static string GetEventMessage(Dictionary<string, object> evt)
        {
            if (_syslogTemplates == null)
                return "";

            var eventType = evt.GetValueOrDefault("audit_event_type", "")?.ToString() ?? "";
            if (string.IsNullOrEmpty(eventType) || !_syslogTemplates.TryGetValue(eventType, out var template))
                return "";

            return Regex.Replace(template, @"\$\{(\w+)\}", match =>
                evt.GetValueOrDefault(match.Groups[1].Value, "<missing>")?.ToString() ?? "<missing>");
        }

        private static async Task<List<Dictionary<string, object>>> LoadAuditDimension(VaultContext context, string dimension)
        {
            if (_dimensionCache.TryGetValue(dimension, out var cached))
                return cached;

            List<Dictionary<string, object>> dimensions = null;

            switch (dimension)
            {
                case "geo_location":
                    var ipDimensions = await LoadAuditDimension(context, "ip_address") ?? new List<Dictionary<string, object>>();
                    dimensions = ipDimensions
                        .Where(g => !string.IsNullOrEmpty(g.GetValueOrDefault("geo_location", "")?.ToString()) &&
                                    !string.IsNullOrEmpty(g.GetValueOrDefault("ip_address", "")?.ToString()))
                        .GroupBy(g => g.GetValueOrDefault("geo_location", "").ToString())
                        .Select(grp =>
                        {
                            var entry = new Dictionary<string, object>(grp.First());
                            entry.Remove("ip_address");
                            var ips = grp.Select(g => (object)g.GetValueOrDefault("ip_address", "").ToString()).ToList();
                            entry["ip_addresses"] = ips;
                            entry["ip_count"] = ips.Count;
                            return entry;
                        }).ToList();
                    break;

                case "device_type":
                    var versionDimensions = await LoadAuditDimension(context, "keeper_version") ?? new List<Dictionary<string, object>>();
                    dimensions = versionDimensions
                        .Where(v => !string.IsNullOrEmpty(v.GetValueOrDefault("type_id", "")?.ToString()) &&
                                    v.GetValueOrDefault<object>("version_id", null) != null)
                        .GroupBy(v => v.GetValueOrDefault("type_id", "").ToString())
                        .Select(grp =>
                        {
                            var entry = new Dictionary<string, object>(grp.First());
                            entry.Remove("version_id");
                            entry["version_ids"] = grp.Select(v => v.GetValueOrDefault<object>("version_id", null)).ToList();
                            return entry;
                        }).ToList();
                    break;

                default:
                    dimensions = await context.Vault.CreateDimAuditReport().ExecuteDimensionReport(dimension);
                    break;
            }

            if (dimensions != null)
            {
                _dimensionCache[dimension] = dimensions;
            }

            return dimensions;
        }

        private static object FormatFieldValue(string field, object value, string reportType)
        {
            if (field != "created" && field != "first_created" && field != "last_created")
                return value ?? "";

            if (value == null || (value is string s && string.IsNullOrEmpty(s)))
                return "";

            if (value is string strValue)
            {
                if (!long.TryParse(strValue, out var parsed))
                    return strValue;
                value = parsed;
            }

            if (!long.TryParse(value.ToString(), out var timestamp))
                return value?.ToString() ?? "";

            var dt = DateTimeOffset.FromUnixTimeSeconds(timestamp);
            return reportType switch
            {
                "day" or "week" => dt.ToString("yyyy-MM-dd"),
                "month" => dt.ToString("MMMM, yyyy"),
                "hour" => dt.ToString("yyyy-MM-dd @HH:00"),
                _ => dt.ToString("yyyy-MM-dd HH:mm:sszzz")
            };
        }

        private static string FieldToTitle(string field)
        {
            return string.Join(" ", field.Split('_').Select(w => char.ToUpper(w[0]) + w.Substring(1)));
        }

        private static T GetValueOrDefault<T>(this Dictionary<string, object> dict, string key, T defaultValue)
            => dict.TryGetValue(key, out var value) && value is T typedValue ? typedValue : defaultValue;

        private static void DisplaySyntaxHelp()
        {
            Console.WriteLine(@"
Audit Report Command Syntax Description:

Output columns (raw report):
  created               Event timestamp
  audit_event_type      Audit event type
  username              User that created the audit event
  ip_address            IP address
  keeper_version        Keeper application version
  geo_location          Geographic location (city, region, country)
  message               Human-readable event description

Additional event properties:
  id                    Event ID
  to_username           User that is audit event target
  from_username         User that is audit event source
  channel               2FA channel
  status                Keeper API result_code
  record_uid            Record UID
  record_title          Record title
  record_url            Record URL
  shared_folder_uid     Shared Folder UID
  shared_folder_title   Shared Folder title
  node                  Node ID (enterprise events only)
  node_title            Node title (enterprise events only)
  team_uid              Team UID (enterprise events only)
  team_title            Team title (enterprise events only)
  role_id               Role ID (enterprise events only)
  role_title            Role title (enterprise events only)

--report-type:
            raw         Returns individual events (default)
                        Columns: created, audit_event_type, username, ip_address, keeper_version, geo_location, message

  span hour day         Aggregates audit events by time period
     week month         Valid parameters: filters, columns, aggregates

            dim         Returns event property descriptions or distinct values
                        Valid columns: audit_event_type, keeper_version, device_type, ip_address, geo_location, username

--columns:              Defines breakdown properties for aggregate reports
                        Can be any event property except: id, created

--aggregate:            Defines the aggregate value:
     occurrences        Number of events (COUNT(*))
   first_created        Starting date (MIN(created))
    last_created        Ending date (MAX(created))

--limit:                Limits the number of returned records (default: 50 for raw, 100 for summary)

--order:                Sort order: ""desc"" (default) or ""asc""

Filters:
--created               Date filter. Predefined: today, yesterday, last_7_days, last_30_days, 
                        month_to_date, last_month, year_to_date, last_year
                        Range: 'BETWEEN <date1> AND <date2>' (UTC date or epoch seconds)
                        Operators: '=', '>', '<', '>=', '<='
--username              Filter by user email
--to-username           Filter by target user email
--record-uid            Filter by Record UID
--shared-folder-uid     Filter by Shared Folder UID
--event-type            Filter by Audit Event Type (id or name)
--geo-location          Filter by location (e.g., ""Munich,Bayern,DE"", ""US"")
--ip-address            Filter by IP Address
--device-type           Filter by Keeper application (e.g., ""Commander"", ""Web App, 16.3.4"")

Examples:
  audit-report                                    Show recent events
  audit-report --limit=100                        Show 100 recent events
  audit-report --created=today                    Show today's events
  audit-report --username=user@example.com        Show events for specific user
  audit-report --report-type=day --column=username --created=last_7_days
                                                  Daily summary by user for last 7 days
");
        }
    }

    class AuditReportCommandOptions
    {
        [Option("syntax-help", Required = false, Default = false,
            HelpText = "Display syntax help")]
        public bool SyntaxHelp { get; set; }

        [Option("report-type", Required = false,
            HelpText = "Report type: raw, dim, hour, day, week, month, span")]
        public string ReportType { get; set; }

        [Option("report-format", Required = false, Default = "message",
            HelpText = "Output format (raw reports only): message, fields")]
        public string ReportFormat { get; set; }

        [Option("column", Required = false, Separator = ',',
            HelpText = "Column to include. Can be repeated. (ignored for raw reports)")]
        public IEnumerable<string> Columns { get; set; }

        [Option("aggregate", Required = false, Separator = ',',
            HelpText = "Aggregated value: occurrences, first_created, last_created. Can be repeated. (ignored for raw reports)")]
        public IEnumerable<string> Aggregates { get; set; }

        [Option("timezone", Required = false,
            HelpText = "Return results for specific timezone")]
        public string Timezone { get; set; }

        [Option("limit", Required = false,
            HelpText = "Maximum number of returned rows (set to -1 to get all rows for raw report-type)")]
        public int? Limit { get; set; }

        [Option("order", Required = false,
            HelpText = "Sort order: desc, asc")]
        public string Order { get; set; }

        [Option("created", Required = false,
            HelpText = "Filter: Created date. Predefined filters: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year")]
        public string Created { get; set; }

        [Option("event-type", Required = false, Separator = ',',
            HelpText = "Filter: Audit Event Type. Can be repeated.")]
        public IEnumerable<string> EventType { get; set; }

        [Option("username", Required = false, Separator = ',',
            HelpText = "Filter: Username of event originator. Can be repeated.")]
        public IEnumerable<string> Username { get; set; }

        [Option("to-username", Required = false, Separator = ',',
            HelpText = "Filter: Username of event target. Can be repeated.")]
        public IEnumerable<string> ToUsername { get; set; }

        [Option("ip-address", Required = false, Separator = ',',
            HelpText = "Filter: IP Address(es). Can be repeated.")]
        public IEnumerable<string> IpAddress { get; set; }

        [Option("record-uid", Required = false, Separator = ',',
            HelpText = "Filter: Record UID. Can be repeated.")]
        public IEnumerable<string> RecordUid { get; set; }

        [Option("shared-folder-uid", Required = false, Separator = ',',
            HelpText = "Filter: Shared Folder UID. Can be repeated.")]
        public IEnumerable<string> SharedFolderUid { get; set; }

        [Option("geo-location", Required = false,
            HelpText = "Filter: Geo location")]
        public string GeoLocation { get; set; }

        [Option("device-type", Required = false,
            HelpText = "Filter: Device type")]
        public string DeviceType { get; set; }
    }
}

