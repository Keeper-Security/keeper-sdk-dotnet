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

            if (reportType == "dim")
            {
                await ExecuteDimensionReport(context, options);
            }
            else if (reportType == "raw")
            {
                await ExecuteRawReport(context, options);
            }
            else if (new[] { "hour", "day", "week", "month", "span" }.Contains(reportType))
            {
                await ExecuteSummaryReport(context, options);
            }
            else
            {
                Console.WriteLine($"Invalid report type: {reportType}");
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

            List<string> fields;
            if (column == "audit_event_type")
            {
                fields = new List<string> { "id", "name", "category", "syslog" };
            }
            else if (column == "keeper_version")
            {
                fields = new List<string> { "version_id", "type_name", "version", "type_category" };
            }
            else if (column == "ip_address")
            {
                fields = new List<string> { "ip_address", "city", "region", "country_code" };
            }
            else if (column == "geo_location")
            {
                fields = new List<string> { "geo_location", "city", "region", "country_code", "ip_count" };
            }
            else if (column == "device_type")
            {
                fields = new List<string> { "type_name", "type_category" };
            }
            else
            {
                fields = new List<string> { column };
            }

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
            
            if (options.Order != null)
            {
                rawReport.Order = options.Order.ToLower() == "asc" ? ReportOrder.Asc : ReportOrder.Desc;
            }
            
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
                var row = new List<object>();
                foreach (var field in fields)
                {
                    if (field == "message")
                    {
                        row.Add(GetEventMessage(evt));
                    }
                    else
                    {
                        evt.TryGetValue(field, out var fieldValue);
                        row.Add(FormatFieldValue(field, fieldValue, "raw"));
                    }
                }
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

            if (options.Order != null)
            {
                summaryReport.Order = options.Order.ToLower() == "asc" ? ReportOrder.Asc : ReportOrder.Desc;
            }

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
                if (validPresets.Contains(options.Created))
                {
                    filter.Created = options.Created;
                }
                else
                {
                    filter.Created = ParseCreatedFilter(options.Created);
                }
            }

            var eventTypeList = options.EventType?.ToList();
            if (eventTypeList != null && eventTypeList.Count > 0)
            {
                if (eventTypeList.Count == 1)
                {
                    var value = eventTypeList[0];
                    if (int.TryParse(value, out var intValue))
                    {
                        filter.EventType = intValue;
                    }
                    else
                    {
                        filter.EventType = value;
                    }
                }
                else
                {
                    var list = new List<object>();
                    foreach (var value in eventTypeList)
                    {
                        if (int.TryParse(value, out var intValue))
                        {
                            list.Add(intValue);
                        }
                        else
                        {
                            list.Add(value);
                        }
                    }
                    filter.EventType = list;
                }
            }

            var usernameList = options.Username?.ToList();
            if (usernameList != null && usernameList.Count > 0)
            {
                filter.Username = usernameList.Count == 1 ? (object)usernameList[0] : usernameList;
            }

            var toUsernameList = options.ToUsername?.ToList();
            if (toUsernameList != null && toUsernameList.Count > 0)
            {
                filter.ToUsername = toUsernameList.Count == 1 ? (object)toUsernameList[0] : toUsernameList;
            }

            var recordUidList = options.RecordUid?.ToList();
            if (recordUidList != null && recordUidList.Count > 0)
            {
                filter.RecordUid = recordUidList.Count == 1 ? (object)recordUidList[0] : recordUidList;
            }

            var sharedFolderUidList = options.SharedFolderUid?.ToList();
            if (sharedFolderUidList != null && sharedFolderUidList.Count > 0)
            {
                filter.SharedFolderUid = sharedFolderUidList.Count == 1 ? (object)sharedFolderUidList[0] : sharedFolderUidList;
            }

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
                        {
                            foreach (var ip in ipList)
                            {
                                ipFilter.Add(ip.ToString());
                            }
                        }
                    }
                }
            }

            var ipAddressList = options.IpAddress?.ToList();
            if (ipAddressList != null && ipAddressList.Count > 0)
            {
                foreach (var ip in ipAddressList)
                {
                    ipFilter.Add(ip);
                }
            }

            if (ipFilter.Count > 0)
            {
                filter.IpAddress = ipFilter.ToList();
            }

            if (!string.IsNullOrEmpty(options.DeviceType))
            {
                var deviceComps = options.DeviceType.Split(',');
                var deviceType = (deviceComps.Length > 0 ? deviceComps[0] : "").Trim().ToLower();
                var version = (deviceComps.Length > 1 ? deviceComps[1] : "").Trim().ToLower();

                if (!string.IsNullOrEmpty(version) && !version.Contains("."))
                {
                    version += ".";
                }

                var versionFilter = new HashSet<int>();
                var deviceTypes = LoadAuditDimension(context, "device_type").Result;
                
                if (deviceTypes != null)
                {
                    foreach (var dev in deviceTypes)
                    {
                        if (!string.IsNullOrEmpty(deviceType))
                        {
                            var typeName = dev.GetValueOrDefault("type_name", "").ToString().ToLower();
                            var typeCategory = dev.GetValueOrDefault("type_category", "").ToString().ToLower();
                            if (deviceType != typeName && deviceType != typeCategory)
                                continue;
                        }

                        if (!string.IsNullOrEmpty(version))
                        {
                            var devVersion = dev.GetValueOrDefault("version", "").ToString();
                            if (!devVersion.StartsWith(version, StringComparison.OrdinalIgnoreCase))
                                continue;
                        }

                        if (dev.TryGetValue("version_ids", out var versionIds) && versionIds is List<object> versionList)
                        {
                            foreach (var vid in versionList)
                            {
                                if (vid is int intVid)
                                {
                                    versionFilter.Add(intVid);
                                }
                            }
                        }
                    }
                }

                if (versionFilter.Count > 0)
                {
                    filter.KeeperVersion = versionFilter.ToList();
                }
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
                    switch (prefix)
                    {
                        case ">=":
                            return new CreatedFilterCriteria { FromDate = value };
                        case "<=":
                            return new CreatedFilterCriteria { ToDate = value };
                        case ">":
                            return new CreatedFilterCriteria { FromDate = value, ExcludeFrom = true };
                        case "<":
                            return new CreatedFilterCriteria { ToDate = value, ExcludeTo = true };
                    }
                }
            }

            throw new ArgumentException($"Invalid created filter value: {filterValue}");
        }

        private static long ParseDateValue(string value)
        {
            value = value.Trim();

            if (long.TryParse(value, out var timestamp))
            {
                return timestamp;
            }

            DateTime dt;
            if (value.Length <= 10)
            {
                dt = DateTime.ParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture);
            }
            else
            {
                dt = DateTime.ParseExact(value, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
            }

            return new DateTimeOffset(dt, TimeSpan.Zero).ToUnixTimeSeconds();
        }

        private static async Task LoadSyslogTemplates(VaultContext context)
        {
            if (_syslogTemplates != null)
                return;

            _syslogTemplates = new Dictionary<string, string>();
            var dimReport = context.Vault.CreateDimAuditReport();
            var eventTypes = await dimReport.ExecuteDimensionReport("audit_event_type");

            foreach (var et in eventTypes)
            {
                var name = et.GetValueOrDefault("name", "").ToString();
                var syslog = et.GetValueOrDefault("syslog", "").ToString();
                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(syslog))
                {
                    _syslogTemplates[name] = syslog;
                }
            }
        }

        private static string GetEventMessage(Dictionary<string, object> evt)
        {
            if (_syslogTemplates == null)
                return "";

            var eventType = evt.GetValueOrDefault("audit_event_type", "").ToString();
            if (string.IsNullOrEmpty(eventType) || !_syslogTemplates.ContainsKey(eventType))
                return "";

            var template = _syslogTemplates[eventType];
            var message = template;

            while (true)
            {
                var match = Regex.Match(message, @"\$\{(\w+)\}");
                if (!match.Success)
                    break;

                var field = match.Groups[1].Value;
                var value = evt.GetValueOrDefault(field, "<missing>").ToString();
                message = message.Substring(0, match.Index) + value + message.Substring(match.Index + match.Length);
            }

            return message;
        }

        private static async Task<List<Dictionary<string, object>>> LoadAuditDimension(VaultContext context, string dimension)
        {
            if (_dimensionCache.ContainsKey(dimension))
            {
                return _dimensionCache[dimension];
            }

            List<Dictionary<string, object>> dimensions = null;

            if (dimension == "geo_location")
            {
                var ipDimensions = await LoadAuditDimension(context, "ip_address");
                if (ipDimensions != null)
                {
                    var geoDim = new Dictionary<string, Dictionary<string, object>>();
                    foreach (var geo in ipDimensions)
                    {
                        var location = geo.GetValueOrDefault("geo_location", "").ToString();
                        var ip = geo.GetValueOrDefault("ip_address", "").ToString();

                        if (!string.IsNullOrEmpty(location) && !string.IsNullOrEmpty(ip))
                        {
                            if (geoDim.ContainsKey(location))
                            {
                                if (geoDim[location]["ip_addresses"] is List<object> ipList)
                                {
                                    ipList.Add(ip);
                                }
                            }
                            else
                            {
                                var entry = new Dictionary<string, object>(geo);
                                entry.Remove("ip_address");
                                entry["ip_addresses"] = new List<object> { ip };
                                geoDim[location] = entry;
                            }
                        }
                    }
                    dimensions = geoDim.Values.ToList();
                    foreach (var geo in dimensions)
                    {
                        if (geo["ip_addresses"] is List<object> ipList)
                        {
                            geo["ip_count"] = ipList.Count;
                        }
                    }
                }
            }
            else if (dimension == "device_type")
            {
                var versionDimensions = await LoadAuditDimension(context, "keeper_version");
                if (versionDimensions != null)
                {
                    var deviceDim = new Dictionary<string, Dictionary<string, object>>();
                    foreach (var version in versionDimensions)
                    {
                        var typeId = version.GetValueOrDefault("type_id", "").ToString();
                        var versionId = version.GetValueOrDefault<object>("version_id", null);

                        if (!string.IsNullOrEmpty(typeId) && versionId != null)
                        {
                            if (deviceDim.ContainsKey(typeId))
                            {
                                if (deviceDim[typeId]["version_ids"] is List<object> versionList)
                                {
                                    versionList.Add(versionId);
                                }
                            }
                            else
                            {
                                var entry = new Dictionary<string, object>(version);
                                entry.Remove("version_id");
                                entry["version_ids"] = new List<object> { versionId };
                                deviceDim[typeId] = entry;
                            }
                        }
                    }
                    dimensions = deviceDim.Values.ToList();
                }
            }
            else
            {
                var dimReport = context.Vault.CreateDimAuditReport();
                dimensions = await dimReport.ExecuteDimensionReport(dimension);
            }

            if (dimensions != null)
            {
                _dimensionCache[dimension] = dimensions;
            }

            return dimensions;
        }

        private static object FormatFieldValue(string field, object value, string reportType)
        {
            if (field == "created" || field == "first_created" || field == "last_created")
            {
                if (value == null || (value is string s && string.IsNullOrEmpty(s)))
                {
                    return "";
                }

                if (value is string strValue && !string.IsNullOrEmpty(strValue))
                {
                    if (long.TryParse(strValue, out var parsed))
                    {
                        value = parsed;
                    }
                    else
                    {
                        return strValue;
                    }
                }

                long timestamp;
                try
                {
                    timestamp = Convert.ToInt64(value);
                }
                catch
                {
                    return value?.ToString() ?? "";
                }

                var dt = DateTimeOffset.FromUnixTimeSeconds(timestamp);

                if (reportType == "day" || reportType == "week")
                {
                    return dt.ToString("yyyy-MM-dd");
                }
                else if (reportType == "month")
                {
                    return dt.ToString("MMMM, yyyy");
                }
                else if (reportType == "hour")
                {
                    return dt.ToString("yyyy-MM-dd @HH:00");
                }
                else
                {
                    return dt.ToString("yyyy-MM-dd HH:mm:sszzz");
                }
            }

            return value ?? "";
        }

        private static string FieldToTitle(string field)
        {
            return string.Join(" ", field.Split('_').Select(w => char.ToUpper(w[0]) + w.Substring(1)));
        }

        private static T GetValueOrDefault<T>(this Dictionary<string, object> dict, string key, T defaultValue)
        {
            if (dict.TryGetValue(key, out var value) && value is T typedValue)
            {
                return typedValue;
            }
            return defaultValue;
        }

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

