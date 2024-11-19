using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise.AuditLogCommands;

namespace KeeperSecurity
{
    namespace Commands 
    {
        [DataContract]
        public class GetAuditEventDimensionsCommand : AuthenticatedCommand
        {
            public GetAuditEventDimensionsCommand() : base("get_audit_event_dimensions")
            {
            }

            [DataMember(Name = "scope")]
            public string Scope { get; private set; } = "enterprise";

            [DataMember(Name = "columns")]
            public string[] Columns { get; private set; } = { "audit_event_type" };
        }

        [DataContract]
        public class AuditEventType
        {
            [DataMember(Name = "id", EmitDefaultValue = false)]
            public int Id { get; set; }

            [DataMember(Name = "name", EmitDefaultValue = false)]
            public string Name { get; set; }

            [DataMember(Name = "category", EmitDefaultValue = false)]
            public string Category { get; set; }

            [DataMember(Name = "critical", EmitDefaultValue = false)]
            public bool Critical { get; set; }

            [DataMember(Name = "syslog", EmitDefaultValue = false)]
            public string SyslogMessage { get; set; }
        }

        [DataContract]
        public class ReportDimensions
        {

            [DataMember(Name = "audit_event_type")]
            public AuditEventType[] AuditEventTypes { get; set; }

        }

        [DataContract]
        public class GetAuditEventDimensionsResponse : KeeperApiResponse
        {

            [DataMember(Name = "dimensions")]
            public ReportDimensions Dimensions { get; private set; }
        }
    }

    namespace Enterprise
    {
        
        namespace AuditLogCommands
        {
            /// <summary>
            /// Represents Event Period Filter
            /// </summary>
            [DataContract]
            public class CreatedFilter
            {
                /// <summary>
                /// Maximum value.
                /// </summary>
                /// <remarks>UNIX epoch time in seconds</remarks>
                [DataMember(Name = "max", EmitDefaultValue = false)]
                public long? Max { get; set; }

                /// <summary>
                /// Mimimum value.
                /// </summary>
                /// <remarks>UNIX epoch time in seconds</remarks>
                [DataMember(Name = "min", EmitDefaultValue = false)]
                public long? Min { get; set; }

                /// <summary>
                /// Exclude Maximum value.
                /// </summary>
                /// <remarks>Less than Maxinum value if true</remarks>
                [DataMember(Name = "exclude_max")]
                public bool ExcludeMax { get; set; } = true;

                /// <summary>
                /// Exclude Minimum value.
                /// </summary>
                /// <remarks>Greater than Mininum value if true</remarks>
                [DataMember(Name = "exclude_min")]
                public bool ExcludeMin { get; set; }
            }

            /// <summary>
            /// Represents Audit Report Filter
            /// </summary>
            [DataContract]
            public class ReportFilter
            {
                /// <summary>
                /// Event Types
                /// </summary>
                /// <seealso cref="Enterprise.AuditLogExtensions.GetAvailableEvents"/>
                [DataMember(Name = "audit_event_type", EmitDefaultValue = false)]
                public string[] EventTypes { get; set; }

                /// <summary>
                /// Users
                /// </summary>
                [DataMember(Name = "username", EmitDefaultValue = false)]
                public string[] Username { get; set; }

                /// <summary>
                /// Target Users
                /// </summary>
                [DataMember(Name = "to_username", EmitDefaultValue = false)]
                public string[] ToUsername { get; set; }

                /// <summary>
                /// Record UIDs
                /// </summary>
                [DataMember(Name = "record_uid", EmitDefaultValue = false)]
                public string[] RecordUid { get; set; }

                /// <summary>
                /// Shared Folder UIDs
                /// </summary>
                [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
                public string[] SharedFolderUid { get; set; }

                /// <summary>
                /// Event Time
                /// </summary>
                /// <seealso cref="CreatedFilter"/>
                /// <remarks>Predefined Filters: today, yesterday, last_30_days, last_7_days, month_to_date, last_month, year_to_date, last_year</remarks>
                [DataMember(Name = "created", EmitDefaultValue = false)]
                public object Created { get; set; }
            }

            /// <summary>
            /// Represents Audit Report Command
            /// </summary>
            [DataContract]
            public class GetAuditEventReportsCommand : AuthenticatedCommand
            {
                /// <exclude />
                public GetAuditEventReportsCommand() : base("get_audit_event_reports")
                {
                }

                /// <summary>
                /// Report Type
                /// <list type="table">
                /// <listheader><term>Report Type</term><description>Description</description></listheader>
                /// <item><term>raw</term><description>Plain audit events. Default.</description></item>
                /// <item><term>span</term><description>Events consolidated by <see cref="GetAuditEventReportsCommand.Columns"/>. Creation time is dropped.</description></item>
                /// <item><term>month</term><description>Events consolidated by event month and <see cref="GetAuditEventReportsCommand.Columns"/>.</description></item>
                /// <item><term>week</term><description>consolidated by event week ...</description></item>
                /// <item><term>day</term><description>consolidated by event day ...</description></item>
                /// <item><term>hour</term><description>consolidated by event hour ...</description></item>
                /// </list>
                /// </summary>
                [DataMember(Name = "report_type")]
                public string ReportType { get; set; } = "raw";

                /// <summary>
                /// Report Scope
                /// <list type="table">
                /// <listheader><term>Scope</term><description>Description</description></listheader>
                /// <item><term>enterprise</term><description>Enterprise</description></item>
                /// <item><term>user</term><description>Logged in user</description></item>
                /// </list>
                /// </summary>
                [DataMember(Name = "scope")]
                public string Scope { get; internal set; } = "enterprise";

                /// <summary>
                /// Sort Order
                /// <list type="table">
                /// <listheader><term>Sort Order</term><description>Description</description></listheader>
                /// <item><term>descending</term><description>Default</description></item>
                /// <item><term>ascending</term><description></description></item>
                /// </list>
                /// </summary>
                [DataMember(Name = "order")]
                public string Order { get; set; } = "descending";

                /// <summary>
                /// Number of rows to return
                /// </summary>
                /// <remarks>Maximum: 1000 - raw reports, 2000 - consolidated reports</remarks>
                [DataMember(Name = "limit")]
                public int Limit { get; set; } = 1000;

                /// <summary>
                /// Repord Filder
                /// </summary>
                /// <seealso cref="ReportFilter"/>
                [DataMember(Name = "filter", EmitDefaultValue = false)]
                public ReportFilter Filter { get; set; }

                /// <summary>
                /// Aggregate columns
                /// <list type="table">
                /// <listheader><term>Column</term><description>Description</description></listheader>
                /// <item><term>occurrences</term><description>Event count</description></item>
                /// <item><term>first_created</term><description>First event time. MIN(Created)</description></item>
                /// <item><term>last_created</term><description>Last event time. MAX(Created)</description></item>
                /// </list>
                /// </summary>
                /// <remarks>Consolidated reports only.</remarks>
                [DataMember(Name = "aggregate", EmitDefaultValue = false)]
                public string[] Aggregate { get; set; }

                /// <summary>
                /// Group by columns
                /// <list type="table">
                /// <listheader><term>Column</term><description>Description</description></listheader>
                /// <item><term>audit_event_type</term><description>Event Type</description></item>
                /// <item><term>username</term><description>Username</description></item>
                /// <item><term>ip_address</term><description>IP Address</description></item>
                /// <item><term>keeper_version</term><description>Keeper Client Version</description></item>
                /// <item><term>to_username</term><description>Target Username</description></item>
                /// <item><term>record_uid</term><description>Record UID</description></item>
                /// <item><term>shared_folder_uid</term><description>Shared Folder UID</description></item>
                /// <item><term>team_uid</term><description>Team UID</description></item>
                /// </list>
                /// </summary>
                [DataMember(Name = "columns", EmitDefaultValue = false)]
                public string[] Columns { get; set; }
            }

            /// <summary>
            /// Represents Audit Report Response
            /// </summary>
            [DataContract]
            public class GetAuditEventReportsResponse : KeeperApiResponse
            {
                /// <summary>
                /// Events
                /// </summary>
                [DataMember(Name = "audit_event_overview_report_rows")]
                public List<Dictionary<string, object>> Events { get; private set; }
            }

        }

        /// <summary>
        /// Enterprise Audit Log access methods.
        /// </summary>
        public static class AuditLogExtensions
        {

            /// <summary>
            /// Gets the list of all available audit events
            /// </summary>
            /// <param name="auth">Keeper Connection</param>
            /// <returns>Awaitable task returning supported audit events</returns>
            public static async Task<AuditEventType[]> GetAvailableEvents(this IAuthentication auth)
            {
                var rq = new GetAuditEventDimensionsCommand();
                var rs = await auth.ExecuteAuthCommand<GetAuditEventDimensionsCommand, GetAuditEventDimensionsResponse>(rq);
                return rs.Dimensions?.AuditEventTypes;
            }

            /// <summary>
            /// Gets audit events in descending order.
            /// </summary>
            /// <param name="auth">Keeper Connection</param>
            /// <param name="filter">Audit report filetr</param>
            /// <param name="recentUnixTime">Recent event epoch time in seconds</param>
            /// <param name="latestUnixTime">Latest event epoch time in seconds</param>
            /// <returns>Awaitable task returning a tuple. Item1 contains the audit event list. Item2 the epoch time in seconds to resume</returns>
            /// <seealso cref="ReportFilter"/>
            /// <remarks>
            ///     This method returns first 1000 events. To get the next chunk of audit events pass the second parameter of result into <c>recentUnixTime</c> parameter.
            ///     Created property of <paramref name="filter"/> is ignored.
            /// </remarks>
            public static async Task<Tuple<GetAuditEventReportsResponse, long>> GetEvents(this IAuthentication auth, ReportFilter filter, long recentUnixTime, long latestUnixTime = 0)
            {
                if (recentUnixTime < 0 || latestUnixTime < 0 || filter == null)
                {
                    return null;
                }

                if (recentUnixTime == 0)
                {
                    recentUnixTime = DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000;
                }

                filter.Created = new CreatedFilter
                {
                    Max = recentUnixTime == 0 ? null : recentUnixTime,
                    Min = latestUnixTime == 0 ? null : latestUnixTime
                };

                var rq = new GetAuditEventReportsCommand
                {
                    Filter = filter,
                    Limit = 1000,
                    ReportType = "raw",
                    Order = "descending"

                };

                var rs = await auth.ExecuteAuthCommand<GetAuditEventReportsCommand, GetAuditEventReportsResponse>(rq);
                var response = Tuple.Create<GetAuditEventReportsResponse, long>(rs, -1);
                if (rs.Events == null || rs.Events.Count == 0) return response;
                if (rq.Limit > 0 && rs.Events.Count < 0.95 * rq.Limit) return response;

                var pos = rs.Events.Count - 1;
                if (!rs.Events[pos].TryGetValue("created", out var lastCreated)) return response;

                while (pos > 0)
                {
                    pos--;
                    if (rs.Events[pos].TryGetValue("created", out var created))
                    {
                        if (!Equals(created, lastCreated))
                        {
                            break;
                        }
                    }
                }

                if (pos <= 0 || pos >= rs.Events.Count - 1) return response;
                if (!(lastCreated is IConvertible conv)) return response;

                rs.Events.RemoveRange(pos + 1, rs.Events.Count - pos - 1);
                return Tuple.Create(rs, conv.ToInt64(CultureInfo.InvariantCulture) + 1);
            }



            /// <summary>
            /// Gets audit events for a user in descending order.
            /// </summary>
            /// <param name="auth">Keeper Connection</param>
            /// <param name="forUser">User email</param>
            /// <param name="recentUnixTime">Recent event epoch time in seconds</param>
            /// <param name="latestUnixTime">Latest event epoch time in seconds</param>
            /// <returns>Awaitable task returning a tuple. Item1 contains the audit event list. Item2 the epoch time in seconds to resume</returns>
            /// <remarks>This method returns first 1000 events. To get the next chunk of audit events pass the second parameter of result into <c>recentUnixTime</c> parameter.</remarks>
            public static Task<Tuple<GetAuditEventReportsResponse, long>> GetUserEvents(this IAuthentication auth, string forUser, long recentUnixTime, long latestUnixTime = 0)
            {
                var filter = new ReportFilter
                {
                    Username = new[] { forUser },
                };
                return auth.GetEvents(filter, recentUnixTime, latestUnixTime);
            }
        }
    }
}
