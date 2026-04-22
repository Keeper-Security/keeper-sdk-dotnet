using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using RMD;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace KeeperSecurity.Enterprise
{
    public class RiskManagementEnterpriseStatResult
    {
        public int UsersLoggedRecent { get; set; }
        public int UsersHasRecords { get; set; }
    }

    public class RiskManagementEnterpriseStatDetailResult
    {
        public long EnterpriseUserId { get; set; }
        public string Username { get; set; }
        public long LastLoggedInMs { get; set; }
        public bool HasRecords { get; set; }
    }

    public class RiskManagementSecurityAlertSummaryResult
    {
        public int AuditEventTypeId { get; set; }
        public string EventName { get; set; }
        public int CurrentCount { get; set; }
        public int PreviousCount { get; set; }
        public int CurrentUserCount { get; set; }
        public int PreviousUserCount { get; set; }
    }

    public class RiskManagementSecurityAlertDetailResult
    {
        public long EnterpriseUserId { get; set; }
        public string Username { get; set; }
        public int CurrentCount { get; set; }
        public int PreviousCount { get; set; }
        public long LastOccurrenceMs { get; set; }
    }

    public class RiskManagementSecurityBenchmarkResult
    {
        public string BenchmarkName { get; set; }
        public string Status { get; set; }
        public long LastUpdatedMs { get; set; }
        public bool AutoResolve { get; set; }
    }

    public static class RiskManagementExtensions
    {
        private static string GetProtoEnumName<T>(T value) where T : struct, Enum
        {
            var field = typeof(T).GetField(value.ToString());
            var attr = field?.GetCustomAttribute<Google.Protobuf.Reflection.OriginalNameAttribute>();
            return attr?.Name ?? value.ToString();
        }

        private static bool TryParseProtoEnum<T>(string input, out T result) where T : struct, Enum
        {
            var normalized = input.Replace("_", "");
            return Enum.TryParse(normalized, true, out result);
        }

        private static string GetValidProtoEnumNames<T>() where T : struct, Enum
        {
            return string.Join(", ", Enum.GetValues(typeof(T)).Cast<T>().Select(GetProtoEnumName));
        }

        /// <summary>
        /// Fetches audit event type dimensions mapping event IDs to names.
        /// </summary>
        public static async Task<Dictionary<int, string>> GetAuditEventDimensions(
            this IAuthentication auth)
        {
            var command = new GetAuditEventDimensionsCommand();
            var response = await auth.ExecuteAuthCommand<GetAuditEventDimensionsCommand, GetAuditEventDimensionsResponse>(command);
            var result = new Dictionary<int, string>();
            if (response?.Dimensions?.AuditEventTypes != null)
            {
                foreach (var et in response.Dimensions.AuditEventTypes)
                {
                    if (!string.IsNullOrEmpty(et.Name))
                    {
                        result[et.Id] = et.Name;
                    }
                }
            }
            return result;
        }

        public static async Task<RiskManagementEnterpriseStatResult> GetRiskManagementEnterpriseStat(
            this IAuthentication auth)
        {
            var rs = (EnterpriseStat) await auth.ExecuteAuthRest(
                "rmd/get_enterprise_stat", null, typeof(EnterpriseStat));

            return new RiskManagementEnterpriseStatResult
            {
                UsersLoggedRecent = rs.UsersLoggedRecent,
                UsersHasRecords = rs.UsersHasRecords
            };
        }

        public static async Task<List<RiskManagementEnterpriseStatDetailResult>> GetRiskManagementEnterpriseStatDetails(
            this EnterpriseData enterpriseData, IAuthentication auth)
        {
            var results = new List<RiskManagementEnterpriseStatDetailResult>();
            long lastUpdated = 0;
            long tokenLastUpdated = 0;
            long tokenUserId = 0;
            bool done = false;

            while (!done)
            {
                var rq = new EnterpriseStatDetailsRequest();
                if (lastUpdated > 0)
                {
                    rq.LastUpdated = lastUpdated;
                }
                if (tokenUserId > 0 || tokenLastUpdated > 0)
                {
                    rq.ContinuationToken = new EnterpriseStatContinuationToken
                    {
                        EnterpriseUserId = tokenUserId,
                        LastUpdated = tokenLastUpdated
                    };
                }

                var rs = await auth.ExecuteAuthRest<EnterpriseStatDetailsRequest, EnterpriseStatDetailsResponse>(
                    "rmd/get_enterprise_stat_details", rq);

                done = !rs.HasMore;
                if (!done)
                {
                    lastUpdated = rs.LastUpdated;
                    tokenLastUpdated = rs.ContinuationToken?.LastUpdated ?? 0;
                    tokenUserId = rs.ContinuationToken?.EnterpriseUserId ?? 0;
                }

                foreach (var detail in rs.EnterpriseStatDetails)
                {
                    string username = null;
                    if (enterpriseData.TryGetUserById(detail.EnterpriseUserId, out var user))
                    {
                        username = user.Email;
                    }

                    results.Add(new RiskManagementEnterpriseStatDetailResult
                    {
                        EnterpriseUserId = detail.EnterpriseUserId,
                        Username = username ?? detail.EnterpriseUserId.ToString(),
                        LastLoggedInMs = detail.LastLoggedIn,
                        HasRecords = detail.HasRecords
                    });
                }
            }

            return results;
        }

        public static async Task<List<RiskManagementSecurityAlertSummaryResult>> GetRiskManagementSecurityAlertsSummary(
            this IAuthentication auth)
        {
            var eventDimensions = await auth.GetAuditEventDimensions();

            var rs = (SecurityAlertsSummaryResponse) await auth.ExecuteAuthRest(
                "rmd/get_security_alerts_summary", null, typeof(SecurityAlertsSummaryResponse));

            var results = new List<RiskManagementSecurityAlertSummaryResult>();
            foreach (var sas in rs.SecurityAlertsSummary)
            {
                eventDimensions.TryGetValue(sas.AuditEventTypeId, out var eventName);
                results.Add(new RiskManagementSecurityAlertSummaryResult
                {
                    AuditEventTypeId = sas.AuditEventTypeId,
                    EventName = eventName,
                    CurrentCount = sas.CurrentCount,
                    PreviousCount = sas.PreviousCount,
                    CurrentUserCount = sas.CurrentUserCount,
                    PreviousUserCount = sas.PreviousUserCount
                });
            }
            return results;
        }

        public static async Task<List<RiskManagementSecurityAlertDetailResult>> GetRiskManagementSecurityAlertsDetail(
            this EnterpriseData enterpriseData, IAuthentication auth, int auditEventTypeId)
        {
            var results = new List<RiskManagementSecurityAlertDetailResult>();
            bool done = false;
            long continuationToken = 0;

            while (!done)
            {
                var rq = new SecurityAlertsDetailRequest
                {
                    AuditEventTypeId = auditEventTypeId,
                    ContinuationToken = continuationToken
                };

                var rs = await auth.ExecuteAuthRest<SecurityAlertsDetailRequest, SecurityAlertsDetailResponse>(
                    "rmd/get_security_alerts_detail", rq);

                done = !rs.HasMore;
                continuationToken = rs.ContinuationToken;

                foreach (var detail in rs.SecurityAlertDetails)
                {
                    string username = null;
                    if (enterpriseData.TryGetUserById(detail.EnterpriseUserId, out var user))
                    {
                        username = user.Email;
                    }

                    results.Add(new RiskManagementSecurityAlertDetailResult
                    {
                        EnterpriseUserId = detail.EnterpriseUserId,
                        Username = username ?? detail.EnterpriseUserId.ToString(),
                        CurrentCount = detail.CurrentCount,
                        PreviousCount = detail.PreviousCount,
                        LastOccurrenceMs = detail.LastOccurrence
                    });
                }
            }

            return results;
        }

        public static async Task<List<RiskManagementSecurityBenchmarkResult>> GetRiskManagementSecurityBenchmarks(
            this IAuthentication auth)
        {
            var rs = (GetSecurityBenchmarksResponse) await auth.ExecuteAuthRest(
                "rmd/get_security_benchmarks", null, typeof(GetSecurityBenchmarksResponse));

            var results = new List<RiskManagementSecurityBenchmarkResult>();
            foreach (var benchmark in rs.EnterpriseSecurityBenchmarks)
            {
                results.Add(new RiskManagementSecurityBenchmarkResult
                {
                    BenchmarkName = GetProtoEnumName(benchmark.SecurityBenchmark),
                    Status = GetProtoEnumName(benchmark.SecurityBenchmarkStatus),
                    LastUpdatedMs = benchmark.LastUpdated,
                    AutoResolve = benchmark.AutoResolve
                });
            }
            return results;
        }

        public static async Task SetRiskManagementSecurityBenchmarks(
            this IAuthentication auth, Dictionary<string, string> benchmarkUpdates)
        {
            var rq = new SetSecurityBenchmarksRequest();
            foreach (var kvp in benchmarkUpdates)
            {
                if (!TryParseProtoEnum<SecurityBenchmark>(kvp.Key, out var benchmarkEnum))
                    throw new ArgumentException(
                        $"Invalid benchmark name: '{kvp.Key}'. Valid values: {GetValidProtoEnumNames<SecurityBenchmark>()}");
                if (!TryParseProtoEnum<SecurityBenchmarkStatus>(kvp.Value, out var statusEnum))
                    throw new ArgumentException(
                        $"Invalid benchmark status: '{kvp.Value}'. Valid values: {GetValidProtoEnumNames<SecurityBenchmarkStatus>()}");

                var esb = new EnterpriseSecurityBenchmark
                {
                    SecurityBenchmark = benchmarkEnum,
                    SecurityBenchmarkStatus = statusEnum
                };
                rq.EnterpriseSecurityBenchmarks.Add(esb);
            }

            await auth.ExecuteAuthRest("rmd/set_security_benchmarks", rq, null);
        }
    }
}
