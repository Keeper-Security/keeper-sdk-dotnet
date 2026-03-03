using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Enterprise.AuditLogCommands;
using KeeperSecurity.Vault;
using Sample.Helpers;

namespace Sample.AuditReportExamples
{
    /// <summary>
    /// Provides example for running enterprise audit reports.
    /// </summary>
    public static class AuditReportExample
    {
        private static readonly Regex ParameterRegex = new Regex(@"\${(\w+)}", RegexOptions.Compiled);

        /// <summary>
        /// Runs an audit report to retrieve recent audit events.
        /// Requires enterprise admin privileges.
        /// </summary>
        /// <param name="vault">Authenticated vault instance from Main; if null, authenticates and gets vault.</param>
        /// <param name="limit">Maximum number of events to retrieve (default: 100, max: 1000).</param>
        public static async Task RunAuditReport(VaultOnline vault, int? limit = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var rowLimit = limit ?? 100;

            try
            {

                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var auditEvents = await vault.Auth.GetAvailableEvents();
                var eventByName = new Dictionary<string, AuditEventType>(StringComparer.OrdinalIgnoreCase);
                foreach (var evt in auditEvents ?? Array.Empty<AuditEventType>())
                {
                    if (!string.IsNullOrEmpty(evt?.Name))
                    {
                        eventByName[evt.Name] = evt;
                    }
                }

                var rq = new GetAuditEventReportsCommand
                {
                    ReportType = "raw",
                    Order = "descending",
                    Limit = Math.Max(1, Math.Min(rowLimit, 1000)),
                };

                var rs = await vault.Auth.ExecuteAuthCommand<GetAuditEventReportsCommand, GetAuditEventReportsResponse>(rq);
                var rows = rs?.Events ?? new List<Dictionary<string, object>>();

                if (rows.Count == 0)
                {
                    Console.WriteLine("No audit events found.");
                    return;
                }

                Console.WriteLine($"======== Audit Report ({rows.Count} events) ========");
                Console.WriteLine();

                var tab = new Tabulate(4) { DumpRowNo = true, MaxColumnWidth = 100 };
                tab.AddHeader("Created", "Username", "Event", "Message");

                foreach (var row in rows)
                {
                    if (row == null) continue;
                    if (!row.TryGetValue("audit_event_type", out var typeObj) || typeObj == null) continue;

                    var eventName = typeObj.ToString();
                    string message = "";
                    if (eventByName.TryGetValue(eventName, out var eventType) && !string.IsNullOrEmpty(eventType?.SyslogMessage))
                    {
                        message = RenderMessage(eventType.SyslogMessage, row);
                    }

                    var created = "";
                    if (row.TryGetValue("created", out var createdObj) && createdObj != null)
                    {
                        var createdStr = createdObj.ToString();
                        if (long.TryParse(createdStr, out var epoch))
                        {
                            created = DateTimeOffset.FromUnixTimeSeconds(epoch).ToString("G");
                        }
                        else
                        {
                            created = createdStr;
                        }
                    }

                    var username = "";
                    if (row.TryGetValue("username", out var usernameObj) && usernameObj != null)
                    {
                        username = usernameObj.ToString();
                    }

                    tab.AddRow(created, username, eventName, message);
                }

                tab.Dump();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static string RenderMessage(string template, Dictionary<string, object> row)
        {
            if (string.IsNullOrEmpty(template) || row == null) return template ?? "";

            return ParameterRegex.Replace(template, m =>
            {
                var key = m.Groups.Count == 2 ? m.Groups[1].Value : "";
                if (string.IsNullOrEmpty(key)) return "";
                return row.TryGetValue(key, out var v) && v != null ? v.ToString() : "";
            });
        }
    }
}
