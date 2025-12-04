using Cli;
using CommandLine;
using KeeperSecurity.Enterprise;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Commander.Enterprise
{
    [Verb("action-report", HelpText = "Run an action based on user activity report")]
    internal class ActionReportCommandOptions
    {
        [Option('t', "target", Required = false, Default = "no-logon",
            HelpText = "Target user status: no-logon, no-update, locked, invited, no-recovery")]
        public string TargetStatus { get; set; }

        [Option('d', "days-since", Required = false,
            HelpText = "Number of days since event of interest (default: 30 for most, 90 for locked)")]
        public int? DaysSince { get; set; }

        [Option("node", Required = false,
            HelpText = "Filter users by node (node name or ID)")]
        public string Node { get; set; }

        [Option('a', "apply-action", Required = false, Default = "none",
            HelpText = "Admin action to apply: none, lock, delete, transfer")]
        public string ApplyAction { get; set; }

        [Option("target-user", Required = false,
            HelpText = "Username/email of account to transfer users to when --apply-action=transfer")]
        public string TargetUser { get; set; }

        [Option('n', "dry-run", Required = false, Default = false,
            HelpText = "Enable dry-run mode (don't actually apply actions)")]
        public bool DryRun { get; set; }

        [Option('f', "force", Required = false, Default = false,
            HelpText = "Skip confirmation prompt for irreversible actions")]
        public bool Force { get; set; }

        [Option("columns", Required = false,
            HelpText = "Comma-separated list of columns to show: name, status, node, 2fa_enabled")]
        public string Columns { get; set; }

        [Option("syntax-help", Required = false, Default = false,
            HelpText = "Display detailed syntax help")]
        public bool SyntaxHelp { get; set; }
    }

    internal static class ActionReportCommandExtensions
    {
        public static async Task ActionReportCommand(this IEnterpriseContext context, ActionReportCommandOptions options)
        {
            if (options.SyntaxHelp)
            {
                DisplaySyntaxHelp();
                return;
            }

            if (!TryParseTargetStatus(options.TargetStatus, out var targetStatus))
            {
                Console.WriteLine($"Invalid target status: {options.TargetStatus}");
                Console.WriteLine("Valid values: no-logon, no-update, locked, invited, no-recovery");
                return;
            }

            if (!TryParseAdminAction(options.ApplyAction, out var adminAction))
            {
                Console.WriteLine($"Invalid action: {options.ApplyAction}");
                Console.WriteLine("Valid values: none, lock, delete, transfer");
                return;
            }

            if (adminAction == ActionReportAdminAction.Transfer && string.IsNullOrEmpty(options.TargetUser))
            {
                Console.WriteLine("Error: --target-user is required when using --apply-action=transfer");
                return;
            }

            var reportOptions = new ActionReportOptions
            {
                TargetStatus = targetStatus,
                DaysSince = options.DaysSince,
                Node = options.Node,
                ApplyAction = adminAction,
                TargetUser = options.TargetUser,
                DryRun = options.DryRun,
                Force = options.Force
            };

            void Logger(string message) => Console.WriteLine(message);

            var result = await context.EnterpriseData.RunActionReport(
                context.Enterprise.Auth,
                reportOptions,
                Logger);

            if (!string.IsNullOrEmpty(result.ErrorMessage))
            {
                Console.WriteLine($"Error: {result.ErrorMessage}");
                return;
            }

            var daysSince = options.DaysSince ?? (targetStatus == ActionReportTargetStatus.Locked ? 90 : 30);

            Console.WriteLine();
            Console.WriteLine("Admin Action Taken:");
            if (adminAction == ActionReportAdminAction.None)
            {
                Console.WriteLine("\tCOMMAND: NONE (No action specified)");
                Console.WriteLine("\tSTATUS: n/a");
                Console.WriteLine("\tSERVER MESSAGE: n/a");
                Console.WriteLine("\tAFFECTED: 0");
            }
            else
            {
                Console.WriteLine($"\tCOMMAND: {result.ActionApplied ?? "none"}");
                Console.WriteLine($"\tSTATUS: {result.ActionStatus ?? "n/a"}");
                Console.WriteLine($"\tSERVER MESSAGE: n/a");
                Console.WriteLine($"\tAFFECTED: {result.AffectedCount}");
            }

            Console.WriteLine();
            Console.WriteLine("Note: the following reflects data prior to any administrative action being applied");

            var statusDescription = GetStatusDescription(targetStatus);
            var nodeInfo = !string.IsNullOrEmpty(options.Node) ? $" in Node \"{options.Node}\"" : "";
            Console.WriteLine($"{result.Users.Count} User(s) With \"{statusDescription}\" Status Older Than {daysSince} Day(s){nodeInfo}: ");

            if (result.Users.Count == 0)
            {
                Console.WriteLine();
                return;
            }

            var columns = GetDisplayColumns(options.Columns);

            var table = new Tabulate(columns.Count)
            {
                DumpRowNo = false,
                MaxColumnWidth = int.MaxValue
            };

            table.AddHeader(columns.Select(c => c.Header).ToArray());

            foreach (var user in result.Users.OrderBy(u => u.Username))
            {
                var row = new List<object>();
                foreach (var col in columns)
                {
                    row.Add(col.GetValue(user));
                }
                table.AddRow(row.ToArray());
            }

            table.Dump();
        }

        private static bool TryParseTargetStatus(string value, out ActionReportTargetStatus status)
        {
            status = ActionReportTargetStatus.NoLogon;
            if (string.IsNullOrEmpty(value)) return true;

            switch (value.ToLowerInvariant().Replace("_", "-"))
            {
                case "no-logon":
                case "nologon":
                    status = ActionReportTargetStatus.NoLogon;
                    return true;
                case "no-update":
                case "noupdate":
                    status = ActionReportTargetStatus.NoUpdate;
                    return true;
                case "locked":
                    status = ActionReportTargetStatus.Locked;
                    return true;
                case "invited":
                    status = ActionReportTargetStatus.Invited;
                    return true;
                case "no-recovery":
                case "norecovery":
                    status = ActionReportTargetStatus.NoRecovery;
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryParseAdminAction(string value, out ActionReportAdminAction action)
        {
            action = ActionReportAdminAction.None;
            if (string.IsNullOrEmpty(value)) return true;

            switch (value.ToLowerInvariant())
            {
                case "none":
                    action = ActionReportAdminAction.None;
                    return true;
                case "lock":
                    action = ActionReportAdminAction.Lock;
                    return true;
                case "delete":
                    action = ActionReportAdminAction.Delete;
                    return true;
                case "transfer":
                    action = ActionReportAdminAction.Transfer;
                    return true;
                default:
                    return false;
            }
        }

        private static string GetStatusDescription(ActionReportTargetStatus status)
        {
            switch (status)
            {
                case ActionReportTargetStatus.NoLogon: return "No-logon";
                case ActionReportTargetStatus.NoUpdate: return "No-update";
                case ActionReportTargetStatus.Locked: return "Locked";
                case ActionReportTargetStatus.Invited: return "Invited";
                case ActionReportTargetStatus.NoRecovery: return "No-recovery";
                default: return status.ToString();
            }
        }

        private static List<ColumnDefinition> GetDisplayColumns(string columnsOption)
        {
            var allColumns = new Dictionary<string, ColumnDefinition>(StringComparer.OrdinalIgnoreCase)
            {
                { "user_id", new ColumnDefinition("User ID", u => u.UserId) },
                { "email", new ColumnDefinition("Email", u => u.Username) },
                { "name", new ColumnDefinition("Name", u => u.DisplayName ?? "") },
                { "status", new ColumnDefinition("Status", u => u.Status.ToString()) },
                { "transfer_status", new ColumnDefinition("Transfer Status", u => u.TransferStatus ?? "") },
                { "node", new ColumnDefinition("Node", u => u.NodePath ?? "") },
            };

            var defaultColumns = new[] { "user_id", "email", "name", "status", "transfer_status", "node" };

            List<string> selectedColumns;
            if (string.IsNullOrEmpty(columnsOption))
            {
                selectedColumns = defaultColumns.ToList();
            }
            else
            {
                selectedColumns = columnsOption.Split(',')
                    .Select(c => c.Trim().ToLowerInvariant().Replace(" ", "_"))
                    .Where(c => allColumns.ContainsKey(c))
                    .ToList();

                if (!selectedColumns.Contains("email"))
                {
                    selectedColumns.Insert(0, "email");
                }
            }

            return selectedColumns.Select(c => allColumns[c]).ToList();
        }

        private class ColumnDefinition
        {
            public string Header { get; }
            public Func<ActionReportUser, object> GetValue { get; }

            public ColumnDefinition(string header, Func<ActionReportUser, object> getValue)
            {
                Header = header;
                GetValue = getValue;
            }
        }

        private static void DisplaySyntaxHelp()
        {
            Console.WriteLine(@"
Action Report Command Syntax Description:

This command generates a report of users based on their activity (or lack thereof)
and can optionally apply administrative actions to those users.

Target Statuses (--target, -t):
  no-logon      Users who haven't logged in within the specified period
                Allowed actions: none, lock

  no-update     Users who haven't added or updated records
                Allowed actions: none

  locked        Users who have been locked for the specified period
                Allowed actions: none, delete, transfer

  invited       Users who have been invited but haven't accepted
                Allowed actions: none, delete

  no-recovery   Users who haven't set up account recovery
                Allowed actions: none

Options:
  --target, -t <status>     Target user status (default: no-logon)
  --days-since, -d <days>   Number of days since event (default: 30, or 90 for locked)
  --node <name|id>          Filter users by node (includes child nodes)
  --apply-action, -a <act>  Admin action: none, lock, delete, transfer
  --target-user <email>     Target user for transfer action
  --dry-run, -n             Preview action without executing
  --force, -f               Skip confirmation for destructive actions
  --columns <cols>          Columns to display: email, name, status, node

Examples:
  action-report                               Users who haven't logged in (30 days)
  action-report --target=no-logon --days-since=60
                                              Users inactive for 60 days
  action-report --target=locked --apply-action=delete --dry-run
                                              Preview deleting locked users
  action-report --target=no-logon --apply-action=lock --node=""Sales""
                                              Lock inactive users in Sales node
  action-report --target=locked --apply-action=transfer --target-user=admin@company.com
                                              Transfer locked user accounts
");
        }
    }
}

