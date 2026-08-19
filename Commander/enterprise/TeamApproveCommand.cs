using Cli;
using CommandLine;
using KeeperSecurity.Enterprise;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    [Verb("team-approve", HelpText = "Approve queued teams and users provisioned by SCIM or Active Directory Bridge")]
    internal class TeamApproveCommandOptions : EnterpriseGenericOptions
    {
        [Option("team", Required = false, Default = false, HelpText = "Approve queued teams only.")]
        public bool Team { get; set; }

        [Option("email", Required = false, Default = false, HelpText = "Approve queued team users only.")]
        public bool Email { get; set; }

        [Option("restrict-edit", Required = false, HelpText = "ON | OFF: disable record edits for approved teams.")]
        public string RestrictEdit { get; set; }

        [Option("restrict-share", Required = false, HelpText = "ON | OFF: disable record re-shares for approved teams.")]
        public string RestrictShare { get; set; }

        [Option("restrict-view", Required = false, HelpText = "ON | OFF: disable view/copy passwords for approved teams.")]
        public string RestrictView { get; set; }

        [Option("dry-run", Required = false, Default = false, HelpText = "Report planned approvals only. Do not run.")]
        public bool DryRun { get; set; }

        [Option("format", Required = false, Default = "table", HelpText = "Output format for --dry-run: table, csv, json")]
        public string Format { get; set; }

        [Option("output", Required = false, HelpText = "Output file for --dry-run (csv or json).")]
        public string Output { get; set; }
    }

    internal static class TeamApproveCommandExtensions
    {
        public static async Task TeamApproveCommand(this IEnterpriseContext context, TeamApproveCommandOptions arguments)
        {
            if (arguments.Force)
            {
                await context.Enterprise.Load();
            }

            if (!TryParseRestrictFlag(arguments.RestrictEdit, "restrict-edit", out var restrictEdit)
                || !TryParseRestrictFlag(arguments.RestrictShare, "restrict-share", out var restrictShare)
                || !TryParseRestrictFlag(arguments.RestrictView, "restrict-view", out var restrictView))
            {
                return;
            }

            var format = (arguments.Format ?? "table").ToLowerInvariant();
            if (format != "table" && format != "csv" && format != "json")
            {
                Console.WriteLine($"Invalid value for --format: \"{arguments.Format}\". Use table, csv, or json.");
                return;
            }
            arguments.Format = format;

            var approveTeams = !arguments.Team && !arguments.Email || arguments.Team;
            var approveUsers = !arguments.Team && !arguments.Email || arguments.Email;

            var result = await context.EnterpriseData.ApproveQueuedTeams(context.QueuedTeamManagement, new TeamApproveOptions
            {
                ApproveTeams = approveTeams,
                ApproveUsers = approveUsers,
                RestrictEdit = restrictEdit,
                RestrictShare = restrictShare,
                RestrictView = restrictView,
                DryRun = arguments.DryRun,
                Warnings = Console.WriteLine,
            });

            if (result.Actions == null || result.Actions.Count == 0)
            {
                Console.WriteLine("No queued teams or users to approve.");
                return;
            }

            if (arguments.DryRun)
            {
                WriteDryRunOutput(arguments, result.Actions);
                return;
            }

            if (result.TeamsApproved > 0 || result.TeamsFailed > 0)
            {
                Console.WriteLine($"Team approval: success {result.TeamsApproved}; failure {result.TeamsFailed}");
            }

            if (result.UsersApproved > 0 || result.UsersFailed > 0)
            {
                Console.WriteLine($"Team User approval: success {result.UsersApproved}; failure {result.UsersFailed}");
            }
        }

        private static bool TryParseRestrictFlag(string value, string flagName, out bool result)
        {
            result = false;
            if (string.IsNullOrEmpty(value))
            {
                return true;
            }

            if (CliCommands.ParseBoolOption(value, out result))
            {
                return true;
            }

            Console.WriteLine($"Invalid value for --{flagName}: \"{value}\". Use on or off.");
            return false;
        }

        private static void WriteDryRunOutput(TeamApproveCommandOptions arguments, IReadOnlyList<TeamApproveAction> actions)
        {
            var format = arguments.Format?.ToLowerInvariant() ?? "table";
            var headers = new[] { "Action", "Team", "User" };
            var rows = actions
                .Select(a => new object[] { a.Action, a.TeamName ?? a.TeamUid, a.UserEmail ?? "" })
                .ToList();
            var jsonData = actions.Select(a => new Dictionary<string, object>
            {
                ["action"] = a.Action,
                ["team"] = a.TeamName ?? a.TeamUid,
                ["user"] = a.UserEmail ?? "",
            }).ToList();

            if (!string.IsNullOrEmpty(arguments.Output))
            {
                using var writer = new StreamWriter(arguments.Output);
                EnterpriseExtensions.WriteFormattedOutput(writer, format, headers, rows, jsonData);
                Console.WriteLine($"Output written to {arguments.Output}");
                return;
            }

            EnterpriseExtensions.WriteFormattedOutput(Console.Out, format, headers, rows, jsonData);
        }
    }
}
