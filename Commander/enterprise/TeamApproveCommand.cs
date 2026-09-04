using Cli;
using CommandLine;
using KeeperSecurity.Authentication;
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

        [Option("output", Required = false, HelpText = "Output file for --dry-run when --format is csv or json.")]
        public string Output { get; set; }
    }

    internal static class TeamApproveCommandExtensions
    {
        public static async Task TeamApproveCommand(this IEnterpriseContext context, TeamApproveCommandOptions arguments)
        {
            if (context.EnterpriseData == null)
            {
                Console.WriteLine("Error: Enterprise data is not available. Connect as an enterprise administrator and try again.");
                return;
            }

            if (context.QueuedTeamManagement?.Enterprise == null)
            {
                Console.WriteLine("Error: Queued team data is not available. Connect as an enterprise administrator and try again.");
                return;
            }

            if (arguments.Force)
            {
                // EnterpriseLoader owns the queued-team plugin, so loading through
                // that plugin explicitly refreshes the data used below.
                await context.QueuedTeamManagement.Enterprise.Load();
            }

            if (!TryParseRestrictFlag(arguments.RestrictEdit, "restrict-edit", out var restrictEdit)
                || !TryParseRestrictFlag(arguments.RestrictShare, "restrict-share", out var restrictShare)
                || !TryParseRestrictFlag(arguments.RestrictView, "restrict-view", out var restrictView))
            {
                return;
            }

            var approveTeams = (!arguments.Team && !arguments.Email) || arguments.Team;
            var approveUsers = (!arguments.Team && !arguments.Email) || arguments.Email;

            TeamApproveResult result;
            try
            {
                result = await context.EnterpriseData.ApproveQueuedTeams(context.QueuedTeamManagement, new TeamApproveOptions
                {
                    ApproveTeams = approveTeams,
                    ApproveUsers = approveUsers,
                    RestrictEdit = restrictEdit,
                    RestrictShare = restrictShare,
                    RestrictView = restrictView,
                    DryRun = arguments.DryRun,
                    Warnings = Console.WriteLine,
                });
            }
            catch (KeeperApiException ex)
            {
                Console.WriteLine($"Team approval failed: {ex.Message}");
                return;
            }

            if (result.Actions == null || result.Actions.Count == 0)
            {
                Console.WriteLine("No queued teams or users to approve.");
                return;
            }

            if (arguments.DryRun)
            {
                if (!TryResolveDryRunFormat(arguments, out var format))
                {
                    return;
                }

                WriteDryRunOutput(arguments, format, result.Actions);
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

        private static bool TryResolveDryRunFormat(TeamApproveCommandOptions arguments, out string format)
        {
            format = (arguments.Format ?? "table").ToLowerInvariant();
            if (format != "table" && format != "csv" && format != "json")
            {
                Console.WriteLine($"Invalid value for --format: \"{arguments.Format}\". Use table, csv, or json.");
                return false;
            }

            if (!string.IsNullOrEmpty(arguments.Output) && format == "table")
            {
                Console.WriteLine("Output file is ignored for table format. Use csv or json.");
            }

            return true;
        }

        private static void WriteDryRunOutput(TeamApproveCommandOptions arguments, string format, IReadOnlyList<TeamApproveAction> actions)
        {
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

            if (!string.IsNullOrEmpty(arguments.Output) && format != "table")
            {
                try
                {
                    using var writer = new StreamWriter(arguments.Output);
                    EnterpriseExtensions.WriteFormattedOutput(writer, format, headers, rows, jsonData);
                    Console.WriteLine($"Output written to {arguments.Output}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Failed to write output to \"{arguments.Output}\": {e.Message}");
                }
                return;
            }

            EnterpriseExtensions.WriteFormattedOutput(Console.Out, format, headers, rows, jsonData);
        }
    }
}
