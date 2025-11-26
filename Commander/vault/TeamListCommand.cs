using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    internal static class TeamListCommandExtensions
    {
        public static async Task TeamListCommand(this VaultContext context, TeamListCommandOptions options)
        {
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Warning || severity == Severity.Error || severity == Severity.Information)
                {
                    Console.WriteLine(message);
                }
                Debug.WriteLine(message);
            }

            var teamOptions = new TeamListOptions
            {
                Verbose = options.Verbose,
                VeryVerbose = options.VeryVerbose,
                ShowAllTeams = options.All,
                SortBy = options.Sort ?? "company"
            };

            try
            {
                var teams = await context.Vault.GetTeamList(teamOptions, Logger);

                if (teams.Count == 0)
                {
                    Console.WriteLine("No teams found.");
                    return;
                }

                Console.WriteLine($"Found {teams.Count} team(s).");
                Console.WriteLine();

                DisplayTeams(teams, options);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Error: Access denied. {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: Failed to retrieve team list. {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        private static void DisplayTeams(System.Collections.Generic.List<TeamListItem> teams, TeamListCommandOptions options)
        {
            var showMembers = options.Verbose || options.VeryVerbose;
            var columnCount = showMembers ? 4 : 3;

            var table = new Tabulate(columnCount)
            {
                DumpRowNo = true,
                LeftPadding = 4
            };

            var headers = new[] { "Company", "Team UID", "Name" };
            if (showMembers)
            {
                headers = headers.Concat(new[] { "Members" }).ToArray();
            }

            table.AddHeader(headers);

            foreach (var team in teams)
            {
                var members = showMembers && team.Members != null && team.Members.Count > 0
                    ? string.Join("\n", team.Members)
                    : "";

                var row = showMembers
                    ? new object[] { team.Company ?? "", team.TeamUid ?? "", team.Name ?? "", members }
                    : new object[] { team.Company ?? "", team.TeamUid ?? "", team.Name ?? "" };

                table.AddRow(row);
            }

            table.Dump();
        }

    }

    class TeamListCommandOptions
    {
        [Option('v', "verbose", Required = false, Default = false,
            HelpText = "Verbose output (include team membership info)")]
        public bool Verbose { get; set; }

        [Option("very-verbose", Required = false, Default = false,
            HelpText = "More verbose output (fetches team membership info not in cache)")]
        public bool VeryVerbose { get; set; }

        [Option('a', "all", Required = false, Default = false,
            HelpText = "Show all teams in your contacts (including those outside your primary organization)")]
        public bool All { get; set; }

        [Option("sort", Required = false, Default = "company",
            HelpText = "Sort teams by column: company, team_uid, name (default: company)")]
        public string Sort { get; set; }
    }
}

