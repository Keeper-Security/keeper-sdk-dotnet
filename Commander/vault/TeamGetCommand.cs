using Cli;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    internal static class TeamGetCommandExtensions
    {
        public static async Task<bool> TryGetTeamCommand(this VaultContext context, string identifier, bool teamOnly)
        {
            var teamResult = await TryResolveTeam(context, identifier);
            if (teamResult.teamUid == null)
            {
                if (teamOnly)
                {
                    Console.WriteLine($"Team with name or UID '{identifier}' not found or not accessible.");
                }

                return false;
            }

            await DisplayTeamInfo(context, teamResult.vaultTeam, teamResult.availableTeam, teamResult.teamUid);
            return true;
        }

        private static async Task<(Team vaultTeam, TeamInfo availableTeam, string teamUid)> TryResolveTeam(
            VaultContext context,
            string identifier)
        {
            if (context.Vault.TryGetTeam(identifier, out var team))
            {
                return (team, null, team.TeamUid);
            }

            var teamByName = context.Vault.Teams.FirstOrDefault(x =>
                string.Compare(x.Name, identifier, StringComparison.CurrentCultureIgnoreCase) == 0);
            if (teamByName != null)
            {
                return (teamByName, null, teamByName.TeamUid);
            }

            try
            {
                var availableTeams = await context.GetAvailableTeams();
                var availableTeam = availableTeams.FirstOrDefault(x =>
                    string.Compare(x.Name, identifier, StringComparison.CurrentCultureIgnoreCase) == 0 ||
                    string.CompareOrdinal(x.TeamUid, identifier) == 0);

                if (availableTeam != null)
                {
                    return (null, availableTeam, availableTeam.TeamUid);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to retrieve available teams: {ex.Message}");
            }

            return (null, null, null);
        }

        private static async Task DisplayTeamInfo(
            VaultContext context,
            Team vaultTeam,
            TeamInfo availableTeam,
            string teamUid)
        {
            var infoTab = new Tabulate(3)
            {
                MaxColumnWidth = 1000
            };

            var nodePath = ResolveTeamNodePath(context, teamUid);

            if (vaultTeam != null)
            {
                infoTab.AddRow("Team UID:", vaultTeam.TeamUid);
                infoTab.AddRow("Name:", vaultTeam.Name);
                if (!string.IsNullOrEmpty(nodePath))
                {
                    infoTab.AddRow("Node:", nodePath);
                }
                infoTab.AddRow("Access Level:", "Full member access");
                infoTab.AddRow("Restrict Edit:", vaultTeam.RestrictEdit.ToString());
                infoTab.AddRow("Restrict Share:", vaultTeam.RestrictShare.ToString());
                infoTab.AddRow("Restrict View:", vaultTeam.RestrictView.ToString());
            }
            else if (availableTeam != null)
            {
                infoTab.AddRow("Team UID:", availableTeam.TeamUid);
                infoTab.AddRow("Name:", availableTeam.Name);
                if (!string.IsNullOrEmpty(nodePath))
                {
                    infoTab.AddRow("Node:", nodePath);
                }
                infoTab.AddRow("Access Level:", "Available for sharing");
            }
            else
            {
                infoTab.AddRow("Team UID:", teamUid);
                if (!string.IsNullOrEmpty(nodePath))
                {
                    infoTab.AddRow("Node:", nodePath);
                }
            }

            IReadOnlyList<TeamMemberInfo> members;
            try
            {
                members = await context.Vault.GetTeamMembers(teamUid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching team members for {teamUid}: {ex.Message}");
                members = Array.Empty<TeamMemberInfo>();
            }

            Console.WriteLine();
            infoTab.SetColumnRightAlign(0, true);
            infoTab.LeftPadding = 4;
            infoTab.Dump();

            Console.WriteLine();
            DisplayTeamMembers(members);
        }

        private static string ResolveTeamNodePath(VaultContext context, string teamUid)
        {
            var enterpriseData = context.EnterpriseData;
            if (enterpriseData == null)
            {
                return null;
            }

            if (!enterpriseData.TryGetTeam(teamUid, out var team))
            {
                return null;
            }

            EnterpriseNode node = null;
            if (team.ParentNodeId > 0)
            {
                enterpriseData.TryGetNode(team.ParentNodeId, out node);
            }
            else
            {
                node = enterpriseData.RootNode;
            }

            if (node == null)
            {
                return null;
            }

            var nodes = enterpriseData.GetNodePath(node).ToArray();
            Array.Reverse(nodes);
            return string.Join(" -> ", nodes);
        }

        private static void DisplayTeamMembers(IReadOnlyList<TeamMemberInfo> members)
        {
            var memberTab = new Tabulate(4)
            {
                DumpRowNo = false,
                LeftPadding = 4
            };

            memberTab.AddHeader("Enterprise User ID", "Email", "Enterprise Username", "Share Admin");

            if (members == null || members.Count == 0)
            {
                Console.WriteLine("No team members found.");
                return;
            }

            foreach (var member in members)
            {
                memberTab.AddRow(
                    member.EnterpriseUserId.ToString(),
                    member.Email ?? "",
                    member.EnterpriseUsername ?? "",
                    member.IsShareAdmin ? "Yes" : "No");
            }

            memberTab.Dump();
        }
    }
}
