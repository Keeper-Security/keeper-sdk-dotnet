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
            var teamResult = TryResolveTeam(context, identifier);
            if (teamResult.multipleFound)
            {
                Console.WriteLine($"Multiple teams found with name '{identifier}'. Please use team UID.");
                return true;
            }

            if (teamResult.teamUid == null)
            {
                if (teamOnly)
                {
                    Console.WriteLine($"Team with name or UID '{identifier}' not found or not accessible.");
                }

                return false;
            }

            await DisplayTeamInfo(context, teamResult.vaultTeam, teamResult.enterpriseTeam, teamResult.teamUid);
            return true;
        }

        private static (Team vaultTeam, EnterpriseTeam enterpriseTeam, string teamUid, bool multipleFound) TryResolveTeam(
            VaultContext context,
            string identifier)
        {
            if (context.Vault.TryGetTeam(identifier, out var team))
            {
                return (team, null, team.TeamUid, false);
            }

            var teamsByName = context.Vault.Teams
                .Where(x => string.Compare(x.Name, identifier, StringComparison.CurrentCultureIgnoreCase) == 0)
                .ToList();
            if (teamsByName.Count > 1)
            {
                return (null, null, null, true);
            }

            if (teamsByName.Count == 1)
            {
                return (teamsByName[0], null, teamsByName[0].TeamUid, false);
            }

            var enterpriseData = context.EnterpriseData;
            if (enterpriseData == null || !context.Vault.Auth.AuthContext.IsEnterpriseAdmin)
            {
                return (null, null, null, false);
            }

            if (enterpriseData.TryGetTeam(identifier, out var enterpriseTeamByUid))
            {
                return (null, enterpriseTeamByUid, enterpriseTeamByUid.Uid, false);
            }

            var enterpriseTeamsByName = enterpriseData.Teams
                .Where(x => string.Compare(x.Name, identifier, StringComparison.CurrentCultureIgnoreCase) == 0)
                .ToList();
            if (enterpriseTeamsByName.Count > 1)
            {
                return (null, null, null, true);
            }

            if (enterpriseTeamsByName.Count == 1)
            {
                return (null, enterpriseTeamsByName[0], enterpriseTeamsByName[0].Uid, false);
            }

            return (null, null, null, false);
        }

        private static async Task DisplayTeamInfo(
            VaultContext context,
            Team vaultTeam,
            EnterpriseTeam enterpriseTeam,
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
            else if (enterpriseTeam != null)
            {
                infoTab.AddRow("Team UID:", enterpriseTeam.Uid);
                infoTab.AddRow("Name:", enterpriseTeam.Name);
                if (!string.IsNullOrEmpty(nodePath))
                {
                    infoTab.AddRow("Node:", nodePath);
                }
                infoTab.AddRow("Access Level:", "Enterprise administrative access");
                infoTab.AddRow("Restrict Edit:", enterpriseTeam.RestrictEdit.ToString());
                infoTab.AddRow("Restrict Share:", enterpriseTeam.RestrictSharing.ToString());
                infoTab.AddRow("Restrict View:", enterpriseTeam.RestrictView.ToString());
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
            if (members == null || members.Count == 0)
            {
                Console.WriteLine("No team members found.");
                return;
            }

            var memberTab = new Tabulate(4)
            {
                DumpRowNo = false,
                LeftPadding = 4
            };

            memberTab.AddHeader("Enterprise User ID", "Email", "Enterprise Username", "Share Admin");

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
