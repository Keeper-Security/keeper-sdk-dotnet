using Cli;
using Google.Protobuf;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    /// <summary>
    /// Team member details returned by vault/get_team_members.
    /// </summary>
    public class TeamMemberInfo
    {
        public long EnterpriseUserId { get; set; }
        public string Email { get; set; }
        public string EnterpriseUsername { get; set; }
        public bool IsShareAdmin { get; set; }
    }

    internal static class TeamMemberExtensions
    {
        /// <summary>
        /// Fetches team members from vault/get_team_members.
        /// An empty member list is returned when the team has no members or the response is empty.
        /// </summary>
        public static async Task<List<TeamMemberInfo>> FetchTeamMembers(
            VaultOnline vault,
            string teamUid,
            Action<Severity, string> logger = null)
        {
            if (vault == null) throw new ArgumentNullException(nameof(vault));
            if (string.IsNullOrEmpty(teamUid)) return new List<TeamMemberInfo>();

            try
            {
                var request = new global::Enterprise.GetTeamMemberRequest
                {
                    TeamUid = ByteString.CopyFrom(teamUid.Base64UrlDecode())
                };

                var response = (global::Enterprise.GetTeamMemberResponse)await vault.Auth.ExecuteAuthRest(
                    "vault/get_team_members",
                    request,
                    typeof(global::Enterprise.GetTeamMemberResponse));

                if (response?.EnterpriseUser == null || response.EnterpriseUser.Count == 0)
                {
                    return new List<TeamMemberInfo>();
                }

                return response.EnterpriseUser
                    .Select(u => new TeamMemberInfo
                    {
                        EnterpriseUserId = u.EnterpriseUserId,
                        Email = u.Email ?? "",
                        EnterpriseUsername = u.EnterpriseUsername ?? "",
                        IsShareAdmin = u.IsShareAdmin
                    })
                    .ToList();
            }
            catch (Exception ex)
            {
                logger?.Invoke(Severity.Warning, $"Error fetching team members for {teamUid}: {ex.Message}");
                return new List<TeamMemberInfo>();
            }
        }
    }

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

            if (vaultTeam != null)
            {
                infoTab.AddRow("Team UID:", vaultTeam.TeamUid);
                infoTab.AddRow("Name:", vaultTeam.Name);
                infoTab.AddRow("Access Level:", "Full member access");
                infoTab.AddRow("Restrict Edit:", vaultTeam.RestrictEdit.ToString());
                infoTab.AddRow("Restrict Share:", vaultTeam.RestrictShare.ToString());
                infoTab.AddRow("Restrict View:", vaultTeam.RestrictView.ToString());
            }
            else if (availableTeam != null)
            {
                infoTab.AddRow("Team UID:", availableTeam.TeamUid);
                infoTab.AddRow("Name:", availableTeam.Name);
                infoTab.AddRow("Access Level:", "Available for sharing");
            }
            else
            {
                infoTab.AddRow("Team UID:", teamUid);
            }

            var members = await TeamMemberExtensions.FetchTeamMembers(context.Vault, teamUid);

            Console.WriteLine();
            infoTab.SetColumnRightAlign(0, true);
            infoTab.LeftPadding = 4;
            infoTab.Dump();

            Console.WriteLine();
            DisplayTeamMembers(members);
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
