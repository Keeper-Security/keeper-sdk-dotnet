using Google.Protobuf;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Options for team list generation
    /// </summary>
    public class TeamListOptions
    {
        /// <summary>
        /// Show team membership information
        /// </summary>
        public bool Verbose { get; set; }

        /// <summary>
        /// Fetch team membership info not in cache
        /// </summary>
        public bool VeryVerbose { get; set; }

        /// <summary>
        /// Show all teams including those outside primary organization
        /// </summary>
        public bool ShowAllTeams { get; set; }

        /// <summary>
        /// Sort column: company, team_uid, name
        /// </summary>
        public string SortBy { get; set; } = "company";
    }

    /// <summary>
    /// Team information for list
    /// </summary>
    public class TeamListItem
    {
        /// <summary>
        /// Team UID
        /// </summary>
        public string TeamUid { get; set; }

        /// <summary>
        /// Team name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Enterprise/Company name
        /// </summary>
        public string Company { get; set; }

        /// <summary>
        /// Team members (if verbose mode)
        /// </summary>
        public List<string> Members { get; set; }
    }

    /// <summary>
    /// Team list generation methods
    /// </summary>
    public static class KeeperTeamList
    {
        /// <summary>
        /// Generate a list of teams
        /// </summary>
        public static async Task<List<TeamListItem>> GetTeamList(
            this VaultOnline vault,
            TeamListOptions options = null,
            Action<Severity, string> logger = null)
        {
            options = options ?? new TeamListOptions();
            var teams = new List<TeamListItem>();

            teams.AddRange(GetTeamsFromSharedFolders(vault, options));
            teams.AddRange(GetTeamsFromRecords(vault, options));
            var uniqueTeams = teams
                .GroupBy(t => t.TeamUid)
                .Select(g => g.First())
                .ToList();

            if (options.Verbose || options.VeryVerbose)
            {
                await LoadTeamMembers(vault, uniqueTeams, logger);
            }

            uniqueTeams = SortTeams(uniqueTeams, options.SortBy);

            return uniqueTeams;
        }

        private static List<TeamListItem> GetTeamsFromSharedFolders(VaultOnline vault, TeamListOptions options)
        {
            var teams = new List<TeamListItem>();

            try
            {
                var request = new global::Records.GetShareObjectsRequest();
                
                var response = (global::Records.GetShareObjectsResponse)vault.Auth.ExecuteAuthRest(
                    "vault/get_share_objects",
                    request,
                    typeof(global::Records.GetShareObjectsResponse)).GetAwaiter().GetResult();

                var enterpriseNames = new Dictionary<long, string>();
                foreach (var enterprise in response.ShareEnterpriseNames)
                {
                    enterpriseNames[enterprise.EnterpriseId] = enterprise.Enterprisename;
                }

                long? currentEnterpriseId = null;
                var allTeams = new List<global::Records.ShareTeam>();
                allTeams.AddRange(response.ShareTeams);
                allTeams.AddRange(response.ShareMCTeams);

                foreach (var team in allTeams)
                {
                    if (!options.ShowAllTeams && currentEnterpriseId.HasValue && 
                        team.EnterpriseId != currentEnterpriseId.Value)
                    {
                        continue;
                    }

                    var companyName = "";
                    if (enterpriseNames.TryGetValue(team.EnterpriseId, out var name))
                    {
                        companyName = name;
                    }

                    teams.Add(new TeamListItem
                    {
                        TeamUid = team.TeamUid.ToByteArray().Base64UrlEncode(),
                        Name = team.Teamname,
                        Company = companyName
                    });
                }
            }
            catch (Exception)
            {
                // If API call fails, return empty list
                // Could log error here if logger was passed
            }

            return teams;
        }

        private static List<TeamListItem> GetTeamsFromRecords(VaultOnline vault, TeamListOptions options)
        {
            // Additional teams could be extracted from record permissions if needed
            // For now, we rely on shared folders as the primary source
            return new List<TeamListItem>();
        }

        private static async Task LoadTeamMembers(
            VaultOnline vault,
            List<TeamListItem> teams,
            Action<Severity, string> logger)
        {
            // Fetch all team members in parallel for better performance
            var fetchTasks = teams.Select(async team =>
            {
                try
                {
                    var members = await FetchTeamMembersFromServer(vault, team.TeamUid, logger);
                    team.Members = members;
                }
                catch (Exception ex)
                {
                    logger?.Invoke(Severity.Warning, $"Failed to load members for team {team.Name}: {ex.Message}");
                    team.Members = new List<string>();
                }
            }).ToList();

            // Wait for all parallel fetches to complete
            await Task.WhenAll(fetchTasks);
        }

        private static async Task<List<string>> FetchTeamMembersFromServer(
            VaultOnline vault,
            string teamUid,
            Action<Severity, string> logger)
        {
            try
            {
                var request = new global::Enterprise.GetTeamMemberRequest
                {
                    TeamUid = Google.Protobuf.ByteString.CopyFrom(teamUid.Base64UrlDecode())
                };

                var response = (global::Enterprise.GetTeamMemberResponse)await vault.Auth.ExecuteAuthRest(
                    "vault/get_team_members",
                    request,
                    typeof(global::Enterprise.GetTeamMemberResponse));

                var members = response.EnterpriseUser?.Select(u => u.Email).ToList() ?? new List<string>();
                return members;
            }
            catch (Exception ex)
            {
                logger?.Invoke(Severity.Warning, $"Error fetching team members for {teamUid}: {ex.Message}");
                return new List<string>();
            }
        }

        private static List<TeamListItem> SortTeams(List<TeamListItem> teams, string sortBy)
        {
            return sortBy?.ToLower() switch
            {
                "team_uid" => teams.OrderBy(t => t.TeamUid).ToList(),
                "name" => teams.OrderBy(t => t.Name ?? "").ToList(),
                "company" => teams.OrderBy(t => t.Company ?? "").ThenBy(t => t.Name ?? "").ToList(),
                _ => teams.OrderBy(t => t.Company ?? "").ThenBy(t => t.Name ?? "").ToList()
            };
        }
    }
}

