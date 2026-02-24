using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamViewExample
    {
        public static async Task EnterpriseTeamView(string teamNameOrId)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Authentication failed. Vault is null.");
                    return;
                }
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (string.IsNullOrWhiteSpace(teamNameOrId))
                {
                    Console.WriteLine("Team name is null or empty.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();

                                EnterpriseTeam team = null;
                enterpriseData.TryGetTeam(teamNameOrId, out team);
                if (team == null)
                {
                    var matchingTeams = enterpriseData.Teams
                        .Where(x => string.Equals(x.Name, teamNameOrId, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (matchingTeams.Count == 1)
                    {
                        team = matchingTeams[0];
                    }
                    else if (matchingTeams.Count > 1)
                    {
                        Console.WriteLine($"Multiple teams found with name '{teamNameOrId}'. Please use team UID instead.");
                        foreach (var t in matchingTeams)
                        {
                            Console.WriteLine($"Team UID: {t.Uid}, Team Name: {t.Name}");
                        }
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"Team with name or UID '{teamNameOrId}' not found.");
                        return;
                    }
                }

                var userIds = enterpriseData.GetUsersForTeam(team.Uid).ToArray();

                Console.WriteLine("Team Name: {0}", team.Name);
                Console.WriteLine("Team Uid: {0}", team.Uid);
                Console.WriteLine("Restrict Edit: {0}", team.RestrictEdit ? "Yes" : "No");
                Console.WriteLine("Restrict Share: {0}", team.RestrictSharing ? "yes" : "No");
                Console.WriteLine("Restrict View: {0}", team.RestrictView ? "Yes" : "No");
                Console.WriteLine("Users: ");
                foreach (var userId in userIds)
                {
                    if (enterpriseData.TryGetUserById(userId, out var user))
                    {
                        Console.WriteLine($"  - {user.Email} ({user.DisplayName})");
                    }
                    else
                    {
                        Console.WriteLine($"  - Unknown User (ID: {userId})");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error viewing team: {ex.Message}");
            }
        }
    }
}
