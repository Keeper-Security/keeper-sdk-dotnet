using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamViewExample
    {
        public static async Task EnterpriseTeamView(string teamName)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();
                var team = enterpriseData.Teams.FirstOrDefault(x => string.CompareOrdinal(x.Name, teamName) == 0);
                if (team == null)
                {
                    Console.WriteLine($"Team {teamName} not found");
                    return;
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
