using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseUserViewExample
    {
        public static async Task ViewUser(string email)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                // Load enterprise data
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                // Get user by email using TryGetUserByEmail
                if (!enterpriseData.TryGetUserByEmail(email, out var user))
                {
                    Console.WriteLine($"User '{email}' not found in enterprise.");
                    return;
                }

                Console.WriteLine("======== Enterprise User Details ========");
                Console.WriteLine($"User ID:      {user.Id}");
                Console.WriteLine($"Email:        {user.Email}");
                Console.WriteLine($"Display Name: {user.DisplayName}");
                Console.WriteLine($"Status:       {user.UserStatus}");
                Console.WriteLine($"Node ID:      {user.ParentNodeId}");
                Console.WriteLine($"Locked:       {(user.UserStatus == UserStatus.Locked ? "Yes" : "No")}");

                // Get teams for user using GetTeamsForUser
                var teamUids = enterpriseData.GetTeamsForUser(user.Id);

                if (teamUids != null && teamUids.Length > 0)
                {
                    Console.WriteLine($"\nTeams ({teamUids.Length}):");
                    foreach (var teamUid in teamUids)
                    {
                        // Get team details using TryGetTeam
                        if (enterpriseData.TryGetTeam(teamUid, out var team))
                        {
                            Console.WriteLine($"  - {team.Name} (UID: {team.Uid})");
                            Console.WriteLine($"      Restrict Edit:  {team.RestrictEdit}");
                            Console.WriteLine($"      Restrict Share: {team.RestrictSharing}");
                            Console.WriteLine($"      Restrict View:  {team.RestrictView}");
                        }
                        else
                        {
                            Console.WriteLine($"  - Unknown Team (UID: {teamUid})");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\nTeams: None");
                }

                Console.WriteLine("=========================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}