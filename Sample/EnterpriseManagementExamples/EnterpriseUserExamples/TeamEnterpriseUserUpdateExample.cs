using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class TeamEnterpriseUserUpdateExample
    {
        public static async Task TeamEnterpriseUserUpdate(string teamUid, string userEmail, int userType)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                if (!enterpriseData.TryGetUserByEmail(userEmail, out var user))
                {
                    Console.WriteLine($"User '{user}' not found in enterprise.");
                    return;
                }

                if (!enterpriseData.TryGetTeam(teamUid, out var team))
                {
                    Console.WriteLine($"team '{team}' not found in enterprise.");
                    return;
                }

                await enterpriseData.TeamEnterpriseUserUpdate(team, user, userType);
                Console.WriteLine($"Enterprise team user updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

    }
}