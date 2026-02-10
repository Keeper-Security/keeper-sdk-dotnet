using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class TeamEnterpriseUserUpdateExample
    {
        public static async Task TeamEnterpriseUserUpdate(string teamUid, string userEmail, int userType)
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
                if (string.IsNullOrWhiteSpace(teamUid))
                {
                    Console.WriteLine("Team UID is required.");
                        return;
                }
                if (string.IsNullOrWhiteSpace(userEmail))
                {
                    Console.WriteLine("User email is required.");
                    return;
                }
                if (userType < 0 || userType > 2)
                {
                    Console.WriteLine("User type must be 0, 1, or 2.");
                    return;
                }

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