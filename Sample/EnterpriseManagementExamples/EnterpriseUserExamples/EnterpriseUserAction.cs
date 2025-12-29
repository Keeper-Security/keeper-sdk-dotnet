using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseUserAction
    {
        public static async Task UserAction(string email, bool locked)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                // Get user by email
                if (!enterpriseData.TryGetUserByEmail(email, out var user))
                {
                    Console.WriteLine($"User '{email}' not found in enterprise.");
                    return;
                }

                // Lock or unlock the user
                var updatedUser = await enterpriseData.SetUserLocked(user, locked);

                var action = locked ? "locked" : "unlocked";
                Console.WriteLine($"User '{updatedUser.Email}' has been {action} successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}