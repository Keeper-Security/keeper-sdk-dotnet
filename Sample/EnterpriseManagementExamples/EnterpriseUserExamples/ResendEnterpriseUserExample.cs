using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class ResendEnterpriseInviteExample
    {
        public static async Task ResendEnterpriseInviteExample(string email)
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

                // Resend invitation
                await enterpriseData.ResendEnterpriseInvite(user);
                Console.WriteLine($"Invitation resent successfully to '{email}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}