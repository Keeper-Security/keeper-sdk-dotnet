using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class ResendEnterpriseInviteExample
    {
        public static async Task ResendEnterpriseInvite(string email)
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
                if (string.IsNullOrWhiteSpace(email))
                {
                    Console.WriteLine("Email is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                if (!enterpriseData.TryGetUserByEmail(email, out var user))
                {
                    Console.WriteLine($"User '{email}' not found in enterprise.");
                    return;
                }
                
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