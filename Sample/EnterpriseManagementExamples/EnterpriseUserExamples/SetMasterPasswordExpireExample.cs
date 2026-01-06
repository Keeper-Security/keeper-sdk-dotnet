using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class SetMasterPasswordExpireExample
    {
        public static async Task SetMasterPasswordExpire(string email)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

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

                await enterpriseData.SetMasterPasswordExpire(email);
                Console.WriteLine($"Set master password expire successfully to '{email}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}