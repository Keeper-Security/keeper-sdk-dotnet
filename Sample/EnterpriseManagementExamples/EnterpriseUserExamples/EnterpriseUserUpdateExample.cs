using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseUserUpdateExample
    {
        public static async Task EnterpriseUserUpdate(string email, long? nodeId = null, string fullName = null, string jobTitle = null, string inviteeLocale = null)
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

                await enterpriseData.EnterpriseUserUpdate(user, nodeId, fullName, jobTitle, inviteeLocale);
                Console.WriteLine($"Enterprise user updated successfully with nodeId: {nodeId}, fullName: {fullName}, jobTitle: {jobTitle}, inviteeLocale: {inviteeLocale}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}