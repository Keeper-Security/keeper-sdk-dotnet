using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamMembershipExample
    {
        public static async Task AddUsersToTeams(string[] emails, string[] teamUids, Action<string> warnings = null)
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
                if (emails.Length == 0)
                {
                    Console.WriteLine("Emails is null or empty.");
                    return;
                }
                if (teamUids.Length == 0)
                {
                    Console.WriteLine("Team UIDs is null or empty.");
                    return;
                }
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();
                await enterpriseData.AddUsersToTeams(emails, teamUids);
                Console.WriteLine("Users Successfully Added to Teams");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error {ex.Message}");
            }
        }

        public static async Task RemoveUsersFromTeams(string[] emails, string[] teamUids, Action<string> warnings = null)
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
                if (emails.Length == 0)
                {
                    Console.WriteLine("Emails is null or empty.");
                    return;
                }
                if (teamUids.Length == 0)
                {
                    Console.WriteLine("Team UIDs is null or empty.");
                    return;
                }
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();
                await enterpriseData.RemoveUsersFromTeams(emails, teamUids);
                Console.WriteLine("Users Successfully Removed from Teams");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error {ex.Message}");
            }
        }
    }
}