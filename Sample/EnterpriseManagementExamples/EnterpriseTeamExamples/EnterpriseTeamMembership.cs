using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamMembershipExample
    {
        public static async Task AddUsersToTeams(VaultOnline vault, string[] emails, string[] teamUids, Action<string> warnings = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
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

        public static async Task RemoveUsersFromTeams(VaultOnline vault, string[] emails, string[] teamUids, Action<string> warnings = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null) return;
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