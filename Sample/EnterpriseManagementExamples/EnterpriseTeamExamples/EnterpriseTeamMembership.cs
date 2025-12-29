using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamMembershipExample
    {
        public static async Task AddUsersToTeams(string[] emails, string[] teams, Action<string> warnings = null)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();
                await enterpriseData.AddUsersToTeams(emails, teams);
                Console.WriteLine("Users Successfully Added to Teams");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error {ex.Message}");
            }
        }

        public static async Task RemoveUsersFromTeams(string[] emails, string[] teams, Action<string> warnings = null)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();
                await enterpriseData.RemoveUsersFromTeams(emails, teams);
                Console.WriteLine("Users Successfully Removed from Teams");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error {ex.Message}");
            }
        }
    }
}