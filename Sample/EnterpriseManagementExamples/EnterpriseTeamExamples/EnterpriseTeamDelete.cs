using System;
using System.Threading.Tasks;
using System.Linq;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamDeleteExample
    {
        public static async Task EnterpriseTeamDelete(string teamIdentifier)
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
                var team = enterpriseData.Teams.FirstOrDefault(x => string.CompareOrdinal(x.Name, teamIdentifier) == 0);
                await enterpriseData.DeleteTeam(team.Uid);
                Console.WriteLine($"Team Deleted: {teamIdentifier}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
