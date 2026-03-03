using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamsListExample
    {
        public static async Task EnterpriseTeamsList(VaultOnline vault = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();

                Console.WriteLine("{0,-30}  {1,-46}", "Team UID", "Team Name");
                Console.WriteLine(new string('-', 30) + "  " + new string('-', 46));

                foreach (var team in enterpriseData.Teams)
                {
                    Console.WriteLine("{0,-30}  {1,-46}", team.Uid, team.Name);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
