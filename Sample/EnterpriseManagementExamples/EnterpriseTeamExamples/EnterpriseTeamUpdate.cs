using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamUpdateExample
    {
        public static async Task EnterpriseTeamUpdate(VaultOnline vault, EnterpriseTeam updateTeam)
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
                var team = await enterpriseData.UpdateTeam(updateTeam);
                Console.WriteLine($"Team Updated: {team.Uid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
