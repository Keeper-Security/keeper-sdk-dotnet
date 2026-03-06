using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamAddExample
    {
        public static async Task EnterpriseTeamAdd(VaultOnline vault, EnterpriseTeam newTeam)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (newTeam == null)
                {
                    Console.WriteLine("Team object is null.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();
                var team = await enterpriseData.CreateTeam(newTeam);
                Console.WriteLine($"Team added: {team.Uid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
