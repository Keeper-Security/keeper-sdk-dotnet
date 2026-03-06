using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspSwitchToManagedCompanyExample
    {
        /// <summary>
        /// Switches (logs in) to a managed company's enterprise context.
        /// After switching, you can load and manage the MC's enterprise data
        /// (users, roles, teams, nodes) as if you were its admin.
        /// </summary>
        /// <param name="companyId">Managed Company Enterprise ID to switch to.</param>
        public static async Task SwitchToManagedCompany(VaultOnline vault, int companyId)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var mspData = new ManagedCompanyData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { mspData });

                await enterpriseLoader.Load();

                var mc = mspData.ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == companyId);
                if (mc == null)
                {
                    Console.WriteLine($"Managed Company with ID {companyId} not found.");
                    return;
                }

                Console.WriteLine($"Switching to Managed Company: {mc.EnterpriseName} (ID: {mc.EnterpriseId})...");

                var mcAuth = new ManagedCompanyAuth();
                await mcAuth.LoginToManagedCompany(enterpriseLoader, mc.EnterpriseId);

                var mcEnterpriseData = new EnterpriseData();
                var mcRoleData = new RoleData();
                var mcLoader = new EnterpriseLoader(
                    mcAuth,
                    new EnterpriseDataPlugin[] { mcEnterpriseData, mcRoleData });

                await mcLoader.Load();

                Console.WriteLine($"Switched to Managed Company \"{mc.EnterpriseName}\" successfully.");
                Console.WriteLine($"  Root Node:        {mcEnterpriseData.RootNode.DisplayName} (ID: {mcEnterpriseData.RootNode.Id})");
                Console.WriteLine($"  Users:            {mcEnterpriseData.Users.Count()}");
                Console.WriteLine($"  Nodes:            {mcEnterpriseData.Nodes.Count()}");
                Console.WriteLine($"  Roles:            {mcRoleData.Roles.Count()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
