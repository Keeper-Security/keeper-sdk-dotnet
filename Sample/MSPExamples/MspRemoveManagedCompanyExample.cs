using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspRemoveManagedCompanyExample
    {
        /// <summary>
        /// Removes a managed company from the MSP enterprise.
        /// </summary>
        /// <param name="companyId">Managed Company Enterprise ID to remove.</param>
        public static async Task RemoveManagedCompany(VaultOnline vault, int companyId)
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

                var existing = mspData.ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == companyId);
                if (existing == null)
                {
                    Console.WriteLine($"Managed Company with ID {companyId} not found.");
                    return;
                }

                Console.WriteLine($"Removing Managed Company: {existing.EnterpriseName} (ID: {existing.EnterpriseId})...");

                await mspData.RemoveManagedCompany(companyId);

                Console.WriteLine($"Managed Company \"{existing.EnterpriseName}\" removed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
