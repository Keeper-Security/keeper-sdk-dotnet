using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspUpdateManagedCompanyExample
    {
        /// <summary>
        /// Updates an existing managed company's settings.
        /// Pass null for any parameter to leave its current value unchanged.
        /// The addons parameter replaces the entire add-on list; pass null to keep existing add-ons.
        /// </summary>
        /// <param name="companyId">Managed Company Enterprise ID.</param>
        /// <param name="newName">Optional new name for the company.</param>
        /// <param name="newPlanId">Optional new plan: "business", "businessPlus", "enterprise", or "enterprisePlus".</param>
        /// <param name="newMaxSeats">Optional new maximum seats. Use -1 for unlimited.</param>
        /// <param name="newStoragePlan">Optional new storage plan: "STORAGE_100GB", "STORAGE_1TB", or "STORAGE_10TB".</param>
        /// <param name="addons">Optional full replacement add-on list. Pass null to keep existing add-ons unchanged.</param>
        public static async Task UpdateManagedCompany(VaultOnline vault, 
            int companyId,
            string newName = null,
            string newPlanId = null,
            int? newMaxSeats = null,
            string newStoragePlan = null,
            ManagedCompanyAddonOptions[] addons = null)
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

                Console.WriteLine($"Updating Managed Company: {existing.EnterpriseName} (ID: {existing.EnterpriseId})");

                var options = new ManagedCompanyOptions
                {
                    Name = newName,
                    ProductId = newPlanId,
                    NumberOfSeats = newMaxSeats,
                    FilePlanType = newStoragePlan,
                    Addons = addons
                };

                var updated = await mspData.UpdateManagedCompany(companyId, options);

                if (updated != null)
                {
                    Console.WriteLine("Managed Company updated successfully.");
                    Console.WriteLine($"  Enterprise ID:    {updated.EnterpriseId}");
                    Console.WriteLine($"  Enterprise Name:  {updated.EnterpriseName}");
                    Console.WriteLine($"  Product ID:       {updated.ProductId}");
                    Console.WriteLine($"  Number of Seats:  {updated.NumberOfSeats}");
                    Console.WriteLine($"  Number of Users:  {updated.NumberOfUsers}");
                    Console.WriteLine($"  File Plan Type:   {updated.FilePlanType}");

                    if (updated.AddOns != null && updated.AddOns.Length > 0)
                    {
                        Console.WriteLine("  Add-Ons:");
                        foreach (var addon in updated.AddOns)
                        {
                            Console.WriteLine($"    - {addon.Name} (Seats: {addon.Seats}, Enabled: {addon.IsEnabled})");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Managed Company update returned null.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
