using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspListManagedCompaniesExample
    {
        /// <summary>
        /// Lists all managed companies under the MSP enterprise with their details,
        /// including plan, seats, users, storage, and add-ons.
        /// </summary>
        public static async Task ListManagedCompanies()
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

                var mspData = new ManagedCompanyData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { mspData });

                await enterpriseLoader.Load();

                var managedCompanies = mspData.ManagedCompanies.ToArray();
                if (managedCompanies.Length == 0)
                {
                    Console.WriteLine("No managed companies found. Ensure this is an MSP enterprise.");
                    return;
                }

                Console.WriteLine($"======== Managed Companies ({managedCompanies.Length}) ========");
                foreach (var mc in managedCompanies)
                {
                    Console.WriteLine($"  Enterprise ID:    {mc.EnterpriseId}");
                    Console.WriteLine($"  Enterprise Name:  {mc.EnterpriseName}");
                    Console.WriteLine($"  Product ID:       {mc.ProductId}");
                    Console.WriteLine($"  Number of Seats:  {mc.NumberOfSeats}");
                    Console.WriteLine($"  Number of Users:  {mc.NumberOfUsers}");
                    Console.WriteLine($"  File Plan Type:   {mc.FilePlanType}");
                    Console.WriteLine($"  Is Expired:       {mc.IsExpired}");
                    Console.WriteLine($"  Parent Node ID:   {mc.ParentNodeId}");

                    if (mc.AddOns != null && mc.AddOns.Length > 0)
                    {
                        Console.WriteLine("  Add-Ons:");
                        foreach (var addon in mc.AddOns)
                        {
                            Console.WriteLine($"    - {addon.Name} (Seats: {addon.Seats}, Enabled: {addon.IsEnabled})");
                        }
                    }
                    else
                    {
                        Console.WriteLine("  Add-Ons:          None");
                    }

                    Console.WriteLine("  ----------------------------------------");
                }

                Console.WriteLine("=============================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
