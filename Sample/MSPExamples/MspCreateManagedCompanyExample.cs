using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.MspExamples
{
    public static class MspCreateManagedCompanyExample
    {
        /// <summary>
        /// Creates a new managed company under the MSP enterprise.
        /// </summary>
        /// <param name="companyName">Name for the new managed company.</param>
        /// <param name="planId">Product plan: "business", "businessPlus", "enterprise", or "enterprisePlus".</param>
        /// <param name="maxSeats">Maximum number of seats. Use -1 for unlimited.</param>
        /// <param name="nodeNameOrId">Optional node name or ID to place the MC under. Defaults to root node.</param>
        /// <param name="storagePlan">Optional storage plan: "STORAGE_100GB", "STORAGE_1TB", or "STORAGE_10TB".</param>
        /// <param name="addons">Optional array of add-on configurations.</param>
        public static async Task CreateManagedCompany(
            string companyName,
            string planId,
            int maxSeats,
            string nodeNameOrId = null,
            string storagePlan = null,
            ManagedCompanyAddonOptions[] addons = null)
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

                if (string.IsNullOrWhiteSpace(companyName))
                {
                    Console.WriteLine("Company name is required.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(planId))
                {
                    Console.WriteLine("Plan ID is required (business, businessPlus, enterprise, or enterprisePlus).");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var mspData = new ManagedCompanyData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, mspData });

                await enterpriseLoader.Load();

                long nodeId = enterpriseData.RootNode.Id;
                if (!string.IsNullOrEmpty(nodeNameOrId))
                {
                    EnterpriseNode node = null;
                    if (long.TryParse(nodeNameOrId, out var parsedNodeId))
                    {
                        enterpriseData.TryGetNode(parsedNodeId, out node);
                    }

                    if (node == null)
                    {
                        node = enterpriseData.Nodes
                            .FirstOrDefault(n => string.Equals(n.DisplayName, nodeNameOrId, StringComparison.OrdinalIgnoreCase));
                    }

                    if (node == null)
                    {
                        Console.WriteLine($"Node '{nodeNameOrId}' not found.");
                        return;
                    }

                    nodeId = node.Id;
                }

                var options = new ManagedCompanyOptions
                {
                    Name = companyName,
                    ProductId = planId,
                    NumberOfSeats = maxSeats,
                    NodeId = nodeId,
                    FilePlanType = storagePlan,
                    Addons = addons
                };

                var mc = await mspData.CreateManagedCompany(options);

                if (mc != null)
                {
                    Console.WriteLine("Managed Company created successfully.");
                    Console.WriteLine($"  Enterprise ID:    {mc.EnterpriseId}");
                    Console.WriteLine($"  Enterprise Name:  {mc.EnterpriseName}");
                    Console.WriteLine($"  Product ID:       {mc.ProductId}");
                    Console.WriteLine($"  Number of Seats:  {mc.NumberOfSeats}");
                    Console.WriteLine($"  File Plan Type:   {mc.FilePlanType}");
                }
                else
                {
                    Console.WriteLine("Managed Company creation returned null.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
