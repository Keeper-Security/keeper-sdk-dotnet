using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeAdd
    {
        public static async Task AddNode(VaultOnline vault, string nodeName, string parentNodeNameOrId = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (string.IsNullOrEmpty(nodeName))
                {
                    Console.WriteLine("Node name is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                EnterpriseNode parentNode = null;
                if (!string.IsNullOrEmpty(parentNodeNameOrId))
                {
                    if (long.TryParse(parentNodeNameOrId, out var parentNodeId))
                    {
                        enterpriseData.TryGetNode(parentNodeId, out parentNode);
                    }
                    if (parentNode == null)
                    {
                        var nodes = enterpriseData.Nodes
                            .Where(x => string.Equals(x.DisplayName, parentNodeNameOrId, StringComparison.InvariantCultureIgnoreCase))
                            .ToArray();

                        if (nodes.Length == 1)
                        {
                            parentNode = nodes[0];
                        }
                        else if (nodes.Length > 1)
                        {
                            Console.WriteLine($"Multiple nodes found with name '{parentNodeNameOrId}'. Please use node ID instead:");
                            foreach (var n in nodes)
                            {
                                Console.WriteLine($"  - {n.DisplayName} (ID: {n.Id})");
                            }
                            return;
                        }
                        else
                        {
                            Console.WriteLine($"Parent node '{parentNodeNameOrId}' not found.");
                            return;
                        }   
                    }
                }

                var newNode = await enterpriseData.CreateNode(nodeName, parentNode);

                Console.WriteLine($"Node '{newNode.DisplayName}' created successfully with ID: {newNode.Id}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
