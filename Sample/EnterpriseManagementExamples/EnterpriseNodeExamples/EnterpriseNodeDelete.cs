using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeDelete
    {
        public static async Task DeleteNode(VaultOnline vault, string nodeNameOrId)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (string.IsNullOrEmpty(nodeNameOrId))
                {
                    Console.WriteLine("Node name or ID is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                EnterpriseNode node = null;

                if (long.TryParse(nodeNameOrId, out var nodeId))
                {
                    enterpriseData.TryGetNode(nodeId, out node);
                }

                if (node == null)
                {
                    var nodes = enterpriseData.Nodes
                        .Where(x => string.Equals(x.DisplayName, nodeNameOrId, StringComparison.InvariantCultureIgnoreCase))
                        .ToArray();

                    if (nodes.Length == 1)
                    {
                        node = nodes[0];
                    }
                    else if (nodes.Length > 1)
                    {
                        Console.WriteLine($"Multiple nodes found with name '{nodeNameOrId}'. Please use node ID instead:");
                        foreach (var n in nodes)
                        {
                            Console.WriteLine($"  - {n.DisplayName} (ID: {n.Id})");
                        }
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"No node found with name '{nodeNameOrId}'.");
                        return;
                    }
                }

                await enterpriseData.DeleteNode(node.Id);

                Console.WriteLine($"Node '{node.DisplayName}' deleted successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
