using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeDelete
    {
        public static async Task DeleteNode(string nodeIdentifier)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                EnterpriseNode node = null;

                if (long.TryParse(nodeIdentifier, out var nodeId))
                {
                    enterpriseData.TryGetNode(nodeId, out node);
                }

                if (node == null)
                {
                    var nodes = enterpriseData.Nodes
                        .Where(x => string.Equals(x.DisplayName, nodeIdentifier, StringComparison.InvariantCultureIgnoreCase))
                        .ToArray();

                    if (nodes.Length == 1)
                    {
                        node = nodes[0];
                    }
                    else if (nodes.Length > 1)
                    {
                        Console.WriteLine($"Multiple nodes found with name '{nodeIdentifier}'. Please use node ID instead:");
                        foreach (var n in nodes)
                        {
                            Console.WriteLine($"  - {n.DisplayName} (ID: {n.Id})");
                        }
                        return;
                    }
                }

                if (node == null)
                {
                    Console.WriteLine($"Node '{nodeIdentifier}' not found.");
                    return;
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
