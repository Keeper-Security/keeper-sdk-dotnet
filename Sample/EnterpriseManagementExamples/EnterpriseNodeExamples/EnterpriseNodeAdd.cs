using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeAdd
    {
        public static async Task AddNode(string nodeName, string parentNodeIdentifier = null)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                EnterpriseNode parentNode = null;

                if (!string.IsNullOrEmpty(parentNodeIdentifier))
                {
                    // Try to parse as node ID first
                    if (long.TryParse(parentNodeIdentifier, out var parentNodeId))
                    {
                        enterpriseData.TryGetNode(parentNodeId, out parentNode);
                    }

                    if (parentNode == null)
                    {
                        var nodes = enterpriseData.Nodes
                            .Where(x => string.Equals(x.DisplayName, parentNodeIdentifier, StringComparison.InvariantCultureIgnoreCase))
                            .ToArray();

                        if (nodes.Length == 1)
                        {
                            parentNode = nodes[0];
                        }
                        else if (nodes.Length > 1)
                        {
                            Console.WriteLine($"Multiple nodes found with name '{parentNodeIdentifier}'. Please use node ID instead:");
                            foreach (var n in nodes)
                            {
                                Console.WriteLine($"  - {n.DisplayName} (ID: {n.Id})");
                            }
                            return;
                        }
                    }

                    if (parentNode == null)
                    {
                        Console.WriteLine($"Parent node '{parentNodeIdentifier}' not found.");
                        return;
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
