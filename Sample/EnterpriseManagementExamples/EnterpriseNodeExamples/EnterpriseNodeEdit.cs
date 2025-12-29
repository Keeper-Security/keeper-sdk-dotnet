using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeEdit
    {
        public static async Task EditNode(string nodeIdentifier, string newName = null, string newParentNodeIdentifier = null)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                // Find the node to edit
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

                // Update the node name if provided
                var oldName = node.DisplayName;
                if (!string.IsNullOrEmpty(newName))
                {
                    node.DisplayName = newName;
                }

                // Find the new parent node (if provided)
                EnterpriseNode parentNode = null;

                if (!string.IsNullOrEmpty(newParentNodeIdentifier))
                {
                    if (long.TryParse(newParentNodeIdentifier, out var parentNodeId))
                    {
                        enterpriseData.TryGetNode(parentNodeId, out parentNode);
                    }

                    if (parentNode == null)
                    {
                        var parentNodes = enterpriseData.Nodes
                            .Where(x => string.Equals(x.DisplayName, newParentNodeIdentifier, StringComparison.InvariantCultureIgnoreCase))
                            .ToArray();

                        if (parentNodes.Length == 1)
                        {
                            parentNode = parentNodes[0];
                        }
                        else if (parentNodes.Length > 1)
                        {
                            Console.WriteLine($"Multiple parent nodes found with name '{newParentNodeIdentifier}'. Please use node ID instead:");
                            foreach (var n in parentNodes)
                            {
                                Console.WriteLine($"  - {n.DisplayName} (ID: {n.Id})");
                            }
                            return;
                        }
                    }

                    if (parentNode == null)
                    {
                        Console.WriteLine($"Parent node '{newParentNodeIdentifier}' not found.");
                        return;
                    }
                }

                await enterpriseData.UpdateNode(node, parentNode);

                Console.WriteLine($"Node '{node.DisplayName}' updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
