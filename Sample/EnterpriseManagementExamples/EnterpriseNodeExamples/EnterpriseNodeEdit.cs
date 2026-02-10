using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeEdit
    {
        public static async Task EditNode(string nodeNameOrId, string newName = null, string newParentNodeIdentifier = null)
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
                        Console.WriteLine($"Node '{nodeNameOrId}' not found.");
                        return;
                    }
                }

                var oldName = node.DisplayName;
                if (!string.IsNullOrEmpty(newName))
                {
                    node.DisplayName = newName;
                }

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
                        else
                        {
                            Console.WriteLine($"Parent node '{newParentNodeIdentifier}' not found.");
                            return;
                        }
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
