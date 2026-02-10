using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class EnterpriseNodeView
    {
        public static async Task ViewNode(string nodeNameOrId)
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

                Console.WriteLine("======== Enterprise Node Details ========");
                Console.WriteLine($"Node ID:            {node.Id}");
                Console.WriteLine($"Display Name:       {node.DisplayName}");
                Console.WriteLine($"Parent Node ID:     {node.ParentNodeId}");
                Console.WriteLine($"Restrict Visibility: {node.RestrictVisibility}");

                if (node.Subnodes != null && node.Subnodes.Count > 0)
                {
                    Console.WriteLine($"\nSubnodes ({node.Subnodes.Count}):");
                    foreach (var subnodeId in node.Subnodes)
                    {
                        if (enterpriseData.TryGetNode(subnodeId, out var subnode))
                        {
                            Console.WriteLine($"  - {subnode.DisplayName} (ID: {subnode.Id})");
                        }
                        else
                        {
                            Console.WriteLine($"  - Unknown Node (ID: {subnodeId})");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\nSubnodes: None");
                }

                var usersInNode = enterpriseData.Users
                    .Where(u => u.ParentNodeId == node.Id)
                    .ToArray();

                if (usersInNode.Length > 0)
                {
                    Console.WriteLine($"\nUsers in Node ({usersInNode.Length}):");
                    foreach (var user in usersInNode)
                    {
                        Console.WriteLine($"  - {user.Email} ({user.DisplayName})");
                    }
                }
                else
                {
                    Console.WriteLine("\nUsers in Node: None");
                }

                Console.WriteLine("=========================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}