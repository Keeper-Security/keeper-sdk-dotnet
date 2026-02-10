using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class SetEnterpriseCustomInvitationExample
    {
        public static async Task SetEnterpriseCustomInvitation(string nodeNameOrId, string jsonFilePath)
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

                await enterpriseData.SetEnterpriseCustomInvitation(node.Id, jsonFilePath);
                Console.WriteLine($"Enterprise custom invitation set successfully with nodeId: {node.Id}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}