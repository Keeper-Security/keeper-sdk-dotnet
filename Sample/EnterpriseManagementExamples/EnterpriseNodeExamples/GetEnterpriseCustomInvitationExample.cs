using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class GetEnterpriseCustomInvitationExample
    {
        public static async Task GetEnterpriseCustomInvitation(VaultOnline vault, string nodeNameOrId)
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
                        Console.WriteLine($"Node '{nodeNameOrId}' not found.");
                        return;
                    }
                }

                var invitation = await enterpriseData.GetEnterpriseCustomInvitation(node.Id);
                Console.WriteLine($"Subject: {invitation.Subject}");
                Console.WriteLine($"Header: {invitation.Header}");
                Console.WriteLine($"Body: {invitation.Body}");
                Console.WriteLine($"ButtonLabel: {invitation.ButtonLabel}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}