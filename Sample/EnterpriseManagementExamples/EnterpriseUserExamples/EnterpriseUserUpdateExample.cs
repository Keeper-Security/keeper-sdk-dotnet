using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseUserUpdateExample
    {
        public static async Task EnterpriseUserUpdate(VaultOnline vault, string email, string nodeNameOrId = null, string fullName = null, string jobTitle = null, string inviteeLocale = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                if (!enterpriseData.TryGetUserByEmail(email, out var user))
                {
                    Console.WriteLine($"User '{email}' not found in enterprise.");
                    return;
                }

                EnterpriseNode node = null;

                if(!string.IsNullOrWhiteSpace(nodeNameOrId))
                {
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
                }

                await enterpriseData.EnterpriseUserUpdate(user, node.Id, fullName, jobTitle, inviteeLocale);
                Console.WriteLine($"Enterprise user updated successfully with nodeId: {node.Id}, fullName: {fullName}, jobTitle: {jobTitle}, inviteeLocale: {inviteeLocale}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}