using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseAddUserExample
    {
        public static async Task InviteUser(VaultOnline vault, string email, string fullName, string nodeNameOrId = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (string.IsNullOrWhiteSpace(email))
                {
                    Console.WriteLine("Email is required.");
                    return;
                }
                if (string.IsNullOrWhiteSpace(fullName))
                {
                    Console.WriteLine("Full name is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

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

                var options = new InviteUserOptions { FullName = fullName, NodeId = node.Id };
                var newUser = await enterpriseData.InviteUser(email, options);

                Console.WriteLine("======== User Invited Successfully ========");
                Console.WriteLine($"User ID:      {newUser.Id}");
                Console.WriteLine($"Email:        {newUser.Email}");
                Console.WriteLine($"Display Name: {newUser.DisplayName}");
                Console.WriteLine($"Status:       {newUser.UserStatus}");
                Console.WriteLine($"Node ID:      {newUser.ParentNodeId}");
                Console.WriteLine("============================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error inviting user: {ex.Message}");
            }
        }
    }
}