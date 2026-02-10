using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleAdd
    {
        public static async Task AddRole(string roleName, string nodeNameOrId, bool newUserInherit = false)
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

                if (string.IsNullOrWhiteSpace(roleName))
                {
                    Console.WriteLine("Role name is required.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(nodeNameOrId))
                {
                    Console.WriteLine("Node name or ID is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData });
                await enterpriseLoader.Load();

                EnterpriseNode node = null;
                if (long.TryParse(nodeNameOrId, out var nodeId))
                {
                    enterpriseData.TryGetNode(nodeId, out node);
                }

                if (node == null)
                {
                    node = enterpriseData.Nodes
                        .FirstOrDefault(n => string.Equals(n.DisplayName, nodeNameOrId, StringComparison.OrdinalIgnoreCase));

                    if (node == null)
                    {
                        Console.WriteLine($"Node '{nodeNameOrId}' not found in enterprise.");
                        return;
                    }
                }


                var role = await roleData.CreateRole(roleName, node.Id, newUserInherit);

                Console.WriteLine("======== Role Created Successfully ========");
                Console.WriteLine($"Role ID:          {role.Id}");
                Console.WriteLine($"Role Name:        {role.DisplayName}");
                Console.WriteLine($"Node ID:          {role.ParentNodeId}");
                Console.WriteLine($"New User Inherit: {role.NewUserInherit}");
                Console.WriteLine($"Visible Below:    {role.VisibleBelow}");
                Console.WriteLine("============================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error adding role: {ex.Message}");
            }
        }
    }
}