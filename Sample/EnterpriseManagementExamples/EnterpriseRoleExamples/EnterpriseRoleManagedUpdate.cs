using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleManagedNodeUpdateExample
    {
        public static async Task RoleManagedNodeUpdate(string roleName, long nodeId, bool cascadeNodeManagement)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData { EnterpriseData = enterpriseData };
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData });
                await enterpriseLoader.Load();

                // Get the role by name
                var role = roleData.Roles.FirstOrDefault(r => r.DisplayName == roleName);
                if (role == null)
                {
                    Console.WriteLine("Role not found");
                    return;
                }

                // Get the node to manage
                if (!enterpriseData.TryGetNode(nodeId, out var node))
                {
                    Console.WriteLine("Node not found");
                    return;
                }
                
                // update managed node to role
                await roleData.RoleManagedNodeUpdate(role, node, cascadeNodeManagement);
                Console.WriteLine($"Managed node update to role: {role.Id}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}