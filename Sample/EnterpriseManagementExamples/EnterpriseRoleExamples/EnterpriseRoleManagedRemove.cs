using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleManagedNodeRemoveExample
    {
       public static async Task RoleManagedNodeRemove(string roleName, long nodeId)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData();
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
                // Removed managed node to role
                await roleData.RoleManagedNodeRemove(role, node);
                Console.WriteLine($"Managed node removed to role: {role.Id}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}