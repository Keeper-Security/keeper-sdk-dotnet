using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleManagedNodePrivilegeRemove
    {
        public static async Task RoleManagedNodePrivilegeRemove(string roleName, long nodeId, List<RoleManagedNodePrivilege> privileges)
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

                var role = roleData.Roles.FirstOrDefault(r => r.DisplayName == roleName);
                if (role == null)
                {
                    Console.WriteLine("Role not found");
                    return;
                }

                if (!enterpriseData.TryGetNode(nodeId, out var node))
                {
                    Console.WriteLine("Node not found");
                    return;
                }
                var responses = await roleData.RoleManagedNodePrivilegeRemoveBatch(role, node, privileges);
                for (int i = 0; i < responses.Count; i++)
                {
                    var response = responses[i];
                    var privilege = privileges[i];
                    if (response.IsSuccess)
                    {
                        Console.WriteLine($"Command: {response.command}, Privilege: {privilege}, Result: {response.result}");
                    }
                    else
                    {
                        Console.WriteLine($"Command: {response.command}, Privilege: {privilege}, Result: {response.result}, Code: {response.resultCode}, Message: {response.message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}