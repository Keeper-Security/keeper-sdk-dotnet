using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleManagedNodePrivilegeRemoveExample
    {
        public static async Task RoleManagedNodePrivilegeRemove(string roleNameOrId, string nodeNameOrId, List<RoleManagedNodePrivilege> privileges)
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
                if (string.IsNullOrWhiteSpace(roleNameOrId))
                {
                    Console.WriteLine("Role name or ID is null or empty.");
                    return;
                }
                if (string.IsNullOrWhiteSpace(nodeNameOrId))
                {
                    Console.WriteLine("Node name or ID is null or empty.");
                    return;
                }
                if (privileges == null || privileges.Count == 0)
                {
                    Console.WriteLine("Privileges list is null or empty.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData { EnterpriseData = enterpriseData };
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData });
                await enterpriseLoader.Load();

                EnterpriseRole role = null;
                if (long.TryParse(roleNameOrId, out var roleId))
                {
                    roleData.TryGetRole(roleId, out role);
                }
                if(role == null)
                {
                    var matchingRoles = roleData.Roles.Where(r => r.DisplayName == roleNameOrId).ToList();
                    if(matchingRoles.Count == 1)
                    {
                        role = matchingRoles[0];
                    }
                    else if(matchingRoles.Count > 1)
                    {
                        Console.WriteLine($"Multiple roles found with name or ID '{roleNameOrId}'. Please use role ID instead.");
                        foreach(var r in matchingRoles)
                        {
                            Console.WriteLine($"Role Id: {r.Id}, Role Name: {r.DisplayName}");
                        }
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"Role with name or ID '{roleNameOrId}' not found.");
                        return;
                    }
                }
                
                EnterpriseNode node = null;
                if (long.TryParse(nodeNameOrId, out var nodeId))
                {
                    enterpriseData.TryGetNode(nodeId, out node);
                }
                if(node == null)
                {
                    node = enterpriseData.Nodes.FirstOrDefault(n => n.DisplayName == nodeNameOrId);
                    if(node == null)
                    {
                        Console.WriteLine($"Node with name or ID '{nodeNameOrId}' not found.");
                        return;
                    }
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