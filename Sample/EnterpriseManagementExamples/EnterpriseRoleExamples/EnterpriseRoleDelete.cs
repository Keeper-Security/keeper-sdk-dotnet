using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleDeleteExample
    {
        public static async Task EnterpriseDeleteRole(VaultOnline vault, string roleNameOrId)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(roleNameOrId))
                {
                    Console.WriteLine("Role name or ID is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData }
                );
                await enterpriseLoader.Load();
                EnterpriseRole role = null;
                if (long.TryParse(roleNameOrId, out var roleId))
                {
                    roleData.TryGetRole(roleId, out role);
                }

                if (role == null)
                {
                    var matchingRoles = roleData.Roles.Where(r => r.DisplayName == roleNameOrId).ToList();
                    if (matchingRoles.Count == 1){
                        role = matchingRoles[0];
                    }
                    else if (matchingRoles.Count > 1)
                    {
                        Console.WriteLine($"Multiple roles found with name or ID '{roleNameOrId}'. Please use role ID instead.");
                        foreach (var r in matchingRoles)
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
                
                await roleData.DeleteRole(role);
                Console.WriteLine($"Role deleted: Name: {role.DisplayName} (ID: {role.Id})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting role: {ex.Message}");
            }
        }
    }
}