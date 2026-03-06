using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleEnforcementRemoveExample
    {
        public static async Task RoleEnforcementRemove(VaultOnline vault, string roleNameOrId, List<RoleEnforcementPolicies> enforcement)
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
                    Console.WriteLine("Role name or ID is null or empty.");
                    return;
                }
                if (enforcement == null || enforcement.Count == 0)                {
                    Console.WriteLine("Enforcements list is null or empty.");
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

                var responses = await roleData.RoleEnforcementRemoveBatch(role, enforcement);
                Console.WriteLine($"Batch enforcement results for role: {role.Id}");
                for (int i = 0; i < responses.Count; i++)
                {
                    var response = responses[i];
                    var enforcementPolicy = enforcement[i];
                    if (response.IsSuccess)
                    {
                        Console.WriteLine($"Command: {response.command}, Enforcement: {enforcementPolicy}, Result: {response.result}");
                    }
                    else
                    {
                        Console.WriteLine($"Command: {response.command}, Enforcement: {enforcementPolicy}, Result: {response.result}, Code: {response.resultCode}, Message: {response.message}");
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