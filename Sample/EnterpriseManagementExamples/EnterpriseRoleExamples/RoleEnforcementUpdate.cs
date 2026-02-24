using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleEnforcementUpdateExample
    {
        public static async Task RoleEnforcementUpdate(string roleNameOrId, IDictionary<RoleEnforcementPolicies, string> enforcements)
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
                if (enforcements == null || enforcements.Count == 0)                {
                    Console.WriteLine("Enforcements dictionary is null or empty.");
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

                var responses = await roleData.RoleEnforcementUpdateBatch(role, enforcements);
                var enforcementKeys = enforcements.Keys.ToList();
                for (int i = 0; i < responses.Count; i++)
                {
                    var response = responses[i];
                    var enforcementPolicy = enforcementKeys[i];
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