using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleAdminExample
    {
        public static async Task EnterpriseAddAdmin(VaultOnline vault, string roleNameOrId, string userName)
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
                if (string.IsNullOrWhiteSpace(userName))
                {
                    Console.WriteLine("User name is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData });
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
                        Console.WriteLine($"Multiple roles found with name '{roleNameOrId}'. Please use role Id instead.");
                        foreach (var r in matchingRoles)
                        {
                            Console.WriteLine($"Role Id: {r.Id}, Role Name: {r.DisplayName}");
                        }
                        return;
                    }
                    else {
                        Console.WriteLine($"Role with name or ID '{roleNameOrId}' not found.");
                        return;
                    }

                }

                var user = enterpriseData.Users.FirstOrDefault(u => u.Email == userName);
                if (user == null)
                {
                    Console.WriteLine($"User with email {userName} not found.");
                    return;
                }

                await roleData.AddUserToAdminRole(role, user);
                Console.WriteLine($"User {user.Email} added as admin to role {role.DisplayName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error adding admin: {ex.Message}");
            }
        }
    }
}
