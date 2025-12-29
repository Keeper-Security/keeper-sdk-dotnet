using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleUpdateExample
    {
        public static async Task EnterpriseUpdateRole(string roleName, bool? newUserInherit = null, bool? visibleBelow = null, string displayName = null)
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

                var role = roleData.Roles.FirstOrDefault(x => string.CompareOrdinal(x.DisplayName, roleName) == 0);
                if (role == null)
                {
                    Console.WriteLine($"Role '{roleName}' not found");
                    return;
                }

                var updatedRole = await roleData.UpdateRole(role, newUserInherit, visibleBelow, displayName);
                Console.WriteLine($"Role updated: {updatedRole.DisplayName} (ID: {updatedRole.Id})");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating role: {ex.Message}");
            }
        }
    }
}