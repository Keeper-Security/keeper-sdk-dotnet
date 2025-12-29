using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleDeleteExample
    {
        public static async Task EnterpriseDeleteRole(long roleId)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData }
                );
                await enterpriseLoader.Load();
                var role = roleData.Roles.FirstOrDefault(r => r.Id == roleId);
                if (role == null)
                {
                    Console.WriteLine($"Role with ID {roleId} not found.");
                    return;
                }
                await roleData.DeleteRole(role);
                Console.WriteLine($"Role deleted: {roleId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting role: {ex.Message}");
            }
        }
    }
}