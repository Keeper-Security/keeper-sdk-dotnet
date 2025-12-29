using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleAddExample
    {
        public static async Task EnterpriseAddRole(string roleName, long nodeId, bool newUserInherit)
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

                var role = await roleData.CreateRole(roleName: roleName, nodeId: nodeId, newUserInherit: newUserInherit);
                Console.WriteLine($"Role added: {role.Id}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error adding role: {ex.Message}");
            }
        }
    }
}