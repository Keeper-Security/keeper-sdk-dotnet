using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleMembershipExample
    {
        public static async Task EnterpriseRemoveRoleMembership(long roleId, string userName)
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

                var role = roleData.Roles.FirstOrDefault(r => r.Id == roleId);
                if (role == null)
                {
                    Console.WriteLine($"Role with ID {roleId} not found.");
                    return;
                }

                var user = enterpriseData.Users.FirstOrDefault(u => u.Email == userName);
                if (user == null)
                {
                    Console.WriteLine($"User with email {userName} not found.");
                    return;
                }

                await roleData.RemoveUserFromRole(role, user);
                Console.WriteLine($"User {user.Email} removed from role {role.DisplayName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing user from role: {ex.Message}");
            }
        }
    }
}
