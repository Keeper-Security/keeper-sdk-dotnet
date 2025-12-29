using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleTeamManagementExample
    {
        public static async Task AddTeamToRoleExample(string roleName, string teamName)
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

                var role = roleData.Roles.FirstOrDefault(r => string.CompareOrdinal(r.DisplayName, roleName) == 0);
                if (role == null)
                {
                    Console.WriteLine($"Role with name {roleName} not found.");
                    return;
                }

                var team = enterpriseData.Teams.FirstOrDefault(t => string.CompareOrdinal(t.Name, teamName) == 0);
                if (team == null)
                {
                    Console.WriteLine($"Team with name {teamName} not found.");
                    return;
                }

                await roleData.AddTeamToRole(role, team);
                Console.WriteLine($"Team {teamName} added to role {roleName}");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task RemoveTeamFromRoleExample(string roleName, string teamName)
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

                var role = roleData.Roles.FirstOrDefault(r => string.CompareOrdinal(r.DisplayName, roleName) == 0);
                if (role == null)
                {
                    Console.WriteLine($"Role with name {roleName} not found.");
                    return;
                }

                var team = enterpriseData.Teams.FirstOrDefault(t => string.CompareOrdinal(t.Name, teamName) == 0);
                if (team == null)
                {
                    Console.WriteLine($"Team with name {teamName} not found.");
                    return;
                }

                await roleData.RemoveTeamFromRole(role, team);
                Console.WriteLine($"Team {teamName} removed from role {roleName}");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating role: {ex.Message}");
            }
        }
    }
}