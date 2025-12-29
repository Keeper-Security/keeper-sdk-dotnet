using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleView
    {
        public static async Task ViewRole(string roleIdentifier)
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

                EnterpriseRole role = null;

                if (long.TryParse(roleIdentifier, out var roleId))
                {
                    roleData.TryGetRole(roleId, out role);
                }

                if (role == null)
                {
                    var roles = roleData.Roles
                        .Where(x => string.Equals(x.DisplayName, roleIdentifier, StringComparison.InvariantCultureIgnoreCase))
                        .ToArray();

                    if (roles.Length == 1)
                    {
                        role = roles[0];
                    }
                    else if (roles.Length > 1)
                    {
                        Console.WriteLine($"Multiple roles found with name '{roleIdentifier}'. Please use role ID instead:");
                        foreach (var r in roles)
                        {
                            Console.WriteLine($"  - {r.DisplayName} (ID: {r.Id})");
                        }
                        return;
                    }
                }

                if (role == null)
                {
                    Console.WriteLine($"Role '{roleIdentifier}' not found.");
                    return;
                }

                Console.WriteLine("======== Enterprise Role Details ========");
                Console.WriteLine($"Role ID:         {role.Id}");
                Console.WriteLine($"Display Name:    {role.DisplayName}");
                Console.WriteLine($"Node ID:         {role.ParentNodeId}");
                Console.WriteLine($"Visible Below:   {role.VisibleBelow}");
                Console.WriteLine($"New User Inherit: {role.NewUserInherit}");

                // Get users in this role
                var userIds = roleData.GetUsersForRole(role.Id).ToArray();
                if (userIds.Length > 0)
                {
                    Console.WriteLine($"\nUsers ({userIds.Length}):");
                    foreach (var userId in userIds)
                    {
                        if (enterpriseData.TryGetUserById(userId, out var user))
                        {
                            Console.WriteLine($"  - {user.Email} ({user.DisplayName})");
                        }
                        else
                        {
                            Console.WriteLine($"  - Unknown User (ID: {userId})");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\nUsers: None");
                }

                // Get teams in this role
                var teamUids = roleData.GetTeamsForRole(role.Id).ToArray();
                if (teamUids.Length > 0)
                {
                    Console.WriteLine($"\nTeams ({teamUids.Length}):");
                    foreach (var teamUid in teamUids)
                    {
                        if (enterpriseData.TryGetTeam(teamUid, out var team))
                        {
                            Console.WriteLine($"  - {team.Name} (UID: {team.Uid})");
                        }
                        else
                        {
                            Console.WriteLine($"  - Unknown Team (UID: {teamUid})");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\nTeams: None");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
