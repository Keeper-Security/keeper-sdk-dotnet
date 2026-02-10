using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleView
    {
        public static async Task ViewRole(string roleNameOrId)
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
