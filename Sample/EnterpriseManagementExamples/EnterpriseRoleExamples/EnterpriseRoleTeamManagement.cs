using System;
using KeeperSecurity.Vault;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class EnterpriseRoleTeamManagementExample
    {
        public static async Task AddTeamToRoleExample(VaultOnline vault, string roleNameOrId, string teamNameOrId)
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
                if (string.IsNullOrWhiteSpace(teamNameOrId))
                {
                    Console.WriteLine("Team name or ID is null or empty.");
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
                
                EnterpriseTeam team = null;
                enterpriseData.TryGetTeam(teamNameOrId, out team);
                if (team == null)
                {
                    team = enterpriseData.Teams.FirstOrDefault(t => string.Equals(t.Name, teamNameOrId, StringComparison.OrdinalIgnoreCase));
                    if (team == null)
                    {
                        Console.WriteLine($"Team with name or UID '{teamNameOrId}' not found.");
                        return;
                    }
                }

                await roleData.AddTeamToRole(role, team);
                Console.WriteLine($"Team {team.Name} added to role {role.DisplayName}");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task RemoveTeamFromRoleExample(VaultOnline vault, string roleNameOrId, string teamNameOrid)
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
                if (string.IsNullOrWhiteSpace(teamNameOrid))
                {
                    Console.WriteLine("Team name or UID is null or empty.");
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
                    if (matchingRoles.Count == 1)
                    {
                        role = matchingRoles[0];
                    }
                    else if (matchingRoles.Count > 1)
                    {
                        Console.WriteLine($"Multiple roles found with name or ID '{roleNameOrId}'. Please use role ID instead.");
                        foreach (var r in matchingRoles)
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

                EnterpriseTeam team = null;

                enterpriseData.TryGetTeam(teamNameOrid, out team);
                if (team == null)
                {
                    team = enterpriseData.Teams.FirstOrDefault(t => string.Equals(t.Name, teamNameOrid, StringComparison.OrdinalIgnoreCase));
                    if (team == null)
                    {
                        Console.WriteLine($"Team with name or UID '{teamNameOrid}' not found.");
                        return;
                    }
                }

                await roleData.RemoveTeamFromRole(role, team);
                Console.WriteLine($"Team {team.Name} removed from role {role.DisplayName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing team from role: {ex.Message}");
            }
        }
    }
}