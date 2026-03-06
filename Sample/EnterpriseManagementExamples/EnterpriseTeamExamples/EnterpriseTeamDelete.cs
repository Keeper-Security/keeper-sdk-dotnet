using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using System.Linq;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseTeamExamples
{
    public static class EnterpriseTeamDeleteExample
    {
        public static async Task EnterpriseTeamDelete(VaultOnline vault, string teamNameOrId)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (string.IsNullOrWhiteSpace(teamNameOrId))
                {
                    Console.WriteLine("Team name or ID is null or empty.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData }
                );
                await enterpriseLoader.Load();

                EnterpriseTeam team = null;
                enterpriseData.TryGetTeam(teamNameOrId, out team);
                if (team == null)
                {
                    var matchingTeams = enterpriseData.Teams
                        .Where(x => string.Equals(x.Name, teamNameOrId, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (matchingTeams.Count == 1)
                    {
                        team = matchingTeams[0];
                    }
                    else if (matchingTeams.Count > 1)
                    {
                        Console.WriteLine($"Multiple teams found with name '{teamNameOrId}'. Please use team UID instead.");
                        foreach (var t in matchingTeams)
                        {
                            Console.WriteLine($"Team UID: {t.Uid}, Team Name: {t.Name}");
                        }
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"Team with name or UID '{teamNameOrId}' not found.");
                        return;
                    }
                }
                await enterpriseData.DeleteTeam(team.Uid);
                Console.WriteLine($"Team Deleted: {team.Name}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
