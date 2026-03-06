using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Sample.Helpers;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseUserViewExample
    {
        public static async Task ViewUser(VaultOnline vault, string email)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
                if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
                {
                    return;
                }
                if (string.IsNullOrWhiteSpace(email))
                {
                    Console.WriteLine("Email is required.");
                    return;
                }

                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                if (!enterpriseData.TryGetUserByEmail(email, out var user))
                {
                    Console.WriteLine($"User '{email}' not found in enterprise.");
                    return;
                }

                Console.WriteLine("======== Enterprise User Details ========");
                Console.WriteLine($"User ID:      {user.Id}");
                Console.WriteLine($"Email:        {user.Email}");
                Console.WriteLine($"Display Name: {user.DisplayName}");
                Console.WriteLine($"Status:       {user.UserStatus}");
                Console.WriteLine($"Node ID:      {user.ParentNodeId}");
                Console.WriteLine($"Locked:       {(user.UserStatus == UserStatus.Locked ? "Yes" : "No")}");

                var teamUids = enterpriseData.GetTeamsForUser(user.Id);

                if (teamUids != null && teamUids.Length > 0)
                {
                    Console.WriteLine($"\nTeams ({teamUids.Length}):");
                    foreach (var teamUid in teamUids)
                    {
                        if (enterpriseData.TryGetTeam(teamUid, out var team))
                        {
                            Console.WriteLine($"  Team Name: {team.Name}");
                            Console.WriteLine($"  Team UID: {team.Uid}");
                            Console.WriteLine($"      Restrict Edit:  {team.RestrictEdit}");
                            Console.WriteLine($"      Restrict Share: {team.RestrictSharing}");
                            Console.WriteLine($"      Restrict View:  {team.RestrictView}");
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

                Console.WriteLine("=========================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}