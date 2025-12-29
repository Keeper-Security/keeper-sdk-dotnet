using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;


namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    // Inherits from QueuedTeamData (same approach as QueuedTeamDataManagement)
    public class EnterpriseEditUserExamples : QueuedTeamData
    {
        private EnterpriseData _enterpriseData;

        public async Task AddUsersToTeams(string[] emails, string[] teamUids)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                _enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { _enterpriseData, this });  // "this" registers ourselves as plugin
                await enterpriseLoader.Load();

                int successCount = 0;

                foreach (var email in emails)
                {
                    if (!_enterpriseData.TryGetUserByEmail(email, out var user))
                    {
                        Console.WriteLine($"User {email} not found.");
                        continue;
                    }

                    foreach (var teamUid in teamUids)
                    {
                        var team = _enterpriseData.Teams
                            .FirstOrDefault(x => string.CompareOrdinal(x.Uid, teamUid) == 0);
                        var queuedTeam = QueuedTeams  // Now we can use QueuedTeams directly (inherited)
                            .FirstOrDefault(x => string.CompareOrdinal(x.Uid, teamUid) == 0);

                        if (team == null && queuedTeam == null)
                        {
                            Console.WriteLine($"Team {teamUid} cannot be found.");
                            continue;
                        }

                        if (team != null)
                        {
                            if (user.UserStatus == UserStatus.Active)
                            {
                                await _enterpriseData.AddUsersToTeams(new[] { user.Email }, new[] { team.Uid }, Console.WriteLine);
                                Console.WriteLine($"User {user.Email} added to team {team.Name} successfully.");
                            }
                            else
                            {
                                await QueueUserToTeam(user.Id, team.Uid);
                                Console.WriteLine($"User {user.Email} queued to team {team.Name} (user not active).");
                            }
                            successCount++;
                        }
                        else if (queuedTeam != null)
                        {
                            await QueueUserToTeam(user.Id, queuedTeam.Uid);
                            Console.WriteLine($"User {user.Email} queued to team {queuedTeam.Name}.");
                            successCount++;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        // Now uses Enterprise.Auth (same as QueuedTeamDataManagement)
        private async Task QueueUserToTeam(long enterpriseUserId, string teamUid)
        {
            var rq = new TeamQueueUserCommand
            {
                TeamUid = teamUid,
                EnterpriseUserId = enterpriseUserId
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);  // Using Enterprise.Auth now!
            await Enterprise.Load();                        // Using Enterprise.Load now!
        }


        public async Task RemoveUsersFromTeams(string[] emails, string[] teamUids)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                _enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { _enterpriseData, this });
                await enterpriseLoader.Load();

                await _enterpriseData.RemoveUsersFromTeams(emails, teamUids);
                Console.WriteLine("User removed from team successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
