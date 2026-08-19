using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Options for approving queued teams and queued team users.
    /// </summary>
    public class TeamApproveOptions
    {
        /// <summary>
        /// Approve queued teams. Defaults to <c>true</c>.
        /// </summary>
        public bool ApproveTeams { get; set; } = true;

        /// <summary>
        /// Approve queued team users. Defaults to <c>true</c>.
        /// </summary>
        public bool ApproveUsers { get; set; } = true;

        /// <summary>
        /// Restrict record edits for newly approved teams.
        /// </summary>
        public bool RestrictEdit { get; set; }

        /// <summary>
        /// Restrict record sharing for newly approved teams.
        /// </summary>
        public bool RestrictShare { get; set; }

        /// <summary>
        /// Restrict viewing/copying passwords for newly approved teams.
        /// </summary>
        public bool RestrictView { get; set; }

        /// <summary>
        /// Report planned approvals without executing them.
        /// </summary>
        public bool DryRun { get; set; }

        /// <summary>
        /// Optional callback that receives non-fatal warnings.
        /// </summary>
        public Action<string> Warnings { get; set; }
    }

    /// <summary>
    /// A queued team or queued team-user approval action.
    /// </summary>
    public class TeamApproveAction
    {
        /// <summary>
        /// Action name: "Approve Team" or "Approve User".
        /// </summary>
        public string Action { get; internal set; }

        /// <summary>
        /// Team UID.
        /// </summary>
        public string TeamUid { get; internal set; }

        /// <summary>
        /// Team name.
        /// </summary>
        public string TeamName { get; internal set; }

        /// <summary>
        /// User email when the action is a user approval.
        /// </summary>
        public string UserEmail { get; internal set; }
    }

    /// <summary>
    /// Result of a queued team approval run.
    /// </summary>
    public class TeamApproveResult
    {
        /// <summary>
        /// Planned or executed approval actions.
        /// </summary>
        public IReadOnlyList<TeamApproveAction> Actions { get; internal set; } = Array.Empty<TeamApproveAction>();

        /// <summary>
        /// Number of teams approved successfully.
        /// </summary>
        public int TeamsApproved { get; internal set; }

        /// <summary>
        /// Number of team approvals that failed.
        /// </summary>
        public int TeamsFailed { get; internal set; }

        /// <summary>
        /// Number of team users approved successfully.
        /// </summary>
        public int UsersApproved { get; internal set; }

        /// <summary>
        /// Number of team user approvals that failed.
        /// </summary>
        public int UsersFailed { get; internal set; }
    }

    public partial class EnterpriseData
    {
        private const int TeamApproveBatchSize = 99;

        /// <inheritdoc />
        public async Task<TeamApproveResult> ApproveQueuedTeams(IQueuedTeamData queuedTeamData, TeamApproveOptions options = null)
        {
            options ??= new TeamApproveOptions();

            var result = new TeamApproveResult();
            var actions = new List<TeamApproveAction>();
            var commands = new List<KeeperApiCommand>();
            var addedTeamKeys = new Dictionary<string, byte[]>();
            var teamNames = Teams.ToDictionary(t => t.Uid, t => t.Name, StringComparer.Ordinal);
            var knownTeamUids = new HashSet<string>(Teams.Select(t => t.Uid), StringComparer.Ordinal);
            var pendingQueuedTeamUids = new HashSet<string>(
                queuedTeamData.QueuedTeams.Select(t => t.Uid),
                StringComparer.Ordinal);

            foreach (var queuedTeam in queuedTeamData.QueuedTeams)
            {
                teamNames[queuedTeam.Uid] = queuedTeam.Name;
            }

            if (options.ApproveTeams)
            {
                foreach (var queuedTeam in queuedTeamData.QueuedTeams)
                {
                    var teamKey = CryptoUtils.GenerateEncryptionKey();
                    addedTeamKeys[queuedTeam.Uid] = teamKey;
                    var rq = CreateTeamAddCommand(queuedTeam.Uid, queuedTeam.Name, queuedTeam.ParentNodeId,
                        options.RestrictEdit, options.RestrictShare, options.RestrictView, teamKey);
                    rq.TeamKey = CryptoUtils.EncryptAesV1(teamKey, Enterprise.Auth.AuthContext.DataKey).Base64UrlEncode();
                    commands.Add(rq);
                    actions.Add(new TeamApproveAction
                    {
                        Action = "Approve Team",
                        TeamUid = queuedTeam.Uid,
                        TeamName = queuedTeam.Name,
                    });
                }
            }

            if (options.ApproveUsers)
            {
                var activeUsers = Users
                    .Where(u => u.UserStatus == UserStatus.Active)
                    .ToDictionary(u => u.Id, u => u);

                var eligibleTeamUids = queuedTeamData.GetTeamUidsWithQueuedUsers()
                    .Distinct(StringComparer.Ordinal)
                    .Where(uid => (queuedTeamData.GetQueuedUsersForTeam(uid) ?? Enumerable.Empty<long>()).Any())
                    .ToArray();

                var usersToLoad = eligibleTeamUids
                    .SelectMany(uid => queuedTeamData.GetQueuedUsersForTeam(uid) ?? Enumerable.Empty<long>())
                    .Where(id => activeUsers.ContainsKey(id))
                    .Select(id => activeUsers[id].Email)
                    .Distinct(StringComparer.InvariantCultureIgnoreCase)
                    .ToArray();

                if (usersToLoad.Length > 0)
                {
                    await Enterprise.Auth.LoadUsersKeys(usersToLoad);
                }

                foreach (var teamUid in eligibleTeamUids)
                {
                    var teamKey = addedTeamKeys.TryGetValue(teamUid, out var generatedKey)
                        ? generatedKey
                        : TryGetTeam(teamUid, out var team) ? team.TeamKey : null;
                    if (teamKey == null)
                    {
                        var teamName = LookupTeamName(teamNames, teamUid);
                        if (!options.ApproveTeams && pendingQueuedTeamUids.Contains(teamUid) && !knownTeamUids.Contains(teamUid))
                        {
                            options.Warnings?.Invoke($"Team \"{teamName}\" is still queued. Approve teams first.");
                        }
                        else
                        {
                            options.Warnings?.Invoke($"Team \"{teamName}\" does not have an encryption key.");
                        }
                        continue;
                    }

                    var existingMemberSet = knownTeamUids.Contains(teamUid)
                        ? new HashSet<long>(GetUsersForTeam(teamUid) ?? Array.Empty<long>())
                        : new HashSet<long>();

                    foreach (var userId in queuedTeamData.GetQueuedUsersForTeam(teamUid) ?? Enumerable.Empty<long>())
                    {
                        if (!activeUsers.TryGetValue(userId, out var user) || existingMemberSet.Contains(user.Id))
                        {
                            continue;
                        }

                        if (!Enterprise.Auth.TryGetUserKeys(user.Email, out var userKeys))
                        {
                            options.Warnings?.Invoke($"Cannot load public keys for user \"{user.Email}\".");
                            continue;
                        }

                        try
                        {
                            var addCommand = new TeamEnterpriseUserAddCommand
                            {
                                TeamUid = teamUid,
                                EnterpriseUserId = user.Id,
                                UserType = 0
                            };
                            ApplyUserTeamKey(addCommand, teamKey, userKeys);
                            commands.Add(addCommand);
                            actions.Add(new TeamApproveAction
                            {
                                Action = "Approve User",
                                TeamUid = teamUid,
                                TeamName = LookupTeamName(teamNames, teamUid),
                                UserEmail = user.Email,
                            });
                        }
                        catch (Exception e)
                        {
                            options.Warnings?.Invoke($"Cannot approve user \"{user.Email}\" to team \"{LookupTeamName(teamNames, teamUid)}\": {e.Message}");
                            Debug.WriteLine(e);
                        }
                    }
                }
            }

            result.Actions = actions;
            if (commands.Count == 0 || options.DryRun)
            {
                return result;
            }

            foreach (var batch in commands
                         .Select((cmd, index) => new { cmd, index })
                         .GroupBy(x => x.index / TeamApproveBatchSize)
                         .Select(g => g.Select(x => x.cmd).ToList()))
            {
                var execRs = await Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(new ExecuteCommand
                {
                    Requests = batch
                });

                var results = execRs?.Results ?? Array.Empty<KeeperApiResponse>();
                foreach (var item in batch.Select((cmd, i) => new
                {
                    Command = cmd,
                    Response = i < results.Count ? results[i] : null
                }))
                {
                    var success = item.Response?.IsSuccess == true;
                    var isTeam = item.Command is TeamAddCommand;
                    if (isTeam)
                    {
                        if (success) result.TeamsApproved++;
                        else result.TeamsFailed++;
                    }
                    else
                    {
                        if (success) result.UsersApproved++;
                        else result.UsersFailed++;
                    }

                    if (!success && !string.IsNullOrEmpty(item.Response?.message))
                    {
                        options.Warnings?.Invoke(item.Response.message);
                    }
                }
            }

            await Enterprise.Load();
            return result;
        }

        private static string LookupTeamName(IDictionary<string, string> teamNames, string teamUid)
        {
            return teamNames.TryGetValue(teamUid, out var name) && !string.IsNullOrEmpty(name) ? name : teamUid;
        }
    }
}
