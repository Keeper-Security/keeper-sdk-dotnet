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
    public partial class EnterpriseData : IEnterpriseDataManagement
    {
        /// <summary>
        /// Invites user to enterprise
        /// </summary>
        /// <param name="email">Email Address</param>
        /// <param name="fullName">Full Name</param>
        /// <returns>Invited User</returns>
        public async Task<EnterpriseUser> InviteUser(string email, InviteUserOptions options = null)
        {
            var userId = await Enterprise.GetEnterpriseId();
            var rq = new EnterpriseUserAddCommand
            {
                EnterpriseUserId = userId,
                EnterpriseUserUsername = email,
                NodeId = RootNode.Id,
            };

            EncryptedData encrypted = new EncryptedData();
            if (options != null)
            {
                if (options.SuppressEmail != null)
                {
                    rq.SuppressEmailInvite = true;
                }

                if (options.NodeId.HasValue)
                {
                    if (TryGetNode(options.NodeId.Value, out _))
                    {
                        rq.NodeId = options.NodeId.Value;
                    }
                }

                encrypted.DisplayName = options.FullName;
            }
            rq.EncryptedData = EnterpriseUtils.EncryptEncryptedData(encrypted, Enterprise.TreeKey);

            var rs = await Enterprise.Auth.ExecuteAuthCommand<EnterpriseUserAddCommand, EnterpriseUserAddResponse>(rq);
            if (options != null && options.SuppressEmail != null) 
            {
                options.SuppressEmail.Invoke(rs.VerificationCode);
            }
            await Enterprise.Load();
            TryGetUserById(userId, out var user);
            return user;
        }

        public async Task<EnterpriseUser> SetUserLocked(EnterpriseUser user, bool locked) 
        {
            var userId = user.Id;
            var rq = new EnterpriseUserLockCommand
            {
                EnterpriseUserId = userId,
                Lock = locked ? "locked" : "unlocked",
                DeleteIfPending = true
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            TryGetUserById(userId, out user);
            return user;
        }

        /// <summary>
        ///     Creates Enterprise Team.
        /// </summary>
        /// <param name="team">Enterprise Team</param>
        /// <returns>Created Team</returns>
        public async Task<EnterpriseTeam> CreateTeam(EnterpriseTeam team)
        {
            var teamKey = CryptoUtils.GenerateEncryptionKey();
            CryptoUtils.GenerateRsaKey(out var privateKey, out var publicKey);
            var encryptedPrivateKey = CryptoUtils.EncryptAesV1(privateKey, teamKey);
            var teamUid = CryptoUtils.GenerateUid();
            var rq = new TeamAddCommand
            {
                TeamUid = teamUid,
                TeamName = team.Name,
                RestrictEdit = team.RestrictEdit,
                RestrictShare = team.RestrictSharing,
                RestrictView = team.RestrictView,
                PublicKey = publicKey.Base64UrlEncode(),
                PrivateKey = encryptedPrivateKey.Base64UrlEncode(),
                NodeId = team.ParentNodeId,
                ManageOnly = true,
                EncryptedTeamKey = CryptoUtils.EncryptAesV2(teamKey, Enterprise.TreeKey).Base64UrlEncode()
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            TryGetTeam(teamUid, out team);
            return team;
        }

        /// <summary>
        ///     Updates Enterprise Team
        /// </summary>
        /// <param name="team">Enterprise Team</param>
        /// <returns>Updated Team</returns>
        public async Task<EnterpriseTeam> UpdateTeam(EnterpriseTeam team)
        {
            if (string.IsNullOrEmpty(team.Uid)) return await CreateTeam(team);

            if (!TryGetTeam(team.Uid, out _)) throw new EnterpriseException($"Team UID {team.Uid} not found in enterprise");

            var rq = new TeamUpdateCommand
            {
                TeamUid = team.Uid,
                TeamName = team.Name,
                RestrictEdit = team.RestrictEdit,
                RestrictShare = team.RestrictSharing,
                RestrictView = team.RestrictView,
                NodeId = team.ParentNodeId
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            TryGetTeam(team.Uid, out team);
            return team;
        }

        /// <summary>
        ///     Deletes Enterprise Team.
        /// </summary>
        /// <param name="teamUid">Enterprise Team UID.</param>
        /// <returns>Awaitable task.</returns>
        public async Task DeleteTeam(string teamUid)
        {
            var rq = new TeamDeleteCommand
            {
                TeamUid = teamUid
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <summary>
        ///     Add Enterprise User(s) to Team(s).
        /// </summary>
        /// <param name="emails">A list of user emails</param>
        /// <param name="teamUids">A list of team UIDs</param>
        /// <param name="warnings">A callback that receives warnings</param>
        /// <returns>Awaitable task.</returns>
        public async Task AddUsersToTeams(string[] emails, string[] teamUids, Action<string> warnings = null)
        {
            var userPublicKeys = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var email in emails)
                if (!TryGetUserByEmail(email, out var user))
                {
                    var message = $"User {email} not found.";
                    if (warnings != null)
                        warnings.Invoke(message);
                    else
                        throw new EnterpriseException(message);
                }
                else
                {
                    if (user.UserStatus != UserStatus.Active)
                    {
                        var message = $"User \'{user.Email}\' cannot be added to a team: user is not active.";
                        if (warnings != null)
                            warnings.Invoke(message);
                        else
                            throw new EnterpriseException(message);
                    }
                    else
                    {
                        userPublicKeys[user.Email] = null;
                    }
                }

            if (userPublicKeys.Count == 0)
            {
                warnings?.Invoke("No users to add");
                return;
            }

            var teamKeys = new Dictionary<string, byte[]>();
            foreach (var teamUid in teamUids)
                if (TryGetTeam(teamUid, out var _))
                {
                    teamKeys[teamUid] = null;
                }
                else
                {
                    var message = $"Team UID {teamUid} not found.";
                    if (warnings != null)
                        warnings.Invoke(message);
                    else
                        throw new EnterpriseException(message);
                }

            if (teamKeys.Count == 0)
            {
                warnings?.Invoke("No teams to add");
                return;
            }

            await this.PopulateUserPublicKeys(userPublicKeys, warnings);
            await this.PopulateTeamKeys(teamKeys, warnings);

            var commands = new List<KeeperApiCommand>();
            foreach (var userPair in userPublicKeys.Where(x => x.Value != null))
            {
                if (userPair.Value == null) continue;
                if (!TryGetUserByEmail(userPair.Key, out var user)) continue;
                try
                {
                    var publicKey = CryptoUtils.LoadPublicKey(userPair.Value);
                    foreach (var teamPair in teamKeys.Where(x => x.Value != null))
                    {
                        if (!TryGetTeam(teamPair.Key, out var team)) continue;
                        var users = GetUsersForTeam(team.Uid);
                        if (users != null && users.Contains(user.Id)) {
                            warnings?.Invoke($"User \"{user.Email}\" is already member of \"{team.Name}\" team. Skipped");
                            continue;
                        }
                        var teamKey = teamPair.Value;
                        commands.Add(new TeamEnterpriseUserAddCommand
                        {
                            TeamUid = team.Uid,
                            EnterpriseUserId = user.Id,
                            TeamKey = CryptoUtils.EncryptRsa(teamKey, publicKey).Base64UrlEncode(),
                            UserType = 0
                        });
                    }
                }
                catch (Exception e)
                {
                    warnings?.Invoke(e.Message);
                    Debug.WriteLine(e);
                }
            }

            if (commands.Count > 0)
            {
                var batch = commands.Take(99).ToList();
                var execRq = new ExecuteCommand
                {
                    Requests = batch
                };
                var execRs = await Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
                if (execRs.Results?.Count > 0)
                {
                    var last = execRs.Results.Last();
                    var success = execRs.Results.Count + (last.IsSuccess ? 0 : -1);
                    warnings?.Invoke($"Successfully added {success} team membership(s)");
                    if (!last.IsSuccess) warnings?.Invoke(last.message);
                }

                await Enterprise.Load();
            }
        }

        /// <summary>
        ///     Removes Users(s) from Team(s)
        /// </summary>
        /// <param name="emails">A list of user emails</param>
        /// <param name="teamUids">A list of team UIDs</param>
        /// <param name="warnings">A callback that receives warnings</param>
        /// <returns>Awaitable task.</returns>
        public async Task RemoveUsersFromTeams(string[] emails, string[] teamUids, Action<string> warnings = null)
        {
            var commands = new List<KeeperApiCommand>();
            foreach (var teamUid in teamUids)
            {
                if (!TryGetTeam(teamUid, out var team))
                {
                    warnings?.Invoke($"Team UID \'{teamUid}\' not found");
                    continue;
                }

                foreach (var email in emails)
                {
                    if (!TryGetUserByEmail(email, out var user)) {
                        warnings?.Invoke($"User \'{email}\' not found");
                        continue;
                    }

                    commands.Add(new TeamEnterpriseUserRemoveCommand
                    {
                        TeamUid = team.Uid,
                        EnterpriseUserId = user.Id
                    });
                }
            }

            if (commands.Count > 0)
            {
                var batch = commands.Take(99).ToList();
                var execRq = new ExecuteCommand
                {
                    Requests = batch
                };
                var execRs = await Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
                if (execRs.Results?.Count > 0)
                {
                    var last = execRs.Results.Last();
                    var success = execRs.Results.Count + (last.IsSuccess ? 0 : -1);
                    warnings?.Invoke($"Successfully removed {success} team membership(s)");
                    if (!last.IsSuccess) warnings?.Invoke(last.message);
                }

                await Enterprise.Load();
            }
        }
    }
}
