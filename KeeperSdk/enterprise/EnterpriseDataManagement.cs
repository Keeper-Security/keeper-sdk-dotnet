﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Enterprise;
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
        /// <param name="options">Optional</param>
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
                if (options.NodeId.HasValue)
                {
                    if (TryGetNode(options.NodeId.Value, out var node))
                    {
                        rq.NodeId = node.Id;
                    }
                }

                encrypted.DisplayName = options.FullName;
            }
            rq.EncryptedData = EnterpriseUtils.EncryptEncryptedData(encrypted, Enterprise.TreeKey);

            var _ = await Enterprise.Auth.ExecuteAuthCommand<EnterpriseUserAddCommand, EnterpriseUserAddResponse>(rq);
            await Enterprise.Load();
            TryGetUserById(userId, out var user);
            return user;
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public async Task DeleteUser(EnterpriseUser user) 
        {
            var rq = new EnterpriseUserDeleteCommand
            {
                EnterpriseUserId = user.Id
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <inheritdoc/>
        public async Task<AccountTransferResult> TransferUserAccount(IRoleData roleData, EnterpriseUser fromUser, EnterpriseUser targetUser)
        {
            if (fromUser.UserStatus == UserStatus.Inactive)
            {
                throw new KeeperApiException("user_not_active", "Cannot transfer inactive user");
            }

            if (fromUser.UserStatus != UserStatus.Locked)
            {
                var rq = new EnterpriseUserLockCommand
                {
                    EnterpriseUserId = fromUser.Id,
                    Lock = "locked"
                };
                await Enterprise.Auth.ExecuteAuthCommand(rq);
            }

            var keys = new Dictionary<string, byte[]>
            {
                [targetUser.Email] = null
            };

            await this.PopulateUserPublicKeys(keys, (error) =>
            {
                throw new KeeperApiException("public_key_error", error);
            });
            var targetPublicKey = keys[targetUser.Email];
            if (targetPublicKey == null)
            {
                throw new KeeperApiException("public_key_error", $"Cannot get user {targetUser.Email} public key");
            }
            var targetKey = CryptoUtils.LoadPublicKey(targetPublicKey);

            var preRq = new PreAccountTransferCommand
            {
                TargetUsername = fromUser.Email
            };
            var preRs = await Enterprise.Auth.ExecuteAuthCommand<PreAccountTransferCommand, PreAccountTransferResponse>(preRq);
            var treeKey = Enterprise.TreeKey;
            byte[] roleKey = null;
            if (!string.IsNullOrEmpty(preRs.RoleKey))
            {
                roleKey = CryptoUtils.DecryptRsa(preRs.RoleKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.PrivateRsaKey);
            }
            else if (preRs.RoleKeyId > 0)
            {
                roleKey = await roleData.GetRoleKey(preRs.RoleKeyId.Value);
            }
            if (roleKey == null)
            {
                throw new KeeperApiException("transfer_key_error", $"Cannot resolve Account Transfer role key for user {targetUser.Email}");
            }
            var pk = CryptoUtils.DecryptAesV1(preRs.RolePrivateKey.Base64UrlDecode(), roleKey);
            var rolePrivateKey = CryptoUtils.LoadPrivateKey(pk);
            var userDataKey = CryptoUtils.DecryptRsa(preRs.TransferKey.Base64UrlDecode(), rolePrivateKey);
            byte[] userRsaPrivateKey = null;
            byte[] userEcPrivateKey = null;
            if (!string.IsNullOrEmpty(preRs.UserPrivateKey))
            {
                userRsaPrivateKey = CryptoUtils.DecryptAesV1(preRs.UserPrivateKey.Base64UrlDecode(), userDataKey);
            }
            if (!string.IsNullOrEmpty(preRs.UserEccPrivateKey))
            {
                userEcPrivateKey = CryptoUtils.DecryptAesV2(preRs.UserEccPrivateKey.Base64UrlDecode(), userDataKey);
            }
            var userRsaKey = userRsaPrivateKey != null ? CryptoUtils.LoadPrivateKey(userRsaPrivateKey) : null;
            var userEcKey = userEcPrivateKey != null ? CryptoUtils.LoadPrivateEcKey(userEcPrivateKey) : null;

            Func<byte[], int, byte[]> convert = (encryptedKey, keyType) =>
            {
                byte[] key = null;
                switch (keyType)
                {
                    case (int) EncryptedKeyType.KtEncryptedByDataKey:
                        key = CryptoUtils.DecryptAesV1(encryptedKey, userDataKey);
                        break;
                    case (int) EncryptedKeyType.KtEncryptedByPublicKey:
                        if (userRsaKey != null)
                        {
                            key = CryptoUtils.DecryptRsa(encryptedKey, userRsaKey);
                        }
                        break;
                    case (int) EncryptedKeyType.KtEncryptedByDataKeyGcm:
                        key = CryptoUtils.DecryptAesV2(encryptedKey, userDataKey);
                        break;
                    case (int) EncryptedKeyType.KtEncryptedByPublicKeyEcc:
                        if (userRsaKey != null)
                        {
                            key = CryptoUtils.DecryptEc(encryptedKey, userEcKey);
                        }
                        break;
                }
                if (key != null)
                {
                    return CryptoUtils.EncryptRsa(key, targetKey);
                }
                throw new KeeperApiException("wrong_key_type", $"Cannot decrypt key. Wrong key type {keyType}");
            };

            var tdRq = new TransferAndDeleteUserCommand
            {
                FromUser = fromUser.Email,
                ToUser = targetUser.Email,
            };
            if (preRs.RecordKeys != null)
            {
                var transfered = new List<TransferAndDeleteRecordKey>();
                var corrupted = new List<PreAccountTransferRecordKey>();
                foreach (var rk in preRs.RecordKeys)
                {
                    try
                    {
                        transfered.Add(new TransferAndDeleteRecordKey
                        {
                            RecordUid = rk.RecordUid,
                            RecordKey = convert(rk.RecordKey.Base64UrlDecode(), rk.RecordKeyType).Base64UrlEncode()
                        });
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        corrupted.Add(rk);
                    }
                }
                tdRq.RecordKeys = transfered.ToArray();
                tdRq.CorruptedRecordKeys = corrupted.ToArray();
            }
            if (preRs.SharedFolderKeys != null)
            {
                var transfered = new List<TransferAndDeleteSharedFolderKey>();
                var corrupted = new List<PreAccountTransferSharedFolderKey>();
                foreach (var sfk in preRs.SharedFolderKeys)
                {
                    try
                    {
                        transfered.Add(new TransferAndDeleteSharedFolderKey
                        {
                            SharedFolderUid = sfk.SharedFolderUid,
                            SharedFolderKey = convert(sfk.SharedFolderKey.Base64UrlDecode(), sfk.SharedFolderKeyType).Base64UrlEncode()
                        });
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        corrupted.Add(sfk);
                    }
                }
                tdRq.SharedFolderKeys = transfered.ToArray();
                tdRq.CorruptedSharedFolderKeys = corrupted.ToArray();
            }
            if (preRs.TeamKeys != null)
            {
                var transfered = new List<TransferAndDeleteTeamKey>();
                var corrupted = new List<PreAccountTransferTeamKey>();
                foreach (var tk in preRs.TeamKeys)
                {
                    try
                    {
                        transfered.Add(new TransferAndDeleteTeamKey
                        {
                            TeamUid = tk.TeamUid,
                            TeamKey = convert(tk.TeamKey.Base64UrlDecode(), tk.TeamKeyType).Base64UrlEncode()
                        });
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        corrupted.Add(tk);
                    }
                }
                tdRq.TeamKeys = transfered.ToArray();
                tdRq.CorruptedTeamKeys = corrupted.ToArray();
            }
            if (preRs.UserFolderKeys != null)
            {
                var transfered = new List<TransferAndDeleteUserFolderKey>();
                var corrupted = new List<PreAccountTransferUserFolderKey>();
                foreach (var ufk in preRs.UserFolderKeys)
                {
                    try
                    {
                        transfered.Add(new TransferAndDeleteUserFolderKey
                        {
                            UserFolderUid = ufk.UserFolderUid,
                            UserFolderKey = convert(ufk.UserFolderKey.Base64UrlDecode(), ufk.UserFolderKeyType).Base64UrlEncode()
                        });
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        corrupted.Add(ufk);
                    }
                }
                tdRq.UserFolderKeys = transfered.ToArray();
                tdRq.CorruptedUserFolderKeys = corrupted.ToArray();

                var targetFolderKey = CryptoUtils.GenerateEncryptionKey();
                var data = new FolderData
                {
                    name = $"Transfer from {fromUser.Email}",
                };
                var dataBytes = JsonUtils.DumpJson(data);
                tdRq.UserFolderTransfer = new TransferAndDeleteUserFolderTransfer
                {
                    TransferFolderUid = CryptoUtils.GenerateUid(),
                    TransferFolderKey = CryptoUtils.EncryptRsa(targetFolderKey, targetKey).Base64UrlEncode(),
                    TransferFolderData = CryptoUtils.EncryptAesV1(dataBytes, targetFolderKey).Base64UrlEncode()
                };
            }

            await Enterprise.Auth.ExecuteAuthCommand(tdRq);
            await Enterprise.Load();

            return new AccountTransferResult
            {
                RecordsTransfered = tdRq.RecordKeys?.Length ?? 0,
                SharedFoldersTransfered = tdRq.SharedFolderKeys?.Length ?? 0,
                TeamsTransfered = tdRq.TeamKeys?.Length ?? 0,
                UserFoldersTransfered = tdRq.UserFolderKeys?.Length ?? 0,
                RecordsCorrupted = tdRq.CorruptedRecordKeys?.Length ?? 0,
                SharedFoldersCorrupted = tdRq.CorruptedSharedFolderKeys?.Length ?? 0,
                TeamsCorrupted = tdRq.CorruptedTeamKeys?.Length ?? 0,
                UserFoldersCorrupted = tdRq.CorruptedUserFolderKeys?.Length ?? 0
            };
        }


        /// <inheritdoc/>
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

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public async Task DeleteTeam(string teamUid)
        {
            var rq = new TeamDeleteCommand
            {
                TeamUid = teamUid
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
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
