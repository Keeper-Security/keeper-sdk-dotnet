using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline : IVaultSharedFolder
    {
        /// <inheritdoc/>>
        public async Task PutUserToSharedFolder(string sharedFolderUid,
            string userId,
            UserType userType,
            ISharedFolderUserOptions options)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);
            var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, true);
            if (perm == null)
            {
                throw new VaultException("You don't have permission to manage users.");
            }

            var request = new SharedFolderUpdateCommand
            {
                pt = Auth.AuthContext.SessionToken.Base64UrlEncode(),
                operation = "update",
                shared_folder_uid = sharedFolder.Uid,
                from_team_uid = perm.UserType == UserType.Team ? perm.UserId : null,
                name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey).Base64UrlEncode(),
                forceUpdate = true,
            };
            if (userType == UserType.User)
            {
                if (sharedFolder.UsersPermissions.Any(x => x.UserType == UserType.User && x.UserId == userId))
                {
                    request.updateUsers = new[]
                    {
                        new SharedFolderUpdateUser
                        {
                            Username = userId,
                            ManageUsers = options?.ManageUsers,
                            ManageRecords = options?.ManageRecords,
                        }
                    };
                }
                else
                {
                    var keyTuple = await GetUserPublicKeys(userId);
                    var publicKey = CryptoUtils.LoadPublicKey(keyTuple.Item1);
                    request.addUsers = new[]
                    {
                        new SharedFolderUpdateUser
                        {
                            Username = userId,
                            ManageUsers = options?.ManageUsers,
                            ManageRecords = options?.ManageRecords,
                            SharedFolderKey = CryptoUtils.EncryptRsa(sharedFolder.SharedFolderKey, publicKey).Base64UrlEncode(),
                        }
                    };
                }
            }
            else
            {
                if (sharedFolder.UsersPermissions.Any(x => x.UserType == UserType.Team && x.UserId == userId))
                {
                    request.updateTeams = new[]
                    {
                        new SharedFolderUpdateTeam
                        {
                            TeamUid = userId,
                            ManageUsers = options?.ManageUsers,
                            ManageRecords = options?.ManageRecords,
                        }
                    };
                }
                else
                {
                    string encryptedSharedFolderKey;
                    if (TryGetTeam(userId, out var team))
                    {
                        encryptedSharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolder.SharedFolderKey, team.TeamKey).Base64UrlEncode();
                    }
                    else
                    {
                        var tkRq = new TeamGetKeysCommand
                        {
                            teams = new[] {userId},
                        };
                        var tkRs = await Auth.ExecuteAuthCommand<TeamGetKeysCommand, TeamGetKeysResponse>(tkRq);
                        if (tkRs.keys == null || tkRs.keys.Length == 0)
                        {
                            throw new VaultException($"Cannot get public key of team: {userId}");
                        }

                        var tk = tkRs.keys[0];
                        if (!string.IsNullOrEmpty(tk.resultCode))
                        {
                            throw new KeeperApiException(tk.resultCode, tk.message);
                        }

                        var tpk = CryptoUtils.LoadPublicKey(tk.key.Base64UrlDecode());
                        encryptedSharedFolderKey = CryptoUtils.EncryptRsa(sharedFolder.SharedFolderKey, tpk).Base64UrlEncode();
                    }

                    request.addTeams = new[]
                    {
                        new SharedFolderUpdateTeam
                        {
                            TeamUid = userId,
                            ManageUsers = options?.ManageUsers,
                            ManageRecords = options?.ManageRecords,
                            SharedFolderKey = encryptedSharedFolderKey,
                        }
                    };
                }
            }


            var response = await Auth.ExecuteAuthCommand<SharedFolderUpdateCommand, SharedFolderUpdateResponse>(request);
            foreach (var arr in (new[] {response.addUsers, response.updateUsers}))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            foreach (var arr in (new[] {response.addTeams, response.updateTeams}))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Put Team Uid \"{failed.TeamUid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        /// <inheritdoc/>>
        public async Task RemoveUserFromSharedFolder(string sharedFolderUid, string userId, UserType userType)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);
            var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, true);
            if (perm == null)
            {
                throw new VaultException("You don't have permission to manage teams.");
            }

            if (!sharedFolder.UsersPermissions.Any(x => x.UserType == userType
                && string.Compare(x.UserId, userId, StringComparison.InvariantCultureIgnoreCase) == 0))
            {
                return;
            }

            var request = new SharedFolderUpdateCommand
            {
                pt = Auth.AuthContext.SessionToken.Base64UrlEncode(),
                operation = "update",
                shared_folder_uid = sharedFolder.Uid,
                from_team_uid = perm.UserType == UserType.Team ? perm.UserId : null,
                name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey).Base64UrlEncode(),
                forceUpdate = true,
            };
            if (userType == UserType.User)
            {
                request.removeUsers = new[] {new SharedFolderUpdateUser {Username = userId}};
            }
            else
            {
                request.removeTeams = new[] {new SharedFolderUpdateTeam {TeamUid = userId}};
            }

            var response = await Auth.ExecuteAuthCommand<SharedFolderUpdateCommand, SharedFolderUpdateResponse>(request);
            foreach (var arr in (new[] {response.removeUsers}))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Remove User \"{failed.Username}\" from Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            foreach (var arr in (new[] {response.removeTeams}))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Remove Team \"{failed.TeamUid}\" from Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        /// <inheritdoc/>>
        public async Task ChangeRecordInSharedFolder(string sharedFolderUid, string recordUid, ISharedFolderRecordOptions options)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);
            var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, false, true);
            if (perm == null)
            {
                throw new VaultException("You don't have permission to manage records.");
            }

            _ = this.GetRecord(recordUid);
            var recordPerm = sharedFolder.RecordPermissions.FirstOrDefault(x => x.RecordUid != recordUid);
            if (recordPerm != null && options != null)
            {
                var sfur = new SharedFolderUpdateRecord
                {
                    RecordUid = recordUid,
                    CanEdit = options.CanEdit ?? recordPerm.CanEdit,
                    CanShare = options.CanShare ?? recordPerm.CanShare,
                };
                var recordPath = this.ResolveRecordAccessPath(sfur, options.CanEdit.HasValue, options.CanShare.HasValue);
                if (recordPath == null)
                {
                    throw new VaultException($"You don't have permission to edit and/or share the record UID \"{recordUid}\"");
                }

                var request = new SharedFolderUpdateCommand
                {
                    pt = Auth.AuthContext.SessionToken.Base64UrlEncode(),
                    operation = "update",
                    shared_folder_uid = sharedFolder.Uid,
                    from_team_uid = perm.UserType == UserType.Team ? perm.UserId : null,
                    name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey).Base64UrlEncode(),
                    forceUpdate = true,
                    updateRecords = new[] {sfur}
                };

                var response = await Auth.ExecuteAuthCommand<SharedFolderUpdateCommand, SharedFolderUpdateResponse>(request);
                foreach (var arr in (new[] {response.updateRecords}))
                {
                    var failed = arr?.FirstOrDefault(x => x.Status != "success");
                    if (failed != null)
                    {
                        throw new VaultException($"Put Record UID \"{failed.RecordUid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"Record UID ({recordUid}) cannot be found in Shared Folder ({sharedFolder.Name})");
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }
        /*
        public async Task RemoveRecordFromSharedFolder(string sharedFolderUid, string recordUid)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);
            var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, false, true);
            if (perm == null)
            {
                throw new VaultException("You don't have permission to manage records.");
            }

            if (sharedFolder.RecordPermissions.All(x => x.RecordUid != recordUid))
            {
                return;
            }

            var request = new SharedFolderUpdateCommand
            {
                pt = Auth.AuthContext.SessionToken.Base64UrlEncode(),
                operation = "update",
                shared_folder_uid = sharedFolder.Uid,
                from_team_uid = perm.UserType == UserType.Team ? perm.UserId : null,
                name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey).Base64UrlEncode(),
                forceUpdate = true,
                removeRecords = new[] {new SharedFolderUpdateRecord {RecordUid = recordUid}}
            };
            var response = await Auth.ExecuteAuthCommand<SharedFolderUpdateCommand, SharedFolderUpdateResponse>(request);
            foreach (var arr in (new[] {response.removeRecords}))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Remove Record Uid \"{failed.RecordUid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }
        */
    }
}
