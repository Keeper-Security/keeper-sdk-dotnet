using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Folder;
using Google.Protobuf;

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

            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey)),
                ForceUpdate = true,

            };
            if (perm != null && perm.UserType == UserType.Team)
            {
                request.FromTeamUid = ByteString.CopyFrom(perm.UserId.Base64UrlDecode());
            }

            if (userType == UserType.User)
            {
                if (sharedFolder.UsersPermissions.Any(x => x.UserType == UserType.User && x.UserId == userId))
                {
                    request.SharedFolderUpdateUser.Add(new Folder.SharedFolderUpdateUser
                    {
                        Username = userId,
                        ManageUsers = options.ManageUsers == null ? SetBooleanValue.BooleanNoChange
                        : options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                        ManageRecords = options.ManageRecords == null ? SetBooleanValue.BooleanNoChange
                        : options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                    });
                }
                else
                {
                    var keyTuple = await GetUserPublicKeys(userId);
                    var publicKey = CryptoUtils.LoadPublicKey(keyTuple.Item1);
                    request.SharedFolderAddUser.Add(new Folder.SharedFolderUpdateUser
                    {
                        Username = userId,
                        ManageUsers = options.ManageUsers == null
                        ? (sharedFolder.DefaultManageUsers ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse)
                        : options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                        ManageRecords = options.ManageRecords == null
                        ? (sharedFolder.DefaultManageRecords ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse)
                        : options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                        SharedFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptRsa(sharedFolder.SharedFolderKey, publicKey)),
                    });
                }
            }
            else
            {
                var p = sharedFolder.UsersPermissions.FirstOrDefault(x => x.UserType == UserType.Team && x.UserId == userId);
                if (p != null)
                {
                    request.SharedFolderUpdateTeam.Add(new Folder.SharedFolderUpdateTeam
                    {
                        TeamUid = ByteString.CopyFrom(userId.Base64UrlDecode()),
                        ManageUsers = options.ManageUsers == null ? p.ManageUsers : options.ManageUsers.Value,
                        ManageRecords = options.ManageRecords == null ? p.ManageRecords : options.ManageRecords.Value,
                    });
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
                            teams = new[] { userId },
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

                    request.SharedFolderAddTeam.Add(new Folder.SharedFolderUpdateTeam
                    {
                        TeamUid = ByteString.CopyFrom(userId.Base64UrlDecode()),
                        ManageUsers = options.ManageUsers == null ? sharedFolder.DefaultManageUsers : options.ManageUsers.Value,
                        ManageRecords = options.ManageRecords == null ? sharedFolder.DefaultManageRecords : options.ManageRecords.Value,
                    });
                }
            }

            var response = await Auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
            foreach (var arr in (new[] { response.SharedFolderAddUserStatus, response.SharedFolderUpdateUserStatus }))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            foreach (var arr in (new[] { response.SharedFolderAddTeamStatus, response.SharedFolderUpdateTeamStatus }))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Put Team Uid \"{uid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        /// <inheritdoc/>>
        public async Task RemoveUserFromSharedFolder(string sharedFolderUid, string userId, UserType userType)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);
            if (!sharedFolder.UsersPermissions.Any(x => x.UserType == userType
                && string.Compare(x.UserId, userId, StringComparison.InvariantCultureIgnoreCase) == 0))
            {
                return;
            }

            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey)),
                ForceUpdate = true,

            };
            {
                var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, true);
                if (perm != null && perm.UserType == UserType.Team)
                {
                    request.FromTeamUid = ByteString.CopyFrom(perm.UserId.Base64UrlDecode());
                }
            }

            if (userType == UserType.User)
            {
                request.SharedFolderRemoveUser.Add(userId);
            }
            else
            {
                request.SharedFolderRemoveTeam.Add(ByteString.CopyFrom(userId.Base64UrlDecode()));
            }

            var response = await Auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
            foreach (var arr in (new[] { response.SharedFolderRemoveUserStatus }))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Remove User \"{failed.Username}\" from Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            foreach (var arr in (new[] { response.SharedFolderRemoveTeamStatus }))
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Remove Team \"{uid}\" from Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        /// <inheritdoc/>>
        public async Task ChangeRecordInSharedFolder(string sharedFolderUid, string recordUid, ISharedFolderRecordOptions options)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);

            _ = this.GetRecord(recordUid);
            var recordPerm = sharedFolder.RecordPermissions.FirstOrDefault(x => x.RecordUid != recordUid);
            if (recordPerm != null && options != null)
            {
                var request = new SharedFolderUpdateV3Request
                {
                    SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                    EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey)),
                    ForceUpdate = true,

                };
                {
                    var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, true);
                    if (perm != null && perm.UserType == UserType.Team)
                    {
                        request.FromTeamUid = ByteString.CopyFrom(perm.UserId.Base64UrlDecode());
                    }
                }
                request.SharedFolderUpdateRecord.Add(new Folder.SharedFolderUpdateRecord
                {
                    RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                    CanEdit = options.CanEdit == null ? SetBooleanValue.BooleanNoChange
                    : (options.CanEdit.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse),
                    CanShare = options.CanShare == null ? SetBooleanValue.BooleanNoChange
                    : (options.CanShare.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse),
                });

                var response = await Auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
                foreach (var arr in (new[] { response.SharedFolderUpdateRecordStatus }))
                {
                    var failed = arr?.FirstOrDefault(x => x.Status != "success");
                    if (failed != null)
                    {
                        var uid = failed.RecordUid.ToArray().Base64UrlEncode();
                        throw new VaultException($"Put Record UID \"{uid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"Record UID ({recordUid}) cannot be found in Shared Folder ({sharedFolder.Name})");
            }

            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }
    }
}
