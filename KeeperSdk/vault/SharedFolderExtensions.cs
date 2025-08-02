using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
            IUserShareOptions options)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);

            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey)),
                ForceUpdate = true,

            };
            var existingPermission = sharedFolder.UsersPermissions
                .FirstOrDefault(x => x.UserType == UserType.User && (string.Equals(x.Name, userId, StringComparison.InvariantCultureIgnoreCase) || x.Uid == userId));
            if (userType == UserType.User)
            {
                if (TryGetUsername(userId, out var u))
                {
                    userId = u;
                }
                var sfuu = new SharedFolderUpdateUser
                {
                    Username = userId,
                    Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
                };
                if (existingPermission != null)
                {
                    sfuu.ManageUsers = options?.ManageUsers == null
                        ? SetBooleanValue.BooleanNoChange
                        : options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse;
                    sfuu.ManageRecords = options?.ManageRecords == null
                        ? SetBooleanValue.BooleanNoChange
                        : options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse;
                    request.SharedFolderUpdateUser.Add(sfuu);
                }
                else
                {
                    sfuu.ManageUsers = options?.ManageUsers == null
                        ? sharedFolder.DefaultManageUsers ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse
                        : options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse;
                    sfuu.ManageRecords = options?.ManageRecords == null
                        ? sharedFolder.DefaultManageRecords ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse
                        : options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse;

                    byte[] encryptedKey = null;
                    var keyType = EncryptedKeyType.NoKey;
                    if (string.Equals(userId, Auth.Username, StringComparison.InvariantCultureIgnoreCase))
                    {
                        encryptedKey = CryptoUtils.EncryptAesV1(sharedFolder.SharedFolderKey, Auth.AuthContext.DataKey);
                        keyType = EncryptedKeyType.EncryptedByDataKey;
                    }
                    else
                    {
                        await Auth.LoadUsersKeys(Enumerable.Repeat(userId, 1));
                        if (Auth.TryGetUserKeys(userId, out var keys))
                        {
                            if (Auth.AuthContext.ForbidKeyType2 && keys.EcPublicKey.Length > 0)
                            {
                                var ecPublicKey = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                                encryptedKey = CryptoUtils.EncryptEc(sharedFolder.SharedFolderKey, ecPublicKey);
                                keyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                            }
                            else if (!Auth.AuthContext.ForbidKeyType2 && keys.RsaPublicKey.Length > 0)
                            {
                                var rsaPublicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                                encryptedKey = CryptoUtils.EncryptRsa(sharedFolder.SharedFolderKey, rsaPublicKey);
                                keyType = EncryptedKeyType.EncryptedByPublicKey;
                            }
                        }
                    }
                    if (encryptedKey != null)
                    {
                        sfuu.TypedSharedFolderKey = new EncryptedDataKey
                        {
                            EncryptedKey = ByteString.CopyFrom(encryptedKey),
                            EncryptedKeyType = keyType
                        };
                    }
                    request.SharedFolderAddUser.Add(sfuu);
                }
            }
            else
            {
                var sfut = new SharedFolderUpdateTeam
                {
                    TeamUid = ByteString.CopyFrom(userId.Base64UrlDecode()),
                    Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
                };

                if (existingPermission != null)
                {
                    sfut.ManageUsers = options?.ManageUsers ?? existingPermission.ManageUsers;
                    sfut.ManageRecords = options?.ManageRecords ?? existingPermission.ManageRecords;
                    request.SharedFolderUpdateTeam.Add(sfut);
                }
                else
                {
                    sfut.ManageUsers = options?.ManageUsers ?? sharedFolder.DefaultManageUsers;
                    sfut.ManageRecords = options?.ManageRecords ?? sharedFolder.DefaultManageRecords;

                    byte[] encryptedSharedFolderKey = null;
                    EncryptedKeyType keyType = EncryptedKeyType.NoKey;

                    await Auth.LoadTeamKeys(Enumerable.Repeat(userId, 1));
                    if (Auth.TryGetTeamKeys(userId, out var keys))
                    {
                        if (keys.AesKey != null)
                        {
                            if (Auth.AuthContext.ForbidKeyType2)
                            {
                                encryptedSharedFolderKey = CryptoUtils.EncryptAesV2(sharedFolder.SharedFolderKey, keys.AesKey);
                                keyType = EncryptedKeyType.EncryptedByDataKeyGcm;
                            }
                            else
                            {
                                encryptedSharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolder.SharedFolderKey, keys.AesKey);
                                keyType = EncryptedKeyType.EncryptedByDataKey;
                            }
                        }
                        else if (Auth.AuthContext.ForbidKeyType2 && keys.EcPublicKey != null)
                        {
                            var publicKey = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                            encryptedSharedFolderKey = CryptoUtils.EncryptEc(sharedFolder.SharedFolderKey, publicKey);
                            keyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                        }
                        else if (!Auth.AuthContext.ForbidKeyType2 && keys.RsaPublicKey != null)
                        {
                            var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                            encryptedSharedFolderKey = CryptoUtils.EncryptRsa(sharedFolder.SharedFolderKey, publicKey);
                            keyType = EncryptedKeyType.EncryptedByPublicKey;
                        }
                    }
                    if (encryptedSharedFolderKey != null)
                    {
                        sfut.TypedSharedFolderKey = new EncryptedDataKey
                        { 
                            EncryptedKey = ByteString.CopyFrom(encryptedSharedFolderKey),
                            EncryptedKeyType = keyType,
                        };
                    }

                    request.SharedFolderAddTeam.Add(sfut);
                }
            }

            var perm = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, true);
            if (perm != null && perm.UserType == UserType.Team)
            {
                request.FromTeamUid = ByteString.CopyFrom(perm.Uid.Base64UrlDecode());
            }
            var response = await Auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
            foreach (var arr in new[] { response.SharedFolderAddUserStatus, response.SharedFolderUpdateUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            foreach (var arr in new[] { response.SharedFolderAddTeamStatus, response.SharedFolderUpdateTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Put Team Uid \"{uid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            await SyncDown();
        }

        /// <inheritdoc/>>
        public async Task RemoveUserFromSharedFolder(string sharedFolderUid, string userId, UserType userType)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);
            var perm = sharedFolder.UsersPermissions.FirstOrDefault(x => x.UserType == userType &&
            (string.Equals(x.Uid, userId, StringComparison.InvariantCulture) || string.Equals(x.Name, userId, StringComparison.InvariantCultureIgnoreCase)));

            if (perm == null)
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
                var ap = this.ResolveSharedFolderAccessPath(Auth.Username, sharedFolderUid, true);
                if (ap != null && ap.UserType == UserType.Team)
                {
                    request.FromTeamUid = ByteString.CopyFrom(perm.Uid.Base64UrlDecode());
                }
            }

            if (userType == UserType.User)
            {
                request.SharedFolderRemoveUser.Add(perm.Name);
            }
            else
            {
                request.SharedFolderRemoveTeam.Add(ByteString.CopyFrom(perm.Uid.Base64UrlDecode()));
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

            await SyncDown();
        }

        /// <inheritdoc/>>
        public async Task ChangeRecordInSharedFolder(string sharedFolderUid, string recordUid, IRecordShareOptions options)
        {
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);

            _ = this.GetRecord(recordUid);
            var recordPerm = sharedFolder.RecordPermissions.FirstOrDefault(x => x.RecordUid == recordUid);
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
                        request.FromTeamUid = ByteString.CopyFrom(perm.Uid.Base64UrlDecode());
                    }
                }
                request.SharedFolderUpdateRecord.Add(new SharedFolderUpdateRecord
                {
                    RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                    CanEdit = options.CanEdit == null ? SetBooleanValue.BooleanNoChange
                    : options.CanEdit.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                    CanShare = options.CanShare == null ? SetBooleanValue.BooleanNoChange
                    : options.CanShare.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                    Expiration = options.Expiration?.ToUnixTimeMilliseconds() ?? 0,
                });

                var response = await Auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
                foreach (var arr in new[] { response.SharedFolderUpdateRecordStatus })
                {
                    var failed = arr?.FirstOrDefault(x => x.Status != "success");
                    if (failed == null) continue;
                    var uid = failed.RecordUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Put Record UID \"{uid}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }
            else
            {
                Console.WriteLine($"Record UID ({recordUid}) cannot be found in Shared Folder ({sharedFolder.Name})");
            }

            await SyncDown();
        }
    }
}
