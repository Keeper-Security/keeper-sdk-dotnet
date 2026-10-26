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
            await PutUserToSharedFolder(sharedFolderUid, userId, userType, options, forceAdd: false);
        }

        /// <summary>
        /// Grants or updates shared-folder membership. When an expired membership remains in the
        /// local cache, forceAdd creates a new membership (and encrypts a new folder key) rather
        /// than attempting to update the stale server-side membership.
        /// </summary>
        private async Task PutUserToSharedFolder(string sharedFolderUid,
            string userId,
            UserType userType,
            IUserShareOptions options,
            bool forceAdd)
        {
            this.ValidateRotateOnExpirationForFolderGrant(sharedFolderUid, options);
            var sharedFolder = this.GetSharedFolder(sharedFolderUid);

            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolder.Uid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(sharedFolder.Name), sharedFolder.SharedFolderKey)),
                ForceUpdate = true,

            };
            var existingPermission = sharedFolder.UsersPermissions
                .FirstOrDefault(x => x.UserType == userType && (string.Equals(x.Name, userId, StringComparison.InvariantCultureIgnoreCase) || x.Uid == userId));
            if (userType == UserType.User && existingPermission?.Owner == true)
            {
                throw ShareOwnerValidation.FolderOwner(userId, sharedFolder: true);
            }
            if (userType == UserType.User)
            {
                if (TryGetUsername(userId, out var u))
                {
                    userId = u;
                }
                var sfuu = new SharedFolderUpdateUser
                {
                    Username = userId,
                };
                VaultShareExpirationExtensions.ApplyShareExpiration(options, sfuu);
                var activeExistingPermission = existingPermission != null &&
                    (!existingPermission.Expiration.HasValue || existingPermission.Expiration.Value > DateTimeOffset.UtcNow);
                if (activeExistingPermission && !forceAdd)
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
                        request.SharedFolderAddUser.Add(sfuu);
                    }
                    else
                    {
                        throw new VaultException($"Cannot retrieve user's \"{userId}\" public key for sharing.");
                    }
                }
            }
            else
            {
                var sfut = new SharedFolderUpdateTeam
                {
                    TeamUid = ByteString.CopyFrom(userId.Base64UrlDecode()),
                };
                VaultShareExpirationExtensions.ApplyShareExpiration(options, sfut);

                var activeExistingPermission = existingPermission != null &&
                    (!existingPermission.Expiration.HasValue || existingPermission.Expiration.Value > DateTimeOffset.UtcNow);
                if (activeExistingPermission && !forceAdd)
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
            if (perm is { UserType: UserType.Team })
            {
                request.FromTeamUid = ByteString.CopyFrom(perm.Uid.Base64UrlDecode());
            }
            var response = await Auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
            foreach (var arr in new[] { response.SharedFolderAddUserStatus, response.SharedFolderUpdateUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    if (!forceAdd && request.SharedFolderUpdateUser.Count > 0 &&
                        string.Equals(failed.Status, "doesnt_exist", StringComparison.OrdinalIgnoreCase))
                    {
                        // The cache said this was an existing member, but the server has already
                        // removed it (normally because its time-limited share expired). Rebuild
                        // the operation as an Add so it includes a freshly encrypted folder key.
                        await PutUserToSharedFolder(sharedFolderUid, userId, userType, options, forceAdd: true);
                        return;
                    }
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{sharedFolder.Name}\" error: {failed.Status}");
                }
            }

            foreach (var arr in new[] { response.SharedFolderAddTeamStatus, response.SharedFolderUpdateTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    if (!forceAdd && request.SharedFolderUpdateTeam.Count > 0 &&
                        string.Equals(failed.Status, "doesnt_exist", StringComparison.OrdinalIgnoreCase))
                    {
                        await PutUserToSharedFolder(sharedFolderUid, userId, userType, options, forceAdd: true);
                        return;
                    }
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

            if (userType == UserType.User && perm.Owner)
            {
                throw ShareOwnerValidation.FolderOwner(userId, sharedFolder: true);
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
            // Expiration of a shared-folder record entry affects the record's membership in the
            // folder, not just a particular user's access. In particular it can remove the
            // owner's record when the timer fires. Time-limit the user/team membership instead.
            if (options?.Expiration != null || options?.RotateOnExpiration == true)
            {
                throw new VaultException(
                    "Expiration is not supported for a shared-folder record. " +
                    "Set expiration on the shared-folder user or team access instead.");
            }

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
                var sfur = new SharedFolderUpdateRecord
                {
                    RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                    CanEdit = options.CanEdit == null ? SetBooleanValue.BooleanNoChange
                    : options.CanEdit.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                    CanShare = options.CanShare == null ? SetBooleanValue.BooleanNoChange
                    : options.CanShare.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse,
                };
                request.SharedFolderUpdateRecord.Add(sfur);

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
