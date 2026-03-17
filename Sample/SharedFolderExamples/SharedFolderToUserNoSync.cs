using System;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Folder;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Sample;

namespace Sample.SharedFolderToUserExamples
{
    public static class ShareFolderToUserNoSync
    {
        /// <summary>Shares a shared folder with a user or team (grant=true) or revokes access (grant=false), using get_shared_folders only.</summary>
        public static async Task ShareFolderWithUser(string sharedFolderUid,
            string userId,
            UserType userType,
            IUserShareOptions options,
            bool grant = false)
        {
            var auth = await AuthenticateAndGetVault.GetAuthAsync();
            if (auth == null) { Console.WriteLine("Not authenticated."); return; }

            if (await LoadSharedFolders(auth, sharedFolderUid) == null)
            {
                Console.WriteLine("Failed to load shared folder data.");
                return;
            }
            try
            {
                if (grant)
                {
                    await PutUserToSharedFolderNoSync(auth, sharedFolderUid, userId, userType, options);
                    Console.WriteLine($"Folder shared successfully to {userId}.");
                }
                else
                {
                    await RemoveUserFromSharedFolderNoSync(auth, sharedFolderUid, userId, userType);
                    Console.WriteLine($"Access revoked for {userId}.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(grant ? $"Failed to share folder: {ex.Message}" : $"Failed to revoke access: {ex.Message}");
            }
        }

        private static GetSharedFoldersResponse _lastGetSharedFoldersResponse;

        private static async Task<GetSharedFoldersResponse> LoadSharedFolders(IAuthentication auth, string sharedFolderUid)
        {
            if (auth == null || string.IsNullOrEmpty(sharedFolderUid)) return null;
            var command = new GetSharedFoldersCommand
            {
                SharedFolders = new[] { new GetSharedFoldersRequestItem { SharedFolderUid = sharedFolderUid } },
                Include = new[] { "sfheaders", "sfusers", "sfteams" }
            };
            try
            {
                var response = await auth.ExecuteAuthCommand<GetSharedFoldersCommand, GetSharedFoldersResponse>(command, throwOnError: false);
                if (response == null)
                {
                    Console.WriteLine("get_shared_folders: no response.");
                    return null;
                }
                if (!response.IsSuccess)
                {
                    Console.WriteLine($"get_shared_folders failed: result={response.result}, result_code={response.resultCode}, message={response.message}");
                    return null;
                }
                if (response.SharedFolders == null || response.SharedFolders.Length == 0)
                {
                    Console.WriteLine("get_shared_folders: success but shared_folders array is null or empty.");
                    return null;
                }
                _lastGetSharedFoldersResponse = response;
                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"get_shared_folders error: {ex.Message}");
                return null;
            }
        }

        private static bool TryResolveSharedFolderFromLoadedData(string sharedFolderUid, IAuthentication auth,
            out SharedFolderObject sf, out byte[] sharedFolderKey)
        {
            sf = null;
            sharedFolderKey = null;
            if (auth?.AuthContext == null || _lastGetSharedFoldersResponse?.SharedFolders == null)
                return false;

            sf = _lastGetSharedFoldersResponse.SharedFolders.FirstOrDefault(x =>
                string.Equals(x.SharedFolderUid, sharedFolderUid, StringComparison.Ordinal));
            if (sf == null || string.IsNullOrEmpty(sf.SharedFolderKey))
                return false;

            var context = auth.AuthContext;
            var keyType = sf.KeyType;
            try
            {
                if (keyType == 1)
                {
                    sharedFolderKey = CryptoUtils.DecryptAesV1(sf.SharedFolderKey.Base64UrlDecode(), context.DataKey);
                    return true;
                }
                if (keyType == 2)
                {
                    var encrypted = sf.SharedFolderKey.Base64UrlDecode();
                    if (context.ForbidKeyType2 && context.PrivateEcKey != null)
                        sharedFolderKey = CryptoUtils.DecryptEc(encrypted, context.PrivateEcKey);
                    else if (!context.ForbidKeyType2 && context.PrivateRsaKey != null)
                        sharedFolderKey = CryptoUtils.DecryptRsa(encrypted, context.PrivateRsaKey);
                    else
                        return false;
                    return sharedFolderKey != null;
                }
            }
            catch { }
            return false;
        }

        private static string DecryptSharedFolderName(SharedFolderObject sf, byte[] sharedFolderKey)
        {
            if (string.IsNullOrEmpty(sf?.Name) || sharedFolderKey == null) return "Shared Folder";
            try
            {
                var encrypted = sf.Name.Base64UrlDecode();
                if (encrypted == null || encrypted.Length == 0) return "Shared Folder";
                var decrypted = CryptoUtils.DecryptAesV1(encrypted, sharedFolderKey);
                return Encoding.UTF8.GetString(decrypted ?? Array.Empty<byte>()) ?? "Shared Folder";
            }
            catch { throw new VaultException("Failed to decrypt shared folder name."); }
        }

        private static async Task PutUserToSharedFolderNoSync(IAuthentication auth, string sharedFolderUid,
            string userId, UserType userType, IUserShareOptions options)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            if (!TryResolveSharedFolderFromLoadedData(sharedFolderUid, auth, out var sf, out var key))
                throw new VaultException($"Shared folder \"{sharedFolderUid}\" not found or key could not be decrypted. Load shared folder via get_shared_folders first.");

            var displayName = DecryptSharedFolderName(sf, key);
            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolderUid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(displayName), key)),
                ForceUpdate = true,
            };

            SharedFolderUserObject existingUser = null;
            SharedFolderTeamObject existingTeam = null;
            if (userType == UserType.User)
                existingUser = sf.Users?.FirstOrDefault(x => string.Equals(x.Email, userId, StringComparison.InvariantCultureIgnoreCase));
            else
                existingTeam = sf.Teams?.FirstOrDefault(x => string.Equals(x.TeamUid, userId, StringComparison.Ordinal));

            if (userType == UserType.User)
            {
                var sfuu = new SharedFolderUpdateUser
                {
                    Username = userId,
                    Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
                };
                if (existingUser != null)
                {
                    sfuu.ManageUsers = options?.ManageUsers == null ? SetBooleanValue.BooleanNoChange : (options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                    sfuu.ManageRecords = options?.ManageRecords == null ? SetBooleanValue.BooleanNoChange : (options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                    request.SharedFolderUpdateUser.Add(sfuu);
                }
                else
                {
                    sfuu.ManageUsers = options?.ManageUsers == null ? (sf.ManageUsers ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse) : (options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                    sfuu.ManageRecords = options?.ManageRecords == null ? (sf.ManageRecords ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse) : (options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);

                    byte[] encryptedKey = null;
                    var keyType = EncryptedKeyType.NoKey;
                    if (string.Equals(userId, auth.Username, StringComparison.InvariantCultureIgnoreCase))
                    {
                        encryptedKey = CryptoUtils.EncryptAesV1(key, auth.AuthContext.DataKey);
                        keyType = EncryptedKeyType.EncryptedByDataKey;
                    }
                    else
                    {
                        await auth.LoadUsersKeys(Enumerable.Repeat(userId, 1));
                        if (auth.TryGetUserKeys(userId, out var keys))
                        {
                            if (auth.AuthContext.ForbidKeyType2 && keys.EcPublicKey != null && keys.EcPublicKey.Length > 0)
                            {
                                var ecPublicKey = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                                encryptedKey = CryptoUtils.EncryptEc(key, ecPublicKey);
                                keyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                            }
                            else if (!auth.AuthContext.ForbidKeyType2 && keys.RsaPublicKey != null && keys.RsaPublicKey.Length > 0)
                            {
                                var rsaPublicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                                encryptedKey = CryptoUtils.EncryptRsa(key, rsaPublicKey);
                                keyType = EncryptedKeyType.EncryptedByPublicKey;
                            }
                        }
                    }
                    if (encryptedKey != null)
                    {
                        sfuu.TypedSharedFolderKey = new EncryptedDataKey { EncryptedKey = ByteString.CopyFrom(encryptedKey), EncryptedKeyType = keyType };
                        request.SharedFolderAddUser.Add(sfuu);
                    }
                    else
                        throw new VaultException($"Cannot retrieve user's \"{userId}\" public key for sharing.");
                }
            }
            else
            {
                var sfut = new SharedFolderUpdateTeam
                {
                    TeamUid = ByteString.CopyFrom(userId.Base64UrlDecode()),
                    Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
                };
                if (existingTeam != null)
                {
                    sfut.ManageUsers = options?.ManageUsers ?? existingTeam.ManageUsers;
                    sfut.ManageRecords = options?.ManageRecords ?? existingTeam.ManageRecords;
                    request.SharedFolderUpdateTeam.Add(sfut);
                }
                else
                {
                    sfut.ManageUsers = options?.ManageUsers ?? sf.ManageUsers;
                    sfut.ManageRecords = options?.ManageRecords ?? sf.ManageRecords;

                    byte[] encryptedSharedFolderKey = null;
                    var keyType = EncryptedKeyType.NoKey;
                    await auth.LoadTeamKeys(Enumerable.Repeat(userId, 1));
                    if (auth.TryGetTeamKeys(userId, out var keys))
                    {
                        if (keys.AesKey != null)
                        {
                            if (auth.AuthContext.ForbidKeyType2)
                            {
                                encryptedSharedFolderKey = CryptoUtils.EncryptAesV2(key, keys.AesKey);
                                keyType = EncryptedKeyType.EncryptedByDataKeyGcm;
                            }
                            else
                            {
                                encryptedSharedFolderKey = CryptoUtils.EncryptAesV1(key, keys.AesKey);
                                keyType = EncryptedKeyType.EncryptedByDataKey;
                            }
                        }
                        else if (auth.AuthContext.ForbidKeyType2 && keys.EcPublicKey != null)
                        {
                            var publicKey = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                            encryptedSharedFolderKey = CryptoUtils.EncryptEc(key, publicKey);
                            keyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                        }
                        else if (!auth.AuthContext.ForbidKeyType2 && keys.RsaPublicKey != null)
                        {
                            var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                            encryptedSharedFolderKey = CryptoUtils.EncryptRsa(key, publicKey);
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
                    else
                        throw new VaultException($"Cannot retrieve team \"{userId}\" key for sharing.");
                    request.SharedFolderAddTeam.Add(sfut);
                }
            }

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
            foreach (var arr in new[] { response.SharedFolderAddUserStatus, response.SharedFolderUpdateUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{displayName}\" error: {failed.Status}");
            }
            foreach (var arr in new[] { response.SharedFolderAddTeamStatus, response.SharedFolderUpdateTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Put Team Uid \"{uid}\" to Shared Folder \"{displayName}\" error: {failed.Status}");
                }
            }
        }

        private static async Task RemoveUserFromSharedFolderNoSync(IAuthentication auth, string sharedFolderUid,
            string userId, UserType userType)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            if (!TryResolveSharedFolderFromLoadedData(sharedFolderUid, auth, out var sf, out var key))
                throw new VaultException($"Shared folder \"{sharedFolderUid}\" not found or key could not be decrypted. Load shared folder via get_shared_folders first.");

            var displayName = DecryptSharedFolderName(sf, key);
            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolderUid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(displayName), key)),
                ForceUpdate = true,
            };

            if (userType == UserType.User)
                request.SharedFolderRemoveUser.Add(userId);
            else
                request.SharedFolderRemoveTeam.Add(ByteString.CopyFrom(userId.Base64UrlDecode()));

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request);
            foreach (var arr in new[] { response.SharedFolderRemoveUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                    throw new VaultException($"Remove user \"{failed.Username}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
            }
            foreach (var arr in new[] { response.SharedFolderRemoveTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => x.Status != "success");
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Remove team \"{uid}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
                }
            }
        }

        [DataContract]
        private class GetSharedFoldersResponse : KeeperApiResponse
        {
            [DataMember(Name = "shared_folders", EmitDefaultValue = false)]
            public SharedFolderObject[] SharedFolders { get; set; }
        }

        [DataContract]
        private class SharedFolderObject
        {
            [DataMember(Name = "shared_folder_uid")] public string SharedFolderUid { get; set; }
            [DataMember(Name = "name")] public string Name { get; set; }
            [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
            [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }
            [DataMember(Name = "shared_folder_key")] public string SharedFolderKey { get; set; }
            [DataMember(Name = "key_type")] public int KeyType { get; set; }
            [DataMember(Name = "users", EmitDefaultValue = false)] public SharedFolderUserObject[] Users { get; set; }
            [DataMember(Name = "records", EmitDefaultValue = false)] public SharedFolderRecordObject[] Records { get; set; }
            [DataMember(Name = "teams", EmitDefaultValue = false)] public SharedFolderTeamObject[] Teams { get; set; }
        }

        [DataContract]
        private class SharedFolderUserObject
        {
            [DataMember(Name = "email")] public string Email { get; set; }
            [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
            [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }
        }

        [DataContract]
        private class SharedFolderRecordObject
        {
            [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
            [DataMember(Name = "record_key")] public string RecordKey { get; set; }
            [DataMember(Name = "can_share")] public bool CanShare { get; set; }
            [DataMember(Name = "can_edit")] public bool CanEdit { get; set; }
        }

        [DataContract]
        private class SharedFolderTeamObject
        {
            [DataMember(Name = "team_uid")] public string TeamUid { get; set; }
            [DataMember(Name = "name")] public string Name { get; set; }
            [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }
            [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
            [DataMember(Name = "restrict_edit")] public bool RestrictEdit { get; set; }
            [DataMember(Name = "restrict_share")] public bool RestrictShare { get; set; }
        }

        [DataContract]
        private class GetSharedFoldersRequestItem
        {
            [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
            public string SharedFolderUid { get; set; }
        }

        [DataContract]
        private class GetSharedFoldersCommand : AuthenticatedCommand
        {
            public GetSharedFoldersCommand() : base("get_shared_folders") { }

            [DataMember(Name = "shared_folders", EmitDefaultValue = false)]
            public GetSharedFoldersRequestItem[] SharedFolders { get; set; }

            [DataMember(Name = "include", EmitDefaultValue = false)]
            public string[] Include { get; set; }
        }
    }
}
