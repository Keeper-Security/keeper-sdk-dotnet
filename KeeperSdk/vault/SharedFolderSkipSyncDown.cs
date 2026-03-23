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
using Records;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Shared-folder operations without loading the full vault. Intended for direct user access to the folder.
    /// For team-only folders or sharing with teams, use <see cref="IVaultSharedFolder"/>.
    /// This only works for shared folders with other users. Teams are not supported.
    /// </summary>
    public static class SharedFolderSkipSyncDown
    {
        /// <summary>
        /// Default <see cref="ISharedFolderSkipSyncDown"/> implementation.
        /// </summary>
        public sealed class SharedFolderSkipSyncDownClient : ISharedFolderSkipSyncDown
        {
            /// <inheritdoc />
            public Task<GetSharedFoldersResponse> GetSharedFolderAsync(IAuthentication auth, string sharedFolderUid)
                => SharedFolderSkipSyncDown.GetSharedFolderAsync(auth, sharedFolderUid);

            /// <inheritdoc />
            public Task PutUserToSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
                string userId, IUserShareOptions options = null)
                => SharedFolderSkipSyncDown.PutUserToSharedFolderAsync(auth, sharedFolderUid, userId, options);

            /// <inheritdoc />
            public Task RemoveUserFromSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
                string userId)
                => SharedFolderSkipSyncDown.RemoveUserFromSharedFolderAsync(auth, sharedFolderUid, userId);
        }

        /// <inheritdoc cref="ISharedFolderSkipSyncDown.GetSharedFolderAsync" />
        public static async Task<GetSharedFoldersResponse> GetSharedFolderAsync(IAuthentication auth, string sharedFolderUid)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrEmpty(sharedFolderUid)) throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));

            var command = new GetSharedFoldersCommand
            {
                SharedFolders = new[]
                {
                    new GetSharedFoldersRequestItem
                    {
                        SharedFolderUid = sharedFolderUid,
                    },
                },
                Include = new[] { "sfheaders", "sfusers" },
            };

            var response = await auth.ExecuteAuthCommand<GetSharedFoldersCommand, GetSharedFoldersResponse>(command, throwOnError: false)
                .ConfigureAwait(false);
            
            if (response == null || !response.IsSuccess || response.SharedFolders == null || response.SharedFolders.Length == 0)
                return null;

            return response;
        }

        /// <inheritdoc cref="ISharedFolderSkipSyncDown.PutUserToSharedFolderAsync" />
        public static async Task PutUserToSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string userId, IUserShareOptions options = null)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");

            if (string.IsNullOrEmpty(sharedFolderUid))
                throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID is required.", nameof(userId));
            await ShareSharedFolderToUser(auth, sharedFolderUid, userId, options).ConfigureAwait(false);
        }

        /// <inheritdoc cref="ISharedFolderSkipSyncDown.RemoveUserFromSharedFolderAsync" />
        public static async Task RemoveUserFromSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string userId)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrEmpty(sharedFolderUid))
                throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID is required.", nameof(userId));
            await RevokeSharedFolderFromUser(auth, sharedFolderUid, userId).ConfigureAwait(false);
        }

        private static SharedFolderObject FindSharedFolder(GetSharedFoldersResponse response, string sharedFolderUid)
        {
            if (response?.SharedFolders == null || string.IsNullOrEmpty(sharedFolderUid))
                throw new VaultException("Shared folder not found.");
            var sf = response.SharedFolders.FirstOrDefault(x =>
                string.Equals(x.SharedFolderUid, sharedFolderUid, StringComparison.OrdinalIgnoreCase));

            if (sf == null)
                throw new VaultException($"Shared folder \"{sharedFolderUid}\" not found.");
            return sf;
        }

        private static bool SharedFolderUserMatches(SharedFolderUserObject u, string userId)
        {
            if (string.IsNullOrEmpty(userId) || u == null)
                return false;
            var userEmail = string.IsNullOrEmpty(u.Email) ? u.Username : u.Email;
            return string.Equals(userEmail, userId, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSharedFolderUserMember(SharedFolderObject sf, string userId)
        {
            return sf.Users?.Any(u => SharedFolderUserMatches(u, userId)) == true;
        }

        private static bool HasNoShareOptionsChanges(IUserShareOptions options)
        {
            if (options == null)
                return true;
            return options.ManageUsers == null && options.ManageRecords == null && options.Expiration == null;
        }

        private static bool IsSharedFolderPutStatusOk(string status)
        {
            if (string.IsNullOrEmpty(status))
                return false;
            if (string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
                return true;
            return string.Equals(status, "duplicate", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSharedFolderRemoveStatusOk(string status)
        {
            if (string.IsNullOrEmpty(status))
                return false;
            if (string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.Equals(status, "not_member", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.Equals(status, "not_in_shared_folder", StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }

        private static async Task<SharedFolderObject> GetSharedFoldersAsync(IAuthentication auth, string sharedFolderUid)
        {
            var loaded = await GetSharedFolderAsync(auth, sharedFolderUid).ConfigureAwait(false);
            if (loaded == null || loaded.SharedFolders == null || loaded.SharedFolders.Length == 0)
            {
                throw new VaultException(
                    $"Could not load shared folder \"{sharedFolderUid}\". " +
                    "Verify the UID and that you have direct user access to the folder (not team-only).");
            }

            return FindSharedFolder(loaded, sharedFolderUid);
        }

        private static byte[] DecryptKeeperKey(IAuthContext context, byte[] encryptedKey, RecordKeyType keyType)
        {
            return keyType switch
            {
                RecordKeyType.NoKey => context.DataKey,
                RecordKeyType.EncryptedByDataKey => CryptoUtils.DecryptAesV1(encryptedKey, context.DataKey),
                RecordKeyType.EncryptedByPublicKey => CryptoUtils.DecryptRsa(encryptedKey, context.PrivateRsaKey),
                RecordKeyType.EncryptedByDataKeyGcm => CryptoUtils.DecryptAesV2(encryptedKey, context.DataKey),
                RecordKeyType.EncryptedByPublicKeyEcc => CryptoUtils.DecryptEc(encryptedKey, context.PrivateEcKey),
                _ => throw new VaultException($"Unsupported key type {keyType}"),
            };
        }

        private static bool TryResolveSharedFolderKey(SharedFolderObject sf, IAuthentication auth,
            out byte[] sharedFolderKey)
        {
            sharedFolderKey = null;
            if (auth?.AuthContext == null || sf == null)
                return false;

            var context = auth.AuthContext;
            var headerKeyType = (RecordKeyType)sf.KeyType;

            if (!string.IsNullOrEmpty(sf.SharedFolderKey))
            {
                try
                {
                    sharedFolderKey = DecryptKeeperKey(context, sf.SharedFolderKey.Base64UrlDecode(), (RecordKeyType)headerKeyType);
                    return sharedFolderKey != null && sharedFolderKey.Length > 0;
                }
                catch
                {
                }
            }
            else if (sf.KeyType == (int)RecordKeyType.NoKey)
            {
                try
                {
                    sharedFolderKey = DecryptKeeperKey(context, Array.Empty<byte>(), (RecordKeyType)headerKeyType);
                    return sharedFolderKey != null && sharedFolderKey.Length > 0;
                }
                catch
                {
                }
            }

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
            catch
            {
                throw new VaultException("Failed to decrypt shared folder name.");
            }
        }

        private static async Task ShareSharedFolderToUser(IAuthentication auth, string sharedFolderUid,
            string userId, IUserShareOptions options)
        {
            var sharedFolder = await GetSharedFoldersAsync(auth, sharedFolderUid).ConfigureAwait(false);
            if (!TryResolveSharedFolderKey(sharedFolder, auth, out var key))
                throw new VaultException(
                    $"Shared folder \"{sharedFolderUid}\" key could not be decrypted.");

            var displayName = DecryptSharedFolderName(sharedFolder, key);
            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolderUid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(displayName), key)),
                ForceUpdate = true,
            };

            var existingUser = sharedFolder.Users?.FirstOrDefault(u => SharedFolderUserMatches(u, userId));

            if (HasNoShareOptionsChanges(options) && existingUser != null)
                return;

            var sfUpdateUser = new SharedFolderUpdateUser
            {
                Username = userId,
                Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
            };
            if (existingUser != null)
            {
                sfUpdateUser.ManageUsers = options?.ManageUsers == null
                    ? SetBooleanValue.BooleanNoChange
                    : (options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                sfUpdateUser.ManageRecords = options?.ManageRecords == null
                    ? SetBooleanValue.BooleanNoChange
                    : (options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                request.SharedFolderUpdateUser.Add(sfUpdateUser);
            }
            else
            {
                sfUpdateUser.ManageUsers = options?.ManageUsers == null
                    ? (sharedFolder.ManageUsers ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse)
                    : (options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                sfUpdateUser.ManageRecords = options?.ManageRecords == null
                    ? (sharedFolder.ManageRecords ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse)
                    : (options.ManageRecords.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);

                byte[] encryptedKey = null;
                var encKeyType = EncryptedKeyType.NoKey;
                if (string.Equals(userId, auth.Username, StringComparison.InvariantCultureIgnoreCase))
                {
                    encryptedKey = CryptoUtils.EncryptAesV1(key, auth.AuthContext.DataKey);
                    encKeyType = EncryptedKeyType.EncryptedByDataKey;
                }
                else
                {
                    await auth.LoadUsersKeys(Enumerable.Repeat(userId, 1)).ConfigureAwait(false);
                    if (auth.TryGetUserKeys(userId, out var keys))
                    {
                        if (auth.AuthContext.ForbidKeyType2 && keys.EcPublicKey != null && keys.EcPublicKey.Length > 0)
                        {
                            var ecPublicKey = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                            encryptedKey = CryptoUtils.EncryptEc(key, ecPublicKey);
                            encKeyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                        }
                        else if (!auth.AuthContext.ForbidKeyType2 && keys.RsaPublicKey != null && keys.RsaPublicKey.Length > 0)
                        {
                            var rsaPublicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                            encryptedKey = CryptoUtils.EncryptRsa(key, rsaPublicKey);
                            encKeyType = EncryptedKeyType.EncryptedByPublicKey;
                        }
                    }
                }

                if (encryptedKey != null)
                {
                    sfUpdateUser.TypedSharedFolderKey = new EncryptedDataKey
                    {
                        EncryptedKey = ByteString.CopyFrom(encryptedKey),
                        EncryptedKeyType = encKeyType,
                    };
                    request.SharedFolderAddUser.Add(sfUpdateUser);
                }
                else
                    throw new VaultException($"Cannot retrieve user's \"{userId}\" public key for sharing.");
            }

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request)
                .ConfigureAwait(false);
            foreach (var arr in new[] { response.SharedFolderAddUserStatus, response.SharedFolderUpdateUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderPutStatusOk(x.Status));
                if (failed != null)
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{displayName}\" error: {failed.Status}");
            }
        }

        private static async Task RevokeSharedFolderFromUser(IAuthentication auth, string sharedFolderUid,
            string userId)
        {
            var sharedFolder = await GetSharedFoldersAsync(auth, sharedFolderUid).ConfigureAwait(false);
            if (!IsSharedFolderUserMember(sharedFolder, userId))
                return;
            if (!TryResolveSharedFolderKey(sharedFolder, auth, out var key))
                throw new VaultException(
                    $"Shared folder \"{sharedFolderUid}\" key could not be decrypted.");

            var displayName = DecryptSharedFolderName(sharedFolder, key);
            var request = new SharedFolderUpdateV3Request
            {
                SharedFolderUid = ByteString.CopyFrom(sharedFolderUid.Base64UrlDecode()),
                EncryptedSharedFolderName = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(displayName), key)),
                ForceUpdate = true,
            };

            request.SharedFolderRemoveUser.Add(userId);

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request)
                .ConfigureAwait(false);
            foreach (var arr in new[] { response.SharedFolderRemoveUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderRemoveStatusOk(x.Status));
                if (failed != null)
                    throw new VaultException($"Remove user \"{failed.Username}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
            }
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

    [DataContract]
    public class GetSharedFoldersResponse : KeeperApiResponse
    {
        [DataMember(Name = "shared_folders", EmitDefaultValue = false)]
        public SharedFolderObject[] SharedFolders { get; set; }
    }

    [DataContract]
    public class SharedFolderObject
    {
        [DataMember(Name = "shared_folder_uid")] public string SharedFolderUid { get; set; }
        [DataMember(Name = "account_folder", EmitDefaultValue = false)] public bool? AccountFolder { get; set; }
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
    public class SharedFolderUserObject
    {
        [DataMember(Name = "email", EmitDefaultValue = false)]
        public string Email { get; set; }

        [DataMember(Name = "username", EmitDefaultValue = false)]
        public string Username { get; set; }

        [DataMember(Name = "manage_users")]
        public bool ManageUsers { get; set; }

        [DataMember(Name = "manage_records")]
        public bool ManageRecords { get; set; }

        [OnDeserialized]
        private void NormalizeEmailFromUsername(StreamingContext context)
        {
            if (string.IsNullOrEmpty(Email) && !string.IsNullOrEmpty(Username))
                Email = Username;
        }
    }

    [DataContract]
    public class SharedFolderRecordObject
    {
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
        [DataMember(Name = "record_key")] public string RecordKey { get; set; }
        [DataMember(Name = "can_share")] public bool CanShare { get; set; }
        [DataMember(Name = "can_edit")] public bool CanEdit { get; set; }
    }

    [DataContract]
    public class SharedFolderTeamObject
    {
        [DataMember(Name = "team_uid")] public string TeamUid { get; set; }
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }
        [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
        [DataMember(Name = "restrict_edit")] public bool RestrictEdit { get; set; }
        [DataMember(Name = "restrict_share")] public bool RestrictShare { get; set; }
        [DataMember(Name = "shared_folder_key", EmitDefaultValue = false)] public string TeamSharedFolderKey { get; set; }
        [DataMember(Name = "key_type", EmitDefaultValue = false)] public int? TeamSharedFolderKeyWrapType { get; set; }
        [DataMember(Name = "team_key", EmitDefaultValue = false)] public string TeamKey { get; set; }
        [DataMember(Name = "team_key_type", EmitDefaultValue = false)] public int? TeamKeyWrapType { get; set; }
        [DataMember(Name = "team_private_key", EmitDefaultValue = false)] public string TeamPrivateKey { get; set; }
        [DataMember(Name = "team_ec_private_key", EmitDefaultValue = false)] public string TeamEcPrivateKey { get; set; }
    }
}
