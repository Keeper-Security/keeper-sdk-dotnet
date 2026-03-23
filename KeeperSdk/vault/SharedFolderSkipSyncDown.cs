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
    /// Shared folder membership without loading the full vault.
    /// </summary>
    public static class SharedFolderSkipSyncDown
    {
        /// <summary>
        /// Default <see cref="ISharedFolderSkipSyncDown"/> implementation.
        /// </summary>
        public sealed class SharedFolderSkipSyncDownClient : ISharedFolderSkipSyncDown
        {
            /// <inheritdoc />
            public Task<GetSharedFoldersResponse> GetSharedFolderAsync(IAuthentication auth, string sharedFolderUid, string teamUidForAccess = null)
                => SharedFolderSkipSyncDown.GetSharedFolderAsync(auth, sharedFolderUid, teamUidForAccess);

            /// <inheritdoc />
            public Task PutUserToSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
                string userId, UserType userType, IUserShareOptions options = null, string teamUidForAccess = null)
                => SharedFolderSkipSyncDown.PutUserToSharedFolderAsync(auth, sharedFolderUid, userId, userType, options, teamUidForAccess);

            /// <inheritdoc />
            public Task RemoveUserFromSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
                string userId, UserType userType, string teamUidForAccess = null)
                => SharedFolderSkipSyncDown.RemoveUserFromSharedFolderAsync(auth, sharedFolderUid, userId, userType, teamUidForAccess);
        }

        /// <summary>
        /// Loads one shared folder and its requested details from the server.
        /// </summary>
        /// <param name="teamUidForAccess">When the folder is only visible through a team, pass that team UID.</param>
        /// <returns>Folder data, or <c>null</c> if unavailable or the call failed.</returns>
        public static async Task<GetSharedFoldersResponse> GetSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string teamUidForAccess = null)
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
                        TeamUid = string.IsNullOrEmpty(teamUidForAccess) ? null : teamUidForAccess,
                    },
                },
                Include = new[] { "sfheaders", "sfusers", "sfteams" },
            };

            var response = await auth.ExecuteAuthCommand<GetSharedFoldersCommand, GetSharedFoldersResponse>(command, throwOnError: false)
                .ConfigureAwait(false);
            if (response == null || !response.IsSuccess)
                return null;

            if ((response.SharedFolders == null || response.SharedFolders.Length == 0) && response.LegacySingleSharedFolder != null)
                response.SharedFolders = new[] { response.LegacySingleSharedFolder };

            if (response.SharedFolders == null || response.SharedFolders.Length == 0)
                return null;

            return response;
        }

        /// <summary>
        /// Adds or updates a user or team on a shared folder.
        /// </summary>
        /// <param name="teamUidForAccess">When the folder is only visible through a team, pass that team UID.</param>
        public static async Task PutUserToSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string userId, UserType userType, IUserShareOptions options = null, string teamUidForAccess = null)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            await ShareSharedFolderToUser(auth, sharedFolderUid, userId, userType, options, teamUidForAccess).ConfigureAwait(false);
        }

        /// <summary>
        /// Removes a user or team from a shared folder.
        /// </summary>
        /// <param name="teamUidForAccess">When the folder is only visible through a team, pass that team UID.</param>
        public static async Task RemoveUserFromSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string userId, UserType userType, string teamUidForAccess = null)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            await RevokeSharedFolderFromUser(auth, sharedFolderUid, userId, userType, teamUidForAccess).ConfigureAwait(false);
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

        private static void ValidateTeamAccessContext(SharedFolderObject sf, string sharedFolderUid, string teamUidForAccess)
        {
            if (string.IsNullOrEmpty(teamUidForAccess))
                return;
            var teamListed = sf.Teams?.Any(t => string.Equals(t.TeamUid, teamUidForAccess, StringComparison.Ordinal)) == true;
            if (!teamListed)
                throw new VaultException(
                    $"Team \"{teamUidForAccess}\" is not listed on shared folder \"{sharedFolderUid}\".");
        }

        private static bool IsSharedFolderMember(SharedFolderObject sf, string userId, UserType userType)
        {
            if (userType == UserType.User)
                return sf.Users?.Any(u =>
                    string.Equals(string.IsNullOrEmpty(u.Email) ? u.Username : u.Email, userId, StringComparison.OrdinalIgnoreCase)) == true;
            return sf.Teams?.Any(t => string.Equals(t.TeamUid, userId, StringComparison.Ordinal)) == true;
        }

        private static bool HasNoShareOptionsChanges(IUserShareOptions options)
        {
            if (options == null)
                return true;
            return options.ManageUsers == null && options.ManageRecords == null && options.Expiration == null;
        }

        private static async Task<SharedFolderObject> RefreshSharedFoldersAsync(IAuthentication auth, string sharedFolderUid,
            string teamUidForAccess)
        {
            await GetSharedFoldersAsync(auth, sharedFolderUid, teamUidForAccess).ConfigureAwait(false);
            return await GetSharedFoldersAsync(auth, sharedFolderUid, teamUidForAccess).ConfigureAwait(false);
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

        private static async Task<SharedFolderObject> GetSharedFoldersAsync(IAuthentication auth, string sharedFolderUid,
            string teamUidForAccess)
        {
            teamUidForAccess = string.IsNullOrEmpty(teamUidForAccess) ? null : teamUidForAccess;

            var loaded = await GetSharedFolderAsync(auth, sharedFolderUid, teamUidForAccess).ConfigureAwait(false);
            if (loaded == null || loaded.SharedFolders == null || loaded.SharedFolders.Length == 0)
            {
                throw new VaultException(
                    $"Could not load shared folder \"{sharedFolderUid}\". " +
                    "Verify the UID, your access to the folder, and pass teamUidForAccess if it is only available through team membership.");
            }

            var sf = FindSharedFolder(loaded, sharedFolderUid);
            ValidateTeamAccessContext(sf, sharedFolderUid, teamUidForAccess);
            return sf;
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

        private static byte[] DecryptSharedFolderKeyFromTeam(byte[] sharedFolderKey, RecordKeyType keyType,
            byte[] teamKey, byte[] teamPrivateKeyBytes, byte[] teamEcPrivateKeyEncryptedBytes)
        {
            switch (keyType)
            {
                case RecordKeyType.EncryptedByDataKey:
                    return CryptoUtils.DecryptAesV1(sharedFolderKey, teamKey);
                case RecordKeyType.EncryptedByPublicKey:
                    var rsaPrivateKey = CryptoUtils.DecryptAesV1(teamPrivateKeyBytes, teamKey);
                    var rsaPk = CryptoUtils.LoadRsaPrivateKey(rsaPrivateKey);
                    return CryptoUtils.DecryptRsa(sharedFolderKey, rsaPk);
                case RecordKeyType.EncryptedByDataKeyGcm:
                    return CryptoUtils.DecryptAesV2(sharedFolderKey, teamKey);
                case RecordKeyType.EncryptedByPublicKeyEcc:
                    if (teamEcPrivateKeyEncryptedBytes == null || teamEcPrivateKeyEncryptedBytes.Length == 0)
                        throw new ArgumentException("Team EC private key payload is required for EncryptedByPublicKeyEcc.",
                            nameof(teamEcPrivateKeyEncryptedBytes));
                    var ecPrivateKeyBytes = CryptoUtils.DecryptAesV2(teamEcPrivateKeyEncryptedBytes, teamKey);
                    var ecPk = CryptoUtils.LoadEcPrivateKey(ecPrivateKeyBytes);
                    return CryptoUtils.DecryptEc(sharedFolderKey, ecPk);
                default:
                    throw new VaultException($"Unsupported shared folder key type: {keyType}");
            }
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

            if (sf.Teams != null)
            {
                foreach (var team in sf.Teams)
                {
                    try
                    {
                        if (string.IsNullOrEmpty(team.TeamSharedFolderKey) || !team.TeamSharedFolderKeyWrapType.HasValue ||
                            string.IsNullOrEmpty(team.TeamKey) || !team.TeamKeyWrapType.HasValue)
                            continue;

                        var teamKey = DecryptKeeperKey(context, team.TeamKey.Base64UrlDecode(),
                            (RecordKeyType)team.TeamKeyWrapType.Value);
                        var teamPrivateKeyBytes = string.IsNullOrEmpty(team.TeamPrivateKey)
                            ? Array.Empty<byte>()
                            : team.TeamPrivateKey.Base64UrlDecode();
                        var teamEcPrivateKeyBytes = string.IsNullOrEmpty(team.TeamEcPrivateKey)
                            ? Array.Empty<byte>()
                            : team.TeamEcPrivateKey.Base64UrlDecode();

                        sharedFolderKey = DecryptSharedFolderKeyFromTeam(
                            team.TeamSharedFolderKey.Base64UrlDecode(),
                            (RecordKeyType)team.TeamSharedFolderKeyWrapType.Value,
                            teamKey,
                            teamPrivateKeyBytes,
                            teamEcPrivateKeyBytes);
                        return true;
                    }
                    catch
                    {
                    }
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
            string userId, UserType userType, IUserShareOptions options, string teamUidForAccess)
        {
            var sharedFolder = await RefreshSharedFoldersAsync(auth, sharedFolderUid, teamUidForAccess).ConfigureAwait(false);
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

            SharedFolderUserObject existingUser = null;
            SharedFolderTeamObject existingTeam = null;
            if (userType == UserType.User)
                existingUser = sharedFolder.Users?.FirstOrDefault(x =>
                    string.Equals(string.IsNullOrEmpty(x.Email) ? x.Username : x.Email, userId, StringComparison.InvariantCultureIgnoreCase));
            else
                existingTeam = sharedFolder.Teams?.FirstOrDefault(x => string.Equals(x.TeamUid, userId, StringComparison.Ordinal));

            if (HasNoShareOptionsChanges(options))
            {
                if (userType == UserType.User && existingUser != null)
                    return;
                if (userType == UserType.Team && existingTeam != null)
                    return;
            }

            if (userType == UserType.User)
            {
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
            }
            else
            {
                var sfUpdateTeams = new SharedFolderUpdateTeam
                {
                    TeamUid = ByteString.CopyFrom(userId.Base64UrlDecode()),
                    Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
                };
                if (existingTeam != null)
                {
                    sfUpdateTeams.ManageUsers = options?.ManageUsers ?? existingTeam.ManageUsers;
                    sfUpdateTeams.ManageRecords = options?.ManageRecords ?? existingTeam.ManageRecords;
                    request.SharedFolderUpdateTeam.Add(sfUpdateTeams);
                }
                else
                {
                    sfUpdateTeams.ManageUsers = options?.ManageUsers ?? sharedFolder.ManageUsers;
                    sfUpdateTeams.ManageRecords = options?.ManageRecords ?? sharedFolder.ManageRecords;

                    byte[] encryptedSharedFolderKey = null;
                    var encKeyType = EncryptedKeyType.NoKey;
                    await auth.LoadTeamKeys(Enumerable.Repeat(userId, 1)).ConfigureAwait(false);
                    if (auth.TryGetTeamKeys(userId, out var keys))
                    {
                        if (keys.AesKey != null)
                        {
                            if (auth.AuthContext.ForbidKeyType2)
                            {
                                encryptedSharedFolderKey = CryptoUtils.EncryptAesV2(key, keys.AesKey);
                                encKeyType = EncryptedKeyType.EncryptedByDataKeyGcm;
                            }
                            else
                            {
                                encryptedSharedFolderKey = CryptoUtils.EncryptAesV1(key, keys.AesKey);
                                encKeyType = EncryptedKeyType.EncryptedByDataKey;
                            }
                        }
                        else if (auth.AuthContext.ForbidKeyType2 && keys.EcPublicKey != null)
                        {
                            var publicKey = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                            encryptedSharedFolderKey = CryptoUtils.EncryptEc(key, publicKey);
                            encKeyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                        }
                        else if (!auth.AuthContext.ForbidKeyType2 && keys.RsaPublicKey != null)
                        {
                            var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                            encryptedSharedFolderKey = CryptoUtils.EncryptRsa(key, publicKey);
                            encKeyType = EncryptedKeyType.EncryptedByPublicKey;
                        }
                    }

                    if (encryptedSharedFolderKey != null)
                    {
                        sfUpdateTeams.TypedSharedFolderKey = new EncryptedDataKey
                        {
                            EncryptedKey = ByteString.CopyFrom(encryptedSharedFolderKey),
                            EncryptedKeyType = encKeyType,
                        };
                    }
                    else
                        throw new VaultException($"Cannot retrieve team \"{userId}\" key for sharing.");

                    request.SharedFolderAddTeam.Add(sfUpdateTeams);
                }
            }

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request)
                .ConfigureAwait(false);
            foreach (var arr in new[] { response.SharedFolderAddUserStatus, response.SharedFolderUpdateUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderPutStatusOk(x.Status));
                if (failed != null)
                    throw new VaultException($"Put \"{failed.Username}\" to Shared Folder \"{displayName}\" error: {failed.Status}");
            }

            foreach (var arr in new[] { response.SharedFolderAddTeamStatus, response.SharedFolderUpdateTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderPutStatusOk(x.Status));
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Put Team Uid \"{uid}\" to Shared Folder \"{displayName}\" error: {failed.Status}");
                }
            }
        }

        private static async Task RevokeSharedFolderFromUser(IAuthentication auth, string sharedFolderUid,
            string userId, UserType userType, string teamUidForAccess)
        {
            var sharedFolder = await RefreshSharedFoldersAsync(auth, sharedFolderUid, teamUidForAccess).ConfigureAwait(false);
            if (!IsSharedFolderMember(sharedFolder, userId, userType))
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

            if (userType == UserType.User)
                request.SharedFolderRemoveUser.Add(userId);
            else
                request.SharedFolderRemoveTeam.Add(ByteString.CopyFrom(userId.Base64UrlDecode()));

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request)
                .ConfigureAwait(false);
            foreach (var arr in new[] { response.SharedFolderRemoveUserStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderRemoveStatusOk(x.Status));
                if (failed != null)
                    throw new VaultException($"Remove user \"{failed.Username}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
            }

            foreach (var arr in new[] { response.SharedFolderRemoveTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderRemoveStatusOk(x.Status));
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException($"Remove team \"{uid}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
                }
            }
        }

        [DataContract]
        private class GetSharedFoldersRequestItem
        {
            [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
            public string SharedFolderUid { get; set; }

            [DataMember(Name = "team_uid", EmitDefaultValue = false)]
            public string TeamUid { get; set; }
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

    /// <summary>
    /// Result of loading shared folders from the server.
    /// </summary>
    [DataContract]
    public class GetSharedFoldersResponse : KeeperApiResponse
    {
        [DataMember(Name = "shared_folders", EmitDefaultValue = false)]
        public SharedFolderObject[] SharedFolders { get; set; }

        [DataMember(Name = "shared_folder", EmitDefaultValue = false)]
        public SharedFolderObject LegacySingleSharedFolder { get; set; }
    }

    /// <summary>
    /// One shared folder: metadata, users, records, and teams.
    /// </summary>
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

    /// <summary>
    /// A user on a shared folder with permission flags.
    /// </summary>
    [DataContract]
    public class SharedFolderUserObject
    {
        /// <summary>Account email.</summary>
        [DataMember(Name = "email", EmitDefaultValue = false)]
        public string Email { get; set; }

        /// <summary>Account username when returned by the API.</summary>
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

    /// <summary>
    /// A record linked to a shared folder with share/edit flags.
    /// </summary>
    [DataContract]
    public class SharedFolderRecordObject
    {
        [DataMember(Name = "record_uid")] public string RecordUid { get; set; }
        [DataMember(Name = "record_key")] public string RecordKey { get; set; }
        [DataMember(Name = "can_share")] public bool CanShare { get; set; }
        [DataMember(Name = "can_edit")] public bool CanEdit { get; set; }
    }

    /// <summary>
    /// A team on a shared folder with permission flags.
    /// </summary>
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
