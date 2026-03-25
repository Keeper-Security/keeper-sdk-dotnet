using System;
using System.Collections.Generic;
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
    /// Supports sharing with users (by email/username) and with teams (by UID or resolved name via <see cref="GetTeamUidFromNameAsync"/>).
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

            /// <inheritdoc />
            public Task PutTeamToSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
                string teamUid, IUserShareOptions options = null)
                => SharedFolderSkipSyncDown.PutTeamToSharedFolderAsync(auth, sharedFolderUid, teamUid, options);

            /// <inheritdoc />
            public Task RemoveTeamFromSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
                string teamUid)
                => SharedFolderSkipSyncDown.RemoveTeamFromSharedFolderAsync(auth, sharedFolderUid, teamUid);

            /// <inheritdoc />
            public Task<IEnumerable<TeamInfo>> GetAvailableTeamsForShareAsync(IAuthentication auth)
                => SharedFolderSkipSyncDown.GetAvailableTeamsForShareAsync(auth);
        }

        /// <summary>
        /// Loads shared folder metadata for the given UID without a full vault sync, or <c>null</c> if it is not available.
        /// </summary>
        /// <param name="auth">Authenticated session.</param>
        /// <param name="sharedFolderUid">Shared folder UID.</param>
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

        /// <inheritdoc cref="ISharedFolderSkipSyncDown.PutTeamToSharedFolderAsync" />
        public static async Task PutTeamToSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string teamUid, IUserShareOptions options = null)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrEmpty(sharedFolderUid))
                throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));
            if (string.IsNullOrEmpty(teamUid))
                throw new ArgumentException("Team UID is required.", nameof(teamUid));
            await ShareSharedFolderToTeam(auth, sharedFolderUid, teamUid, options).ConfigureAwait(false);
        }

        /// <inheritdoc cref="ISharedFolderSkipSyncDown.RemoveTeamFromSharedFolderAsync" />
        public static async Task RemoveTeamFromSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string teamUid)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrEmpty(sharedFolderUid))
                throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));
            if (string.IsNullOrEmpty(teamUid))
                throw new ArgumentException("Team UID is required.", nameof(teamUid));
            await RevokeSharedFolderFromTeam(auth, sharedFolderUid, teamUid).ConfigureAwait(false);
        }

        /// <inheritdoc cref="ISharedFolderSkipSyncDown.GetAvailableTeamsForShareAsync" />
        public static async Task<IEnumerable<TeamInfo>> GetAvailableTeamsForShareAsync(IAuthentication auth)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");

            var request = new GetAvailableTeamsCommand();
            var response = await auth.ExecuteAuthCommand<GetAvailableTeamsCommand, GetAvailableTeamsResponse>(request)
                .ConfigureAwait(false);

            if (response?.teams == null || response.teams.Length == 0)
                return Enumerable.Empty<TeamInfo>();

            return response.teams.Select(x => new TeamInfo
            {
                TeamUid = x.teamUid,
                Name = x.teamName,
            });
        }

        /// <summary>
        /// Resolves a team display name to a team UID. Returns <c>null</c> if none match; throws if multiple match.
        /// </summary>
        public static async Task<string> GetTeamUidFromNameAsync(IAuthentication auth, string teamName)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(teamName))
                throw new ArgumentException("Team name is required.", nameof(teamName));

            var name = teamName.Trim();
            var teams = (await GetAvailableTeamsForShareAsync(auth).ConfigureAwait(false)).ToList();
            var matches = MatchTeamsByName(teams, name, includeUidMatch: false);

            if (matches.Count == 0)
                return null;
            if (matches.Count > 1)
                throw new VaultException($"Multiple teams match name \"{name}\". Please specify Team UID.");

            return matches[0].TeamUid;
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

        private static SharedFolderTeamObject FindSharedFolderTeam(SharedFolderObject sf, string teamUid)
        {
            if (sf?.Teams == null || string.IsNullOrEmpty(teamUid))
                return null;
            return sf.Teams.FirstOrDefault(t =>
                string.Equals(t.TeamUid, teamUid, StringComparison.OrdinalIgnoreCase));
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
                    sharedFolderKey = DecryptKeeperKey(context, sf.SharedFolderKey.Base64UrlDecode(), headerKeyType);
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
                    sharedFolderKey = DecryptKeeperKey(context, Array.Empty<byte>(), headerKeyType);
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

        private static async Task ShareSharedFolderToTeam(IAuthentication auth, string sharedFolderUid,
            string teamNameOrUid, IUserShareOptions options)
        {
            if (string.IsNullOrEmpty(teamNameOrUid))
                throw new ArgumentException("Team name or UID is required.", nameof(teamNameOrUid));

            var teamUid = await ResolveTeamUidFromNameOrUidAsync(auth, teamNameOrUid).ConfigureAwait(false);

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

            var existingTeam = FindSharedFolderTeam(sharedFolder, teamUid);
            var teamIsMember = existingTeam != null;

            if (HasNoShareOptionsChanges(options) && teamIsMember)
                return;

            var sfut = new SharedFolderUpdateTeam
            {
                TeamUid = ByteString.CopyFrom(teamUid.Base64UrlDecode()),
                Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
            };

            if (teamIsMember)
            {
                sfut.ManageUsers = options?.ManageUsers ?? existingTeam.ManageUsers;
                sfut.ManageRecords = options?.ManageRecords ?? existingTeam.ManageRecords;
                request.SharedFolderUpdateTeam.Add(sfut);
            }
            else
            {
                sfut.ManageUsers = options?.ManageUsers ?? sharedFolder.DefaultManageUsers;
                sfut.ManageRecords = options?.ManageRecords ?? sharedFolder.DefaultManageRecords;

                byte[] encryptedSharedFolderKey = null;
                var keyType = EncryptedKeyType.NoKey;

                await auth.LoadTeamKeys(Enumerable.Repeat(teamUid, 1)).ConfigureAwait(false);
                if (auth.TryGetTeamKeys(teamUid, out var teamKeys))
                {
                    if (teamKeys.AesKey != null)
                    {
                        if (auth.AuthContext.ForbidKeyType2)
                        {
                            encryptedSharedFolderKey = CryptoUtils.EncryptAesV2(key, teamKeys.AesKey);
                            keyType = EncryptedKeyType.EncryptedByDataKeyGcm;
                        }
                        else
                        {
                            encryptedSharedFolderKey = CryptoUtils.EncryptAesV1(key, teamKeys.AesKey);
                            keyType = EncryptedKeyType.EncryptedByDataKey;
                        }
                    }
                    else if (auth.AuthContext.ForbidKeyType2 && teamKeys.EcPublicKey != null)
                    {
                        var publicKey = CryptoUtils.LoadEcPublicKey(teamKeys.EcPublicKey);
                        encryptedSharedFolderKey = CryptoUtils.EncryptEc(key, publicKey);
                        keyType = EncryptedKeyType.EncryptedByPublicKeyEcc;
                    }
                    else if (!auth.AuthContext.ForbidKeyType2 && teamKeys.RsaPublicKey != null)
                    {
                        var publicKey = CryptoUtils.LoadRsaPublicKey(teamKeys.RsaPublicKey);
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
                    request.SharedFolderAddTeam.Add(sfut);
                }
                else
                {
                    throw new VaultException(
                        $"Cannot retrieve team \"{teamUid}\" keys for sharing (team_get_keys).");
                }
            }

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request)
                .ConfigureAwait(false);
            foreach (var arr in new[] { response.SharedFolderAddTeamStatus, response.SharedFolderUpdateTeamStatus })
            {
                var failed = arr?.FirstOrDefault(x => !IsSharedFolderPutStatusOk(x.Status));
                if (failed != null)
                {
                    var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                    throw new VaultException(
                        $"Put Team \"{uid}\" to Shared Folder \"{displayName}\" error: {failed.Status}");
                }
            }
        }

        private static async Task RevokeSharedFolderFromTeam(IAuthentication auth, string sharedFolderUid,
            string teamNameOrUid)
        {
            var teamUid = await ResolveTeamUidFromNameOrUidAsync(auth, teamNameOrUid).ConfigureAwait(false);

            var sharedFolder = await GetSharedFoldersAsync(auth, sharedFolderUid).ConfigureAwait(false);

            if (sharedFolder.Teams != null && sharedFolder.Teams.Length > 0 &&
                FindSharedFolderTeam(sharedFolder, teamUid) == null)
            {
                return;
            }

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

            request.SharedFolderRemoveTeam.Add(ByteString.CopyFrom(teamUid.Base64UrlDecode()));

            var response = await auth.ExecuteAuthRest<SharedFolderUpdateV3Request, SharedFolderUpdateV3Response>("vault/shared_folder_update_v3", request)
                .ConfigureAwait(false);
            var failed = response.SharedFolderRemoveTeamStatus?.FirstOrDefault(x => !IsSharedFolderRemoveStatusOk(x.Status));
            if (failed != null)
            {
                var uid = failed.TeamUid.ToArray().Base64UrlEncode();
                throw new VaultException(
                    $"Remove Team \"{uid}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
            }
        }

        internal static async Task<string> ResolveTeamUidFromNameAsync(IAuthentication auth, string teamName)
        {
            if (auth == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(teamName))
                throw new ArgumentException("Team name is required.", nameof(teamName));

            var name = teamName.Trim();
            var teams = (await GetAvailableTeamsForShareAsync(auth).ConfigureAwait(false)).ToList();
            var matches = MatchTeamsByName(teams, name, includeUidMatch: true);

            if (matches.Count == 0)
                throw new VaultException($"Team \"{name}\" not found.");
            if (matches.Count > 1)
                throw new VaultException($"Multiple teams match name \"{name}\". Please specify Team UID.");

            return matches[0].TeamUid;
        }

        private static List<TeamInfo> MatchTeamsByName(IList<TeamInfo> teams, string name, bool includeUidMatch)
        {
            return teams.Where(t =>
                    !string.IsNullOrEmpty(t.TeamUid) &&
                    (string.Equals(t.Name?.Trim(), name, StringComparison.OrdinalIgnoreCase) ||
                     (includeUidMatch && string.Equals(t.TeamUid, name, StringComparison.OrdinalIgnoreCase))))
                .ToList();
        }

        /// <summary>True when <paramref name="value"/> is base64url for 16 bytes (Keeper UID).</summary>
        private static bool IsKeeperUidString(string value)
        {
            if (string.IsNullOrEmpty(value))
                return false;
            var bytes = value.Base64UrlDecode();
            return bytes.Length == 16;
        }

        private static async Task<string> ResolveTeamUidFromNameOrUidAsync(IAuthentication auth, string teamNameOrUid)
        {
            if (string.IsNullOrEmpty(teamNameOrUid))
                throw new ArgumentException("Team name or UID is required.", nameof(teamNameOrUid));
            var trimmed = teamNameOrUid.Trim();
            if (IsKeeperUidString(trimmed))
                return trimmed;
            return await ResolveTeamUidFromNameAsync(auth, trimmed).ConfigureAwait(false);
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

            var userIsMember = IsSharedFolderUserMember(sharedFolder, userId);

            if (HasNoShareOptionsChanges(options) && userIsMember)
                return;

            var sfUpdateUser = new SharedFolderUpdateUser
            {
                Username = userId,
                Expiration = options?.Expiration?.ToUnixTimeMilliseconds() ?? 0,
            };
            if (userIsMember)
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
                    ? (sharedFolder.DefaultManageUsers ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse)
                    : (options.ManageUsers.Value ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse);
                sfUpdateUser.ManageRecords = options?.ManageRecords == null
                    ? (sharedFolder.DefaultManageRecords ? SetBooleanValue.BooleanTrue : SetBooleanValue.BooleanFalse)
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
            var failed = response.SharedFolderRemoveUserStatus?.FirstOrDefault(x => !IsSharedFolderRemoveStatusOk(x.Status));
            if (failed != null)
                throw new VaultException($"Remove user \"{failed.Username}\" from Shared Folder \"{displayName}\" error: {failed.Status}");
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
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "revision")]
        public long Revision { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "data", EmitDefaultValue = false)]
        public string Data { get; set; }

        [DataMember(Name = "owner", EmitDefaultValue = false)]
        public string Owner { get; set; }

        [DataMember(Name = "full_sync", EmitDefaultValue = false)]
        public bool FullSync { get; set; }

        [DataMember(Name = "key_type")]
        public int KeyType { get; set; }

        [DataMember(Name = "shared_folder_key", EmitDefaultValue = false)]
        public string SharedFolderKey { get; set; }

        [DataMember(Name = "manage_users")]
        public bool ManageUsers { get; set; }

        [DataMember(Name = "manage_records")]
        public bool ManageRecords { get; set; }

        [DataMember(Name = "default_can_edit", EmitDefaultValue = false)]
        public bool DefaultCanEdit { get; set; }

        [DataMember(Name = "default_can_share", EmitDefaultValue = false)]
        public bool DefaultCanShare { get; set; }

        [DataMember(Name = "default_manage_records", EmitDefaultValue = false)]
        public bool DefaultManageRecords { get; set; }

        [DataMember(Name = "default_manage_users", EmitDefaultValue = false)]
        public bool DefaultManageUsers { get; set; }

        [DataMember(Name = "account_folder", EmitDefaultValue = false)]
        public bool? AccountFolder { get; set; }

        [DataMember(Name = "users", EmitDefaultValue = false)]
        public SharedFolderUserObject[] Users { get; set; }

        [DataMember(Name = "records", EmitDefaultValue = false)]
        public SharedFolderRecordObject[] Records { get; set; }

        [DataMember(Name = "teams", EmitDefaultValue = false)]
        public SharedFolderTeamObject[] Teams { get; set; }
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
