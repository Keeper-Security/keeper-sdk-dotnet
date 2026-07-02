using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using Records;
using FolderProto = Folder;

namespace KeeperSecurity.Vault
{
    internal enum NsfShareRecipientKind
    {
        User,
        Team,
    }

    internal readonly struct NsfShareRecipient
    {
        public NsfShareRecipient(NsfShareRecipientKind kind, string identifier)
        {
            Kind = kind;
            Identifier = identifier;
        }

        public NsfShareRecipientKind Kind { get; }
        public string Identifier { get; }
    }

    internal static class NsfShareRecipientHelper
    {
        private static Dictionary<string, string> _shareTeamCache;
        private static string _shareTeamCacheAccountUid;

        internal static void ResetShareTeamCache()
        {
            _shareTeamCache = null;
            _shareTeamCacheAccountUid = null;
        }

        /// <summary>
        /// Classify a recipient as a user email or team (name/UID).
        /// </summary>
        public static async Task<NsfShareRecipient?> ClassifyShareRecipientAsync(VaultOnline vault, string recipient)
        {
            if (string.IsNullOrWhiteSpace(recipient))
            {
                return null;
            }

            var trimmed = recipient.Trim();
            if (IsEmailAddress(trimmed))
            {
                return new NsfShareRecipient(NsfShareRecipientKind.User, trimmed.ToLowerInvariant());
            }

            var teamsMap = await GetShareTeamsMapAsync(vault).ConfigureAwait(false);
            var matches = teamsMap
                .Where(pair => string.Equals(pair.Key, trimmed, StringComparison.OrdinalIgnoreCase)
                               || string.Equals(pair.Value, trimmed, StringComparison.OrdinalIgnoreCase))
                .Select(pair => pair.Key)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (matches.Count == 1)
            {
                return new NsfShareRecipient(NsfShareRecipientKind.Team, matches[0]);
            }

            return null;
        }

        public static async Task<string> ResolveTeamDisplayNameAsync(VaultOnline vault, string teamUid)
        {
            if (string.IsNullOrEmpty(teamUid))
            {
                return teamUid;
            }

            if (vault.TryGetTeam(teamUid, out var team) && !string.IsNullOrEmpty(team.Name))
            {
                return team.Name;
            }

            var teamsMap = await GetShareTeamsMapAsync(vault).ConfigureAwait(false);
            if (teamsMap.TryGetValue(teamUid, out var shareName) && !string.IsNullOrEmpty(shareName))
            {
                return shareName;
            }

            foreach (var available in await SharedFolderSkipSyncDown.GetAvailableTeamsForShareAsync(vault.Auth)
                         .ConfigureAwait(false))
            {
                if (string.Equals(available.TeamUid, teamUid, StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrEmpty(available.Name))
                {
                    return available.Name;
                }
            }

            return teamUid;
        }

        public static async Task<string> ResolveTeamUidAsync(IAuthentication auth, string teamNameOrUid)
        {
            return await SharedFolderSkipSyncDown.ResolveTeamUidFromNameOrUidAsync(auth, teamNameOrUid)
                .ConfigureAwait(false);
        }

        public static (byte[] encryptedKey, FolderProto.EncryptedKeyType keyType) EncryptFolderKeyForTeam(
            byte[] folderKey, UserKeys teamKeys, bool forbidRsa)
        {
            if (teamKeys == null)
            {
                throw new VaultException("Team keys are not available.");
            }

            if (!forbidRsa && teamKeys.RsaPublicKey != null && teamKeys.RsaPublicKey.Length > 0)
            {
                var rsaPk = CryptoUtils.LoadRsaPublicKey(teamKeys.RsaPublicKey);
                return (CryptoUtils.EncryptRsa(folderKey, rsaPk), FolderProto.EncryptedKeyType.EncryptedByPublicKey);
            }

            if (teamKeys.EcPublicKey != null && teamKeys.EcPublicKey.Length > 0)
            {
                var ecPk = CryptoUtils.LoadEcPublicKey(teamKeys.EcPublicKey);
                return (CryptoUtils.EncryptEc(folderKey, ecPk), FolderProto.EncryptedKeyType.EncryptedByPublicKeyEcc);
            }

            throw new VaultException("Team has no asymmetric public key for folder sharing.");
        }

        private static bool IsEmailAddress(string value)
        {
            try
            {
                _ = new System.Net.Mail.MailAddress(value);
                return value.Contains("@");
            }
            catch
            {
                return false;
            }
        }

        private static async Task<Dictionary<string, string>> GetShareTeamsMapAsync(VaultOnline vault)
        {
            var currentAccountUid = vault.Auth.AuthContext.AccountUid.Base64UrlEncode();
            if (_shareTeamCacheAccountUid != null && _shareTeamCacheAccountUid != currentAccountUid)
            {
                ResetShareTeamCache();
            }

            if (_shareTeamCache != null)
            {
                return _shareTeamCache;
            }

            var teamsMap = new Dictionary<string, string>(StringComparer.Ordinal);
            try
            {
                var rs = await vault.Auth.ExecuteAuthRest<GetShareObjectsRequest, GetShareObjectsResponse>(
                    "vault/get_share_objects", new GetShareObjectsRequest()).ConfigureAwait(false);
                foreach (var team in rs.ShareTeams.Concat(rs.ShareMCTeams))
                {
                    if (team.TeamUid == null || team.TeamUid.IsEmpty)
                    {
                        continue;
                    }

                    var uid = team.TeamUid.ToByteArray().Base64UrlEncode();
                    if (!teamsMap.ContainsKey(uid))
                    {
                        teamsMap[uid] = team.Teamname ?? string.Empty;
                    }
                }
            }
            catch
            {
                // fall through to available teams lookup
            }

            foreach (var team in await SharedFolderSkipSyncDown.GetAvailableTeamsForShareAsync(vault.Auth)
                         .ConfigureAwait(false))
            {
                if (!string.IsNullOrEmpty(team.TeamUid) && !teamsMap.ContainsKey(team.TeamUid))
                {
                    teamsMap[team.TeamUid] = team.Name ?? string.Empty;
                }
            }

            _shareTeamCache = teamsMap;
            _shareTeamCacheAccountUid = currentAccountUid;
            return teamsMap;
        }
    }
}
