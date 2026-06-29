using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Authentication;

namespace KeeperSecurity.Authentication
{
    public abstract partial class AuthCommon
    {
        private readonly IDictionary<string, UserKeys> _keyCache = new ConcurrentDictionary<string, UserKeys>();

        /// <inheritdoc/>
        public async Task<IEnumerable<string>> LoadTeamKeys(IEnumerable<string> teamUids)
        {
            List<string> skipped = null;
            var newUids = teamUids.Where(x => !_keyCache.ContainsKey(x)).ToArray();
            const int chunkSize = 100;
            var pos = 0;
            while (pos < newUids.Length)
            {
                var size = Math.Min(chunkSize, newUids.Length - pos);
                var tkRq = new TeamGetKeysCommand
                {
                    teams = newUids.Skip(pos).Take(size).ToArray(),
                };
                pos += chunkSize;

                var tkRs = await this.ExecuteAuthCommand<TeamGetKeysCommand, TeamGetKeysResponse>(tkRq);
                foreach (var key in tkRs.keys)
                {
                    if (key.key == null && string.IsNullOrEmpty(key.teamPublicKey))
                    {
                        if (skipped == null)
                        {
                            skipped = new List<string>();
                        }
                        skipped.Add(key.teamUid);
                        continue;
                    }

                    try
                    {
                        byte[] aes = null;
                        byte[] rsa = null;
                        byte[] ec = null;
                        if (!string.IsNullOrEmpty(key.key))
                        {
                            var encryptedKey = key.key.Base64UrlDecode();
                            switch (key.keyType)
                            {
                                case 1:
                                    aes = CryptoUtils.DecryptAesV1(encryptedKey, AuthContext.DataKey);
                                    break;
                                case 2:
                                    aes = CryptoUtils.DecryptRsa(encryptedKey, AuthContext.PrivateRsaKey);
                                    break;
                                case 3:
                                    aes = CryptoUtils.DecryptAesV2(encryptedKey, AuthContext.DataKey);
                                    break;
                                case 4:
                                    aes = CryptoUtils.DecryptEc(encryptedKey, AuthContext.PrivateEcKey);
                                    break;
                                case -1:
                                    ec = encryptedKey;
                                    break;
                                case -3:
                                    rsa = encryptedKey;
                                    break;
                                default:
                                    throw new Exception($"Team key type {key.keyType} is not supported");
                            }
                        }

                        TeamKeyParser.ParseTeamAsymmetricKeyEntry(key, out var pubRsa, out var pubEc);
                        if (pubRsa != null && pubRsa.Length > 0)
                        {
                            rsa = pubRsa;
                        }
                        if (pubEc != null && pubEc.Length > 0)
                        {
                            ec = pubEc;
                        }

                        _keyCache[key.teamUid] = new UserKeys(aes: aes, rsa: rsa, ec: ec);
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError(e.Message);
                    }
                }
            }
            return skipped ?? Enumerable.Empty<string>();
        }

        /// <summary>
        /// Returns cached team keys, loading asymmetric keys via <c>team_get_keys</c> fallback when needed.
        /// </summary>
        internal async Task<UserKeys> GetTeamKeysForSharing(string teamUid)
        {
            await LoadTeamKeys(new[] { teamUid }).ConfigureAwait(false);
            if (TryGetTeamKeys(teamUid, out var keys) && HasAsymmetricTeamKeys(keys))
            {
                return keys;
            }

            var existingAes = keys?.AesKey;
            try
            {
                var tkRq = new TeamGetKeysCommand { teams = new[] { teamUid } };
                var tkRs = await this.ExecuteAuthCommand<TeamGetKeysCommand, TeamGetKeysResponse>(tkRq)
                    .ConfigureAwait(false);
                foreach (var tk in tkRs.keys ?? Enumerable.Empty<TeamKeyObject>())
                {
                    if (!string.Equals(tk.teamUid, teamUid, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    TeamKeyParser.ParseTeamAsymmetricKeyEntry(tk, out var rsa, out var ec);
                    if ((rsa != null && rsa.Length > 0) || (ec != null && ec.Length > 0))
                    {
                        keys = new UserKeys(aes: existingAes, rsa: rsa, ec: ec);
                        _keyCache[teamUid] = keys;
                        return keys;
                    }
                }
            }
            catch (Exception e)
            {
                Trace.TraceError($"team_get_keys fallback failed for {teamUid}: {e.Message}");
            }

            if (!TryGetTeamKeys(teamUid, out keys))
            {
                throw new VaultException($"Team key not found for team {teamUid}");
            }

            return keys;
        }

        private static bool HasAsymmetricTeamKeys(UserKeys keys)
        {
            return keys != null
                   && ((keys.RsaPublicKey != null && keys.RsaPublicKey.Length > 0)
                       || (keys.EcPublicKey != null && keys.EcPublicKey.Length > 0));
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<string>> LoadUsersKeys(IEnumerable<string> usernames)
        {
            List<string> skipped = null;
            var newEmails = usernames.Where(x => !_keyCache.ContainsKey(x)).ToArray();
            const int chunkSize = 1000;
            var pos = 0;
            while (pos < newEmails.Length)
            {
                var size = Math.Min(chunkSize, newEmails.Length - pos);
                var pkRq = new GetPublicKeysRequest();
                pkRq.Usernames.AddRange(newEmails.Skip(pos).Take(size));
                pos += chunkSize;
                var pkRss = await this.ExecuteAuthRest<GetPublicKeysRequest, GetPublicKeysResponse>("vault/get_public_keys", pkRq);
                foreach (var rs in pkRss.KeyResponses)
                {
                    if (string.IsNullOrEmpty(rs.ErrorCode) || string.Equals(rs.ErrorCode, "success", StringComparison.InvariantCultureIgnoreCase))
                    {
                        var rsa = rs.PublicKey.Length > 0 ? rs.PublicKey.ToByteArray() : null;
                        var ec = rs.PublicEccKey.Length > 0 ? rs.PublicEccKey.ToByteArray() : null;
                        _keyCache[rs.Username] = new UserKeys(rsa: rsa, ec: ec);
                    }
                    else
                    {
                        if (skipped == null)
                        {
                            skipped = new List<string>();
                        }
                        skipped.Add(rs.Username);
                    }
                }
            }

            return skipped ?? Enumerable.Empty<string>();
        }

        /// <inheritdoc/>
        public bool TryGetTeamKeys(string teamUid, out UserKeys keys)
        {
            return _keyCache.TryGetValue(teamUid, out keys);
        }

        /// <inheritdoc/>
        public bool TryGetUserKeys(string username, out UserKeys keys)
        {
            return _keyCache.TryGetValue(username, out keys);
        }
    }

    internal static class TeamKeyLoaderExtensions
    {
        public static Task<UserKeys> GetTeamKeysForSharingAsync(this IAuthentication auth, string teamUid)
        {
            if (auth is AuthCommon common)
            {
                return common.GetTeamKeysForSharing(teamUid);
            }

            throw new VaultException("Authentication provider does not support team key loading.");
        }
    }
}