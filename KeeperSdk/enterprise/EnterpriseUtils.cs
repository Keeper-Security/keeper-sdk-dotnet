using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public static class EnterpriseUtils
    {

        public static string EncryptEncryptedData(EncryptedData encryptedData, byte[] encryptionKey)
        {
            return CryptoUtils.EncryptAesV1(JsonUtils.DumpJson(encryptedData), encryptionKey).Base64UrlEncode();
        }

        public static void DecryptEncryptedData(string encryptedData, byte[] encryptionKey, IDisplayName entity)
        {
            if (string.IsNullOrEmpty(encryptedData)) return;

            try
            {
                var encryptedBytes = encryptedData.Base64UrlDecode();
                if (encryptedBytes != null && encryptedBytes.Length > 0)
                {
                    var jData = CryptoUtils.DecryptAesV1(encryptedBytes, encryptionKey);
                    var data = JsonUtils.ParseJson<EncryptedData>(jData);
                    entity.DisplayName = data.DisplayName;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
        }

        public static async Task PopulateUserPublicKeys(this EnterpriseData enterpriseData, IDictionary<string, byte[]> publicKeys, Action<string> warnings = null)
        {
            var toLoad = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
            toLoad.UnionWith(publicKeys.Keys);
            toLoad.ExceptWith(enterpriseData.UserPublicKeyCache.Keys);
            if (toLoad.Count > 0)
            {
                var publicKeyRq = new PublicKeysCommand
                {
                    keyOwners = toLoad.ToArray()
                };
                var auth = enterpriseData.Enterprise.Auth;
                var publicKeyRs = await auth.ExecuteAuthCommand<PublicKeysCommand, PublicKeysResponse>(publicKeyRq);
                if (publicKeyRs.publicKeys != null)
                {
                    foreach (var key in publicKeyRs.publicKeys)
                    {
                        if (!string.IsNullOrEmpty(key.publicKey))
                        {
                            enterpriseData.UserPublicKeyCache[key.keyOwner] = key.publicKey.Base64UrlDecode();
                        }
                        else
                        {
                            warnings?.Invoke($"User \'{key.keyOwner}\': Public key error ({key.resultCode}): {key.message}");
                            enterpriseData.UserPublicKeyCache[key.keyOwner] = null;
                        }
                    }
                }
            }

            foreach (var email in publicKeys.Keys.ToArray())
            {
                if (enterpriseData.UserPublicKeyCache.TryGetValue(email, out var pk))
                {
                    publicKeys[email] = pk;
                }
            }
        }

        public static async Task PopulateTeamKeys(this EnterpriseData enterpriseData, IDictionary<string, byte[]> teamKeys, Action<string> warnings = null)
        {
            var toLoad = new HashSet<string>();
            foreach (var teamUid in teamKeys.Keys.ToArray())
            {
                if (enterpriseData.TryGetTeam(teamUid, out var team))
                {
                    if (team.TeamKey != null)
                    {
                        teamKeys[teamUid] = team.TeamKey;
                    }
                    else
                    {
                        toLoad.Add(teamUid);
                    }
                }
            }

            if (toLoad.Count > 0)
            {
                var teamKeyRq = new TeamGetKeysCommand
                {
                    teams = toLoad.ToArray()
                };
                var auth = enterpriseData.Enterprise.Auth;
                var teamKeyRs = await auth.ExecuteAuthCommand<TeamGetKeysCommand, TeamGetKeysResponse>(teamKeyRq);
                if (teamKeyRs.keys != null)
                {
                    foreach (var tk in teamKeyRs.keys)
                    {
                        byte[] key = null;
                        if (!string.IsNullOrEmpty(tk.key))
                        {
                            try
                            {
                                switch (tk.keyType)
                                {
                                    case 1:
                                        key = CryptoUtils.DecryptAesV1(tk.key.Base64UrlDecode(), auth.AuthContext.DataKey);
                                        break;
                                    case 2:
                                        key = CryptoUtils.DecryptRsa(tk.key.Base64UrlDecode(), auth.AuthContext.PrivateKey);
                                        break;
                                    default:
                                        warnings?.Invoke($"Team \'{tk.teamUid}\' unsupported key type: {tk.keyType}");
                                        break;
                                }
                            }
                            catch (Exception e)
                            {
                                warnings?.Invoke(e.Message);
                            }
                        }

                        if (key == null) continue;

                        if (enterpriseData.TryGetTeam(tk.teamUid, out var team))
                        {
                            team.TeamKey = key;
                        }

                        teamKeys[tk.teamUid] = key;
                    }
                }
            }
        }
    }
}
