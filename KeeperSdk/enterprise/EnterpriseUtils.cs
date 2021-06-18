using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using System.Text;

namespace KeeperSecurity.Enterprise
{
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

        public static byte[] DecryptEncryptedData(byte[] encryptedData, byte[] encryptionKey)
        {
            var data = new byte[0];
            if (encryptedData != null && encryptedData.Length > 0 && encryptionKey != null && encryptionKey.Length > 0)
            {
                try
                {
                    data = CryptoUtils.DecryptAesV1(encryptedData, encryptionKey);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            }
            return data;
        }

        public static string DecryptEncryptedData(string encryptedData, byte[] encryptionKey)
        {
            string data = string.Empty;
            if (!string.IsNullOrWhiteSpace(encryptedData) && encryptionKey != null && encryptionKey.Length > 0)
            {
                try
                {
                    byte[] encryptedBytes = encryptedData.Base64UrlDecode();
                    byte[] decryptedBytes = DecryptEncryptedData(encryptedBytes, encryptionKey);
                    data = Encoding.UTF8.GetString(decryptedBytes);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            }
            return data;
        }

        public static async Task PopulateUserPublicKeys(this EnterpriseData enterprise, IDictionary<string, byte[]> publicKeys, Action<string> warnings = null)
        {
            var toLoad = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
            toLoad.UnionWith(publicKeys.Keys);
            toLoad.ExceptWith(enterprise.UserPublicKeyCache.Keys);
            if (toLoad.Count > 0)
            {
                var publicKeyRq = new PublicKeysCommand
                {
                    keyOwners = toLoad.ToArray()
                };
                var publicKeyRs = await enterprise.Auth.ExecuteAuthCommand<PublicKeysCommand, PublicKeysResponse>(publicKeyRq);
                if (publicKeyRs.publicKeys != null)
                {
                    foreach (var key in publicKeyRs.publicKeys)
                    {
                        if (!string.IsNullOrEmpty(key.publicKey))
                        {
                            enterprise.UserPublicKeyCache[key.keyOwner] = key.publicKey.Base64UrlDecode();
                        }
                        else
                        {
                            warnings?.Invoke($"User \'{key.keyOwner}\': Public key error ({key.resultCode}): {key.message}");
                            enterprise.UserPublicKeyCache[key.keyOwner] = null;
                        }
                    }
                }
            }

            foreach (var email in publicKeys.Keys.ToArray())
            {
                if (enterprise.UserPublicKeyCache.TryGetValue(email, out var pk))
                {
                    publicKeys[email] = pk;
                }
            }
        }

        public static async Task PopulateTeamKeys(this EnterpriseData enterprise, IDictionary<string, byte[]> teamKeys, Action<string> warnings = null)
        {
            var toLoad = new HashSet<string>();
            foreach (var teamUid in teamKeys.Keys.ToArray())
            {
                if (enterprise.TryGetTeam(teamUid, out var team))
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
                var teamKeyRs = await enterprise.Auth.ExecuteAuthCommand<TeamGetKeysCommand, TeamGetKeysResponse>(teamKeyRq);
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
                                        key = CryptoUtils.DecryptAesV1(tk.key.Base64UrlDecode(), enterprise.Auth.AuthContext.DataKey);
                                        break;
                                    case 2:
                                        key = CryptoUtils.DecryptRsa(tk.key.Base64UrlDecode(), enterprise.Auth.AuthContext.PrivateKey);
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

                        if (enterprise.TryGetTeam(tk.teamUid, out var team))
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
