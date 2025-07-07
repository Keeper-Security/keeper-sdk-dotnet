using System;
using KeeperSecurity.Authentication;
using Authentication;
using BreachWatch;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using System.Collections.Generic;
using Google.Protobuf;
using System.Linq;
using System.Security.Cryptography;

namespace KeeperSecurity.BreachWatch
{
    public static class BreachWatch
    {
        /// <summary>
        /// Gets the breach watch status.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <returns><c>True</c> if breach watch is enabled.</returns>
        public static bool IsBreachWatchEnabled(this IAuthentication auth)
        {
            return auth.AuthContext.License.AccountType == (int) AccountType.Enterprise;
        }

        private static KeeperEndpoint _endpoint;
        private static IAuthentication auth;
        public static byte[] DomainToken { get; private set; } = Array.Empty<byte>();
        public static byte[] EmailToken { get; private set; } = Array.Empty<byte>();
        public static byte[] PasswordToken { get; private set; } = Array.Empty<byte>();

        public static bool SendAuditEvents { get; set; } = false;

        public static async Task InitializeBreachWatch(IAuthentication auth)
        {
            var keeperEndpoint = auth.Endpoint;
            BreachWatch.auth = auth;
            _endpoint = new KeeperEndpoint(new Configuration.InMemoryConfigurationStorage(), keeperEndpoint.Server);

            // Initialize BreachWatch
            BreachWatchTokenResponse rs = await auth.ExecuteAuthRest<BreachWatchTokenRequest, BreachWatchTokenResponse>("breachwatch/initialize", null);

            if (rs != null)
            {
                byte[] breachWatchToken;
                byte[] encryptedToken;

                if (rs.ClientEncrypted)
                {
                    encryptedToken = rs.BreachWatchToken.ToByteArray();
                    breachWatchToken = CryptoUtils.DecryptAesV2(encryptedToken, auth.AuthContext.DataKey);
                }
                else
                {
                    breachWatchToken = rs.BreachWatchToken.ToByteArray();
                    encryptedToken = CryptoUtils.EncryptAesV2(breachWatchToken, auth.AuthContext.DataKey);

                    var saveRq = new BreachWatchTokenRequest { BreachWatchToken = Google.Protobuf.ByteString.CopyFrom(encryptedToken) };
                    await auth.ExecuteAuthRest<BreachWatchTokenRequest, BreachWatchTokenResponse>("breachwatch/save_token", saveRq);
                }

                var tokenRq = new BreachWatchTokenRequest
                {
                    BreachWatchToken = Google.Protobuf.ByteString.CopyFrom(breachWatchToken)
                };

                var tokenRs = await auth.ExecuteAuthRest<BreachWatchTokenRequest, AnonymizedTokenResponse>("breachwatch/anonymize_token", tokenRq);

                if (tokenRs != null)
                {
                    DomainToken = tokenRs.DomainToken.ToByteArray();
                    EmailToken = tokenRs.EmailToken.ToByteArray();
                    PasswordToken = tokenRs.PasswordToken.ToByteArray();
                }
            }
        }

        public static async Task DeleteEuids(IEnumerable<byte[]> euids)
        {
            const int chunkSize = 999;
            var euidList = new List<byte[]>(euids);

            for (int i = 0; i < euidList.Count; i += chunkSize)
            {
                var chunk = euidList.GetRange(i, Math.Min(chunkSize, euidList.Count - i));

                var rq = new BreachWatchStatusRequest
                {
                    AnonymizedToken = ByteString.CopyFrom(PasswordToken)
                };
                rq.RemovedEuid.AddRange(chunk.Select(ByteString.CopyFrom));

                await auth.ExecuteAuthRest<BreachWatchStatusRequest, BreachWatchStatusResponse>("breachwatch/status", rq);
            }
        }

        public static async Task<List<(string Password, HashStatus Status)>> ScanPasswords(
            IEnumerable<(string Password, byte[] Euid)> passwordEntries)
        {
            var results = new List<(string Password, HashStatus Status)>();
            var bwHashes = new Dictionary<ByteString, string>();
            var bwEuids = new Dictionary<ByteString, ByteString>();

            foreach (var (password, euid) in passwordEntries)
            {
                int score = PasswordUtils.PasswordScore(password);
                var hash = PasswordUtils.BreachWatchHash(password);

                if (score >= 40)
                {
                    bwHashes[hash] = password;
                    if (euid != null)
                        bwEuids[hash] = ByteString.CopyFrom(euid);
                }
                else
                {
                    results.Add((password, new HashStatus
                    {
                        Hash1 = hash,
                        BreachDetected = true
                    }));
                }
            }

            if (bwHashes.Count > 0)
            {
                Console.WriteLine($"Breachwatch: {bwHashes.Count} password(s) to scan");

                var hashList = bwHashes.Keys.ToList();
                for (int i = 0; i < hashList.Count; i += 500)
                {
                    var chunk = hashList.Skip(i).Take(500);

                    var rq = new BreachWatchStatusRequest
                    {
                        AnonymizedToken = ByteString.CopyFrom(PasswordToken)
                    };

                    foreach (var h in chunk)
                    {
                        var hc = new HashCheck { Hash1 = h };
                        if (bwEuids.TryGetValue(h, out var euid))
                            hc.Euid = euid;

                        rq.HashCheck.Add(hc);
                    }

                    var rs = await auth.ExecuteAuthRest("breachwatch/status", rq, typeof(BreachWatchStatusResponse))
                        as BreachWatchStatusResponse;

                    if (rs == null) throw new Exception("BreachWatch status response is null");

                    foreach (var status in rs.HashStatus)
                    {
                        if (bwHashes.TryGetValue(status.Hash1, out var pw))
                        {
                            results.Add((pw, status));
                        }
                    }
                }
            }

            return results;
        }
    }

    public static class PasswordUtils
    {
        public static int PasswordScore(string password)
        {
            // Basic zxcvbn-like scoring logic placeholder
            return password.Length * 5; // simplistic scoring
        }

        public static ByteString BreachWatchHash(string password)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return ByteString.CopyFrom(hash.Take(20).ToArray()); // Truncate to 20 bytes
        }
    }
}