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
using System.Net.Http;
using System.Threading;
using System.Text;
using Tokens;
using KeeperSecurity.Vault;

namespace KeeperSecurity.BreachWatch
{
    /// <summary>
    /// Exception thrown when BreachWatch operations fail.
    /// </summary>
    public class BreachWatchException : Exception
    {
        public BreachWatchException(string message) : base(message) { }
        public BreachWatchException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Manages ignored BreachWatch records and provides functionality to ignore records.
    /// </summary>
    public static class BreachWatchIgnore
    {
        /// <summary>
        /// Ignores a BreachWatch record by setting its status to BWStatus.Ignore.
        /// </summary>
        public static async Task IgnoreRecord(IAuthentication auth, VaultOnline vault, string recordUid)
        {
            if (string.IsNullOrEmpty(recordUid))
            {
                throw new ArgumentException("Record UID cannot be null or empty", nameof(recordUid));
            }

            if (auth == null)
            {
                throw new ArgumentNullException(nameof(auth));
            }

            if (vault == null)
            {
                throw new ArgumentNullException(nameof(vault));
            }

            if (!vault.TryLoadKeeperRecord(recordUid, out var record))
            {
                throw new BreachWatchException($"Record with UID '{recordUid}' not found");
            }

            var updateRequest = CreateIgnoreUpdateRequest(recordUid, record, BWStatus.Ignore);

            try
            {
                await auth.ExecuteAuthRest("breachwatch/update_record_data", updateRequest);
            }
            catch (Exception ex)
            {
                throw new BreachWatchException($"Failed to ignore record: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Checks if a specific record is currently ignored.
        /// </summary>
        public static bool IsRecordIgnored(VaultOnline vault, string recordUid)
        {
            if (vault == null || string.IsNullOrEmpty(recordUid))
            {
                return false;
            }

            var breachWatchRecords = vault.BreachWatchRecords();
            var bwRecord = breachWatchRecords.FirstOrDefault(x => x.RecordUid == recordUid);
            
            return bwRecord?.Status == BWStatus.Ignore;
        }

        private static global::BreachWatch.BreachWatchUpdateRequest CreateIgnoreUpdateRequest(
            string recordUid, 
            KeeperRecord record, 
            BWStatus status)
        {
            var breachWatchData = new BreachWatchData();
            
            // For ignore functionality, we need to include at least one password entry
            // even if we're just setting the ignore status
            var password = record.ExtractPassword();
            var passwordInfo = new BWPassword
            {
                Value = password ?? "",
                Status = status,
                Resolved = 0
            };
            breachWatchData.Passwords.Add(passwordInfo);

            var dataBytes = breachWatchData.ToByteArray();
            var encryptedData = CryptoUtils.EncryptAesV2(dataBytes, record.RecordKey);

            var recordRequest = new global::BreachWatch.BreachWatchRecordRequest
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                EncryptedData = ByteString.CopyFrom(encryptedData),
                BreachWatchInfoType = global::BreachWatch.BreachWatchInfoType.Record,
                UpdateUserWhoScanned = true
            };

            var updateRequest = new global::BreachWatch.BreachWatchUpdateRequest();
            updateRequest.BreachWatchRecordRequest.Add(recordRequest);

            return updateRequest;
        }
    }

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
        public static byte[] PasswordToken { get; private set; } = Array.Empty<byte>();

        private const int MinimumPasswordScore = 40;
        private const int HashBatchSize = 500;
        private const int EuidBatchSize = 999;

        public static async Task InitializeBreachWatch(IAuthentication auth)
        {
            var keeperEndpoint = auth.Endpoint;
            BreachWatch.auth = auth;
            _endpoint = new KeeperEndpoint(new Configuration.InMemoryConfigurationStorage(), keeperEndpoint.Server);

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
                    BreachWatchToken = ByteString.CopyFrom(breachWatchToken)
                };

                var tokenRs = await auth.ExecuteAuthRest<BreachWatchTokenRequest, AnonymizedTokenResponse>("breachwatch/anonymize_token", tokenRq);

                if (tokenRs != null)
                {
                    PasswordToken = tokenRs.PasswordToken.ToByteArray();
                }
            }
        }

        /// <summary>
        /// Re-initializes BreachWatch tokens. Use this if you encounter "Invalid Payload" errors.
        /// </summary>
        public static async Task ReInitializeBreachWatch(IAuthentication auth)
        {
            PasswordToken = Array.Empty<byte>();
            await InitializeBreachWatch(auth);
        }

        private static async Task<BreachWatchStatusResponse> ExecuteBreachWatchStatus(BreachWatchStatusRequest rq)
        {
            rq.AnonymizedToken = ByteString.CopyFrom(PasswordToken);
            var apiRequestPayload = new ApiRequestPayload
            {
                Payload = rq.ToByteString()
            };
            var responseBytes = await _endpoint.ExecuteRest("breachwatch/status", apiRequestPayload);
            var rs = BreachWatchStatusResponse.Parser.ParseFrom(responseBytes);
            return rs;
        }

        public static async Task DeleteEuids(IEnumerable<byte[]> euids)
        {
            var euidList = new List<byte[]>(euids);
            for (int i = 0; i < euidList.Count; i += EuidBatchSize)
            {
                var chunk = euidList.GetRange(i, Math.Min(EuidBatchSize, euidList.Count - i));

                var rq = new BreachWatchStatusRequest
                {
                    AnonymizedToken = ByteString.CopyFrom(PasswordToken)
                };
                rq.RemovedEuid.AddRange(chunk.Select(ByteString.CopyFrom));

                await ExecuteBreachWatchStatus(rq);
            }
        }

        public static async Task<List<(string Password, HashStatus Status)>> ScanPasswordsAsync(
            IEnumerable<(string Password, byte[] Euid)> passwordEntries,
            CancellationToken cancellationToken = default)
        {
            if (PasswordToken == null || PasswordToken.Length == 0)
            {
                throw new BreachWatchException("BreachWatch not properly initialized. Password token is missing.");
            }
            if (passwordEntries == null)
            {
                throw new ArgumentNullException(nameof(passwordEntries));
            }
            try
            {
                var results = new Dictionary<string, HashStatus>(); 
                var bwHashes = new Dictionary<ByteString, string>();

                foreach (var (password, euid) in passwordEntries)
                {
                    if (string.IsNullOrEmpty(password)) continue;

                    int score = PasswordUtils.PasswordScore(password);
                    var bwHash = PasswordUtils.BreachWatchHash(password);

                    if (bwHash == null || bwHash.IsEmpty)
                    {
                        throw new BreachWatchException($"Failed to generate hash for password");
                    }

                    if (score >= MinimumPasswordScore)
                    {
                        bwHashes[bwHash] = password;
                    }
                    else
                    {
                        var status = new HashStatus
                        {
                            Hash1 = bwHash,
                            BreachDetected = true
                        };
                        results[password] = status;
                    }
                }

                if (bwHashes.Count > 0)
                {
                    var hashes = new List<HashCheck>();
                    foreach (var bwHash in bwHashes.Keys)
                    {
                        var check = new HashCheck { Hash1 = bwHash };
                        hashes.Add(check);
                    }

                    while (hashes.Count > 0)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        var chunk = hashes.Take(HashBatchSize).ToList(); 
                        hashes = hashes.Skip(HashBatchSize).ToList();

                        var rq = new BreachWatchStatusRequest()
                        {
                            AnonymizedToken = ByteString.CopyFrom(PasswordToken)
                        };
                        rq.HashCheck.AddRange(chunk);

                        try
                        {
                            var rs = await ExecuteBreachWatchStatus(rq);
                            
                            if (rs == null)
                            {
                                throw new BreachWatchException("BreachWatch status response is null");
                            }

                            foreach (var status in rs.HashStatus)
                            {
                                if (bwHashes.TryGetValue(status.Hash1, out var password))
                                {
                                    results[password] = status;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            throw new BreachWatchException(ex.Message);
                        }
                    }
                }

                var resultList = new List<(string Password, HashStatus Status)>();
                foreach (var kvp in results)
                {
                    resultList.Add((kvp.Key, kvp.Value));
                }
                return resultList;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new BreachWatchException("Request timeout during password scan", ex);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (HttpRequestException ex)
            {
                throw new BreachWatchException("Network error during password scan", ex);
            }
            catch (BreachWatchException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new BreachWatchException($"Unexpected error during password scan: {ex.Message}", ex);
            }
        }
    }

    public static class PasswordUtils
    {
        public static int PasswordScore(string password)
        {
            if (string.IsNullOrEmpty(password))
                return 0;

            int score = 0;
            int total = password.Length;
            int uppers = 0;
            int lowers = 0;
            int digits = 0;
            int symbols = 0;

            foreach (char c in password)
            {
                if (char.IsUpper(c))
                    uppers++;
                else if (char.IsLower(c))
                    lowers++;
                else if (char.IsDigit(c))
                    digits++;
                else
                    symbols++;
            }

            // Adjust digits + symbols count for non-alpha start/end
            int ds = digits + symbols;
            if (!char.IsLetter(password[0]))
                ds--;
            if (!char.IsLetter(password[password.Length - 1]))
                ds--;
            if (ds < 0)
                ds = 0;

            score += total * 4;
            if (uppers > 0)
                score += (total - uppers) * 2;
            if (lowers > 0)
                score += (total - lowers) * 2;
            if (digits > 0)
                score += digits * 4;
            score += symbols * 6;
            score += ds * 2;

            int variance = 0;
            if (uppers > 0) variance++;
            if (lowers > 0) variance++;
            if (digits > 0) variance++;
            if (symbols > 0) variance++;
            
            if (total >= 8 && variance >= 3)
                score += (variance + 1) * 2;

            if (digits + symbols == 0)
                score -= total;

            if (uppers + lowers + symbols == 0)
                score -= total;

            // Repeated characters penalty
            int repInc = 0;
            int repCount = 0;
            for (int i = 0; i < total; i++)
            {
                bool charExists = false;
                for (int j = 0; j < total; j++)
                {
                    if (i != j && password[i] == password[j])
                    {
                        charExists = true;
                        repInc += total / Math.Abs(i - j);
                    }
                }
                if (charExists)
                    repCount++;
            }

            if (repCount > 0)
            {
                int unqCount = total - repCount;
                repInc = unqCount == 0 ? repInc : (int)Math.Ceiling((double)repInc / unqCount);
                score -= repInc;
            }

            int consecCount = 0;
            consecCount += CountConsecutiveChars(password, char.IsUpper);
            consecCount += CountConsecutiveChars(password, char.IsLower);
            consecCount += CountConsecutiveChars(password, char.IsDigit);
            
            if (consecCount > 0)
                score -= 2 * consecCount;

            int seqCount = 0;
            seqCount += CountSequentialChars(password.ToLower(), char.IsLetter, 26);
            seqCount += CountSequentialChars(password, char.IsDigit, 10);
            seqCount += CountSequentialSymbols(password);

            if (seqCount > 0)
                score -= 3 * seqCount;

            return Math.Max(0, Math.Min(100, score));
        }

        private static int CountConsecutiveChars(string password, Func<char, bool> predicate)
        {
            int count = 0;
            int consecutive = 0;
            
            for (int i = 0; i < password.Length; i++)
            {
                if (predicate(password[i]))
                {
                    consecutive++;
                }
                else
                {
                    if (consecutive >= 2)
                        count += consecutive - 1;
                    consecutive = 0;
                }
            }
            
            if (consecutive >= 2)
                count += consecutive - 1;
                
            return count;
        }

        private static int CountSequentialChars(string password, Func<char, bool> predicate, int alphabetSize)
        {
            int count = 0;
            var chunks = GetChunks(password, predicate);
            
            foreach (var chunk in chunks)
            {
                if (chunk.Length >= 3)
                {
                    var offsets = GetCharOffsets(chunk, alphabetSize);
                    if (offsets.Count > 1)
                    {
                        int op = offsets[0];
                        for (int i = 1; i < offsets.Count; i++)
                        {
                            if (offsets[i] == op && op != 0)
                                count++;
                            else
                                op = offsets[i];
                        }
                    }
                }
            }
            
            return count;
        }

        private static int CountSequentialSymbols(string password)
        {
            var symbolLookup = new Dictionary<char, int>();
            string symbols = "!@#$%^&*()_+[]\\{}|;':\",./<>?";
            for (int i = 0; i < symbols.Length; i++)
            {
                symbolLookup[symbols[i]] = i;
            }

            int count = 0;
            var chunks = GetChunks(password, c => symbolLookup.ContainsKey(c));
            
            foreach (var chunk in chunks)
            {
                if (chunk.Length >= 3)
                {
                    var offsets = new List<int>();
                    for (int i = 0; i < chunk.Length - 1; i++)
                    {
                        if (symbolLookup.ContainsKey(chunk[i]) && symbolLookup.ContainsKey(chunk[i + 1]))
                        {
                            int offset = symbolLookup[chunk[i]] - symbolLookup[chunk[i + 1]];
                            offsets.Add(offset >= 0 ? offset : offset + symbols.Length);
                        }
                    }
                    
                    if (offsets.Count > 1)
                    {
                        int op = offsets[0];
                        for (int i = 1; i < offsets.Count; i++)
                        {
                            if (offsets[i] == op && op != 0)
                                count++;
                            else
                                op = offsets[i];
                        }
                    }
                }
            }
            
            return count;
        }

        private static List<string> GetChunks(string text, Func<char, bool> predicate)
        {
            var chunks = new List<string>();
            var current = new System.Text.StringBuilder();
            
            foreach (char c in text)
            {
                if (predicate(c))
                {
                    current.Append(c);
                }
                else
                {
                    if (current.Length > 0)
                    {
                        chunks.Add(current.ToString());
                        current.Clear();
                    }
                }
            }
            
            if (current.Length > 0)
                chunks.Add(current.ToString());
                
            return chunks;
        }

        private static List<int> GetCharOffsets(string chunk, int alphabetSize)
        {
            var offsets = new List<int>();
            
            for (int i = 0; i < chunk.Length - 1; i++)
            {
                int offset = chunk[i] - chunk[i + 1];
                offsets.Add(offset >= 0 ? offset : offset + alphabetSize);
            }
            
            return offsets;
        }

    public static ByteString BreachWatchHash(string password)
    {
        if (string.IsNullOrEmpty(password)) return ByteString.Empty;

        var msg = Encoding.UTF8.GetBytes($"password:{password}");
        using var hmac = new HMACSHA512(BreachWatch.PasswordToken);
        return ByteString.CopyFrom(hmac.ComputeHash(msg));
    }
    }
}