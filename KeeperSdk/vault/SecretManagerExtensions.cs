using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Records;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AuthProto = Authentication;
using Authentication;
using EnterpriseProto = Enterprise;

#if NETSTANDARD2_0_OR_GREATER
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
#endif

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline : ISecretManager
    {
        /// <inheritdoc/>
        public async Task<SecretsManagerApplication> GetSecretManagerApplication(string recordUid, bool force = false)
        {
            if (!TryGetKeeperRecord(recordUid, out var r))
            {
                return null;
            }
            var ar = r as ApplicationRecord;
            if (ar == null)
            {
                return null;
            }

            if (!force && ar is SecretsManagerApplication ksma)
            {
                return ksma;
            }

            var applicationUid = r.Uid.Base64UrlDecode();
            var rq = new AuthProto.GetAppInfoRequest();
            rq.AppRecordUid.Add(ByteString.CopyFrom(applicationUid));

            var rs = await Auth.ExecuteAuthRest<AuthProto.GetAppInfoRequest, AuthProto.GetAppInfoResponse>("vault/get_app_info", rq);
            var appInfo = rs.AppInfo.FirstOrDefault(x => x.AppRecordUid.SequenceEqual(applicationUid));
            if (appInfo == null)
            {
                return null;
            }
            var application = new SecretsManagerApplication
            {
                Uid = ar.Uid,
                Revision = ar.Revision,
                ClientModified = ar.ClientModified,
                Title = ar.Title,
                Type = ar.Type,
                Version = ar.Version,
                Owner = ar.Owner,
                Shared = ar.Shared,
                RecordKey = ar.RecordKey,
                IsExternalShare = appInfo.IsExternalShare,
                Devices = appInfo.Clients.Select(x => new SecretsManagerDevice
                {
                    Name = x.Id,
                    DeviceId = x.ClientId.ToByteArray().Base64UrlEncode(),
                    CreatedOn = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.CreatedOn),
                    FirstAccess = x.FirstAccess > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.FirstAccess) : (DateTimeOffset?) null,
                    LastAccess = x.LastAccess > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.LastAccess) : (DateTimeOffset?) null,
                    LockIp = x.LockIp,
                    IpAddress = x.IpAddress,
                    PublicKey = x.PublicKey.ToByteArray(),
                    FirstAccessExpireOn = x.FirstAccessExpireOn > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.FirstAccessExpireOn) : (DateTimeOffset?) null,
                    AccessExpireOn = x.AccessExpireOn > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.AccessExpireOn) : (DateTimeOffset?) null,
                }).ToArray(),
                Shares = appInfo.Shares
                .Where(x =>
                {
                    var uid = x.SecretUid.ToByteArray().Base64UrlEncode();
                    if (x.ShareType == AuthProto.ApplicationShareType.ShareTypeRecord)
                    {
                        return TryGetKeeperRecord(uid, out _);
                    }
                    else
                    {
                        return TryGetSharedFolder(uid, out _);
                    }
                })
                .Select(x => new SecretManagerShare
                {
                    SecretUid = x.SecretUid.ToByteArray().Base64UrlEncode(),
                    SecretType = (SecretManagerSecretType) x.ShareType,
                    Editable = x.Editable,
                    CreatedOn = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.CreatedOn)
                }).ToArray()
            };

            _keeperRecords.TryAdd(application.Uid, application);

            return application;
        }

        /// <inheritdoc/>
        public async Task<ApplicationRecord> CreateSecretManagerApplication(string title)
        {
            if (string.IsNullOrEmpty(title))
            {
                throw new KeeperInvalidParameter("CreateSecretManagerApplication", "title", "", "Application Title cannot be empty");
            }
            var data = new RecordApplicationData
            {
                Title = title,
                Type = "app"
            };
            var appUid = CryptoUtils.GenerateUid();
            var appKey = CryptoUtils.GenerateEncryptionKey();
            var dataBytes = JsonUtils.DumpJson(data);
            var rq = new ApplicationAddRequest
            {
                AppUid = ByteString.CopyFrom(appUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(appKey, Auth.AuthContext.DataKey)),
                Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(dataBytes, appKey)),
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            await Auth.ExecuteAuthRest("vault/application_add", rq);
            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
            if (TryGetKeeperRecord(appUid, out var r))
            {
                return r as ApplicationRecord;
            }
            return null;
        }

        /// <inheritdoc/>
        public async Task DeleteSecretManagerApplication(string applicationId)
        {
            await this.DeleteVaultObjects(new[] { new RecordPath { RecordUid = applicationId } }, true);
        }


        /// <inheritdoc/>
        public async Task<SecretsManagerApplication> ShareToSecretManagerApplication(string applicationId, string sharedFolderOrRecordUid, bool editable)
        {
            if (!TryGetKeeperRecord(applicationId, out var record))
            {
                throw new KeeperInvalidParameter("ShareToSecretManagerApplication", "applicationId", applicationId, "Application not found");
            }
            var application = record as ApplicationRecord;
            if (application == null)
            {
                throw new KeeperInvalidParameter("ShareToSecretManagerApplication", "applicationId", applicationId, "Application not found");
            }

            var isRecord = false;
            byte[] secretKey;
            if (TryGetSharedFolder(sharedFolderOrRecordUid, out var sf))
            {
                secretKey = sf.SharedFolderKey;
            }
            else if (TryGetKeeperRecord(sharedFolderOrRecordUid, out var r))
            {
                if (r is PasswordRecord || r is TypedRecord)
                {
                    isRecord = true;
                    secretKey = r.RecordKey;
                }
                else
                {
                    throw new KeeperInvalidParameter("ShareToSecretManagerApplication", "sharedFolderOrRecordUid", sharedFolderOrRecordUid, "Invalid record type");
                }
            }
            else
            {
                throw new KeeperInvalidParameter("ShareToSecretManagerApplication", "sharedFolderOrRecordUid", sharedFolderOrRecordUid, "Shared folder or Record do not exist");
            }
            var addRq = new AuthProto.AppShareAdd
            {
                SecretUid = ByteString.CopyFrom(sharedFolderOrRecordUid.Base64UrlDecode()),
                ShareType = isRecord ? AuthProto.ApplicationShareType.ShareTypeRecord : AuthProto.ApplicationShareType.ShareTypeFolder,
                EncryptedSecretKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(secretKey, application.RecordKey)),
                Editable = editable,
            };
            var rq = new AuthProto.AddAppSharesRequest
            {
                AppRecordUid = ByteString.CopyFrom(application.Uid.Base64UrlDecode())
            };
            rq.Shares.Add(addRq);
            await Auth.ExecuteAuthRest("vault/app_share_add", rq);
            return await GetSecretManagerApplication(application.Uid, true);
        }

        /// <inheritdoc/>
        public async Task<SecretsManagerApplication> UnshareFromSecretManagerApplication(string applicationId, string sharedFolderOrRecordUid)
        {
            if (!TryGetKeeperRecord(applicationId, out var record))
            {
                throw new KeeperInvalidParameter("UnshareFromSecretManagerApplication", "applicationId", applicationId, "Application not found");
            }
            var application = record as ApplicationRecord;
            if (application == null)
            {
                throw new KeeperInvalidParameter("UnshareFromSecretManagerApplication", "applicationId", applicationId, "Application not found");
            }

            var rq = new AuthProto.RemoveAppSharesRequest
            {
                AppRecordUid = ByteString.CopyFrom(application.Uid.Base64UrlDecode())
            };
            var uidBytes = sharedFolderOrRecordUid.Base64UrlDecode();
            if (uidBytes.Length > 0)
            {
                rq.Shares.Add(ByteString.CopyFrom(uidBytes));
            }

            await Auth.ExecuteAuthRest("vault/app_share_remove", rq);

            return await GetSecretManagerApplication(application.Uid, true);
        }


        /// <inheritdoc/>
        public async Task<Tuple<SecretsManagerDevice, string>> AddSecretManagerClient(
            string applicationId, bool? unlockIp = null, int? firstAccessExpireInMinutes = null,
            int? accessExpiresInMinutes = null, string name = null)
        {
            if (!TryGetKeeperRecord(applicationId, out var record))
            {
                throw new KeeperInvalidParameter("AddSecretManagerClient", "applicationId", applicationId, "Application not found");
            }
            var application = record as ApplicationRecord;
            if (application == null)
            {
                throw new KeeperInvalidParameter("AddSecretManagerClient", "applicationId", applicationId, "Application not found");
            }

            var clientKey = CryptoUtils.GenerateEncryptionKey();
            var hash = new HMACSHA512(clientKey);
            var clientId = hash.ComputeHash(Encoding.UTF8.GetBytes("KEEPER_SECRETS_MANAGER_CLIENT_ID"));

            var encryptedAppKey = CryptoUtils.EncryptAesV2(application.RecordKey, clientKey);

            var rq = new AuthProto.AddAppClientRequest
            {
                AppRecordUid = ByteString.CopyFrom(application.Uid.Base64UrlDecode()),
                EncryptedAppKey = ByteString.CopyFrom(encryptedAppKey),
                ClientId = ByteString.CopyFrom(clientId),
                LockIp = !unlockIp ?? true,
                FirstAccessExpireOn = DateTimeOffset.UtcNow.AddMinutes(
                    firstAccessExpireInMinutes ?? 60).ToUnixTimeMilliseconds(),
                AppClientType = EnterpriseProto.AppClientType.General,
            };
            if (accessExpiresInMinutes.HasValue)
            {
                rq.AccessExpireOn = DateTimeOffset.UtcNow.AddMinutes(accessExpiresInMinutes.Value).ToUnixTimeMilliseconds();
            }
            if (!string.IsNullOrEmpty(name))
            {
                rq.Id = name;
            }

            await Auth.ExecuteAuthRest("vault/app_client_add", rq);
            var appDetails = await GetSecretManagerApplication(application.Uid, true);
            var client = clientId.Base64UrlEncode();
            var device = appDetails.Devices.FirstOrDefault(x => x.DeviceId == client);
            if (device == null)
            {
                throw new Exception("Client Error");
            }

            var host = Auth.Endpoint.Server;
            switch (host)
            {
                case "keepersecurity.com":
                    host = "US";
                    break;
                case "keeperseurity.eu":
                    host = "EU";
                    break;
                case "keepersecurity.com.au":
                    host = "AU";
                    break;
                case "keepersecurity.jp":
                    host = "JP";
                    break;
                case "keepersecurity.ca":
                    host = "CA";
                    break;
                case "govcloud.keepersecurity.us":
                    host = "GOV";
                    break;
            }
            return Tuple.Create(device, $"{host}:{clientKey.Base64UrlEncode()}");
        }

        private const string ClientIdHashTag = "KEEPER_SECRETS_MANAGER_CLIENT_ID"; // Tag for hashing the client key to client id
        private const string KsmClientVersion = "mn16.6.4";

        [DataContract]
        internal class KsmPayload
        {
            [DataMember(Name = "clientVersion", EmitDefaultValue = false)]
            public string ClientVersion { get; set; }
            [DataMember(Name = "clientId", EmitDefaultValue = false)]
            public string ClientId { get; set; }
            [DataMember(Name = "publicKey", EmitDefaultValue = false)]
            public string PublicKey { get; set; }
            [DataMember(Name = "appKey", EmitDefaultValue = false)]
            public string AppKey { get; set; }
            [DataMember(Name = "requestedRecords", EmitDefaultValue = false)]
            public string[] RequestedRecords { get; set; }
        }

        [DataContract]
        internal class KsmResponseFile
        {
            [DataMember(Name = "fileUid", EmitDefaultValue = false)]
            public string FileUid { get; set; }
            [DataMember(Name = "fileKey", EmitDefaultValue = false)]
            public string FileKey { get; set; }
            [DataMember(Name = "data", EmitDefaultValue = false)]
            public string Data { get; set; }
            [DataMember(Name = "url", EmitDefaultValue = false)]
            public string Url { get; set; }
            [DataMember(Name = "thumbnailUrl", EmitDefaultValue = false)]
            public string ThumbnailUrl { get; set; }
        }

        [DataContract]
        internal class KsmResponseRecord
        {
            [DataMember(Name = "recordUid", EmitDefaultValue = false)]
            public string RecordUid { get; set; }
            [DataMember(Name = "recordKey", EmitDefaultValue = false)]
            public string RecordKey { get; set; }
            [DataMember(Name = "data", EmitDefaultValue = false)]
            public string Data { get; set; }
            [DataMember(Name = "revision", EmitDefaultValue = false)]
            public long Revision { get; set; }
            [DataMember(Name = "isEditable", EmitDefaultValue = false)]
            public bool IsEditable { get; set; }
            [DataMember(Name = "files", EmitDefaultValue = false)]
            public KsmResponseFile[] Files { get; set; }
            [DataMember(Name = "innerFolderUid", EmitDefaultValue = false)]
            public string InnerFolderUid { get; set; }
        }

        [DataContract]
        internal class KsmResponseFolder
        {
            [DataMember(Name = "folderUid", EmitDefaultValue = false)]
            public string FolderUid { get; set; }
            [DataMember(Name = "folderKey", EmitDefaultValue = false)]
            public string FolderKey { get; set; }
            [DataMember(Name = "data", EmitDefaultValue = false)]
            public string Data { get; set; }
            [DataMember(Name = "parent", EmitDefaultValue = false)]
            public string Parent { get; set; }
            [DataMember(Name = "records", EmitDefaultValue = false)]
            public KsmResponseRecord[] Records { get; set; }
        }

        [DataContract]
        internal class KsmResponse
        {
            [DataMember(Name = "appData", EmitDefaultValue = false)]
            public string AppData { get; set; }
            [DataMember(Name = "encryptedAppKey", EmitDefaultValue = false)]
            public string EncryptedAppKey { get; set; }
            [DataMember(Name = "appOwnerPublicKey", EmitDefaultValue = false)]
            public string AppOwnerPublicKey { get; set; }
            [DataMember(Name = "folders", EmitDefaultValue = false)]
            public KsmResponseFolder[] Folders { get; set; }
            [DataMember(Name = "records", EmitDefaultValue = false)]
            public KsmResponseRecord[] Records { get; set; }
            [DataMember(Name = "expiresOn", EmitDefaultValue = false)]
            public long ExpiresOn { get; set; }
            [DataMember(Name = "warnings", EmitDefaultValue = false)]
            public string[] Warnings { get; set; }
        }

        [DataContract]
        internal class KsmError
        {
            [DataMember(Name = "key_id", EmitDefaultValue = false)]
            public int KeyId { get; set; }
            [DataMember(Name = "error", EmitDefaultValue = false)]
            public string Error { get; set; }
        }

        [DataContract]
        public class SecretManagerConfiguration : ISecretManagerConfiguration
        {
            [DataMember(Name = "hostname", EmitDefaultValue = false)]
            public string Hostname { get; set; }
            [DataMember(Name = "clientId", EmitDefaultValue = false)]
            public string ClientId { get; set; }
            [DataMember(Name = "appKey", EmitDefaultValue = false)]
            public string AppKey { get; set; }
            [DataMember(Name = "privateKey", EmitDefaultValue = false)]
            public string PrivateKey { get; set; }
            [DataMember(Name = "serverPublicKeyId", EmitDefaultValue = false)]
            public string ServerPublicKeyId { get; set; }
            [DataMember(Name = "appOwnerPublicKey", EmitDefaultValue = false)]
            public string AppOwnerPublicKey { get; set; }
        }

        private EcPrivateKey LoadKsmPrivateKey(byte[] data)
        {
#if NET8_0_OR_GREATER
            var ecKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ecKey.ImportPkcs8PrivateKey(data, out _);
            return ecKey;
#elif NETSTANDARD2_0_OR_GREATER
            var privateKeyInfo = PrivateKeyInfo.GetInstance(data);
            var privateKeyStructure = ECPrivateKeyStructure.GetInstance(privateKeyInfo.ParsePrivateKey());
            var privateKeyValue = privateKeyStructure.GetKey();
            return new ECPrivateKeyParameters(privateKeyValue, CryptoUtils.EcParameters);
#endif
        }

        private byte[] UnloadKsmPrivateKey(EcPrivateKey privateKey)
        {
#if NET8_0_OR_GREATER
            return privateKey.ExportPkcs8PrivateKey();
#elif NETSTANDARD2_0_OR_GREATER
            var publicKey = CryptoUtils.GetEcPublicKey(privateKey);
            var publicKeyDer = new DerBitString(publicKey.Q.GetEncoded(false));
            var dp = privateKey.Parameters;
            var orderBitLength = dp.N.BitLength;
            var x962 = new X962Parameters(X9ObjectIdentifiers.Prime256v1);
            var ec = new ECPrivateKeyStructure(orderBitLength, privateKey.D, publicKeyDer, x962);
            var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, x962);
            var privateKeyInfo = new PrivateKeyInfo(algId, ec);
            return privateKeyInfo.GetDerEncoded();
#endif
        }

        private async Task<TRs> ExecuteKsm<TRq, TRs>(SecretManagerConfiguration configuration, string endpoint, TRq payload)
            where TRq : class
        {

            var payloadBytes = JsonUtils.DumpJson(payload);
#if DEBUG
            var rq = Encoding.UTF8.GetString(payloadBytes);
            Debug.WriteLine($"[KSM RQ]: {endpoint}: {rq}");
#endif
            var privateKeyDer = Convert.FromBase64String(configuration.PrivateKey);
            var privateKey = LoadKsmPrivateKey(privateKeyDer);

            var transmissionKey = CryptoUtils.GenerateEncryptionKey();
            var encryptedPayload = CryptoUtils.EncryptAesV2(payloadBytes, transmissionKey);

            var handler = new HttpClientHandler();
            using var httpClient = new HttpClient(handler, disposeHandler: true);
            httpClient.Timeout = TimeSpan.FromMinutes(5);
            if (Auth.Endpoint.WebProxy != null)
            {
                handler.Proxy = Auth.Endpoint.WebProxy;
            }

            var attempt = 0;
            var keyId = Auth.Endpoint.ServerKeyId;
            if (!string.IsNullOrEmpty(configuration.ServerPublicKeyId))
            {
                if (int.TryParse(configuration.ServerPublicKeyId, out keyId))
                {
                }
            }
            if (!KeeperSettings.KeeperEcPublicKeys.ContainsKey(keyId))
            {
                keyId = 7;
            }
            var url = $"https://{configuration.Hostname}/api/rest/sm/v1/{endpoint}";

            while (attempt < 2)
            {
                attempt++;
                var encTransmissionKey = Auth.Endpoint.EncryptWithKeeperKey(transmissionKey, keyId);
                byte[] signature;
#if NET8_0_OR_GREATER
                byte[] hash;
                using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    hasher.AppendData(encTransmissionKey);
                    hasher.AppendData(encryptedPayload);
                    hash = hasher.GetHashAndReset();
                }

                var parameters = privateKey.ExportParameters(includePrivateParameters: true);
                using (var signer = ECDsa.Create(parameters))
                {
                    signature = signer.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
                }
#elif NETSTANDARD2_0_OR_GREATER
                var signatureBase = encTransmissionKey.Concat(encryptedPayload).ToArray();
                var signer = SignerUtilities.GetSigner("SHA256withECDSA");

                signer.Init(true, privateKey);
                signer.BlockUpdate(signatureBase, 0, signatureBase.Length);
                signature = signer.GenerateSignature();
#endif
                var request = new HttpRequestMessage(HttpMethod.Post, new Uri(url));
                request.Headers.Authorization = new AuthenticationHeaderValue("Signature", Convert.ToBase64String(signature));
                request.Headers.Add("User-Agent", $"KSM.Net/{KsmClientVersion}");
                request.Headers.Add("PublicKeyId", keyId.ToString());
                request.Headers.Add("Signature", Convert.ToBase64String(signature));
                request.Headers.Add("TransmissionKey", Convert.ToBase64String(encTransmissionKey));
                request.Content = new ByteArrayContent(encryptedPayload);

                var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);
                var contentTypes = Array.Empty<string>();
                if (response.Content.Headers.TryGetValues("Content-Type", out var values))
                {
                    contentTypes = values.ToArray();
                }
                if (response.IsSuccessStatusCode)
                {
                    configuration.ServerPublicKeyId = keyId.ToString();
                    if (contentTypes.Any(x => x.StartsWith("application/octet-stream", StringComparison.InvariantCultureIgnoreCase)))
                    {
                        var data = await response.Content.ReadAsByteArrayAsync();
                        var decryptedRs = CryptoUtils.DecryptAesV2(data, transmissionKey);
#if DEBUG
                        var rs = Encoding.UTF8.GetString(decryptedRs);
                        Debug.WriteLine($"[KSM RS]: {endpoint}: {rs}");
#endif
                        return JsonUtils.ParseJson<TRs>(decryptedRs);
                    }
                    return default;
                }
                if (contentTypes.Any(x => x.StartsWith("application/octet-stream", StringComparison.InvariantCultureIgnoreCase)))
                {
                    var data = await response.Content.ReadAsByteArrayAsync();
#if DEBUG
                    var rs = Encoding.UTF8.GetString(data);
                    Debug.WriteLine($"[KSM Error RS]: {endpoint}: {rs}");
#endif
                    var errorRs = JsonUtils.ParseJson<KsmError>(data);
                    if (errorRs.Error == "key")
                    {
                        keyId = errorRs.KeyId;
                        continue;
                    }
                    throw new KeeperApiException("ksm_error", errorRs.Error);
                }
                throw new Exception("KSM API Http error: " + response.StatusCode);
            }
            throw new Exception("KSM API error");
        }

        /// <inheritdoc/>
        public async Task<ISecretManagerConfiguration> GetConfiguration(string oneTimeToken)
        {
            var tokenParts = oneTimeToken.Split(':');
            string host;
            string clientKey;
            if (tokenParts.Length == 1)
            {
                host = Auth.Endpoint.Server;
                clientKey = oneTimeToken;
            }
            else
            {
                switch (tokenParts[0].ToUpper())
                {
                    case "US":
                        host = "keepersecurity.com";
                        break;
                    case "EU":
                        host = "keepersecurity.eu";
                        break;
                    case "AU":
                        host = "keepersecurity.com.au";
                        break;
                    case "GOV":
                        host = "govcloud.keepersecurity.us";
                        break;
                    case "JP":
                        host = "keepersecurity.jp";
                        break;
                    case "CA":
                        host = "keepersecurity.ca";
                        break;
                    default:
                        host = Auth.Endpoint.Server;
                        break;
                }
                clientKey = tokenParts[1];
            }

            var clientKeyBytes = clientKey.Base64UrlDecode();
            var hmac = new HMACSHA512(clientKeyBytes);
            var clientKeyHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(ClientIdHashTag));
            var clientId = Convert.ToBase64String(clientKeyHash);

            CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
            var privateKeyBytes = UnloadKsmPrivateKey(privateKey);

            var configuration = new SecretManagerConfiguration
            {
                Hostname = host,
                ClientId = clientId,
                PrivateKey = Convert.ToBase64String(privateKeyBytes),
                ServerPublicKeyId = Auth.Endpoint.ServerKeyId.ToString(),
            };

            var ksmPayload = new KsmPayload
            {
                ClientVersion = KsmClientVersion,
                ClientId = clientId,
                PublicKey = CryptoUtils.UnloadEcPublicKey(publicKey).Base64UrlEncode(),
                RequestedRecords = new[] { "NON-EXISTING-RECORD-UID" },
            };

            var rs = await ExecuteKsm<KsmPayload, KsmResponse>(configuration, "get_secret", ksmPayload);
            if (!string.IsNullOrEmpty(rs.EncryptedAppKey))
            {
                configuration.AppKey = Convert.ToBase64String(CryptoUtils.DecryptAesV2(rs.EncryptedAppKey.Base64UrlDecode(), clientKeyBytes));
                ksmPayload.PublicKey = null;
                if (!string.IsNullOrEmpty(rs.AppOwnerPublicKey))
                {
                    configuration.AppOwnerPublicKey = rs.AppOwnerPublicKey;
                }
                _ = await ExecuteKsm<KsmPayload, KsmResponse>(configuration, "get_secret", ksmPayload);
            }

            return configuration;
        }

        /// <inheritdoc/>
        public async Task DeleteSecretManagerClient(string applicationId, string deviceId)
        {
            if (!TryGetKeeperRecord(applicationId, out var record))
            {
                throw new KeeperInvalidParameter("RemoveSecretManagerClient", "applicationId", applicationId, "Application not found");
            }
            var application = record as ApplicationRecord;
            if (application == null)
            {
                throw new KeeperInvalidParameter("RemoveSecretManagerClient", "applicationId", applicationId, "Application not found");
            }

            var rq = new AuthProto.RemoveAppClientsRequest
            {
                AppRecordUid = ByteString.CopyFrom(application.Uid.Base64UrlDecode()),
            };
            var clientBytes = deviceId.Base64UrlDecode();
            if (clientBytes.Length > 0)
            {
                rq.Clients.Add(ByteString.CopyFrom(clientBytes));
            }

            await Auth.ExecuteAuthRest("vault/app_client_remove", rq);
            await GetSecretManagerApplication(application.Uid, true);
        }

        public async Task ShareSecretsManagerApplicationWithUser(
            string applicationId, string userUid, bool unshare, SharedFolderOptions sharedFolderOptions = null, DateTimeOffset expiration = default)
        {
            if (!TryGetKeeperRecord(applicationId, out var record))
            {
                throw new KeeperInvalidParameter("ShareSecretsManagerApplicationWithUser", "applicationId", applicationId, "Application not found");
            }
            var application = record as ApplicationRecord;
            if (application == null)
            {
                throw new KeeperInvalidParameter("ShareSecretsManagerApplicationWithUser", "applicationId", applicationId, "Application not found");
            }

            var appInfoResponse = await GetAppInfo(application.Uid);
            var appInfo = appInfoResponse.FirstOrDefault(x => x.AppRecordUid.ToByteArray().SequenceEqual(application.Uid.Base64UrlDecode()));

            var shareFolderAction = unshare ? REMOVE : GRANT;
            var shareRecordAction = unshare ? REVOKE : GRANT;

            var sharedFolderPermissions = new SharedFolderOptions();
            var isAdmin = Auth.AuthContext.IsEnterpriseAdmin;
            sharedFolderPermissions.CanEdit = isAdmin && (sharedFolderOptions?.CanEdit ?? !unshare);
            sharedFolderPermissions.CanShare = isAdmin && (sharedFolderOptions?.CanShare ?? !unshare);
            sharedFolderPermissions.ManageRecords = isAdmin && (sharedFolderOptions?.ManageRecords ?? !unshare);
            sharedFolderPermissions.ManageUsers = isAdmin && (sharedFolderOptions?.ManageUsers ?? !unshare);

            var sharedRecordPermissions = new SharedFolderRecordOptions();
            sharedRecordPermissions.CanEdit = isAdmin && (sharedFolderOptions?.CanEdit ?? !unshare);
            sharedRecordPermissions.CanShare = isAdmin && (sharedFolderOptions?.CanShare ?? !unshare);
            if( !unshare && expiration != default)
            {
                sharedRecordPermissions.Expiration = expiration;
            }

            await ShareRecordWithUser(application.Uid, userUid, sharedRecordPermissions);

            var sharedFolderShares = appInfo.Shares.Where(x => x.ShareType == ApplicationShareType.ShareTypeFolder)
                .Select(x => x.SecretUid).ToArray();
            if (sharedFolderShares.Length > 0)
            {
                foreach (var sharedFolderUid in sharedFolderShares)
                {
                    string sharedFolderUidString = sharedFolderUid.ToByteArray().Base64UrlEncode();
                    if (unshare)
                    {
                        await RemoveUserFromSharedFolder(sharedFolderUidString, userUid, UserType.User);
                    }
                    else
                    {
                        var sharedfolderUserOptions = new SharedFolderUserOptions();
                        sharedfolderUserOptions.ManageUsers = sharedFolderPermissions.ManageUsers;
                        sharedfolderUserOptions.ManageRecords = sharedFolderPermissions.ManageRecords;
                        if (expiration != default)
                        {
                            sharedfolderUserOptions.Expiration = expiration;
                        }
                        await PutUserToSharedFolder(sharedFolderUidString, userUid, UserType.User, sharedfolderUserOptions);
                    }
                }
            }

            var sharedRecordShares = appInfo.Shares.Where(x => x.ShareType == ApplicationShareType.ShareTypeRecord)
                .Select(x => x.SecretUid).ToArray();
            if (sharedRecordShares.Length > 0)
            {
                foreach (var sharedRecordUid in sharedRecordShares)
                {
                    string sharedRecordUidString = sharedRecordUid.ToByteArray().Base64UrlEncode();
                    if (unshare)
                    {
                        await RevokeShareFromUser(sharedRecordUidString, userUid);
                    }
                    else
                    {
                        await ShareRecordWithUser(sharedRecordUidString, userUid, sharedRecordPermissions);
                    }
                }
            }

            await SyncDown();
        }

        private async Task<System.Collections.Generic.IEnumerable<AppInfo>> GetAppInfo(string applicationId)
        {
            var rq = new GetAppInfoRequest
            {
                AppRecordUid = { ByteString.CopyFrom(applicationId.Base64UrlDecode()) }
            };

            var appInforResponse = await Auth.ExecuteAuthRest<AuthProto.GetAppInfoRequest, AuthProto.GetAppInfoResponse>("vault/get_app_info", rq);
            if (appInforResponse.AppInfo.Count == 0)
            {
                throw new KeeperInvalidParameter("GetAppInfo", "applicationId", applicationId, "Application not found");
            }
            return appInforResponse.AppInfo;
        }

        internal const string GRANT = "grant";
        internal const string REMOVE = "remove";
        internal const string REVOKE = "revoke";
    }
}
