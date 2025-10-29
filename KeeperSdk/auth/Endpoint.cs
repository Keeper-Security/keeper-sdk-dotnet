using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Net;
using System.IO;
using Authentication;
using Google.Protobuf;
using System.Runtime.Serialization.Json;
using System.Diagnostics;
using System.Text;
using System.Linq;
using KeeperSecurity.Commands;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using System.Net.Http;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Describes Keeper server endpoint.
    /// </summary>
    public interface IKeeperEndpoint
    {
        /// <summary>
        /// Gets / sets Client version.
        /// </summary>
        string ClientVersion { get; set; }

        /// <summary>
        /// Gets / sets device name.
        /// </summary>
        string DeviceName { get; set; }

        /// <summary>
        /// Gets / sets user locale / interface language.
        /// </summary>
        string Locale { get; set; }

        /// <summary>
        /// Gets / sets Keeper server host name.
        /// </summary>
        string Server { get; set; }

        /// <exclude/>
        int ServerKeyId { get; }

        /// <summary>
        /// Gets / sets HTTP Proxy
        /// </summary>
        IWebProxy WebProxy { get; set; }

        /// <summary>
        /// Executes Protobuf request.
        /// </summary>
        /// <param name="endpoint">URL path for request.</param>
        /// <param name="payload">Protobuf Payload.</param>
        /// <returns>Task returning serialized response.</returns>
        Task<byte[]> ExecuteRest(string endpoint, ApiRequestPayload payload);

        /// <exclude/>
        string PushServer();

        /// <exclude/>
        byte[] EncryptWithKeeperKey(byte[] data, int keyId);
    }

    /// <summary>
    /// Endpoint extension methods.
    /// </summary>
    public static class KeeperEndpointExtensions
    {
        /// <summary>
        /// Executes Keeper JSON command. Generic version.
        /// </summary>
        /// <typeparam name="TC">Keeper Protobuf Request Type.</typeparam>
        /// <typeparam name="TR">Keeper Protobuf Response Type.</typeparam>
        /// <param name="endpoint">Keeper endpoint interface.</param>
        /// <param name="request">Keeper Protobuf Request.</param>
        /// <returns>Task returning Protobuf Response.</returns>
        public static async Task<TR> ExecuteV2Command<TC, TR>(this IKeeperEndpoint endpoint, TC request)
            where TC : KeeperApiCommand where TR : KeeperApiResponse
        {
            return (TR) await endpoint.ExecuteV2Command(request, typeof(TR));
        }

        /// <summary>
        /// Executes JSON request.
        /// </summary>
        /// <param name="endpoint">Keeper endpoint interface.</param>
        /// <param name="command">Keeper JSON command.</param>
        /// <param name="responseType">Keeper JSON response type.</param>
        /// <returns>Task returning Keeper JSON response.</returns>
        public static async Task<KeeperApiResponse> ExecuteV2Command(this IKeeperEndpoint endpoint, KeeperApiCommand command, Type responseType)
        {
            if (responseType == null)
            {
                responseType = typeof(KeeperApiResponse);
            }
            else if (!typeof(KeeperApiResponse).IsAssignableFrom(responseType))
            {
                responseType = typeof(KeeperApiResponse);
            }

            command.locale = endpoint.Locale;
            command.clientVersion = endpoint.ClientVersion;

            byte[] rq;
            using (var ms = new MemoryStream())
            {
                var cmdSerializer = new DataContractJsonSerializer(command.GetType(), JsonUtils.JsonSettings);
                cmdSerializer.WriteObject(ms, command);
                rq = ms.ToArray();
            }

            var apiPayload = new ApiRequestPayload()
            {
                Payload = ByteString.CopyFrom(rq)
            };
#if DEBUG
            Debug.WriteLine("Request: " + Encoding.UTF8.GetString(rq));
#endif
            var rs = await endpoint.ExecuteRest("vault/execute_v2_command", apiPayload);
#if DEBUG
            if (rs.Length < 10000)
            {
                Debug.WriteLine("Response: " + Encoding.UTF8.GetString(rs));
            }
            else
            {
                Debug.WriteLine($"Response: {rs.Length} bytes");
            }
#endif
            using (var ms = new MemoryStream(rs))
            {
                var rsSerializer = new DataContractJsonSerializer(responseType, JsonUtils.JsonSettings);
                return (KeeperApiResponse) rsSerializer.ReadObject(ms);
            }
        }
        public static ApiRequest PrepareApiRequest(this IKeeperEndpoint endpoint, IMessage request, byte[] transmissionKey, byte[] sessionToken = null, 
            int? payloadVersion = null)
        {
            var payload = new ApiRequestPayload
            {
                Payload = request.ToByteString()
            };
            if (payloadVersion.HasValue)
            {
                payload.ApiVersion = payloadVersion.Value;
            }

            if (sessionToken != null)
            {
                payload.EncryptedSessionToken = ByteString.CopyFrom(sessionToken);
            }

            var encPayload = CryptoUtils.EncryptAesV2(payload.ToByteArray(), transmissionKey);
            var encKey = endpoint.ServerKeyId <= 6
                ? CryptoUtils.EncryptRsa(transmissionKey, KeeperSettings.KeeperRsaPublicKeys[endpoint.ServerKeyId])
                : CryptoUtils.EncryptEc(transmissionKey, KeeperSettings.KeeperEcPublicKeys[endpoint.ServerKeyId]);
            return new ApiRequest()
            {
                EncryptedTransmissionKey = ByteString.CopyFrom(encKey),
                PublicKeyId = endpoint.ServerKeyId,
                Locale = endpoint.Locale,
                EncryptedPayload = ByteString.CopyFrom(encPayload)
            };
        }

    }

    /// <exclude/>
    public class KeeperEndpoint : IKeeperEndpoint
    {
        private const string DefaultDeviceName = ".NET Keeper API";
        private const string DefaultKeeperServer = "keepersecurity.com";
        private const string DefaultClientVersion = "c17.1.9";

        private readonly IConfigurationStorage _storage;
        private readonly HttpClient _httpClient;
        private readonly HttpClientHandler _httpMessageHandler;
        private string _clientVersion;

        static KeeperEndpoint()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
//            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        }

        public KeeperEndpoint(IConfigurationStorage storage, string keeperServer = null)
        {
            _httpMessageHandler = new HttpClientHandler();
            _httpClient = new HttpClient(_httpMessageHandler, disposeHandler: true);
            _httpClient.Timeout = TimeSpan.FromMinutes(5);
            ClientVersion = DefaultClientVersion;
            DeviceName = DefaultDeviceName;
            Locale = DefaultLocale();
            ServerKeyId = 7;

            _storage = storage;
            if (string.IsNullOrEmpty(keeperServer))
            {
                var config = storage.Get();
                keeperServer = config.LastServer;
            }

            Server = keeperServer ?? DefaultKeeperServer;
        }

        public string PushServer()
        {
            return $"push.services.{Server}";
        }

        public async Task<byte[]> ExecuteRest(string endpoint, ApiRequestPayload payload)
        {
            Uri uri;

            if (endpoint.StartsWith("https://"))
            {
                uri = new Uri(endpoint);
            }
            else
            {
                var builder = new UriBuilder(Server)
                {
                    Path = "/api/rest/",
                    Scheme = "https",
                    Port = 443
                };
                uri = new Uri(builder.Uri, endpoint);
            }

            var keyId = ServerKeyId;
            var transmissionKey = CryptoUtils.GenerateEncryptionKey();

            var attempt = 0;
            Exception lastKeeperError = null;
            while (attempt < 3)
            {
                attempt++;

                var encPayload = CryptoUtils.EncryptAesV2(payload.ToByteArray(), transmissionKey);
                var encKey = keyId <= 6
                    ? CryptoUtils.EncryptRsa(transmissionKey, KeeperSettings.KeeperRsaPublicKeys[keyId])
                    : CryptoUtils.EncryptEc(transmissionKey, KeeperSettings.KeeperEcPublicKeys[keyId]);

                var apiRequest = new ApiRequest()
                {
                    EncryptedTransmissionKey = ByteString.CopyFrom(encKey),
                    PublicKeyId = keyId,
                    Locale = Locale,
                    EncryptedPayload = ByteString.CopyFrom(encPayload)
                };

                var content = new ByteArrayContent(apiRequest.ToByteArray());
                content.Headers.Add("Content-Type", "application/octet-stream");
                // TODO timeout + read header 
                using var response = await _httpClient.PostAsync(uri, content);
                var contentTypes = Array.Empty<string>();
                if (response.Content.Headers.TryGetValues("Content-Type", out var values))
                {
                    contentTypes = values.ToArray();
                }

                if (response.IsSuccessStatusCode)
                {
                    if (contentTypes.Any(x =>
                            x.StartsWith("application/octet-stream", StringComparison.InvariantCultureIgnoreCase)))
                    {
                        SetConfigurationValid(keyId);
                        var data = await response.Content.ReadAsByteArrayAsync();
                        if (data != null && data.Length > 0)
                        {
                            return CryptoUtils.DecryptAesV2(data, transmissionKey);
                        }
                    }

                    return null;
                }

                if (response.StatusCode == HttpStatusCode.ProxyAuthenticationRequired)
                {
                    var proxyAuthenticate = Array.Empty<string>();
                    if (response.Headers.TryGetValues("Proxy-Authenticate", out var proxyValues))
                    {
                        proxyAuthenticate = proxyValues.ToArray();
                    }

                    throw new ProxyAuthenticationRequired(proxyAuthenticate);
                }

                if (contentTypes.Any(x =>
                        x.StartsWith("application/json", StringComparison.InvariantCultureIgnoreCase)))
                {
                    var jsonData = await response.Content.ReadAsByteArrayAsync();
#if DEBUG
                    Debug.WriteLine("Error Response: " + Encoding.UTF8.GetString(jsonData));
#endif
                    var keeperRs = JsonUtils.ParseJson<KeeperApiErrorResponse>(jsonData);
                    lastKeeperError = new KeeperApiException(keeperRs.Error, keeperRs.Message);
                    switch (keeperRs.Error)
                    {
                        case "key":
                            keyId = keeperRs.KeyId;
                            continue;

                        case "throttled":
                            if (!string.Equals("keep_alive", endpoint, StringComparison.InvariantCultureIgnoreCase)) {
#if DEBUG
                                Debug.WriteLine("\"throttled\" sleeping for 10 seconds");
#endif
                                await Task.Delay(TimeSpan.FromSeconds(10));
                                continue;
                            }
                            break;

                        case "region_redirect":
                            throw new KeeperRegionRedirect(keeperRs.RegionHost);

                        case "device_not_registered":
                            throw new KeeperInvalidDeviceToken(keeperRs.AdditionalInfo);

                        case "session_token":
                        case "auth_failed":
                            throw new KeeperAuthFailed(keeperRs.Message);

                        case "login_token_expired":
                            throw new KeeperCanceled(keeperRs.Error, keeperRs.Message);
                    }

                    throw lastKeeperError;
                }
                else if (contentTypes.Any(x => x.StartsWith("text/", StringComparison.InvariantCultureIgnoreCase)))
                {
                    var message = await response.Content.ReadAsStringAsync();
                    throw new KeeperApiException(response.StatusCode.ToString(), message);
                }

                throw new Exception("Keeper Api Http error: " + response.StatusCode);
            }

            throw lastKeeperError ?? new Exception("Keeper Api error");
        }

        private void SetConfigurationValid(int keyId)
        {
            if (keyId == ServerKeyId) return;
            var config = _storage.Get();
            ServerKeyId = keyId;
            var sc = config.Servers.Get(Server);
            var serverConfiguration = sc != null ? new ServerConfiguration(sc) : new ServerConfiguration(Server);
            serverConfiguration.ServerKeyId = ServerKeyId;
            config.Servers.Put(serverConfiguration);
            _storage.Put(config);
        }

        private string _server;

        public string Server
        {
            get => string.IsNullOrEmpty(_server) ? DefaultKeeperServer : _server;
            set
            {
                _server = string.IsNullOrEmpty(value) ? DefaultKeeperServer : value;
                var configuration = _storage.Get();
                var sc = configuration.Servers.Get(_server);
                if (sc == null) return;
                if (KeeperSettings.KeeperRsaPublicKeys.ContainsKey(sc.ServerKeyId) ||
                    KeeperSettings.KeeperEcPublicKeys.ContainsKey(sc.ServerKeyId))
                {
                    ServerKeyId = sc.ServerKeyId;
                }
                else
                {
                    ServerKeyId = 7;
                }
            }
        }

        public int ServerKeyId { get; private set; }
        private const string UserAgentHeader = "User-Agent";

        public string ClientVersion
        {
            get => _clientVersion;
            set
            {
                _clientVersion = value;
                if (_httpClient.DefaultRequestHeaders.Contains(UserAgentHeader))
                {
                    _httpClient.DefaultRequestHeaders.Remove(UserAgentHeader);
                }

                _httpClient.DefaultRequestHeaders.Add(UserAgentHeader, $"KeeperSDK.Net/{_clientVersion}");
            }
        }

        public string DeviceName { get; set; }
        public string Locale { get; set; }

        public IWebProxy WebProxy
        {
            get => _httpMessageHandler?.Proxy;
            set => _httpMessageHandler.Proxy = value;
        }

        /// <summary>
        /// Returns language supported by Keeper.
        /// </summary>
        /// <returns>locale in format xx_YY where xx - 2 character language code, YY - 2 character country code</returns>
        public static string DefaultLocale()
        {
            var culture = System.Globalization.CultureInfo.CurrentCulture;

            if (KeeperSettings.KeeperLanguages.TryGetValue(culture.Name, out var locale))
            {
                return locale;
            }

            return KeeperSettings.KeeperLanguages.TryGetValue(culture.TwoLetterISOLanguageName, out locale)
                ? locale
                : "en_US";
        }

        /// <exclude/>
        public byte[] EncryptWithKeeperKey(byte[] data, int keyId)
        {
            return keyId switch
            {
                >= 1 and <= 6 when KeeperSettings.KeeperRsaPublicKeys.TryGetValue(keyId, value: out var key) =>
                    CryptoUtils.EncryptRsa(data, key),
                >= 7 and <= 17 when KeeperSettings.KeeperEcPublicKeys.TryGetValue(keyId, out var publicKey) =>
                    CryptoUtils.EncryptEc(data, publicKey),
                _ => throw new KeeperInvalidParameter("Endpoint.EncryptWithKeeperKey", "keyId", keyId.ToString(),
                    "Server Key Id is invalid")
            };
        }
    }

    internal static class KeeperSettings
    {
        public static IEnumerable<string> ParseProxyAuthentication(string authentication)
        {
            if (!string.IsNullOrEmpty(authentication))
            {
                var pos = authentication.IndexOf(' ');
                if (pos > 0)
                {
                    var methods = authentication.Substring(0, pos).Trim();
                    if (!string.IsNullOrEmpty(methods))
                    {
                        return methods.Split(',').Select(x => x.Trim());
                    }
                }
            }

            return new[] {"Basic"};
        }


        internal static readonly IDictionary<int, RsaPublicKey> KeeperRsaPublicKeys;
        internal static readonly IDictionary<int, EcPublicKey> KeeperEcPublicKeys;

        static KeeperSettings()
        {
            var rsaList = new[]
            {
                new KeyValuePair<int, RsaPublicKey>(1, CryptoUtils.LoadRsaPublicKey(KeeperKey1.Base64UrlDecode())),
                new KeyValuePair<int, RsaPublicKey>(2, CryptoUtils.LoadRsaPublicKey(KeeperKey2.Base64UrlDecode())),
                new KeyValuePair<int, RsaPublicKey>(3, CryptoUtils.LoadRsaPublicKey(KeeperKey3.Base64UrlDecode())),
                new KeyValuePair<int, RsaPublicKey>(4, CryptoUtils.LoadRsaPublicKey(KeeperKey4.Base64UrlDecode())),
                new KeyValuePair<int, RsaPublicKey>(5, CryptoUtils.LoadRsaPublicKey(KeeperKey5.Base64UrlDecode())),
                new KeyValuePair<int, RsaPublicKey>(6, CryptoUtils.LoadRsaPublicKey(KeeperKey6.Base64UrlDecode()))
            };
            KeeperRsaPublicKeys = new ConcurrentDictionary<int, RsaPublicKey>(rsaList);

            var ecList = new[] 
            {
                new KeyValuePair<int, EcPublicKey>(7, CryptoUtils.LoadEcPublicKey(KeeperKey7.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(8, CryptoUtils.LoadEcPublicKey(KeeperKey8.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(9, CryptoUtils.LoadEcPublicKey(KeeperKey9.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(10, CryptoUtils.LoadEcPublicKey(KeeperKey10.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(11, CryptoUtils.LoadEcPublicKey(KeeperKey11.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(12, CryptoUtils.LoadEcPublicKey(KeeperKey12.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(13, CryptoUtils.LoadEcPublicKey(KeeperKey13.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(14, CryptoUtils.LoadEcPublicKey(KeeperKey14.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(15, CryptoUtils.LoadEcPublicKey(KeeperKey15.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(16, CryptoUtils.LoadEcPublicKey(KeeperKey16.Base64UrlDecode())),
                new KeyValuePair<int, EcPublicKey>(17, CryptoUtils.LoadEcPublicKey(KeeperKey17.Base64UrlDecode())),
            };
            KeeperEcPublicKeys = new ConcurrentDictionary<int, EcPublicKey>(ecList);
        }

        internal static readonly IDictionary<string, string> KeeperLanguages = new Dictionary<string, string>()
        {
            {"ar", "ar_AE"},
            {"de", "de_DE"},
            {"el", "el_GR"},
            {"en-GB", "en_GB"},
            {"en", "en_US"},
            {"es", "es_ES"},
            {"fr", "fr_FR"},
            {"he", "iw_IL"},
            {"it", "it_IT"},
            {"ja", "ja_JP"},
            {"ko", "ko_KR"},
            {"nl", "nl_NL"},
            {"pl", "pl_PL"},
            {"pt", "pt_PT"},
            {"pt-BR", "pt_BR"},
            {"ro", "ro_RO"},
            {"ru", "ru_RU"},
            {"sk", "sk_SK"},
            {"zh", "zh_CN"},
            {"zh-HK", "zh_HK"},
            {"zh-TW", "zh_TW"}
        };

        private const string KeeperKey1 = "MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH" +
            "OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn" +
            "j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb" +
            "_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V" +
            "xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB" +
            "6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB";

        private const string KeeperKey2 = "MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq" +
            "YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY" +
            "KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd" +
            "WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl" +
            "BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN" +
            "ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB";

        private const string KeeperKey3 = "MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI" +
            "hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi" +
            "rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS" +
            "HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N" +
            "Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE" +
            "AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB";

        private const string KeeperKey4 = "MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR" +
            "FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H" +
            "CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX" +
            "-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ" +
            "KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5" +
            "osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB";

        const string KeeperKey5 = "MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv" +
            "sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH" +
            "FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_" +
            "uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV" +
            "hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO" +
            "WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB";

        const string KeeperKey6 = "MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL" +
            "AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v" +
            "w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl" +
            "_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-" +
            "ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ" +
            "17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB";

        const string KeeperKey7  = "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM";
        const string KeeperKey8  = "BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ";
        const string KeeperKey9  = "BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g";
        const string KeeperKey10 = "BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg";
        const string KeeperKey11 = "BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk";
        const string KeeperKey12 = "BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY";
        const string KeeperKey13 = "BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI";
        const string KeeperKey14 = "BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE";
        const string KeeperKey15 = "BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8";
        const string KeeperKey16 = "BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c";
        const string KeeperKey17 = "BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU";

    }
}