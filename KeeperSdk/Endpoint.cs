//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Concurrent;
using System.Net;
using System.IO;
using Authentication;
using Google.Protobuf;
using System.Runtime.Serialization.Json;
using System.Diagnostics;
using System.Text;
using KeeperSecurity.Sdk.UI;
using System.Linq;
using System.Net.WebSockets;
using System.Threading;
using Push;

namespace KeeperSecurity.Sdk
{
    public interface IWebSocketChannel : IFanOut<WssClientResponse>
    {
        Task SendToWebSocket(byte[] payload, bool encrypted);
    }

    internal class WebSocketChannel : FanOut<WssClientResponse>, IWebSocketChannel
    {
        private ClientWebSocket _webSocket;

        public WebSocketChannel(ClientWebSocket webSocket, byte[] transmissionKey, CancellationToken token)
        {
            _webSocket = webSocket;
            var tk = transmissionKey;
            _ = Task.Run(async () =>
                {
                    try
                    {
                        var buffer = new byte[1024];
                        var segment = new ArraySegment<byte>(buffer);
                        while (_webSocket.State == WebSocketState.Open)
                        {
                            var rs = await _webSocket.ReceiveAsync(segment, token);
                            if (rs != null && rs.Count > 0)
                            {
                                var responseBytes = new byte[rs.Count];
                                Array.Copy(buffer, 0, responseBytes, 0, responseBytes.Length);
                                responseBytes = CryptoUtils.DecryptAesV2(responseBytes, tk);
                                var wssRs = WssClientResponse.Parser.ParseFrom(responseBytes);
#if DEBUG
                                Debug.WriteLine($"REST push notification: {wssRs}");
#endif
                                Push(wssRs);
                            }
                        }

                        if (_webSocket.State == WebSocketState.Open)
                        {
                            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "", token);
                        }
                        webSocket.Dispose();
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }

                    _webSocket = null;
                },
                token);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _webSocket?.Dispose();
        }

        public async Task SendToWebSocket(byte[] payload, bool encrypted)
        {
            if (_webSocket == null) return;
            if (_webSocket.State == WebSocketState.Open)
            {
                var buffer = new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload.Base64UrlEncode()));
                await  _webSocket.SendAsync(buffer, WebSocketMessageType.Text, true, CancellationToken.None);
            }
        }
    }

    public interface IKeeperEndpoint
    {
        string ClientVersion { get; set; }
        string DeviceName { get; set; }
        string Locale { get; set; }
        string Server { get; set; }
        int ServerKeyId { get; }

        Task<byte[]> ExecuteRest(string endpoint, ApiRequestPayload payload);
        Task<KeeperApiResponse> ExecuteV2Command(KeeperApiCommand command, Type responseType);
        Task<IWebSocketChannel> ConnectToPushServer(WssConnectionRequest connectionRequest, CancellationToken token);
        ApiRequest PrepareApiRequest(IMessage request, byte[] transmissionKey, byte[] sessionToken = null);
    }

    public static class KeeperEndpointUtils
    {
        public static async Task<TR> ExecuteV2Command<TC, TR>(this IKeeperEndpoint endpoint, TC command)
            where TC : KeeperApiCommand where TR : KeeperApiResponse
        {
            return (TR) await endpoint.ExecuteV2Command(command, typeof(TR));
        }
    }

    public class KeeperEndpoint : IKeeperEndpoint
    {
        private const string DefaultDeviceName = ".NET Keeper API";
        public static string DefaultKeeperServer = "keepersecurity.com";
        private const string DefaultClientVersion = "c15.0.0";

        static KeeperEndpoint()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
//            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        }

        public KeeperEndpoint(string server, IConfigCollection<IServerConfiguration> storage)
        {
            _storage = storage;
            ClientVersion = DefaultClientVersion;
            DeviceName = DefaultDeviceName;
            Locale = KeeperSettings.DefaultLocale();
            Server = server;
        }

        private string PushServer()
        {
            return "push.services.dev.keepersecurity.com";// + (Server ?? DefaultKeeperServer);
        }


        public ApiRequest PrepareApiRequest(IMessage request, byte[] transmissionKey, byte[] sessionToken = null)
        {
            if (transmissionKey == null)
            {
                transmissionKey = _transmissionKey;
            }

            var payload = new ApiRequestPayload
            {
                ApiVersion = 3,
                Payload = request.ToByteString()
            };
            if (sessionToken != null)
            {
                payload.EncryptedSessionToken = ByteString.CopyFrom(sessionToken);
            }
            var encPayload = CryptoUtils.EncryptAesV2(payload.ToByteArray(), transmissionKey);
            var encKey = CryptoUtils.EncryptRsa(transmissionKey, KeeperSettings.KeeperPublicKeys[ServerKeyId]);
            return new ApiRequest()
            {
                EncryptedTransmissionKey = ByteString.CopyFrom(encKey),
                PublicKeyId = ServerKeyId,
                Locale = Locale,
                EncryptedPayload = ByteString.CopyFrom(encPayload)
            };
        }

        public async Task<IWebSocketChannel> ConnectToPushServer(WssConnectionRequest connectionRequest, CancellationToken token)
        {
            var transmissionKey = CryptoUtils.GenerateEncryptionKey();
            var apiRequest = PrepareApiRequest(connectionRequest, transmissionKey);
            var builder = new UriBuilder
            {
                Scheme = "wss",
                Host = PushServer(),
                Path = "wss_open_connection/" + apiRequest.ToByteArray().Base64UrlEncode()
            };
            var ws = new ClientWebSocket();
            await ws.ConnectAsync(builder.Uri, token);

            return new WebSocketChannel(ws, transmissionKey, token);
        }

        public async Task<byte[]> ExecuteRest(string endpoint, ApiRequestPayload payload)
        {
            var builder = new UriBuilder(Server ?? DefaultKeeperServer)
            {
                Path = "/api/rest/",
                Scheme = "https",
                Port = 443
            };
            var uri = new Uri(builder.Uri, endpoint);

            var keyId = ServerKeyId;

            payload.ApiVersion = 3;
            var attempt = 0;
            while (attempt < 3)
            {
                attempt++;

                var request = (HttpWebRequest) WebRequest.Create(uri);
                if (WebProxy != null)
                {
                    request.Proxy = WebProxy;
                }

                request.UserAgent = "KeeperSDK.Net/" + ClientVersion;
                request.ContentType = "application/octet-stream";
                request.Method = "POST";


                var encPayload = CryptoUtils.EncryptAesV2(payload.ToByteArray(), _transmissionKey);
                var encKey = CryptoUtils.EncryptRsa(_transmissionKey, KeeperSettings.KeeperPublicKeys[keyId]);
                var apiRequest = new ApiRequest()
                {
                    EncryptedTransmissionKey = ByteString.CopyFrom(encKey),
                    PublicKeyId = keyId,
                    Locale = Locale,
                    EncryptedPayload = ByteString.CopyFrom(encPayload)
                };

                HttpWebResponse response;
                try
                {
                    using (var requestStream = request.GetRequestStream())
                    {
                        var p = apiRequest.ToByteArray();
                        await requestStream.WriteAsync(p, 0, p.Length);
                    }

                    response = (HttpWebResponse) request.GetResponse();
                }
                catch (WebException e)
                {
                    response = (HttpWebResponse) e.Response;
                    if (response == null) throw;

                    if (response.StatusCode == HttpStatusCode.ProxyAuthenticationRequired)
                    {
                        if (ProxyUi != null)
                        {
                            var authHeader = response.Headers.AllKeys
                                .FirstOrDefault(x =>
                                    string.Compare(x, "Proxy-Authenticate", StringComparison.OrdinalIgnoreCase) ==
                                    0);
                            var sysProxy = WebRequest.GetSystemWebProxy();
                            var directUri = sysProxy.GetProxy(uri);
                            WebProxy = await ProxyUi.GetHttpProxyCredentials(directUri, authHeader);
                        }

                        if (WebProxy != null)
                        {
                            continue;
                        }

                        throw;
                    }
                }

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    SetConfigurationValid(keyId);
                    if (response.ContentType == "application/octet-stream")
                    {
                        using (var ms = new MemoryStream())
                        using (var rss = response.GetResponseStream())
                        {
                            await rss.CopyToAsync(ms);
                            var bytes = ms.ToArray();
                            if (bytes.Length > 0)
                            {
                                bytes = CryptoUtils.DecryptAesV2(bytes, _transmissionKey);
                            }

                            return bytes;
                        }
                    }

                    return null;
                }

                if (response.ContentType == "application/json")
                {
                    using (var ms = new MemoryStream())
                    using (var rss = response.GetResponseStream())
                    {
                        await rss.CopyToAsync(ms);
                        await ms.FlushAsync();
#if DEBUG
                        var jsonData = ms.ToArray();
                        Debug.WriteLine("Error Response: " + Encoding.UTF8.GetString(jsonData));
#endif
                        ms.Seek(0, SeekOrigin.Begin);

                        var serializer = new DataContractJsonSerializer(typeof(KeeperApiErrorResponse));
                        var keeperRs = serializer.ReadObject(ms) as KeeperApiErrorResponse;
                        switch (keeperRs.Error)
                        {
                            case "key":
                                if (KeeperSettings.KeeperPublicKeys.ContainsKey(keeperRs.KeyId))
                                {
                                    keyId = keeperRs.KeyId;
                                    continue;
                                }

                                break;
                            case "region_redirect":
                                throw new KeeperRegionRedirect(keeperRs.RegionHost);

                            case "bad_request":
                                throw new KeeperInvalidDeviceToken(keeperRs.AdditionalInfo);

                            case "session_token":
                            case "auth_failed":
                                throw new KeeperAuthFailed();
                            
                            case "login_token_expired":
                                throw new KeeperCanceled();
                        }

                        throw new KeeperApiException(keeperRs.Error, keeperRs.Message);
                    }
                }

                throw new Exception("Keeper Api Http error: " + response.StatusCode);
            }

            throw new Exception("Keeper Api error");
        }

        public async Task<KeeperApiResponse> ExecuteV2Command(KeeperApiCommand command, Type responseType)
        {
            if (responseType == null)
            {
                responseType = typeof(KeeperApiResponse);
            }
            else if (!typeof(KeeperApiResponse).IsAssignableFrom(responseType))
            {
                responseType = typeof(KeeperApiResponse);
            }

            command.locale = Locale;
            command.clientVersion = ClientVersion;

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
            var rs = await ExecuteRest("vault/execute_v2_command", apiPayload);
#if DEBUG
            Debug.WriteLine("Response: " + Encoding.UTF8.GetString(rs));
#endif
            using (var ms = new MemoryStream(rs))
            {
                var rsSerializer = new DataContractJsonSerializer(responseType, JsonUtils.JsonSettings);
                return (KeeperApiResponse) rsSerializer.ReadObject(ms);
            }
        }

        private readonly byte[] _transmissionKey = CryptoUtils.GetRandomBytes(32);

        private readonly IConfigCollection<IServerConfiguration> _storage;

        private string _server;

        private void SetConfigurationValid(int keyId)
        {
            if (keyId != ServerKeyId)
            {
                ServerKeyId = keyId;
                if (_storage != null)
                {
                    var sc = _storage.Get(_server);
                    var configuration = sc != null ? new ServerConfiguration(sc) : new ServerConfiguration(_server);
                    configuration.ServerKeyId = ServerKeyId;
                    _storage.Put(configuration);
                }
            }
        }

        public string Server
        {
            get => _server;
            set
            {
                _server = value ?? DefaultKeeperServer;
                if (ServerKeyId < 1 || ServerKeyId > KeeperSettings.KeeperPublicKeys.Count)
                {
                    ServerKeyId = 1;
                }
                var configuration = _storage?.Get(_server);
                if (configuration == null) return;
                if (configuration.ServerKeyId > 0 && configuration.ServerKeyId <= KeeperSettings.KeeperPublicKeys.Count)
                {
                    ServerKeyId = configuration.ServerKeyId;
                }
            }
        }

        public int ServerKeyId { get; private set; }

        public string ClientVersion { get; set; }
        public string DeviceName { get; set; }
        public string Locale { get; set; }

        public IHttpProxyCredentialUI ProxyUi { get; set; }
        public IWebProxy WebProxy { get; private set; }
    }

    public static class KeeperSettings
    {
        public static string DefaultLocale()
        {
            var culture = System.Globalization.CultureInfo.CurrentCulture;

            if (KeeperLanguages.TryGetValue(culture.Name, out var locale))
            {
                return locale;
            }

            return KeeperLanguages.TryGetValue(culture.TwoLetterISOLanguageName, out locale) ? locale : "en_US";
        }


        internal static readonly IDictionary<int, RsaKeyParameters> KeeperPublicKeys;

        static KeeperSettings()
        {
            var list = new[]
            {
                new KeyValuePair<int, RsaKeyParameters>(1, CryptoUtils.LoadPublicKey(KeeperKey1.Base64UrlDecode())),
                new KeyValuePair<int, RsaKeyParameters>(2, CryptoUtils.LoadPublicKey(KeeperKey2.Base64UrlDecode())),
                new KeyValuePair<int, RsaKeyParameters>(3, CryptoUtils.LoadPublicKey(KeeperKey3.Base64UrlDecode())),
                new KeyValuePair<int, RsaKeyParameters>(4, CryptoUtils.LoadPublicKey(KeeperKey4.Base64UrlDecode())),
                new KeyValuePair<int, RsaKeyParameters>(5, CryptoUtils.LoadPublicKey(KeeperKey5.Base64UrlDecode())),
                new KeyValuePair<int, RsaKeyParameters>(6, CryptoUtils.LoadPublicKey(KeeperKey6.Base64UrlDecode()))
            };
            KeeperPublicKeys = new ConcurrentDictionary<int, RsaKeyParameters>(list);
        }

        private static readonly IDictionary<string, string> KeeperLanguages = new Dictionary<string, string>()
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
    }
}