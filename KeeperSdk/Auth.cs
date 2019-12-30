//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Threading.Tasks;
using KeeperSecurity.Sdk.UI;
using System.Linq;
using System.Diagnostics;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;
using System.Net.WebSockets;
using System.Threading;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.IO;
using Google.Protobuf;

namespace KeeperSecurity.Sdk
{
    public interface IAuth
    {
        KeeperEndpoint Endpoint { get; }
        IAuthUI Ui { get; }
        IConfigurationStorage Storage { get; }
        bool IsAuthenticated { get; }
        AuthContext AuthContext { get; }

        Task Login(string username, string password);
        void Logout();

        Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType = null, bool throwOnError = true);
    }

    public static class AuthExtensions
    {
        public static async Task<TR> ExecuteAuthCommand<TC, TR>(this IAuth auth, TC command, bool throwOnError = true)
            where TC : AuthenticatedCommand
            where TR : KeeperApiResponse
        {
            return (TR)await auth.ExecuteAuthCommand(command, typeof(TR), throwOnError);
        }

        public static Task ExecuteAuthCommand<TC>(this IAuth auth, TC command)
            where TC : AuthenticatedCommand
        {
            return auth.ExecuteAuthCommand<TC, KeeperApiResponse>(command, true);
        }
    }

    public class AuthContext
    {
        internal AccountSettings accountSettings;
        internal AccountEnforcements enforcements;
        public RsaPrivateCrtKeyParameters PrivateKey { get; set; }
        public string Username { get; set; }
        public byte[] DataKey { get; set; }
        public byte[] ClientKey { get; set; }
        public bool IsEnterpriseAdmin { get; set; }
        public string SessionToken { get; set; }
        public string TwoFactorToken { get; set; }
    }

    public class Auth : IAuth
    {
        public Auth(IAuthUI authUi, IConfigurationStorage storage, KeeperEndpoint endpoint = null)
        {
            Endpoint = endpoint ?? new KeeperEndpoint();
            Ui = authUi;
            Storage = storage ?? new InMemoryConfigurationStorage();
            var conf = Storage.Get();
            if (!string.IsNullOrEmpty(conf.LastServer))
            {
                Endpoint.Server = conf.LastServer;
                var serverConf = conf.GetServerConfiguration(conf.LastServer);
                if (serverConf == null) return;
                Endpoint.EncryptedDeviceToken = serverConf.DeviceId;
                Endpoint.ServerKeyId = serverConf.ServerKeyId;
            }
        }

        internal AuthContext authContext;
        public AuthContext AuthContext => authContext;
        public bool IsAuthenticated => authContext != null && !string.IsNullOrEmpty(authContext.SessionToken);

        private async Task<byte[]> GetDeviceToken()
        {
            byte[] token = null;
            lock (this)
            {
                token = Endpoint.EncryptedDeviceToken;
            }
            if (token == null)
            {
                var deviceRequest = new DeviceRequest
                {
                    ClientVersion = Endpoint.ClientVersion,
                    DeviceName = KeeperEndpoint.DefaultDeviceName
                };

                var rs = await Endpoint.ExecuteRest("authentication/get_device_token", deviceRequest.ToByteArray());
                var deviceRs = DeviceResponse.Parser.ParseFrom(rs);
                if (deviceRs.Status == DeviceStatus.Ok)
                {
                    token = deviceRs.EncryptedDeviceToken.ToByteArray();
                    lock (this)
                    {
                        Endpoint.EncryptedDeviceToken = token;
                    }
                }
                else
                {
                    throw new KeeperInvalidDeviceToken();
                }
            }
            return token;
        }

        public async virtual Task<PreLoginResponse> GetPreLogin(string username, byte[] twoFactorToken = null)
        {
            var attempt = 0;
            while (attempt < 5)
            {
                attempt++;

                var preLogin = new PreLoginRequest()
                {
                    AuthRequest = new AuthRequest
                    {
                        ClientVersion = Endpoint.ClientVersion,
                        Username = username.ToLowerInvariant(),
                        EncryptedDeviceToken = ByteString.CopyFrom(await GetDeviceToken())
                    },
                    LoginType = LoginType.Normal
                };

                if (twoFactorToken != null)
                {
                    preLogin.TwoFactorToken = ByteString.CopyFrom(twoFactorToken);
                }

                try
                {
                    var response = await Endpoint.ExecuteRest("authentication/pre_login", preLogin.ToByteArray());
                    return PreLoginResponse.Parser.ParseFrom(response);
                }
                catch (ProxyAuthenticateException pe)
                {
                    if (!(Ui is IHttpProxyCredentialUI proxyUi)) throw pe;
                    var webProxy = await proxyUi.GetHttpProxyCredentials(pe.ProxyAuthenticate);
                    if (webProxy == null) throw pe;
                    Endpoint.WebProxy = webProxy;
                }
                catch (KeeperInvalidDeviceToken)
                {
                    Endpoint.EncryptedDeviceToken = null;
                    continue;
                }
                catch (KeeperRegionRedirect redirect)
                {
                    // store old server configuration if changed
                    var conf = Storage.Get();
                    var serverConf = conf.GetServerConfiguration(Endpoint.Server);
                    if (serverConf != null)
                    {
                        if (!(Endpoint.EncryptedDeviceToken.SequenceEqual(serverConf.DeviceId) && Endpoint.ServerKeyId == serverConf.ServerKeyId))
                        {
                            var newConf = new Configuration(conf);
                            newConf.MergeServerConfiguration(new ServerConfiguration(Endpoint.Server)
                            {
                                DeviceId = Endpoint.EncryptedDeviceToken,
                                ServerKeyId = Endpoint.ServerKeyId
                            });
                            Storage.Put(newConf);
                            conf = Storage.Get();
                        }
                    }


                    Endpoint.EncryptedDeviceToken = null;
                    Endpoint.Server = redirect.RegionHost;
                    serverConf = conf.GetServerConfiguration(Endpoint.Server);
                    if (serverConf != null)
                    {
                        Endpoint.EncryptedDeviceToken = serverConf.DeviceId;
                        Endpoint.ServerKeyId = serverConf.ServerKeyId;
                    }
                    continue;
                }
            }

            throw new KeeperTooManyAttempts();
        }

        internal async Task<NewUserMinimumParams> GetNewUserParams(string userName)
        {
            var authRequest = new AuthRequest()
            {
                ClientVersion = Endpoint.ClientVersion,
                Username = userName.ToLowerInvariant(),
                EncryptedDeviceToken = ByteString.CopyFrom(Endpoint.EncryptedDeviceToken)
            };

            var rs = await Endpoint.ExecuteRest("authentication/get_new_user_params", authRequest.ToByteArray());
            return NewUserMinimumParams.Parser.ParseFrom(rs);
        }

        public async Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType = null, bool throwOnError = true)
        {
            if (!IsAuthenticated)
            {
                throw new KeeperApiException("auth_failed", "auth_failed");
            }
            command.username = authContext.Username;
            command.sessionToken = authContext.SessionToken;

            KeeperApiResponse response = await Endpoint.ExecuteV2Command(command, responseType);
            if (!response.IsSuccess && response.resultCode == "auth_failed")
            {
                Debug.WriteLine("Refresh Session Token");
                authContext.SessionToken = null;
                await RefreshSessionToken();
                if (IsAuthenticated)
                {
                    command.sessionToken = authContext.SessionToken;
                    response = await Endpoint.ExecuteV2Command(command, responseType);
                }
                else
                {
                    Logout();
                }
            }
            if (response != null && !response.IsSuccess && throwOnError)
            {
                throw new KeeperApiException(response.resultCode, response.message);
            }
            return response;
        }

        public async Task Login(string username, string password)
        {
            var configuration = Storage.Get();
            var userConf = configuration.GetUserConfiguration(username);
            var token = userConf?.TwoFactorToken;
            var tokenType = "device_token";
            var tokenDuration = TwoFactorCodeDuration.Forever;

            string authHash = null;
            PreLoginResponse preLogin = null;
            authContext = new AuthContext();

            while (true)
            {
                if (preLogin == null)
                {
                    preLogin = await GetPreLogin(username);
                    authHash = null;
                }

                var authParams = preLogin.Salt[0];
                int iterations = authParams.Iterations;
                byte[] salt = authParams.Salt_.ToByteArray();
                if (authHash == null)
                {
                    authHash = CryptoUtils.DeriveV1KeyHash(password, salt, iterations).Base64UrlEncode();
                }

                var command = new LoginCommand
                {
                    username = username.ToLowerInvariant(),
                    authResponse = authHash,
                    include = new[] { "keys", "settings", "enforcements", "is_enterprise_admin", "client_key" },
                    twoFactorToken = token,
                    twoFactorType = !string.IsNullOrEmpty(token) ? tokenType : null
                };
                if (!string.IsNullOrEmpty(token))
                {
                    switch (tokenDuration)
                    {
                        case TwoFactorCodeDuration.Every30Days:
                            command.deviceTokenExpiresInDays = 30;
                            break;
                        case TwoFactorCodeDuration.Forever:
                            command.deviceTokenExpiresInDays = 9999;
                            break;
                        default:
                            command.deviceTokenExpiresInDays = null;
                            break;
                    }
                }
                else
                {
                    command.deviceTokenExpiresInDays = null;
                }

                var loginRs = await Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
                if (!loginRs.IsSuccess && loginRs.resultCode == "auth_failed") // invalid password
                {
                    loginRs.message = "Invalid username or password";
                    throw new KeeperApiException(loginRs.resultCode, loginRs.message);
                }
                else
                {
                    if (!string.IsNullOrEmpty(loginRs.deviceToken))
                    {
                        token = loginRs.deviceToken;
                        tokenType = "device_token";
                    }

                    authContext.Username = username;
                    authContext.SessionToken = loginRs.sessionToken;
                    authContext.accountSettings = loginRs.accountSettings;

                    if (loginRs.keys != null)
                    {
                        if (loginRs.keys.encryptedDataKey != null)
                        {
                            var key = CryptoUtils.DeriveKeyV2("data_key", password, salt, iterations);
                            authContext.DataKey = CryptoUtils.DecryptAesV2(loginRs.keys.encryptedDataKey.Base64UrlDecode(), key);
                        }
                        else
                        if (loginRs.keys.encryptionParams != null)
                        {
                            authContext.DataKey = CryptoUtils.DecryptEncryptionParams(password, loginRs.keys.encryptionParams.Base64UrlDecode());
                        }
                        else
                        {
                            throw new Exception("Missing data key");
                        }
                        if (loginRs.keys.encryptedPrivateKey != null)
                        {
                            var privateKeyData = CryptoUtils.DecryptAesV1(loginRs.keys.encryptedPrivateKey.Base64UrlDecode(), authContext.DataKey);
                            authContext.PrivateKey = CryptoUtils.LoadPrivateKey(privateKeyData);
                        }
                    }

                    if (loginRs.IsSuccess)
                    {
                        authContext.TwoFactorToken = token;
                        authResponse = authHash;
                        authContext.IsEnterpriseAdmin = loginRs.isEnterpriseAdmin ?? false;
                        authContext.enforcements = loginRs.enforcements;
                        StoreConfigurationIfChanged(configuration);

                        if (!string.IsNullOrEmpty(loginRs.clientKey))
                        {
                            authContext.ClientKey = CryptoUtils.DecryptAesV1(loginRs.clientKey.Base64UrlDecode(), authContext.DataKey);
                        }
                        else
                        {
                            try
                            {
                                authContext.ClientKey = CryptoUtils.GenerateEncryptionKey();
                                var clientKeyCommand = new SetClientKeyCommand
                                {
                                    clientKey = CryptoUtils.EncryptAesV1(authContext.ClientKey, authContext.DataKey).Base64UrlEncode()
                                };
                                var clientKeyRs = await this.ExecuteAuthCommand<SetClientKeyCommand, SetClientKeyResponse>(clientKeyCommand, throwOnError: false);
                                if (clientKeyRs.result == "fail" && clientKeyRs.resultCode == "exists")
                                {
                                    authContext.ClientKey = CryptoUtils.DecryptAesV1(clientKeyRs.clientKey.Base64UrlDecode(), authContext.DataKey);
                                }
                            }
                            catch (Exception e)
                            {
                                Trace.TraceError(e.Message);
                            }
                        }

                        break;
                    }

                    switch (loginRs.resultCode)
                    {
                        case "need_totp":
                        case "invalid_device_token":
                        case "invalid_totp":
                            var channel = TwoFactorCodeChannel.Other;
                            switch (loginRs.channel)
                            {
                                case "two_factor_channel_sms":
                                    channel = TwoFactorCodeChannel.TextMessage;
                                    break;
                                case "two_factor_channel_google":
                                    channel = TwoFactorCodeChannel.Authenticator;
                                    break;
                                case "two_factor_channel_duo":
                                    channel = TwoFactorCodeChannel.DuoSecurity;
                                    break;
                                default:
                                    break;

                            }

                            TaskCompletionSource<TwoFactorCode> tfaTaskSource =
                                channel == TwoFactorCodeChannel.DuoSecurity
                                    ? GetDuoTwoFactorCode(command, loginRs)
                                    : Ui.GetTwoFactorCode(channel);
                            if (tfaTaskSource != null)
                            {
                                var tfaCode = await tfaTaskSource.Task;

                                if (tfaCode != null)
                                {
                                    token = tfaCode.Code;
                                    tokenType = "one_time";
                                    tokenDuration = tfaCode.Duration;
                                    continue;
                                }
                            }

                            break;

                        case "auth_expired":
                            password = await this.ChangeMasterPassword(iterations);
                            if (!string.IsNullOrEmpty(password))
                            {
                                preLogin = null;
                                continue;
                            }
                            break;

                        case "auth_expired_transfer":
                            var shareAccountTo = loginRs.accountSettings.shareAccountTo;
                            if (await Ui.Confirmation("Do you accept Account Transfer policy?"))
                            {
                                await this.ShareAccount();
                                continue;
                            }
                            break;
                    }
                    throw new KeeperApiException(loginRs.resultCode, loginRs.message);
                }
            }
        }

        private TaskCompletionSource<TwoFactorCode> GetDuoTwoFactorCode(LoginCommand loginCommand, LoginResponse loginResponse)
        {
            if (Ui is IDuoTwoFactorUI duoUi)
            {
                var account = new DuoAccount
                {
                    Phone = loginResponse.phone,
                    EnrollmentUrl = loginResponse.enroll_url
                };
                if (loginResponse.capabilities != null)
                {
                    account.Capabilities = loginResponse.capabilities
                        .Select<string, DuoAction?>(x =>
                        {
                            if (DuoActionExtensions.TryParseDuoAction(x, out DuoAction action))
                            {
                                return action;
                            }
                            return null;
                        })
                        .Where(x => x != null)
                        .Select(x => x.Value)
                        .ToArray();
                }
                TaskCompletionSource<TwoFactorCode> taskSource = null;

                taskSource = duoUi.GetDuoTwoFactorResult(account, async (duoAction) =>
                {
                    CancellationTokenSource tokenSource = null;
                    ClientWebSocket ws = null;
                    try
                    {
                        if (duoAction == DuoAction.DuoPush)
                        {
                            ws = new ClientWebSocket();
                            tokenSource = new CancellationTokenSource();
                            await ws.ConnectAsync(new Uri(loginResponse.url), tokenSource.Token);
                        }
                        loginCommand.twoFactorMode = duoAction.GetDuoActionText();
                        loginCommand.twoFactorType = "one_time";
                        var actionRs = await Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(loginCommand);
                        if (actionRs.resultCode == "need_totp" && ws != null)
                        {
                            if (ws != null)
                            {
                                tokenSource.CancelAfter(TimeSpan.FromSeconds(60));
                                byte[] buffer = new byte[1024];
                                var segment = new ArraySegment<byte>(buffer);
                                var rs = await ws.ReceiveAsync(segment, tokenSource.Token);
                                if (rs != null)
                                {
                                    var serializer = new DataContractJsonSerializer(typeof(DuoPushNotification));
                                    using (var rss = new MemoryStream(buffer, 0, rs.Count))
                                    {
                                        var notification = serializer.ReadObject(rss) as DuoPushNotification;
                                        if (taskSource != null && !taskSource.Task.IsCompleted)
                                        {
                                            if (!string.IsNullOrEmpty(notification?.Passcode))
                                            {
                                                taskSource.SetResult(new TwoFactorCode(notification.Passcode, TwoFactorCodeDuration.EveryLogin));
                                            }
                                        }
                                    }
                                }
                                await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", tokenSource.Token);
                            }
                        }
                    }
                    finally
                    {
                        loginCommand.twoFactorMode = null;
                        loginCommand.twoFactorType = null;
                        if (ws != null && tokenSource != null)
                        {
                            tokenSource.Cancel();
                            lock (tokenSource)
                            {
                                ws?.Dispose();
                            }
                        }
                    }
                });

                return taskSource;
            }

            return Ui.GetTwoFactorCode(TwoFactorCodeChannel.DuoSecurity);
        }

        public void Logout()
        {
            authContext = null;
            authResponse = null;
        }

        public async Task RefreshSessionToken()
        {
            var command = new LoginCommand
            {
                username = authContext.Username,
                authResponse = authResponse,
                twoFactorToken = authContext.TwoFactorToken,
                twoFactorType = !string.IsNullOrEmpty(authContext.TwoFactorToken) ? "device_token" : null
            };

            var loginRs = await Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
            if (loginRs.IsSuccess)
            {
                authContext.SessionToken = loginRs.sessionToken;
            }
            else
            {
                throw new KeeperApiException(loginRs.resultCode, loginRs.message);
            }
        }

        private void StoreConfigurationIfChanged(Configuration configuration)
        {
            var shouldSaveConfig = !(configuration.LastServer?.AdjustServerName() == Endpoint.Server?.AdjustServerName() &&
                configuration.LastLogin?.AdjustUserName() == authContext.Username.AdjustUserName());
            var serverConf = configuration.GetServerConfiguration(Endpoint.Server);
            var shouldSaveServer = serverConf == null || serverConf.DeviceId == null || !(serverConf.DeviceId.SequenceEqual(Endpoint.EncryptedDeviceToken) && serverConf.ServerKeyId == Endpoint.ServerKeyId);

            var userConf = configuration.GetUserConfiguration(authContext.Username);
            var shouldSaveUser = userConf == null || string.CompareOrdinal(userConf.TwoFactorToken, authContext.TwoFactorToken) != 0;

            if (shouldSaveConfig || shouldSaveServer || shouldSaveUser)
            {
                var conf = new Configuration
                {
                    LastLogin = authContext.Username,
                    LastServer = Endpoint.Server.AdjustServerName()
                };
                if (shouldSaveServer)
                {
                    conf._servers.Add(Endpoint.Server.AdjustServerName(), new ServerConfiguration(Endpoint.Server)
                    {
                        DeviceId = Endpoint.EncryptedDeviceToken,
                        ServerKeyId = Endpoint.ServerKeyId

                    });
                }
                if (shouldSaveUser)
                {
                    conf._users.Add(authContext.Username.AdjustUserName(), new UserConfiguration(authContext.Username)
                    {
                        TwoFactorToken = authContext.TwoFactorToken
                    });
                }
                Storage.Put(conf);
            }
        }

        internal string authResponse;

        public KeeperEndpoint Endpoint { get; }
        public IAuthUI Ui { get; }
        public IConfigurationStorage Storage { get; }
    }


#pragma warning disable 0649
    [DataContract]
    internal class DuoPushNotification
    {
        [DataMember(Name = "event")]
        public string Event;
        [DataMember(Name = "passcode")]
        public string Passcode;
    }
#pragma warning restore 0649

}
