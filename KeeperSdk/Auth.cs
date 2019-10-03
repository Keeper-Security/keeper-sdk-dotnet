﻿//  _  __
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
using System.Text;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;
using System.Net.WebSockets;
using System.Threading;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.IO;
using Google.Protobuf;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Tests")]
namespace KeeperSecurity.Sdk
{
    public class Auth
    {
        public Auth(IAuthUI authUI, IConfigurationStorage storage) : this(authUI, storage, null)
        {
        }
        public Auth(IAuthUI authUI, IConfigurationStorage storage, KeeperEndpoint endpoint)
        {
            Endpoint = endpoint ?? new KeeperEndpoint();
            Ui = authUI;
            Storage = storage ?? new InMemoryConfigurationStorage();
            var conf = Storage.Get();
            if (!string.IsNullOrEmpty(conf.LastServer))
            {
                Endpoint.Server = conf.LastServer;
                var server_conf = conf.GetServerConfiguration(conf.LastServer);
                if (server_conf != null)
                {
                    Endpoint.EncryptedDeviceToken = server_conf.DeviceId;
                    Endpoint.ServerKeyId = server_conf.ServerKeyId;
                }
            }
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
                        EncryptedDeviceToken = ByteString.CopyFrom(await Endpoint.GetDeviceToken())
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
                    if (Ui is IHttpProxyCredentialUI proxyUi)
                    {
                        var webProxy = await proxyUi.GetHttpProxyCredentials(pe.ProxyAuthenticate);
                        if (webProxy != null)
                        {
                            Endpoint.WebProxy = webProxy;
                            continue;
                        }
                    }
                    throw pe;
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
                            var new_conf = new Configuration(conf);
                            new_conf.MergeServerConfiguration(new ServerConfiguration
                            {
                                Server = Endpoint.Server,
                                DeviceId = Endpoint.EncryptedDeviceToken,
                                ServerKeyId = Endpoint.ServerKeyId
                            });
                            Storage.Put(new_conf);
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

        public async Task<NewUserMinimumParams> GetNewUserParams(string userName)
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

        public async Task<KeeperApiResponse> ExecuteAuthCommand<C>(C command, bool throwOnError = true) where C : AuthorizedCommand
        {
            return await ExecuteAuthCommand<C, KeeperApiResponse>(command);
        }

        public async Task<R> ExecuteAuthCommand<C, R>(C command, bool throwOnError = true) where C : AuthorizedCommand where R : KeeperApiResponse
        {
            command.username = Username.ToLowerInvariant();
            command.deviceId = KeeperEndpoint.DefaultDeviceName;

            R response = null;
            int attempt = 0;
            while (attempt < 3)
            {
                attempt++;
                command.sessionToken = SessionToken;
                response = await Endpoint.ExecuteV2Command<C, R>(command);
                if (!response.IsSuccess && response.resultCode == "auth_failed")
                {
                    Debug.WriteLine("Refresh Session Token");
                    SessionToken = null;
                    await RefreshSessionToken();
                }
                else
                {
                    break;
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
            var user_conf = configuration.GetUserConfiguration(username);
            var token = user_conf?.TwoFactorToken;
            var tokenType = "device_token";
            var tokenDuration = TwoFactorCodeDuration.Forever;

            string authHash = null;
            PreLoginResponse preLogin = null;

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

                var command = new LoginCommand();
                command.username = username.ToLowerInvariant();
                command.authResponse = authHash;
                command.include = new[] { "keys", "settings", "enforcements", "is_enterprise_admin", "client_key" };
                command.twoFactorToken = token;
                command.twoFactorType = !string.IsNullOrEmpty(token) ? tokenType : null;
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
                    throw new KeeperApiException(loginRs.resultCode, loginRs.message);
                }
                else
                {
                    if (!string.IsNullOrEmpty(loginRs.deviceToken))
                    {
                        token = loginRs.deviceToken;
                        tokenType = "device_token";
                    }

                    SessionToken = loginRs.sessionToken;
                    Username = username;
                    accountSettings = loginRs.accountSettings;

                    if (loginRs.keys != null)
                    {
                        if (loginRs.keys.encryptedDataKey != null)
                        {
                            var key = CryptoUtils.DeriveKeyV2("data_key", password, salt, iterations);
                            DataKey = CryptoUtils.DecryptAesV2(loginRs.keys.encryptedDataKey.Base64UrlDecode(), key);
                        }
                        else
                        if (loginRs.keys.encryptionParams != null)
                        {
                            DataKey = CryptoUtils.DecryptEncryptionParams(password, loginRs.keys.encryptionParams.Base64UrlDecode());
                        }
                        else
                        {
                            throw new Exception("Missing data key");
                        }
                        if (loginRs.keys.encryptedPrivateKey != null)
                        {
                            privateKeyData = CryptoUtils.DecryptAesV1(loginRs.keys.encryptedPrivateKey.Base64UrlDecode(), DataKey);
                            privateKey = null;
                        }
                    }

                    if (loginRs.IsSuccess)
                    {
                        EncryptedPassword = CryptoUtils.EncryptAesV2(Encoding.UTF8.GetBytes(password), DataKey);
                        TwoFactorToken = token;
                        authResponse = authHash;
                        IsEnterpriseAdmin = loginRs.isEnterpriseAdmin ?? false;
                        enforcements = loginRs.enforcements;
                        StoreConfigurationIfChanged(configuration);

                        if (!string.IsNullOrEmpty(loginRs.clientKey))
                        {
                            ClientKey = CryptoUtils.DecryptAesV1(loginRs.clientKey.Base64UrlDecode(), DataKey);
                        }
                        else
                        {
                            try
                            {
                                ClientKey = CryptoUtils.GenerateEncryptionKey();
                                var clientKeyCommand = new SetClientKeyCommand
                                {
                                    clientKey = CryptoUtils.EncryptAesV1(ClientKey, DataKey).Base64UrlEncode()
                                };
                                var clientKeyRs = await ExecuteAuthCommand<SetClientKeyCommand, SetClientKeyResponse>(clientKeyCommand, throwOnError: false);
                                if (clientKeyRs.result == "fail" && clientKeyRs.resultCode == "exists")
                                {
                                    ClientKey = CryptoUtils.DecryptAesV1(clientKeyRs.clientKey.Base64UrlDecode(), DataKey);
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

                            TwoFactorCode tfaCode = null;
                            if (channel == TwoFactorCodeChannel.DuoSecurity)
                            {
                                tfaCode = await GetDuoTwoFactorCode(command, loginRs);
                            }
                            else
                            {
                                tfaCode = await Ui.GetTwoFactorCode(channel);
                            }
                            if (tfaCode != null)
                            {
                                token = tfaCode.Code;
                                tokenType = "one_time";
                                tokenDuration = tfaCode.Duration;
                                continue;
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

        private async Task<TwoFactorCode> GetDuoTwoFactorCode(LoginCommand loginCommand, LoginResponse loginResponse)
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
                string code = null;
                ClientWebSocket ws = null;
                var tokenSource = new CancellationTokenSource();
                var result = await duoUi.GetDuoTwoFactorResult(account, async (duoAction) =>
                {
                    try
                    {
                        if (duoAction == DuoAction.DuoPush)
                        {
                            ws = new ClientWebSocket();
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
                                        code = notification.passcode_;
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
                        tokenSource.Cancel();
                        if (ws != null)
                        {
                            lock (tokenSource)
                            {
                                ws?.Dispose();
                                ws = null;
                            }
                        }
                    }
                });

                if (!tokenSource.IsCancellationRequested)
                {
                    var shouldWait = false;
                    lock (tokenSource)
                    {
                        shouldWait = ws != null;
                    }
                    if (shouldWait)
                    {
                        try
                        {
                            await Task.Delay(TimeSpan.FromSeconds(60), tokenSource.Token);
                        }
                        catch (TaskCanceledException e)
                        {
                            Debug.WriteLine("DUO push tash is canceled.");
                        }
                    }
                }

                if (result != null && !string.IsNullOrEmpty(code))
                {
                    result = new TwoFactorCode(code, result.Duration);
                }
                return result;
            }
            else
            {
                return await Ui.GetTwoFactorCode(TwoFactorCodeChannel.DuoSecurity);
            }
        }

        public void Logout()
        {
            TwoFactorToken = null;
            EncryptedPassword = null;
            SessionToken = null;
            authResponse = null;
            accountSettings = null;
            enforcements = null;
            privateKeyData = null;
            privateKey = null;
            DataKey = null;
            ClientKey = null;
            IsEnterpriseAdmin = false;
        }

        public async Task RefreshSessionToken()
        {
            var command = new LoginCommand
            {
                username = Username,
                authResponse = authResponse,
                twoFactorToken = TwoFactorToken,
                twoFactorType = !string.IsNullOrEmpty(TwoFactorToken) ? "device_token" : null
            };

            var loginRs = await Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
            if (loginRs.IsSuccess)
            {
                SessionToken = loginRs.sessionToken;
            }
            else
            {
                throw new KeeperApiException(loginRs.resultCode, loginRs.message);
            }
        }

        private void StoreConfigurationIfChanged(IConfiguration configuration)
        {
            var shouldSaveConfig = !(configuration.LastServer?.AdjustServerUrl() == Endpoint.Server?.AdjustServerUrl() && configuration.LastLogin?.AdjustUserName() == Username.AdjustUserName());
            var serverConf = configuration.GetServerConfiguration(Endpoint.Server);
            var shouldSaveServer = serverConf == null || !(serverConf.DeviceId.SequenceEqual(Endpoint.EncryptedDeviceToken) && serverConf.ServerKeyId == Endpoint.ServerKeyId);

            var userConf = configuration.GetUserConfiguration(Username);
            var shouldSaveUser = userConf == null || string.Compare(userConf.TwoFactorToken, TwoFactorToken) != 0;

            if (shouldSaveConfig || shouldSaveServer || shouldSaveUser)
            {
                var conf = new Configuration
                {
                    LastLogin = Username,
                    LastServer = Endpoint.Server.AdjustServerUrl()
                };
                if (shouldSaveServer)
                {
                    conf._servers.Add(Endpoint.Server.AdjustServerUrl(), new ServerConfiguration
                    {
                        Server = Endpoint.Server,
                        DeviceId = Endpoint.EncryptedDeviceToken,
                        ServerKeyId = Endpoint.ServerKeyId

                    });
                }
                if (shouldSaveUser)
                {
                    conf._users.Add(Username.AdjustUserName(), new UserConfiguration
                    {
                        Username = Username,
                        TwoFactorToken = TwoFactorToken
                    });
                }
                Storage.Put(conf);
            }
        }

        internal string authResponse;
        internal AccountSettings accountSettings;
        internal AccountEnforcements enforcements;
        internal byte[] privateKeyData;
        private RsaPrivateCrtKeyParameters privateKey;

        public byte[] DataKey { get; internal set; }
        public byte[] ClientKey { get; internal set; }
        public RsaPrivateCrtKeyParameters PrivateKey
        {
            get
            {
                if (privateKey == null)
                {
                    privateKey = privateKeyData.LoadPrivateKey();
                }
                return privateKey;
            }
        }

        public bool IsEnterpriseAdmin { get; internal set; }

        public string SessionToken { get; internal set; }
        public string TwoFactorToken { get; set; }
        public string Username { get; internal set; }
        public byte[] EncryptedPassword { get; internal set; }

        public KeeperEndpoint Endpoint { get; }
        public IAuthUI Ui { get; }
        public IConfigurationStorage Storage { get; }
    }


#pragma warning disable 0649
    [DataContract]
    internal class DuoPushNotification
    {
        [DataMember(Name = "event")]
        public string event_;
        [DataMember(Name = "passcode")]
        public string passcode_;
    }
#pragma warning restore 0649

}
