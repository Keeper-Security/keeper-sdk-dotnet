using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.WebSockets;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Sdk.UI;
using TwoFactorChannel = KeeperSecurity.Sdk.UI.TwoFactorChannel;

namespace KeeperSecurity.Sdk
{
    public class AuthContextV2 : AuthContext
    {
        public string AuthResponse { get; internal set; }
        public string TwoFactorToken { get; internal set; }
        public bool PersistTwoFactorToken { get; internal set; }

        internal ClientWebSocket WebSocket;
        internal CancellationTokenSource CancellationToken;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (CancellationToken == null) return;
            if (!CancellationToken.IsCancellationRequested)
            {
                CancellationToken.Cancel();
            }
            CancellationToken.Dispose();
        }
    }

    public class PrimaryCredentials
    {
        public string Username { get; set; }
        public byte[] Salt { get; set; }
        public int Iterations { get; set; }
    }

    public class SecondaryCredentials
    {
        public string SecondFactorType { get; set; }
        public string SecondFactorToken { get; set; }
    }

    public class TwoFactorCode
    {
        public TwoFactorCode(TwoFactorChannel channel, string code, TwoFactorDuration duration)
        {
            Channel = channel;
            Code = code;
            Duration = duration;
        }

        public TwoFactorChannel Channel { get; }
        public string Code { get; }
        public TwoFactorDuration Duration { get; }
    }

    public class AuthV2 : IAuth
    {
        private readonly Auth _auth;
        public AuthV2(Auth auth)
        {
            _auth = auth;
            PushToken = new FanOut<TwoFactorCode>();
        }

        public string Username
        {
            get => _auth.Username;
            set => _auth.Username = value;
        }

        public IKeeperEndpoint Endpoint => _auth.Endpoint;
        public byte[] DeviceToken
        {
            get => _auth.DeviceToken;
            set => _auth.DeviceToken = value;
        }
        public bool ResumeSession
        {
            get => _auth.ResumeSession;
            set => _auth.ResumeSession = value;
        }

        public IAuthUI Ui => _auth.Ui;
        public IConfigurationStorage Storage => _auth.Storage;
        public FanOut<TwoFactorCode> PushToken { get; }

        internal Queue<string> PasswordQueue { get; } = new Queue<string>();
        internal SsoLoginInfo SsoLoginInfo { get; set; }
    }

    public static class LoginV2Extensions
    {
        private static readonly ISet<string> _secondFactorErrorCodes =
            new HashSet<string>(new[] {"need_totp", "invalid_device_token", "invalid_totp"});

        private static readonly ISet<string> _postLoginErrorCodes =
            new HashSet<string>(new[] {"auth_expired", "auth_expired_transfer"});


        internal static void RedirectToRegionV2(this IAuth auth, string newRegion)
        {
            auth.Endpoint.Server = newRegion;
            if (auth.Ui is IAuthInfoUI infoUi)
            {
                infoUi.RegionChanged(auth.Endpoint.Server);
            }
        }

        internal static async Task RefreshSessionTokenV2(IKeeperEndpoint endpoint, AuthContextV2 context)
        {
            var command = new LoginCommand
            {
                username = context.Username,
                authResponse = context.AuthResponse,
                twoFactorToken = context.TwoFactorToken,
                twoFactorType = !string.IsNullOrEmpty(context.TwoFactorToken) ? "device_token" : null
            };

            var loginRs = await endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
            if (!loginRs.IsSuccess)
            {
                throw new KeeperApiException(loginRs.resultCode, loginRs.message);
            }

            context.SessionToken = loginRs.sessionToken.Base64UrlDecode();
        }

        internal static async Task<AuthContextV2> LoginSsoV2(this AuthV2 auth, string providerName, bool forceLogin)
        {
            var rq = new GetSsoServiceProviderCommand
            {
                Name = providerName
            };

            var rs = (GetSsoServiceProviderResponse) await auth.Endpoint.ExecuteV2Command(rq, typeof(GetSsoServiceProviderResponse));
            if (!rs.IsSuccess) throw new KeeperApiException(rs.resultCode, rs.message);
            if (auth.Ui != null && auth.Ui is IAuthSsoUI ssoUi)
            {
                if (!string.IsNullOrEmpty(rs.RegionHost))
                {
                    if (string.Compare(auth.Endpoint.Server, rs.RegionHost, StringComparison.InvariantCultureIgnoreCase) != 0)
                    {
                        throw new KeeperRegionRedirect(rs.RegionHost);
                    }
                }

                var queryString = System.Web.HttpUtility.ParseQueryString("");
                CryptoUtils.GenerateRsaKey(out var privateKey, out var publicKey);
                queryString.Add("key", publicKey.Base64UrlEncode());
                queryString.Add("embedded", "");
                if (forceLogin)
                {
                    queryString.Add("relogin", "");
                }

                var builder = new UriBuilder(new Uri(rs.SpUrl))
                {
                    Query = queryString.ToString()
                };

                var tokenSource = new TaskCompletionSource<bool>();
                var ssoAction = new GetSsoTokenActionInfo(builder.Uri.AbsoluteUri, false)
                {
                    InvokeGetSsoTokenAction = (tokenStr) =>
                    {
                        var token = JsonUtils.ParseJson<SsoToken>(Encoding.UTF8.GetBytes(tokenStr));
                        var pk = CryptoUtils.LoadPrivateKey(privateKey);
                        if (!string.IsNullOrEmpty(token.Password))
                        {
                            var password = Encoding.UTF8.GetString(CryptoUtils.DecryptRsa(token.Password.Base64UrlDecode(), pk));
                            auth.PasswordQueue.Enqueue(password);
                        }

                        if (!string.IsNullOrEmpty(token.NewPassword))
                        {
                            var password = Encoding.UTF8.GetString(CryptoUtils.DecryptRsa(token.NewPassword.Base64UrlDecode(), pk));
                            auth.PasswordQueue.Enqueue(password);
                        }

                        auth.Username = token.Email;
                        auth.SsoLoginInfo = new SsoLoginInfo {SsoProvider = token.ProviderName, SpBaseUrl = rs.SpUrl, IdpSessionId = token.SessionId};
                        tokenSource.TrySetResult(true);
                        return (Task) Task.FromResult(true);
                    }
                };
                using (var cancellationSource = new CancellationTokenSource())
                {
                    var userTask = ssoUi.WaitForSsoToken(ssoAction, cancellationSource.Token);
                    var index = Task.WaitAny(userTask, tokenSource.Task);
                    if (index == 0)
                    {
                        await userTask;
                        throw new KeeperCanceled();
                    }
                    cancellationSource.Cancel();
                    await tokenSource.Task;
                    return await auth.LoginV2();
                }
            }
            throw new KeeperAuthFailed();
        }

        public static async Task<AuthContextV2> LoginV2(this AuthV2 auth, params string[] passwords)
        {
            foreach (var p in passwords)
            {
                if (string.IsNullOrEmpty(p)) continue;
                auth.PasswordQueue.Enqueue(p);
            }

            var preLogin = await auth.GetPreLogin();
            var salt = preLogin.Salt[0];

            var primaryCredentials = new PrimaryCredentials
            {
                Username = auth.Username,
                Salt = salt.Salt_.ToByteArray(),
                Iterations = salt.Iterations
            };

            var userConf = auth.Storage.Users.Get(auth.Username);
            string storedDeviceToken = userConf?.TwoFactorToken;
            var context = await auth.ExecuteLoginCommand(primaryCredentials, storedDeviceToken);
            return context;
        }

        private delegate Task<bool> TryLoginWithTwoFactorCodeDelegate(string code, TwoFactorDuration duration);
        private static ITwoFactorChannelInfo[] PrepareTwoFactorChannels(this AuthV2 auth,
            LoginCommand loginRq,
            LoginResponse loginRs,
            TryLoginWithTwoFactorCodeDelegate codeAction,
            CancellationToken cancellationToken)
        {

            TwoFactorCodeActionDelegate GetCodeDelegate(ITwoFactorChannelInfo info)
            {
                return async code =>
                {
                    var duration = info is ITwoFactorDurationInfo dur ? dur.Duration : TwoFactorDuration.EveryLogin;
                    return await codeAction(code, duration);
                };
            }

            AuthUIExtensions.TryParseTwoFactorChannel(loginRs.channel, out var channel);
            var channels = new List<ITwoFactorChannelInfo>();
            switch (channel)
            {
                case TwoFactorChannel.Authenticator:
                {
                    var totp = new AuthenticatorTwoFactorChannel();
                    totp.InvokeTwoFactorCodeAction = GetCodeDelegate(totp);
                    channels.Add(totp);
                }
                break;

                case TwoFactorChannel.TextMessage:
                {
                    var sms = new TwoFactorSmsChannel();
                    sms.InvokeTwoFactorCodeAction = GetCodeDelegate(sms);
                    channels.Add(sms);
                }
                break;

                case TwoFactorChannel.DuoSecurity:
                {
                    ClientWebSocket ws = null;

                    var duoChannel = new TwoFactorDuoChannel
                    {
                        PhoneNumber = loginRs.phone,
                        SupportedActions = (loginRs.capabilities ?? new string[0])
                            .Select<string, TwoFactorPushAction?>(x =>
                            {
                                switch (x)
                                {
                                    case "push":
                                        return TwoFactorPushAction.DuoPush;
                                    case "sms":
                                        return TwoFactorPushAction.DuoTextMessage;
                                    case "phone":
                                        return TwoFactorPushAction.DuoVoiceCall;
                                    default:
                                        return null;
                                }
                            })
                            .Where(x => x != null)
                            .Select(x => x.Value)
                            .ToArray(),
                    };
                    duoChannel.InvokeTwoFactorCodeAction = GetCodeDelegate(duoChannel);
                    duoChannel.InvokeTwoFactorPushAction = async (action) =>
                    {
                        var duoMode = "";
                        switch (action)
                        {
                            case TwoFactorPushAction.DuoPush:
                                duoMode = "push";
                                break;
                            case TwoFactorPushAction.DuoTextMessage:
                                duoMode = "sms";
                                break;
                            case TwoFactorPushAction.DuoVoiceCall:
                                duoMode = "phone";
                                break;
                        }

                        if (string.IsNullOrEmpty(duoMode)) return;

                        var duoRequest = new LoginCommand
                        {
                            username = loginRq.username,
                            authResponse = loginRq.authResponse,
                            twoFactorType = "one_time",
                            twoFactorMode = duoMode,
                        };
                        var duoRs = await auth.Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(duoRequest);
                        var isSuccess = _secondFactorErrorCodes.Contains(duoRs.resultCode);
                        if (!isSuccess || action != TwoFactorPushAction.DuoPush || ws != null) return;

                        ws = new ClientWebSocket();
                        _ = Task.Run(async () =>
                            {
                                try
                                {
                                    await ws.ConnectAsync(new Uri(loginRs.url), cancellationToken);
                                    var buffer = new byte[1024];
                                    var segment = new ArraySegment<byte>(buffer);

                                    var rs = await ws.ReceiveAsync(segment, cancellationToken);
                                    if (rs != null && rs.Count > 0)
                                    {
                                        var json = new byte[rs.Count];
                                        Array.Copy(buffer, 0, json, 0, json.Length);
                                        var notification = JsonUtils.ParseJson<NotificationEvent>(json);
                                        if (!string.IsNullOrEmpty(notification.Passcode))
                                        {
                                            auth.PushToken.Push(new TwoFactorCode(duoChannel.Channel, notification.Passcode, duoChannel.Duration));
                                        }
                                    }

                                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", cancellationToken);
                                }
                                catch (TaskCanceledException)
                                {
                                }
                                catch (Exception e)
                                {
                                    Debug.WriteLine(e);
                                }
                                finally
                                {
                                    ws.Dispose();
                                    ws = null;
                                }
                            },
                            cancellationToken);
                    };
                    channels.Add(duoChannel);
                }
                    break;
            }

            return channels.ToArray();
        }

        internal static async Task SubscribeToNotifications(this IAuthentication auth, AuthContextV2 context)
        {

            var command = new GetPushInfoCommand();
            var pushInfoRs = await auth.ExecuteAuthCommand<GetPushInfoCommand, GetPushInfoResponse>(command);
            var pushUrl = pushInfoRs.url;

            context.WebSocket = new ClientWebSocket();
            context.CancellationToken = new CancellationTokenSource();
            await context.WebSocket.ConnectAsync(new Uri(pushUrl), context.CancellationToken.Token);
            _ = Task.Run(async () =>
            {
                var webSocket = context.WebSocket;
                var tokenSource = context.CancellationToken;
                var buffer = new byte[1024];
                var segment = new ArraySegment<byte>(buffer);
                try
                {
                    while (webSocket.State == WebSocketState.Open && !tokenSource.IsCancellationRequested)
                    {
                        var rs = await webSocket.ReceiveAsync(segment, tokenSource.Token);
                        if (rs == null) break;
                        if (rs.Count <= 0) continue;

                        var notification = new byte[rs.Count];
                        Array.Copy(buffer, notification, rs.Count);
                        var notificationEvent = JsonUtils.ParseJson<NotificationEvent>(notification);
                        context.PushNotifications.Push(notificationEvent);
                    }

                    if (webSocket.State == WebSocketState.Open)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            }, context.CancellationToken.Token);
        }

        public static async Task<AuthContextV2> ParseLoginResponse(this AuthV2 auth, string password, LoginCommand loginRq, LoginResponse loginRs)
        {
            if (loginRs.IsSuccess || (auth.Ui != null && _postLoginErrorCodes.Contains(loginRs.resultCode)))
            {
                var context = new AuthContextV2
                {
                    Username = loginRq.username,
                    SessionToken = loginRs.sessionToken.Base64UrlDecode(),
                    AuthResponse = loginRq.authResponse,
                    DeviceToken = auth.DeviceToken
                };
                var validatorSalt = CryptoUtils.GetRandomBytes(16);
                context.PasswordValidator = 
                    CryptoUtils.CreateEncryptionParams(password, validatorSalt, 100000, CryptoUtils.GetRandomBytes(32));

                ParseResponseKeys(context, password, loginRs);
                if (!string.IsNullOrEmpty(loginRs.deviceToken))
                {
                    context.TwoFactorToken = loginRs.deviceToken;
                    context.PersistTwoFactorToken = (loginRs.deviceTokenScope ?? "").Equals("expiration");
                }
                else if (string.IsNullOrEmpty(loginRq.twoFactorToken))
                {
                    if ((loginRq.twoFactorType ?? "").Equals("device_token"))
                    {
                        context.TwoFactorToken = loginRs.deviceToken;
                    }
                }

                if (loginRs.IsSuccess)
                {

                }
                else
                {
                    switch (loginRs.resultCode)
                    {
                        case "auth_expired":
                            context.SessionTokenRestriction = SessionTokenRestriction.AccountRecovery;
                            break;
                        case "auth_expired_transfer":
                            context.SessionTokenRestriction = SessionTokenRestriction.ShareAccount;
                            break;
                    }
                }
                return context;
            }
            // TODO device verification

            if (auth.Ui != null && _secondFactorErrorCodes.Contains(loginRs.resultCode))
            {
                using (var tokenSource = new CancellationTokenSource())
                {
                    var login2FaRq = new LoginCommand
                    {
                        username = loginRq.username,
                        authResponse = loginRq.authResponse,
                        include = loginRq.include,
                        twoFactorType = "one_time",
                    };
                    var loginResponseSource = new TaskCompletionSource<LoginResponse>();

                    TryLoginWithTwoFactorCodeDelegate callback = async (code, duration) =>
                    {
                        login2FaRq.twoFactorToken = code;
                        login2FaRq.deviceTokenExpiresInDays = (int) duration; 
                        loginRs = await auth.Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(login2FaRq);
                        if (loginRs.IsSuccess)
                        {
                            loginResponseSource.TrySetResult(loginRs);
                            return true;
                        }

                        if (loginRs.resultCode != "auth_failed")
                        {
                            loginResponseSource.TrySetResult(loginRs);
                        }
                        return false;
                    };
                    
                    var channels = auth.PrepareTwoFactorChannels(loginRq, loginRs, callback, tokenSource.Token);
                    if (channels != null && channels.Length > 0)
                    {
                        bool Callback(TwoFactorCode code)
                        {
                            Task.Run(async () =>
                            {
                                await callback(code.Code, code.Duration);
                            });
                            return true;
                        }
                        auth.PushToken?.RegisterCallback(Callback);

                        using (var cancelToken = new CancellationTokenSource())
                        {
                            var uiTask = auth.Ui.WaitForTwoFactorCode(channels.ToArray(), cancelToken.Token);
                            var responseTask = loginResponseSource.Task;
                            var index = Task.WaitAny(uiTask, responseTask);
                            auth.PushToken?.RemoveCallback(Callback);
                            if (index == 0)
                            {
                                throw new KeeperCanceled();
                            }

                            var login2FaRs = await responseTask;
                            return await auth.ParseLoginResponse(password, login2FaRq, login2FaRs);
                        }
                    }
                }
            }

            throw new KeeperApiException(loginRs.resultCode, loginRs.message);
        }

        private static async Task<AuthContextV2> ExecuteLoginCommand(this AuthV2 auth,
            PrimaryCredentials primary,
            string deviceToken = null)
        {
            var loginCommand = new LoginCommand
            {
                username = primary.Username.ToLowerInvariant(),
                include = new[] {"keys"},
            };

            async Task<LoginResponse> TryLoginWithPassword(string password)
            {
                var authHash = CryptoUtils.DeriveV1KeyHash(password, primary.Salt, primary.Iterations)
                    .Base64UrlEncode();
                loginCommand.authResponse = authHash;

                if (!string.IsNullOrEmpty(deviceToken))
                {
                    loginCommand.twoFactorType = "device_token";
                    loginCommand.twoFactorToken = deviceToken;
                }

                return await auth.Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(loginCommand);
            }

            while (auth.PasswordQueue.Count > 0)
            {
                var password = auth.PasswordQueue.Dequeue();
                var rs = await TryLoginWithPassword(password);
                if (rs.resultCode != "auth_failed")
                {
                    return await auth.ParseLoginResponse(password, loginCommand, rs);
                }
            }

            if (auth.Ui != null)
            {
                LoginResponse loginRs = null;
                string loginPassword = null;
                var rsTaskSource = new TaskCompletionSource<bool>();
                using (var cancellationToken = new CancellationTokenSource())
                {
                    var passwordInfo = new MasterPasswordInfo(auth.Username)
                    {
                        InvokePasswordActionDelegate = async password =>
                        {
                            var rs = await TryLoginWithPassword(password);
                            if (rs.IsSuccess)
                            {
                                loginRs = rs;
                                loginPassword = password;
                                rsTaskSource.TrySetResult(true);
                            }

                            if (rs.resultCode == "auth_failed")
                            {
                                throw new KeeperAuthFailed();
                            }
                            throw new KeeperApiException(rs.resultCode, rs.message);
                        }
                    };
                
                    var uiTask = auth.Ui.WaitForUserPassword(passwordInfo, cancellationToken.Token);
                    var index = Task.WaitAny(uiTask, rsTaskSource.Task);
                    if (index == 1)
                    {
                        cancellationToken.Cancel();
                        return await auth.ParseLoginResponse(loginPassword, loginCommand, loginRs);
                    }
                    throw new KeeperCanceled();
                }
            }

            throw new KeeperApiException("auth_failed", "Invalid username or password");
        }

        private static void ParseResponseKeys(AuthContext context, string password, LoginResponse loginRs)
        {
            if (loginRs.keys == null) throw new Exception("Missing data key");

            if (loginRs.keys.encryptedDataKey != null)
            {
                context.DataKey = CryptoUtils.DecryptEncryptionParams(password,
                    loginRs.keys.encryptedDataKey.Base64UrlDecode());
            }
            else if (loginRs.keys.encryptionParams != null)
            {
                context.DataKey = CryptoUtils.DecryptEncryptionParams(password,
                    loginRs.keys.encryptionParams.Base64UrlDecode());
            }
            else
            {
                throw new Exception("Missing data key");
            }
        }

        private static async Task<byte[]> GetDeviceToken(this IAuth auth)
        {
            var deviceRequest = new DeviceRequest
            {
                ClientVersion = auth.Endpoint.ClientVersion,
                DeviceName = auth.Endpoint.DeviceName
            };

            var apiPayload = new ApiRequestPayload()
            {
                Payload = deviceRequest.ToByteString()
            };
            var rs = await auth.Endpoint.ExecuteRest("authentication/get_device_token", apiPayload);
            var deviceRs = DeviceResponse.Parser.ParseFrom(rs);
            if (deviceRs.Status == DeviceStatus.DeviceOk)
            {
                return deviceRs.EncryptedDeviceToken.ToByteArray();
            }

            throw new KeeperApiException("device_token_rejected", "Device is rejected");
        }

        public static async Task<PreLoginResponse> GetPreLogin(this IAuth auth,
            LoginType loginType = LoginType.Normal,
            byte[] twoFactorToken = null)
        {
            var attempt = 0;
            var encryptedDeviceToken = auth.DeviceToken;
            while (attempt < 5)
            {
                attempt++;

                if (encryptedDeviceToken == null)
                {
                    encryptedDeviceToken = await auth.GetDeviceToken();
                }

                var preLogin = new PreLoginRequest()
                {
                    AuthRequest = new AuthRequest
                    {
                        ClientVersion = auth.Endpoint.ClientVersion,
                        Username = auth.Username.ToLowerInvariant(),
                        EncryptedDeviceToken = ByteString.CopyFrom(encryptedDeviceToken)
                    },
                    LoginType = loginType
                };

                if (twoFactorToken != null)
                {
                    preLogin.TwoFactorToken = ByteString.CopyFrom(twoFactorToken);
                }

                var apiPayload = new ApiRequestPayload()
                {
                    Payload = preLogin.ToByteString()
                };
                try
                {
                    var response = await auth.Endpoint.ExecuteRest("authentication/pre_login", apiPayload);
                    auth.DeviceToken = encryptedDeviceToken;
                    return PreLoginResponse.Parser.ParseFrom(response);
                }
                catch (KeeperInvalidDeviceToken)
                {
                    encryptedDeviceToken = null;
                }
            }

            throw new KeeperAuthFailed();
        }

        internal static void StoreConfigurationIfChangedV2(this Auth auth, AuthContextV2 context)
        {
            if (string.CompareOrdinal(auth.Storage.LastLogin ?? "", context.Username) != 0)
            {
                auth.Storage.LastLogin = context.Username;
            }

            if (string.CompareOrdinal(auth.Storage.LastServer ?? "", auth.Endpoint.Server) != 0)
            {
                auth.Storage.LastServer = auth.Endpoint.Server;
            }

            var existingUser = auth.Storage.Users.Get(context.Username);
            if (existingUser == null || 
                (!context.PersistTwoFactorToken && existingUser.TwoFactorToken?.Length > 0) ||
                (context.PersistTwoFactorToken && 
                    string.CompareOrdinal(existingUser.TwoFactorToken ?? "", context.TwoFactorToken??"") != 0))
            {
                var uc = existingUser != null ? new UserConfiguration(existingUser) : new UserConfiguration(context.Username);
                uc.TwoFactorToken = context.PersistTwoFactorToken ? context.TwoFactorToken : "";
                auth.Storage.Users.Put(uc);
            }
        }
    }

    [DataContract]
    public class GetSsoServiceProviderCommand : KeeperApiCommand
    {
        public GetSsoServiceProviderCommand() : base("get_sso_service_provider") { }

        [DataMember(Name = "name")]
        public string Name { get; set; }
    }

    [DataContract]
    public class GetSsoServiceProviderResponse : KeeperApiResponse
    {
        [DataMember(Name = "sp_url")]
        public string SpUrl { get; set; }

        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "region_host")]
        public string RegionHost { get; set; }
    }

}
