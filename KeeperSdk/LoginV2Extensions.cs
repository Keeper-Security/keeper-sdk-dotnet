using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.WebSockets;
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
        public string Password { get; set; }
        public byte[] Salt { get; set; }
        public int Iterations { get; set; }
    }

    public class SecondaryCredentials
    {
        public string SecondFactorType { get; set; }
        public string SecondFactorToken { get; set; }
        public string SecondFactorMode { get; set; }
        public TwoFactorDuration? SecondFactorDuration { get; set; }
    }

    public class AuthV2 : IAuth
    {
        private readonly Auth _auth;
        public AuthV2(Auth auth)
        {
            _auth = auth;
            PushToken = new FanOut<TwoFactorCode>();
        }

        public string Username => _auth.Username;
        public string Password
        {
            get => _auth.Password;
            set => _auth.Password = value;
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
    }

    public static class LoginV2Extensions
    {
        private static readonly ISet<string> SecondFactorErrorCodes =
            new HashSet<string>(new[] {"need_totp", "invalid_device_token", "invalid_totp"});

        private static readonly ISet<string> PostLoginErrorCodes =
            new HashSet<string>(new[] {"auth_expired", "auth_expired_transfer"});


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

            SecondaryCredentials secondaryCredentials = null;
            {
                var userConf = auth.Storage.Users.Get(auth.Username);
                var storedToken = userConf?.TwoFactorToken;
                if (!string.IsNullOrEmpty(storedToken))
                {
                    secondaryCredentials = new SecondaryCredentials
                    {
                        SecondFactorType = "device_token",
                        SecondFactorToken = storedToken,
                    };
                }
            }

            var context = await auth.ExecuteLoginCommand(primaryCredentials, secondaryCredentials);
            auth.Password = primaryCredentials.Password;
            return context;
        }

        private static ITwoFactorChannelInfo[] PrepareTwoFactorChannels(this AuthV2 auth,
            LoginCommand loginRq,
            LoginResponse loginRs,
            CancellationToken cancellationToken)
        {
            
            AuthUIExtensions.TryParseTwoFactorChannel(loginRs.channel, out var channel);
            var channels = new List<ITwoFactorChannelInfo>();
            switch (channel)
            {
                case TwoFactorChannel.Authenticator:
                    channels.Add(new AuthenticatorTwoFactorChannel());
                    break;
                case TwoFactorChannel.TextMessage:
                    channels.Add(new TwoFactorSmsChannel());
                    break;
                case TwoFactorChannel.DuoSecurity:
                    ClientWebSocket ws = null;

                    var duoChannel = new TwoFactorDuoChannel
                    {
                        EnrollmentUrl = loginRs.enrollUrl,
                        Phone = loginRs.phone,
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
                        InvokeTwoFactorPushAction = async (action, duration) =>
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

                            if (string.IsNullOrEmpty(duoMode)) return false;

                            var duoRequest = new LoginCommand
                            {
                                username = loginRq.username,
                                authResponse = loginRq.authResponse,
                                twoFactorType = "one_time",
                                twoFactorMode = duoMode,
                            };
                            var duoRs = await auth.Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(duoRequest);
                            var isSuccess = SecondFactorErrorCodes.Contains(duoRs.resultCode);
                            if (!isSuccess || action != TwoFactorPushAction.DuoPush || ws != null) return isSuccess;

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
                                            if (!string.IsNullOrEmpty(notification.passcode))
                                            {
                                                auth.PushToken.Push(new TwoFactorCode(channel, notification.passcode, duration));
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

                            return true;
                        }
                    };
                    channels.Add(duoChannel);
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
            if (loginRs.IsSuccess || (auth.Ui != null && PostLoginErrorCodes.Contains(loginRs.resultCode)))
            {
                var context = new AuthContextV2
                {
                    Username = loginRq.username,
                    SessionToken = loginRs.sessionToken.Base64UrlDecode(),
                    AuthResponse = loginRq.authResponse,
                    DeviceToken = auth.DeviceToken
                };
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

            if (auth.Ui != null && SecondFactorErrorCodes.Contains(loginRs.resultCode))
            {
                using (var tokenSource = new CancellationTokenSource())
                {
                    var channels = auth.PrepareTwoFactorChannels(loginRq, loginRs, tokenSource.Token);
                    if (channels != null && channels.Length > 0)
                    {
                        while (true)
                        {
                            var duoTokenTaskSource = new TaskCompletionSource<TwoFactorCode>();

                            bool Callback(TwoFactorCode tfaCode)
                            {
                                duoTokenTaskSource.TrySetResult(tfaCode);
                                return true;
                            }

                            auth.PushToken?.RegisterCallback(Callback);
                            using (var cancelToken = new CancellationTokenSource())
                            {
                                var userInputTask = auth.Ui.GetTwoFactorCode(channels[0].Channel, channels.ToArray(), cancelToken.Token);
                                var duoTokenTask = duoTokenTaskSource.Task;
                                int index = Task.WaitAny(userInputTask, duoTokenTask);
                                if (index == 1)
                                {
                                    cancelToken.Cancel();
                                }

                                var code = await (index == 0 ? userInputTask : duoTokenTask);
                                auth.PushToken?.RemoveCallback(Callback);
                                if (code != null && !string.IsNullOrEmpty(code.Code))
                                {
                                    var login2faRq = new LoginCommand
                                    {
                                        username = loginRq.username,
                                        authResponse = loginRq.authResponse,
                                        include = loginRq.include,
                                        twoFactorToken = code.Code,
                                        twoFactorType = "one_time",
                                        deviceTokenExpiresInDays = (int) code.Duration,
                                    };
                                    var login2faRs = await auth.Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(login2faRq);
                                    if (!SecondFactorErrorCodes.Contains(login2faRs.resultCode))
                                    {
                                        return await auth.ParseLoginResponse(password, login2faRq, login2faRs);
                                    }
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            throw new KeeperApiException(loginRs.resultCode, loginRs.message);
        }

        public static async Task<AuthContextV2> ExecuteLoginCommand(this AuthV2 auth,
            PrimaryCredentials primary,
            SecondaryCredentials secondary = null)
        {
            var attempt = 0;
            while (attempt < 10)
            {
                attempt++;
                if (string.IsNullOrEmpty(primary.Password))
                {
                    if (auth.PasswordQueue.Count > 0)
                    {
                        primary.Password = auth.PasswordQueue.Dequeue();
                    }
                }

                if (string.IsNullOrEmpty(primary.Password))
                {
                    if (auth.Ui == null) break;
                    var passwordTask = auth.Ui.GetMasterPassword(auth.Username);
                    var index = Task.WaitAny(passwordTask);
                    if (index == 0)
                    {
                        if (passwordTask.IsFaulted)
                        {
                            throw passwordTask.Exception.GetBaseException();
                        }

                        if (!passwordTask.IsCanceled)
                        {
                            primary.Password = passwordTask.Result;
                        }
                    }

                    if (string.IsNullOrEmpty(primary.Password)) throw new KeeperCanceled();
                }

                var authHash = CryptoUtils.DeriveV1KeyHash(primary.Password, primary.Salt, primary.Iterations)
                    .Base64UrlEncode();
                var command = new LoginCommand
                {
                    username = primary.Username.ToLowerInvariant(),
                    authResponse = authHash,
                    include = new[] {"keys"},
                };

                if (secondary != null)
                {
                    command.twoFactorType = secondary.SecondFactorType;
                    command.twoFactorToken = secondary.SecondFactorToken;
                    command.twoFactorMode = secondary.SecondFactorMode;
                    if (secondary.SecondFactorDuration != null)
                    {
                        command.deviceTokenExpiresInDays = (int) secondary.SecondFactorDuration;
                    }
                }

                var loginRs = await auth.Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
                if (loginRs.resultCode == "auth_failed")
                {
                    primary.Password = null;
                }
                else
                {
                    return await auth.ParseLoginResponse(primary.Password, command, loginRs);
                }
            }

            throw new KeeperApiException("auth_failed", "Invalid username or password");
        }

        public static void ParseResponseKeys(AuthContext context, string password, LoginResponse loginRs)
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
                catch (KeeperRegionRedirect redirect)
                {
                    auth.Endpoint.Server = redirect.RegionHost;
                }
            }

            throw new KeeperTooManyAttempts();
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
                (!context.PersistTwoFactorToken && existingUser.DeviceToken?.Length > 0) ||
                (context.PersistTwoFactorToken && 
                    string.CompareOrdinal(existingUser.DeviceToken??"", context.TwoFactorToken??"") != 0))
            {
                var uc = existingUser != null ? new UserConfiguration(existingUser) : new UserConfiguration(context.Username);
                uc.TwoFactorToken = context.PersistTwoFactorToken ? context.TwoFactorToken : "";
                auth.Storage.Users.Put(uc);
            }
        }
    }
}
