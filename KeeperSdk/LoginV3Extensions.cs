using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Sdk.UI;
using Org.BouncyCastle.Crypto.Parameters;
using Push;
using SsoCloud;
using TwoFactorChannel = KeeperSecurity.Sdk.UI.TwoFactorChannel;

namespace KeeperSecurity.Sdk
{
    public class AuthContextV3 : AuthContext
    {
        public byte[] AccountUid { get; internal set; }
        internal IWebSocketChannel WebSocketChannel { get; set; }
        public byte[] CloneCode { get; internal set; }

        internal ECPrivateKeyParameters DeviceKey { get; set; }
        internal byte[] MessageSessionUid { get; set; }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (WebSocketChannel != null)
            {
                WebSocketChannel.Dispose();
                WebSocketChannel = null;
            }
        }
    }

    public class AuthV3 : IAuth
    {
        private readonly Auth _auth;

        public AuthV3(Auth auth)
        {
            _auth = auth;
            MessageSessionUid = CryptoUtils.GetRandomBytes(16);
        }

        public bool IsSsoAccount { get; set; }
        public string Username => _auth.Username;
        public byte[] CloneCode { get; set; }

        public string Password
        {
            get => _auth.Password;
            set => _auth.Password = value;
        }

        public IKeeperEndpoint Endpoint => _auth.Endpoint;
        public bool ResumeSession
        {
            get => _auth.ResumeSession;
            set => _auth.ResumeSession = value;
        }

        public byte[] DeviceToken
        {
            get => _auth.DeviceToken;
            set => _auth.DeviceToken = value;
        }

        public IAuthUI Ui => _auth.Ui;
        public IConfigurationStorage Storage => _auth.Storage;

        internal IWebSocketChannel WebSocketChannel { get; set; }
        internal ECPrivateKeyParameters DeviceKey { get; set; }
        internal byte[] MessageSessionUid { get; }
        internal Queue<string> PasswordQueue { get; } = new Queue<string>();
    }

    public static class LoginV3Extensions
    {
        internal static async Task<AuthContextV3> LoginV3(this AuthV3 auth, params string[] passwords)
        {
            foreach (var p in passwords)
            {
                if (string.IsNullOrEmpty(p)) continue;
                auth.PasswordQueue.Enqueue(p);
            }

            auth.DeviceToken = null;

            var userConf = auth.Storage.Users.Get(auth.Username);
            var lastDevice = userConf?.LastDevice;
            if (lastDevice != null)
            {
                var dc = auth.Storage.Devices.Get(lastDevice.DeviceToken);
                if (dc != null)
                {
                    try
                    {
                        if (dc.DeviceKey?.Length > 0)
                        {
                            auth.DeviceToken = lastDevice.DeviceToken.Base64UrlDecode();
                            auth.DeviceKey = CryptoUtils.LoadPrivateEcKey(dc.DeviceKey);
                            if (!string.IsNullOrEmpty(lastDevice.ResumeCode))
                            {
                                auth.CloneCode = lastDevice.ResumeCode.Base64UrlDecode();
                            }
                        }
                        else
                        {
                            throw new KeeperInvalidDeviceToken("user configuration");
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        auth.Storage.Devices.Delete(lastDevice.DeviceToken);
                        auth.DeviceToken = null;
                        auth.DeviceKey = null;
                        auth.CloneCode = null;
                    }
                }
            }

            try
            {
                return await auth.StartLogin();
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
                throw;
            }
        }

        private static async Task RegisterDeviceInRegion(this IAuth auth, IDeviceConfiguration device)
        {
            var privateKey = CryptoUtils.LoadPrivateEcKey(device.DeviceKey);
            var publicKey = CryptoUtils.GetPublicEcKey(privateKey);
            var request = new RegisterDeviceInRegionRequest
            {
                EncryptedDeviceToken = ByteString.CopyFrom(device.DeviceToken.Base64UrlDecode()),
                ClientVersion = auth.Endpoint.ClientVersion,
                DeviceName = auth.Endpoint.DeviceName,
                DevicePublicKey = ByteString.CopyFrom(CryptoUtils.UnloadEcPublicKey(publicKey)),
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"register_device_in_region\": {request}");
#endif
            try
            {
                await auth.Endpoint.ExecuteRest("authentication/register_device_in_region", new ApiRequestPayload {Payload = request.ToByteString()});
            }

            catch (KeeperInvalidDeviceToken idt)
            {
                Debug.WriteLine(idt);
                if (idt.AdditionalInfo != "public key already exists")
                {
                    throw;
                }
            }

            var dc = new DeviceConfiguration(device);
            dc.KeeperServers.Add(auth.Endpoint.Server);
            auth.Storage.Devices.Put(dc);
        }

        private static async Task<IDeviceConfiguration> RegisterDevice(this IAuth auth)
        {
            CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
            var request = new DeviceRegistrationRequest
            {
                DeviceName = auth.Endpoint.DeviceName,
                ClientVersion = auth.Endpoint.ClientVersion,
                DevicePublicKey = ByteString.CopyFrom(CryptoUtils.UnloadEcPublicKey(publicKey)),
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"register_device\": {request}");
#endif
            var rs = await auth.Endpoint.ExecuteRest("authentication/register_device", new ApiRequestPayload {Payload = request.ToByteString()});
            var response = Device.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"register_device\": {response}");
#endif
            var deviceToken = response.EncryptedDeviceToken.ToByteArray();
            var dc = new DeviceConfiguration(deviceToken.Base64UrlEncode())
            {
                DeviceKey = CryptoUtils.UnloadEcPrivateKey(privateKey)
            };
            dc.KeeperServers.Add(auth.Endpoint.Server);
            auth.Storage.Devices.Put(dc);

            return dc;
        }

        internal static async Task RequestDeviceVerification(this AuthV3 auth, string channel)
        {
            var request = new DeviceVerificationRequest
            {
                Username = auth.Username,
                ClientVersion = auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                VerificationChannel = channel
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"request_device_verification\": {request}");
#endif
            await auth.Endpoint.ExecuteRest("authentication/request_device_verification",
                new ApiRequestPayload {Payload = request.ToByteString()});
        }

        internal static async Task ValidateDeviceVerificationCode(this AuthV3 auth, string code)
        {
            var request = new ValidateDeviceVerificationCodeRequest
            {
                Username = auth.Username,
                ClientVersion = auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                VerificationCode = code
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"validate_device_verification_code\": {request}");
#endif
            await auth.Endpoint.ExecuteRest("authentication/validate_device_verification_code",
                new ApiRequestPayload { Payload = request.ToByteString() });
        }

        private static async Task<AuthContextV3> ExecuteStartLogin(this AuthV3 auth, StartLoginRequest request)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"start_login\": {request}");
#endif

            var rs = await auth.Endpoint.ExecuteRest("authentication/start_login", new ApiRequestPayload {Payload = request.ToByteString()});
            var response = Authentication.LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"start_login\": {response}");
#endif
            switch (response.LoginState)
            {
                case LoginState.LoggedIn:
                    var authContext = new AuthContextV3
                    {
                        Username = response.PrimaryUsername,
                        AccountUid = response.AccountUid.ToByteArray(),
                        SessionToken = response.EncryptedSessionToken.ToByteArray(),
                        SessionTokenRestriction = GetSessionTokenScope(response.SessionTokenType),
                        CloneCode = response.CloneCode.ToByteArray(),
                        DeviceToken = auth.DeviceToken,
                        MessageSessionUid = auth.MessageSessionUid,
                        DeviceKey = auth.DeviceKey,
                    };
                    var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
                    switch (response.EncryptedDataKeyType)
                    {
                        case EncryptedDataKeyType.ByDevicePublicKey:
                            authContext.DataKey = CryptoUtils.DecryptEc(encryptedDataKey, auth.DeviceKey);
                            break;
                    }

                    return authContext;

                case LoginState.RequiresUsername:
                    return await auth.ResumeLogin(response.EncryptedLoginToken);

                case LoginState.Requires2Fa:
                    if (auth.Ui != null)
                    {
                        return await auth.TwoFactorValidate(response.EncryptedLoginToken, response.Channels);
                    }

                    break;
                case LoginState.RequiresAuthHash:
                    if (auth.Ui != null)
                    {
                        return await auth.ValidateAuthHash(response.EncryptedLoginToken, response.Salt);
                    }

                    break;

                case LoginState.DeviceApprovalRequired:
                    if (auth.Ui != null)
                    {
                        return await auth.ApproveDevice(response.EncryptedLoginToken);
                    }

                    break;

                case LoginState.RedirectCloudSso:
                    auth.IsSsoAccount = true;
                    return await auth.AuthorizeUsingCloudSso(response);

                case LoginState.RedirectOnsiteSso:
                    auth.IsSsoAccount = true;
                    return await auth.AuthorizeUsingOnsiteSso(response);

                case LoginState.RequiresDeviceEncryptedDataKey:
                {
                    if (auth.Ui != null)
                    {
                        auth.CloneCode = null;
                        if (auth.IsSsoAccount)
                        {
                            return await auth.RequestDataKey(response.EncryptedLoginToken);
                        }

                        auth.ResumeSession = false;
                        auth.CloneCode = null;
                        var newRequest = new StartLoginRequest
                        {
                            Username = auth.Username,
                            ClientVersion = auth.Endpoint.ClientVersion,
                            EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                            LoginType = LoginType.Normal,
                            LoginMethod = LoginMethod.ExistingAccount,
                            MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                        };
                        return await auth.ExecuteStartLogin(newRequest);
                    }

                    break;
                }

                case LoginState.RequiresAccountCreation:
                    if (auth.IsSsoAccount)
                    {
                        return await auth.CreateSsoUser(response.EncryptedLoginToken);
                    }

                    break;

                case LoginState.RegionRedirect:
                {
                }
                    break;

                case LoginState.DeviceAccountLocked:
                case LoginState.DeviceLocked:
                    throw new KeeperInvalidDeviceToken(response.Message);

                case LoginState.AccountLocked:
                case LoginState.LicenseExpired:
                case LoginState.Upgrade:
                    break;
            }

            throw new KeeperStartLoginException(response.LoginState, response.Message);
        }

        private static async Task<AuthContextV3> ResumeLogin(this AuthV3 auth, ByteString loginToken, LoginMethod method = LoginMethod.ExistingAccount)
        {
            var request = new StartLoginRequest
            {
                ClientVersion = auth.Endpoint.ClientVersion,
                EncryptedLoginToken = loginToken,
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                Username = auth.Username,
                LoginMethod = method
            };
            return await auth.ExecuteStartLogin(request);
        }

        internal static async Task<AuthContextV3> StartLogin(this AuthV3 auth, bool forceNewLogin = false)
        {
            var attempt = 0;
            while (true)
            {
                attempt++;
                if (auth.DeviceToken == null || auth.DeviceKey == null)
                {
                    auth.DeviceKey = null;
                    auth.CloneCode = null;
                    var dc = auth.Storage.Devices.List.FirstOrDefault() ?? await auth.RegisterDevice();
                    if (dc.DeviceKey?.Length > 0)
                    {
                        try
                        {
                            auth.DeviceToken = dc.DeviceToken.Base64UrlDecode();
                            auth.DeviceKey = CryptoUtils.LoadPrivateEcKey(dc.DeviceKey);
                            if (dc.Servers == null || dc.Servers.All(x => x != auth.Endpoint.Server))
                            {
                                await auth.RegisterDeviceInRegion(dc);
                            }
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e);
                        }

                    }
                    if (auth.DeviceKey == null)
                    {
                        if (dc?.DeviceToken != null)
                        {
                            auth.Storage.Devices.Delete(dc.DeviceToken);
                            auth.DeviceToken = null;
                        }
                        continue;
                    }
                }

                var cancellationTokenSource = new CancellationTokenSource();
                try
                {
                    try
                    {
                        var connectRequest = new WssConnectionRequest
                        {
                            EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                            MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                            DeviceTimeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                        };
                        auth.WebSocketChannel = await auth.Endpoint.ConnectToPushServer(connectRequest, cancellationTokenSource.Token);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }

                    var request = new StartLoginRequest
                    {
                        ClientVersion = auth.Endpoint.ClientVersion,
                        EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                        LoginType = LoginType.Normal,
                        LoginMethod = LoginMethod.ExistingAccount,
                        MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                        ForceNewLogin = forceNewLogin
                    };
                    if (auth.ResumeSession && auth.CloneCode != null)
                    {
                        request.CloneCode = ByteString.CopyFrom(auth.CloneCode);
                    }
                    else
                    {
                        request.Username = auth.Username;
                    }

                    var context = await auth.ExecuteStartLogin(request);
                    if (context.SessionTokenRestriction == 0 && auth.WebSocketChannel != null)
                    {
                        context.WebSocketChannel = auth.WebSocketChannel;
                        await context.WebSocketChannel.SendToWebSocket(context.SessionToken, false);
                        context.WebSocketChannel.RegisterCallback(wssResponse =>
                        {
                            try
                            {
                                var notificationEvent = JsonUtils.ParseJson<NotificationEvent>(Encoding.UTF8.GetBytes(wssResponse.Message));
                                context.PushNotifications.Push(notificationEvent);
                                return false;
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e);
                            }

                            return false;
                        });
                    }

                    return context;
                }
                catch (Exception e)
                {
                    if (auth.WebSocketChannel != null)
                    {
                        auth.WebSocketChannel.Dispose();
                        auth.WebSocketChannel = null;
                    }

                    cancellationTokenSource.Cancel();

                    if (attempt < 3 && e is KeeperInvalidDeviceToken)
                    {
                        auth.Storage.Devices.Delete(auth.DeviceToken.Base64UrlEncode());
                        auth.DeviceToken = null;
                        auth.DeviceKey = null;
                        continue;
                    }

                    Debug.WriteLine(e);
                    throw;
                }
            }
        }

        private static SessionTokenRestriction GetSessionTokenScope(SessionTokenType tokenTypes)
        {
            SessionTokenRestriction result = 0;
            switch (tokenTypes)
            {
                case SessionTokenType.AccountRecovery:
                    result |= SessionTokenRestriction.AccountRecovery;
                    break;
                case SessionTokenType.ShareAccount:
                    result |= SessionTokenRestriction.ShareAccount;
                    break;
                case SessionTokenType.AcceptInvite:
                    result |= SessionTokenRestriction.AcceptInvite;
                    break;
            }

            return result;
        }

        private static async Task<AuthContextV3> ExecuteValidateAuthHash(this AuthV3 auth, ByteString loginToken, string password, Salt salt)
        {
            var request = new ValidateAuthHashRequest
            {
                PasswordMethod = PasswordMethod.Entered,
                EncryptedLoginToken = loginToken,
                AuthResponse = ByteString.CopyFrom(CryptoUtils.DeriveV1KeyHash(password, salt.Salt_.ToByteArray(), salt.Iterations))
            };

#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"validate_auth_hash\": {request}");
#endif
            var rs = await auth.Endpoint.ExecuteRest("authentication/validate_auth_hash",
                new ApiRequestPayload {Payload = request.ToByteString()});
            var response = Authentication.LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST response: endpoint \"validate_auth_hash\": {response}");
#endif
            auth.Password = password;
            var authContext = new AuthContextV3
            {
                Username = response.PrimaryUsername,
                AccountUid = response.AccountUid.ToByteArray(),
                SessionToken = response.EncryptedSessionToken.ToByteArray(),
                SessionTokenRestriction = GetSessionTokenScope(response.SessionTokenType),
                CloneCode = response.CloneCode.ToByteArray(),
                DeviceToken = auth.DeviceToken,
                MessageSessionUid = auth.MessageSessionUid,
                DeviceKey = auth.DeviceKey,
            };
            var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
            switch (response.EncryptedDataKeyType)
            {
                case EncryptedDataKeyType.ByPassword:
                    authContext.DataKey = CryptoUtils.DecryptEncryptionParams(auth.Password, encryptedDataKey);
                    break;
                case EncryptedDataKeyType.ByDevicePublicKey:
                    authContext.DataKey = CryptoUtils.DecryptEc(encryptedDataKey, auth.DeviceKey);
                    break;
            }

            return authContext;
        }

        private static async Task<AuthContextV3> ValidateAuthHash(this AuthV3 auth, ByteString loginToken, IEnumerable<Salt> salts)
        {
            Salt masterSalt = null;
            Salt firstSalt = null;
            foreach (var salt in salts)
            {
                if (firstSalt == null)
                {
                    firstSalt = salt;
                }

                if (salt.Name == "Master")
                {
                    masterSalt = salt;
                }

                if (masterSalt != null)
                {
                    break;
                }
            }

            var saltInfo = masterSalt ?? firstSalt;
            if (saltInfo == null)
            {
                throw new KeeperStartLoginException(LoginState.RequiresAuthHash, "can not find salt");
            }

            while (true)
            {
                var password = auth.PasswordQueue.Count > 0 ? auth.PasswordQueue.Dequeue() : null;
                if (string.IsNullOrEmpty(password))
                {
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
                            password = passwordTask.Result;
                        }
                    }
                }

                if (string.IsNullOrEmpty(password)) throw new KeeperCanceled();

                try
                {
                    return await auth.ExecuteValidateAuthHash(loginToken, password, saltInfo);
                }
                catch (KeeperAuthFailed)
                {
                }
            }
        }

        private static async Task ExecuteDeviceApprovePushAction(
            this IAuth auth,
            TwoFactorPushType type,
            ByteString loginToken,
            TwoFactorExpiration expiration = TwoFactorExpiration.TwoFaExpImmediately)
        {
            var request = new TwoFactorSendPushRequest
            {
                EncryptedLoginToken = loginToken,
                PushType = type,
                ExpireIn = expiration
            };
            try
            {
                await auth.ExecutePushAction(request);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }
        }

        private static async Task ExecuteDeviceApproveOtpAction(
            this AuthV3 auth,
            TwoFactorValueType type,
            ByteString loginToken,
            string otp,
            TwoFactorExpiration expiration = TwoFactorExpiration.TwoFaExpImmediately)
        {
            var request = new TwoFactorValidateRequest
            {
                EncryptedLoginToken = loginToken,
                ValueType = type,
                Value = otp,
                ExpireIn = expiration
            };
            try
            {
                var validateRs = await auth.ExecuteTwoFactorValidateCode(request);
                var resumeToken = validateRs.EncryptedLoginToken.ToByteArray();
                var notification = new NotificationEvent
                {
                    Event = "received_totp",
                    EncryptedLoginToken = resumeToken.Base64UrlEncode(),
                };
                var wssRs = new WssClientResponse
                {
                    MessageType = MessageType.Dna,
                    Message = Encoding.UTF8.GetString(JsonUtils.DumpJson(notification)),
                };
                auth.WebSocketChannel.Push(wssRs);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }
        }

        private static async Task<AuthContextV3> ApproveDevice(this AuthV3 auth, ByteString loginToken)
        {
            var resumeLoginToken = loginToken;
            var loginTokenTaskSource = new TaskCompletionSource<bool>();
            IDeviceApprovalChannelInfo email = new DeviceApprovalEmailResend
            {
                InvokeDeviceApprovalPushAction = async () =>
                {
                    try
                    {
                        await auth.RequestDeviceVerification("email");
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                },
                InvokeDeviceApprovalOtpAction = async (code) =>
                {
                    try
                    {
                        await auth.ValidateDeviceVerificationCode(code);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                }
                
            };
            IDeviceApprovalChannelInfo push = new DeviceApprovalKeeperPushAction
            {
                InvokeDeviceApprovalPushAction = async () =>
                {
                    await auth.ExecuteDeviceApprovePushAction(TwoFactorPushType.TwoFaPushKeeper, loginToken);
                }
            };
            var otp = new DeviceApprovalTwoFactorAuth();
            otp.InvokeDeviceApprovalPushAction = async () =>
            {
                await auth.ExecuteDeviceApprovePushAction(TwoFactorPushType.TwoFaPushNone, loginToken, SdkExpirationToKeeper(otp.Duration));
            };
            otp.InvokeDeviceApprovalOtpAction = async (oneTimePassword) =>
            {
                await auth.ExecuteDeviceApproveOtpAction(TwoFactorValueType.TwoFaCodeNone, loginToken, oneTimePassword, SdkExpirationToKeeper(otp.Duration));
            };

            bool NotificationCallback(WssClientResponse rs)
            {
                if (loginTokenTaskSource.Task.IsCompleted) return true;
                var message = JsonUtils.ParseJson<NotificationEvent>(Encoding.UTF8.GetBytes(rs.Message));
                if (string.CompareOrdinal(message.Event, "received_totp") == 0)
                {
                    if (!string.IsNullOrEmpty(message.EncryptedLoginToken))
                    {
                        resumeLoginToken = ByteString.CopyFrom(message.EncryptedLoginToken.Base64UrlDecode());
                    }

                    loginTokenTaskSource.TrySetResult(true);
                    return true;
                }

                if (string.CompareOrdinal(message.Message, "device_approved") == 0)
                {
                    loginTokenTaskSource.TrySetResult(message.Approved);
                    return true;
                }

                if (string.CompareOrdinal(message.Command, "device_verified") == 0)
                {
                    loginTokenTaskSource.TrySetResult(true);
                    return true;
                }

                return false;
            }

            auth.WebSocketChannel?.RegisterCallback(NotificationCallback);

            var sdkCancellation = new CancellationTokenSource();
            var uiTask = auth.Ui.WaitForDeviceApproval(new[] {email, push, otp}, sdkCancellation.Token);
            var tokenTask = loginTokenTaskSource.Task;

            var index = Task.WaitAny(uiTask, tokenTask);
            if (index == 0)
            {
                auth.WebSocketChannel?.RemoveCallback(NotificationCallback);
                var resume = await uiTask;
                if (!resume) throw new KeeperCanceled();
            }
            else
            {
                sdkCancellation.Cancel();
            }

            return await auth.ResumeLogin(resumeLoginToken);
        }

        private static TwoFactorPushType SdkPushActionToKeeper(TwoFactorPushAction sdkPush)
        {
            switch (sdkPush)
            {
                case TwoFactorPushAction.DuoPush:
                    return TwoFactorPushType.TwoFaPushDuoPush;
                case TwoFactorPushAction.DuoTextMessage:
                    return TwoFactorPushType.TwoFaPushDuoText;
                case TwoFactorPushAction.DuoVoiceCall:
                    return TwoFactorPushType.TwoFaPushDuoCall;
                case TwoFactorPushAction.TextMessage:
                    return TwoFactorPushType.TwoFaPushSms;
                case TwoFactorPushAction.KeeperPush:
                    return TwoFactorPushType.TwoFaPushKeeper;
                default:
                    return TwoFactorPushType.TwoFaPushNone;
            }
        }

        private static TwoFactorExpiration SdkExpirationToKeeper(TwoFactorDuration duration)
        {
            switch (duration)
            {
                case TwoFactorDuration.EveryLogin:
                    return TwoFactorExpiration.TwoFaExpImmediately;
                case TwoFactorDuration.Every30Days:
                    return TwoFactorExpiration.TwoFaExp30Days;
                case TwoFactorDuration.Forever:
                    return TwoFactorExpiration.TwoFaExpNever;
                default:
                    return TwoFactorExpiration.TwoFaExp5Minutes;
            }
        }

        private static TwoFactorValueType SdkTwoFactorChannelToKeeper(TwoFactorChannel channel)
        {
            switch (channel)
            {
                case TwoFactorChannel.Authenticator:
                case TwoFactorChannel.KeeperDNA:
                    return TwoFactorValueType.TwoFaCodeTotp;
                case TwoFactorChannel.DuoSecurity:
                    return TwoFactorValueType.TwoFaCodeDuo;
                case TwoFactorChannel.RSASecurID:
                    return TwoFactorValueType.TwoFaCodeRsa;
                case TwoFactorChannel.TextMessage:
                    return TwoFactorValueType.TwoFaCodeSms;
                default:
                    return TwoFactorValueType.TwoFaCodeNone;
            }
        }

        private static async Task ExecutePushAction(this IAuth auth, TwoFactorSendPushRequest request)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"2fa_send_push\": {request}");
#endif
            await auth.Endpoint.ExecuteRest("authentication/2fa_send_push", new ApiRequestPayload {Payload = request.ToByteString()});
        }

        private static async Task<TwoFactorValidateResponse> ExecuteTwoFactorValidateCode(this IAuth auth, TwoFactorValidateRequest request)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"2fa_validate\": {request}");
#endif
            var rs = await auth.Endpoint.ExecuteRest("authentication/2fa_validate",
                new ApiRequestPayload
                {
                    Payload = request.ToByteString()
                });
            var response = TwoFactorValidateResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"2fa_validate\": {response}");
#endif
            return response;
        }

        private static TwoFactorPushActionDelegate GetActionDelegate(IAuth auth, TwoFactorChannelInfo info, ByteString loginToken)
        {
            return async (action, duration) =>
            {
                var rq = new TwoFactorSendPushRequest
                {
                    ChannelUid = info.ChannelUid,
                    ExpireIn = SdkExpirationToKeeper(duration),
                    EncryptedLoginToken = loginToken,
                    PushType = SdkPushActionToKeeper(action)
                };
                try
                {
                    await auth.ExecutePushAction(rq);
                    return true;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e);
                    return false;
                }

            };
        }

        private static async Task<AuthContextV3> TwoFactorValidate(this AuthV3 auth,
            ByteString loginToken,
            IEnumerable<TwoFactorChannelInfo> channels)
        {
            var resumeWithToken = loginToken;
            var firstChannel = TwoFactorChannel.Other;
            var availableChannels = new List<ITwoFactorChannelInfo>();

            foreach (var ch in channels)
            {
                switch (ch.ChannelType)
                {
                    case TwoFactorChannelType.TwoFaCtTotp:
                        availableChannels.Add(new AuthenticatorTwoFactorChannel());
                        break;

                    case TwoFactorChannelType.TwoFaCtRsa:
                        availableChannels.Add(new RsaSecurIdTwoFactorChannel());
                        break;

                    case TwoFactorChannelType.TwoFaCtSms:
                        availableChannels.Add(new TwoFactorSmsChannel
                        {
                            InvokeTwoFactorPushAction = GetActionDelegate(auth, ch, loginToken)
                        });
                        break;

                    case TwoFactorChannelType.TwoFaCtDuo:
                        var duoTfa = new TwoFactorDuoChannel
                        {
                            InvokeTwoFactorPushAction = GetActionDelegate(auth, ch, loginToken),
                            SupportedActions = (ch.Capabilities ?? Enumerable.Empty<string>())
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
                                    }

                                    return null;
                                })
                                .Where(x => x.HasValue)
                                .Select(x => x.Value)
                                .ToArray()
                        };

                        availableChannels.Add(duoTfa);
                        break;

                    case TwoFactorChannelType.TwoFaCtKeeper:
                        availableChannels.Add(new TwoFactorKeeperDnaChannel
                        {
                            InvokeTwoFactorPushAction = GetActionDelegate(auth, ch, loginToken)
                        });
                        break;

                    case TwoFactorChannelType.TwoFaCtU2F:
                    case TwoFactorChannelType.TwoFaCtWebauthn:
                        break;
                }

                var chi = availableChannels.FirstOrDefault(x => x.Channel != TwoFactorChannel.Other);
                if (chi != null)
                {
                    firstChannel = chi.Channel;
                }
            }

            while (true)
            {

                var loginTaskSource = new TaskCompletionSource<bool>();

                bool NotificationCallback(WssClientResponse rs)
                {
                    if (loginTaskSource.Task.IsCompleted) return true;
                    var message = JsonUtils.ParseJson<NotificationEvent>(Encoding.UTF8.GetBytes(rs.Message));
                    if (message.Event != "received_totp") return false;
                    if (string.IsNullOrEmpty(message.EncryptedLoginToken)) return false;
                    resumeWithToken = ByteString.CopyFrom(message.EncryptedLoginToken.Base64UrlDecode());
                    loginTaskSource.TrySetResult(true);
                    return true;
                }

                auth.WebSocketChannel?.RegisterCallback(NotificationCallback);

                using (var tokenSource = new CancellationTokenSource())
                {
                    var userTask = auth.Ui.GetTwoFactorCode(firstChannel, availableChannels.ToArray(), tokenSource.Token);
                    int index = Task.WaitAny(userTask, loginTaskSource.Task);
                    auth.WebSocketChannel?.RemoveCallback(NotificationCallback);
                    if (index == 0)
                    {
                        loginTaskSource.TrySetCanceled();

                        var twoFaCode = await userTask;
                        if (twoFaCode == null || string.IsNullOrEmpty(twoFaCode.Code))
                            throw new KeeperCanceled();

                        var expiration = SdkExpirationToKeeper(twoFaCode.Duration);
                        var tfaType = SdkTwoFactorChannelToKeeper(twoFaCode.Channel);
                        var request = new TwoFactorValidateRequest
                        {
                            EncryptedLoginToken = loginToken,
                            ExpireIn = expiration,
                            ValueType = tfaType,
                            Value = twoFaCode.Code,
                        };
                        try
                        {
                            var validateRs = await auth.ExecuteTwoFactorValidateCode(request);
                            resumeWithToken = validateRs.EncryptedLoginToken;
                            break;
                        }
                        catch (KeeperAuthFailed)
                        {
                        }
                    }
                    else
                    {
                        tokenSource.Cancel();
                        break;
                    }
                }
            }

            return await auth.ResumeLogin(resumeWithToken);
        }

        internal static void StoreConfigurationIfChangedV3(this Auth auth, AuthContextV3 context)
        {
            if (string.CompareOrdinal(auth.Storage.LastLogin ?? "", context.Username) != 0)
            {
                auth.Storage.LastLogin = context.Username;
            }

            if (string.CompareOrdinal(auth.Storage.LastServer ?? "", auth.Endpoint.Server) != 0)
            {
                auth.Storage.LastServer = auth.Endpoint.Server;
            }

            var sc = auth.Storage.Servers.Get(auth.Endpoint.Server);
            if (sc == null || sc.Server != auth.Endpoint.Server || sc.ServerKeyId != auth.Endpoint.ServerKeyId)
            {
                var serverConf = sc == null ? new ServerConfiguration(auth.Endpoint.Server) : new ServerConfiguration(sc);
                serverConf.ServerKeyId = auth.Endpoint.ServerKeyId;
                auth.Storage.Servers.Put(serverConf);
            }

            var existingUser = auth.Storage.Users.Get(context.Username);
            var deviceToken = context.DeviceToken.Base64UrlEncode();
            if (existingUser == null || auth.ResumeSession || existingUser.LastDevice?.DeviceToken != deviceToken)
            {
                var uc = existingUser != null ? new UserConfiguration(existingUser) : new UserConfiguration(context.Username);
                uc.Server = auth.Endpoint.Server;
                UserDeviceConfiguration lastDevice;
                if (existingUser?.LastDevice != null && existingUser.LastDevice.DeviceToken == deviceToken)
                {
                    lastDevice = new UserDeviceConfiguration(existingUser.LastDevice);
                }
                else
                {
                    lastDevice = new UserDeviceConfiguration(deviceToken);
                }
                lastDevice.ResumeCode = auth.ResumeSession ? context.CloneCode.Base64UrlEncode() : null;

                uc.LastDevice = lastDevice;
                auth.Storage.Users.Put(uc);
            }
        }

        internal static async Task<AuthContextV3> AuthorizeUsingOnsiteSso(this AuthV3 auth, Authentication.LoginResponse response)
        {
            Salt masterSalt = null;
            Salt firstSalt = null;
            foreach (var salt in response.Salt)
            {
                if (firstSalt == null)
                {
                    firstSalt = salt;
                }

                if (salt.Name == "Master")
                {
                    masterSalt = salt;
                }

                if (masterSalt != null)
                {
                    break;
                }
            }

            var saltInfo = masterSalt ?? firstSalt;
            if (saltInfo == null)
            {
                throw new KeeperStartLoginException(LoginState.RequiresAuthHash, "can not find salt");
            }

            while (auth.PasswordQueue.Count > 0)
            {
                var pwd = auth.PasswordQueue.Dequeue();
                if (string.IsNullOrEmpty(pwd)) continue;
                try
                {
                    return await auth.ExecuteValidateAuthHash(response.EncryptedLoginToken, pwd, saltInfo);
                }
                catch (KeeperAuthFailed)
                {
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e);
                }
            }

            if (auth.Ui != null && auth.Ui is IAuthSsoUI ssoUi)
            {
                var queryString = System.Web.HttpUtility.ParseQueryString("");
                CryptoUtils.GenerateRsaKey(out var privateKey, out var publicKey);
                queryString.Add("key", publicKey.Base64UrlEncode());
                var builder = new UriBuilder(new Uri(response.Url))
                {
                    Query = queryString.ToString()
                };
                var userTask = ssoUi.GetSsoToken(builder.Uri.AbsoluteUri, false);
                var index = Task.WaitAny(userTask);
                if (index == 0)
                {
                    if (userTask.IsFaulted)
                    {
                        throw userTask.Exception.GetBaseException();
                    }

                    if (userTask.IsCanceled)
                    {
                        throw new KeeperCanceled();
                    }

                    var tokenStr = userTask.Result;
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

                    return await auth.ResumeLogin(response.EncryptedLoginToken, LoginMethod.AfterSso);
                }
            }

            throw new KeeperAuthFailed();
        }

        internal static async Task<AuthContextV3> AuthorizeUsingCloudSso(this AuthV3 auth, Authentication.LoginResponse response)
        {
            if (auth.Ui != null && auth.Ui is IAuthSsoUI ssoUi)
            {
                var rq = new SsoCloudRequest
                {
                    ClientVersion = auth.Endpoint.ClientVersion,
                    MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                    Embedded = true,
                    ForceLogin = false
                };
                var transmissionKey = CryptoUtils.GenerateEncryptionKey();
                var apiRequest = auth.Endpoint.PrepareApiRequest(rq, transmissionKey);

                var queryString = System.Web.HttpUtility.ParseQueryString("");
                queryString.Add("payload", apiRequest.ToByteArray().Base64UrlEncode());
                var builder = new UriBuilder(new Uri(response.Url))
                {
                    Query = queryString.ToString()
                };

                var tokenTask = ssoUi.GetSsoToken(builder.Uri.AbsoluteUri, true);
                var index = Task.WaitAny(tokenTask);
                if (index == 0)
                {
                    if (tokenTask.IsFaulted)
                    {
                        throw tokenTask.Exception.GetBaseException();
                    }

                    if (tokenTask.IsCanceled)
                    {
                        throw new KeeperCanceled();
                    }

                    var rsBytes = tokenTask.Result.Base64UrlDecode();
                    rsBytes = CryptoUtils.DecryptAesV2(rsBytes, transmissionKey);
                    var rs = SsoCloudResponse.Parser.ParseFrom(rsBytes);
                    return await auth.ResumeLogin(rs.EncryptedLoginToken, LoginMethod.AfterSso);
                }
            }

            throw new KeeperAuthFailed();
        }

        internal static async Task<AuthContextV3> CreateSsoUser(this AuthV3 auth, ByteString loginToken)
        {
            var dataKey = CryptoUtils.GenerateEncryptionKey();
            var clientKey = CryptoUtils.GenerateEncryptionKey();
            CryptoUtils.GenerateEcKey(out var ecPrivateKey, out var ecPublicKey);
            CryptoUtils.GenerateRsaKey(out var rsaPrivateKey, out var rsaPublicKey);
            var devicePublicKey = CryptoUtils.GetPublicEcKey(auth.DeviceKey);
            var request = new CreateUserRequest
            {
                Username = auth.Username,
                RsaPublicKey = ByteString.CopyFrom(rsaPublicKey),
                RsaEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(rsaPrivateKey, dataKey)),
                EccPublicKey = ByteString.CopyFrom(CryptoUtils.UnloadEcPublicKey(ecPublicKey)),
                EccEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(CryptoUtils.UnloadEcPrivateKey(ecPrivateKey), dataKey)),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                EncryptedClientKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(clientKey, dataKey)),
                ClientVersion = auth.Endpoint.ClientVersion,
                EncryptedDeviceDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(dataKey, devicePublicKey)),
                EncryptedLoginToken = loginToken,
                MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
            };
            var apiRequest = new ApiRequestPayload
            {
                Payload = request.ToByteString()
            };
            await auth.Endpoint.ExecuteRest("authentication/create_user_sso", apiRequest);

            return await auth.ResumeLogin(loginToken);
        }

        internal static async Task RequestDeviceAdminApproval(this AuthV3 auth)
        {
            var request = new DeviceVerificationRequest
            {
                Username = auth.Username,
                ClientVersion = auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(auth.MessageSessionUid),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"request_device_admin_approval\": {request}");
#endif
            await auth.Endpoint.ExecuteRest("authentication/request_device_admin_approval",
                new ApiRequestPayload { Payload = request.ToByteString() });
        }


        internal static async Task<AuthContextV3> RequestDataKey(this AuthV3 auth, ByteString loginToken)
        {
            if (!(auth.Ui is IAuthSsoUI ssoUi)) throw new KeeperCanceled();

            var completeToken = new CancellationTokenSource();
            var completeTask = new TaskCompletionSource<bool>();

            var pushChannel = new GetDataKeyActionInfo(DataKeyShareChannel.KeeperPush)
            {
                InvokeGetDataKeyAction = async () =>
                {
                    var rq = new TwoFactorSendPushRequest
                    {
                        PushType = TwoFactorPushType.TwoFaPushKeeper,
                        EncryptedLoginToken = loginToken,
                    };
                    await auth.ExecutePushAction(rq);
                }
            };

            var adminChannel = new GetDataKeyActionInfo(DataKeyShareChannel.AdminApproval)
            {
                InvokeGetDataKeyAction = async () =>
                {
                    await auth.RequestDeviceAdminApproval();
                }
            };

            bool ProcessDataKeyRequest(WssClientResponse wssRs)
            {
                if (completeTask.Task.IsCompleted) return true;
                var message = JsonUtils.ParseJson<NotificationEvent>(Encoding.UTF8.GetBytes(wssRs.Message));
                if (string.CompareOrdinal(message.Message, "device_approved") == 0)
                {
                    completeTask.TrySetResult(message.Approved);
                    return true;
                }
                if (string.CompareOrdinal(message.Command, "device_verified") == 0)
                {
                    completeTask.TrySetResult(true);
                    return true;
                }
                return false;
            }

            auth.WebSocketChannel.RegisterCallback(ProcessDataKeyRequest);
            var uiTask = ssoUi.WaitForDataKey(new IGetDataKeyChannelInfo[] {pushChannel, adminChannel}, completeToken.Token);
            var index = Task.WaitAny(uiTask, completeTask.Task);
            auth.WebSocketChannel.RemoveCallback(ProcessDataKeyRequest);
            if (index == 0)
            {
                var result = await uiTask;
                if (!result) throw new KeeperCanceled();
            }
            else
            {
                completeToken.Cancel();
            }

            return await auth.ResumeLogin(loginToken);
        }
    }

    [DataContract]
    internal class SsoToken
    {
        [DataMember(Name = "command")]
        public string Command { get; set; }

        [DataMember(Name = "result")]
        public string Result { get; set; }

        [DataMember(Name = "email")]
        public string Email { get; set; }

        [DataMember(Name = "password")]
        public string Password { get; set; }

        [DataMember(Name = "new_password")]
        public string NewPassword { get; set; }

        [DataMember(Name = "provider_name")]
        public string ProviderName { get; set; }

        [DataMember(Name = "session_id")]
        public string SessionId { get; set; }

        [DataMember(Name = "login_token")]
        public string LoginToken { get; set; }
    }
}
