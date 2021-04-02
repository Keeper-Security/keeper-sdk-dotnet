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
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using Push;
using SsoCloud;

namespace KeeperSecurity.Authentication
{
    /// <exclude />
    public class LoginContext
    {
        public LoginContext()
        {
            MessageSessionUid = CryptoUtils.GetRandomBytes(16);
            AccountAuthType = AccountAuthType.Regular;
        }

        public AccountAuthType AccountAuthType { get; set; }

        public byte[] CloneCode { get; set; }

        internal string V2TwoFactorToken { get; set; }

       public ECPrivateKeyParameters DeviceKey { get; set; }

        public byte[] MessageSessionUid { get; }
        internal Queue<string> PasswordQueue { get; } = new Queue<string>();

        internal SsoLoginInfo SsoLoginInfo { get; set; }
    }

    /// <exclude />
    public static class LoginV3Extensions
    {
        public static async Task EnsureDeviceTokenIsRegistered(this IAuth auth, LoginContext v3, string username)
        {
            if (string.Compare(auth.Username, username, StringComparison.InvariantCultureIgnoreCase) != 0)
            {
                auth.Username = username;
                auth.DeviceToken = null;
                v3.DeviceKey = null;
                v3.CloneCode = null;
            }

            IDeviceConfiguration deviceConf = null;
            if (auth.DeviceToken != null)
            {
                var token = auth.DeviceToken.Base64UrlEncode();
                deviceConf = auth.Storage.Devices.Get(token);
                if (deviceConf == null)
                {
                    auth.DeviceToken = null;
                    v3.DeviceKey = null;
                    v3.CloneCode = null;
                }
            }

            var userConf = auth.Storage.Users.Get(auth.Username);
            var lastDevice = userConf?.LastDevice;
            var attempt = 0;
            while (auth.DeviceToken == null || v3.DeviceKey == null)
            {
                attempt++;
                if (attempt > 10) throw new KeeperInvalidDeviceToken("too many attempts");

                auth.DeviceToken = null;
                v3.DeviceKey = null;
                v3.CloneCode = null;

                if (lastDevice != null)
                {
                    deviceConf = auth.Storage.Devices.Get(lastDevice.DeviceToken);
                    if (deviceConf != null)
                    {
                        var serverInfo = deviceConf.ServerInfo?.Get(auth.Endpoint.Server);
                        if (serverInfo != null)
                        {
                            v3.CloneCode = serverInfo.CloneCode.Base64UrlDecode();
                        }
                    }

                    lastDevice = null;
                }

                if (deviceConf == null)
                {
                    deviceConf = auth.Storage.Devices.List.FirstOrDefault();
                }

                if (deviceConf == null)
                {
                    deviceConf = await auth.RegisterDevice();
                }

                try
                {
                    if (!(deviceConf.DeviceKey?.Length > 0)) throw new KeeperInvalidDeviceToken("invalid configuration");
                    auth.DeviceToken = deviceConf.DeviceToken.Base64UrlDecode();
                    v3.DeviceKey = CryptoUtils.LoadPrivateEcKey(deviceConf.DeviceKey);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    auth.Storage.Devices.Delete(deviceConf.DeviceToken);
                    deviceConf = null;
                }
            }

            {
                var token = auth.DeviceToken.Base64UrlEncode();
                deviceConf = auth.Storage.Devices.Get(token);
                if (deviceConf == null) throw new KeeperInvalidDeviceToken("invalid configuration");
                if (deviceConf.ServerInfo?.Get(auth.Endpoint.Server) == null)
                {
                    await auth.RegisterDeviceInRegion(deviceConf);
                }
            }

            {
                if (attempt > 0 && auth.PushNotifications != null)
                {
                    try
                    {
                        auth.PushNotifications.Dispose();
                        auth.SetPushNotifications(null);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }

                if (auth.PushNotifications == null)
                {
                    var cancellationTokenSource = new CancellationTokenSource();
                    try
                    {
                        var connectRequest = new WssConnectionRequest
                        {
                            EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                            MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                            DeviceTimeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                        };
                        var pushes = await auth.Endpoint.ConnectToPushServer(connectRequest, cancellationTokenSource.Token);
                        auth.SetPushNotifications(pushes);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }
            }
        }

        internal static async Task RedirectToRegionV3(this IAuth auth, string newRegion)
        {
            auth.Endpoint.Server = newRegion;
            if (auth.AuthCallback is IAuthInfoUI infoUi)
            {
                infoUi.RegionChanged(auth.Endpoint.Server);
            }

            if (auth.DeviceToken != null)
            {
                var token = auth.DeviceToken.Base64UrlEncode();
                var deviceConf = auth.Storage.Devices.Get(token);
                if (deviceConf == null) throw new KeeperInvalidDeviceToken("invalid configuration");

                if (deviceConf.ServerInfo?.Get(auth.Endpoint.Server) == null)
                {
                    await auth.RegisterDeviceInRegion(deviceConf);
                }
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
            catch (KeeperApiException kae)
            {
                if (kae.Code != "exists")
                {
                    throw;
                }
            }
            catch (KeeperInvalidDeviceToken idt)
            {
                Debug.WriteLine(idt.Message);
                if (idt.AdditionalInfo != "public key already exists")
                {
                    throw;
                }
            }

            var dc = new DeviceConfiguration(device);
            dc.ServerInfo.Put(new DeviceServerConfiguration(auth.Endpoint.Server));
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
            dc.ServerInfo.Put(new DeviceServerConfiguration(auth.Endpoint.Server));
            auth.Storage.Devices.Put(dc);

            return dc;
        }

        private static async Task RequestDeviceVerification(this IAuth auth, LoginContext v3, string channel)
        {
            var request = new DeviceVerificationRequest
            {
                Username = auth.Username,
                ClientVersion = auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                VerificationChannel = channel
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"request_device_verification\": {request}");
#endif
            await auth.Endpoint.ExecuteRest("authentication/request_device_verification",
                new ApiRequestPayload {Payload = request.ToByteString()});
        }

        internal static async Task ValidateDeviceVerificationCode(this IAuth auth, LoginContext v3, string code)
        {
            var request = new ValidateDeviceVerificationCodeRequest
            {
                Username = auth.Username,
                ClientVersion = auth.Endpoint.ClientVersion,
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                VerificationCode = code
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"validate_device_verification_code\": {request}");
#endif
            await auth.Endpoint.ExecuteRest("authentication/validate_device_verification_code",
                new ApiRequestPayload {Payload = request.ToByteString()});
        }

        internal static Task<T> ResumeLogin<T>(
            this IAuth auth,
            LoginContext v3,
            Func<StartLoginRequest, Task<T>> onContinue,
            ByteString loginToken,
            LoginMethod method = LoginMethod.ExistingAccount)
        {
            var request = new StartLoginRequest
            {
                ClientVersion = auth.Endpoint.ClientVersion,
                EncryptedLoginToken = loginToken,
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                Username = auth.Username,
                LoginMethod = method,
            };
            if (auth.ResumeSession && v3.CloneCode != null)
            {
                request.CloneCode = ByteString.CopyFrom(v3.CloneCode);
            }

            return onContinue(request);
        }

        internal static async Task<T> StartLogin<T>(
            this IAuth auth,
            LoginContext v3,
            Func<StartLoginRequest, Task<T>> onComplete,
            bool forceNewLogin = false,
            LoginMethod loginMethod = LoginMethod.ExistingAccount)
        {
            var attempt = 0;

            while (true)
            {
                attempt++;
                await auth.EnsureDeviceTokenIsRegistered(v3, auth.Username);
                if (auth.AuthCallback is IAuthInfoUI infoUi)
                {
                    infoUi.SelectedDevice(auth.DeviceToken.Base64UrlEncode());
                }

                if (auth.ResumeSession && v3.CloneCode == null)
                {
                    v3.CloneCode = new byte[0];
                }

                try
                {
                    var request = new StartLoginRequest
                    {
                        ClientVersion = auth.Endpoint.ClientVersion,
                        EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                        LoginType = auth.AlternatePassword ? LoginType.Alternate : LoginType.Normal,
                        LoginMethod = loginMethod,
                        MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                        ForceNewLogin = forceNewLogin,
                    };
                    if (!forceNewLogin && auth.ResumeSession && loginMethod == LoginMethod.ExistingAccount && v3.CloneCode != null)
                    {
                        request.CloneCode = ByteString.CopyFrom(v3.CloneCode);
                    }
                    else
                    {
                        request.Username = auth.Username;
                        if (!string.IsNullOrEmpty(v3.V2TwoFactorToken))
                        {
                            request.V2TwoFactorToken = v3.V2TwoFactorToken;
                        }
                    }

                    return await onComplete(request);
                }
                catch (Exception e)
                {
                    auth.PushNotifications?.Dispose();
                    auth.SetPushNotifications(null);
                    if (attempt < 3 && e is KeeperInvalidDeviceToken)
                    {
                        auth.Storage.Devices.Delete(auth.DeviceToken.Base64UrlEncode());
                        auth.DeviceToken = null;
                        v3.DeviceKey = null;
                        continue;
                    }

                    Debug.WriteLine(e.Message);
                    throw;
                }
            }
        }

        internal static SessionTokenRestriction GetSessionTokenScope(SessionTokenType tokenTypes)
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
                case SessionTokenType.Restrict:
                case SessionTokenType.Purchase:
                    result |= SessionTokenRestriction.AccountExpired;
                    break;
            }

            return result;
        }

        private static async Task<AuthContext> ExecuteValidateBiometricKey(
            this IAuth auth,
            LoginContext v3,
            ByteString loginToken,
            byte[] biometricKey)
        {
            var request = new ValidateAuthHashRequest
            {
                PasswordMethod = PasswordMethod.Biometrics,
                EncryptedLoginToken = loginToken,
                AuthResponse = ByteString.CopyFrom(CryptoUtils.CreateBioAuthHash(biometricKey))
            };
            var context = await auth.ExecuteValidateAuthHash(v3,
                request,
                (keyType, encryptedKey) =>
                {
                    switch (keyType)
                    {
                        case EncryptedDataKeyType.ByAlternate:
                        case EncryptedDataKeyType.ByBio:
                            return CryptoUtils.DecryptAesV2(encryptedKey, biometricKey);
                    }

                    throw new KeeperCanceled();
                });
            return context;
        }

        private static async Task<AuthContext> ExecuteValidatePassword(
            this IAuth auth,
            LoginContext v3,
            ByteString loginToken,
            string password,
            Salt salt)
        {
            var request = new ValidateAuthHashRequest
            {
                PasswordMethod = PasswordMethod.Entered,
                EncryptedLoginToken = loginToken,
                AuthResponse = ByteString.CopyFrom(CryptoUtils.DeriveV1KeyHash(password, salt.Salt_.ToByteArray(), salt.Iterations))
            };

            var context = await auth.ExecuteValidateAuthHash(v3, request,
                (keyType, encryptedKey) =>
                {
                    switch (keyType)
                    {
                        case EncryptedDataKeyType.ByAlternate:
                            var key = CryptoUtils.DeriveKeyV2("data_key", password, salt.Salt_.ToByteArray(), salt.Iterations);
                            return CryptoUtils.DecryptAesV2(encryptedKey, key);
                        case EncryptedDataKeyType.ByPassword:
                            return CryptoUtils.DecryptEncryptionParams(password, encryptedKey);
                    }
                    throw new KeeperCanceled();
                });
            var validatorSalt = CryptoUtils.GetRandomBytes(16);
            context.PasswordValidator =
                CryptoUtils.CreateEncryptionParams(password, validatorSalt, 100000, CryptoUtils.GetRandomBytes(32));
            return context;
        }

        private static async Task<AuthContext> ExecuteValidateAuthHash(
            this IAuth auth, 
            LoginContext v3, 
            ValidateAuthHashRequest request,
            Func<EncryptedDataKeyType, byte[], byte[]> dataKeyDecryptor)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"validate_auth_hash\": {request}");
#endif
            var rs = await auth.Endpoint.ExecuteRest("authentication/validate_auth_hash",
                new ApiRequestPayload {Payload = request.ToByteString()});
            var response = LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST response: endpoint \"validate_auth_hash\": {response}");
#endif
            auth.Username = response.PrimaryUsername;
            v3.CloneCode = response.CloneCode.ToByteArray();
            var authContext = new AuthContext
            {
                SessionToken = response.EncryptedSessionToken.ToByteArray(),
                SessionTokenRestriction = GetSessionTokenScope(response.SessionTokenType),
                SsoLoginInfo = v3.SsoLoginInfo,
            };

            var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
            authContext.DataKey = dataKeyDecryptor(response.EncryptedDataKeyType, encryptedDataKey);
            return authContext;
        }

        internal static MasterPasswordInfo ValidateAuthHashPrepare(
            this IAuth auth,
            LoginContext v3,
            Func<AuthContext, Task> onAuthHashValidated,
            ByteString loginToken,
            IEnumerable<Salt> salts)
        {
            Salt passwordSalt = null;
            Salt firstSalt = null;
            foreach (var salt in salts)
            {
                if (firstSalt == null)
                {
                    firstSalt = salt;
                }

                if (string.Compare(salt.Name, auth.AlternatePassword ? "alternate" : "master", StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    passwordSalt = salt;
                }

                if (passwordSalt != null)
                {
                    break;
                }
            }

            var saltInfo = passwordSalt ?? firstSalt;
            if (saltInfo == null)
            {
                throw new KeeperStartLoginException(
                    LoginState.RequiresAuthHash, 
                    "Master Password has not been created.");
            }

            return new MasterPasswordInfo(auth.Username)
            {
                InvokePasswordActionDelegate = async password =>
                {
                    var context = await auth.ExecuteValidatePassword(v3, loginToken, password, saltInfo);
                    await onAuthHashValidated.Invoke(context);
                },
                InvokeBiometricsActionDelegate = async bioKey =>
                {
                    var context = await auth.ExecuteValidateBiometricKey(v3, loginToken, bioKey);
                    await onAuthHashValidated.Invoke(context);
                }
            };
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
                Debug.WriteLine(e.Message);
            }
        }

        private static async Task ExecuteDeviceApproveOtpAction(
            this IAuth auth,
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
                auth.PushNotifications?.Push(notification);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
        }

        internal static Tuple<IDeviceApprovalChannelInfo[], Action> ApproveDevicePrepare(
            this IAuth auth,
            LoginContext v3,
            Action<ByteString> onLoginToken,
            ByteString loginToken)
        {
            var email = new DeviceApprovalEmailResend();
            email.InvokeDeviceApprovalPushAction = async () =>
            {
                await auth.RequestDeviceVerification(v3, email.Resend ? "email_resend" : "email");
                email.Resend = true;
            };
            email.InvokeDeviceApprovalOtpAction = async (code) =>
            {
                await auth.ValidateDeviceVerificationCode(v3, code);
                onLoginToken(loginToken);
            };

            var push = new DeviceApprovalKeeperPushAction
            {
                InvokeDeviceApprovalPushAction = async () => { await auth.ExecuteDeviceApprovePushAction(TwoFactorPushType.TwoFaPushKeeper, loginToken); }
            };

            var otp = new TwoFactorTwoFactorAuth();
            otp.InvokeDeviceApprovalPushAction = async () => { await auth.ExecuteDeviceApprovePushAction(TwoFactorPushType.TwoFaPushNone, loginToken, SdkExpirationToKeeper(otp.Duration)); };
            otp.InvokeDeviceApprovalOtpAction = async (oneTimePassword) => { await auth.ExecuteDeviceApproveOtpAction(TwoFactorValueType.TwoFaCodeNone, loginToken, oneTimePassword, SdkExpirationToKeeper(otp.Duration)); };

            bool NotificationCallback(NotificationEvent message)
            {
                if (string.CompareOrdinal(message.Event, "received_totp") == 0)
                {
                    var token = loginToken;
                    if (!string.IsNullOrEmpty(message.EncryptedLoginToken))
                    {
                        token = ByteString.CopyFrom(message.EncryptedLoginToken.Base64UrlDecode());
                    }

                    onLoginToken(token);
                    return true;
                }

                if (string.CompareOrdinal(message.Message, "device_approved") == 0)
                {
                    if (message.Approved)
                    {
                        onLoginToken(loginToken);
                        return true;
                    }
                }

                if (string.CompareOrdinal(message.Command, "device_verified") == 0)
                {
                    onLoginToken(loginToken);
                    return true;
                }

                return false;
            }

            auth.PushNotifications?.RegisterCallback(NotificationCallback);

            return Tuple.Create<IDeviceApprovalChannelInfo[], Action>(
                new IDeviceApprovalChannelInfo[] {email, push, otp},
                () => { auth.PushNotifications?.RemoveCallback(NotificationCallback); });
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
                case TwoFactorPushAction.KeeperDna:
                    return TwoFactorPushType.TwoFaPushDna;
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

        private static TwoFactorValueType TwoFactorChannelToValue(TwoFactorChannelType channel)
        {
            switch (channel)
            {
                case TwoFactorChannelType.TwoFaCtDna:
                    return TwoFactorValueType.TwoFaCodeDna;
                case TwoFactorChannelType.TwoFaCtTotp:
                    return TwoFactorValueType.TwoFaCodeTotp;
                case TwoFactorChannelType.TwoFaCtDuo:
                    return TwoFactorValueType.TwoFaCodeDuo;
                case TwoFactorChannelType.TwoFaCtRsa:
                    return TwoFactorValueType.TwoFaCodeRsa;
                case TwoFactorChannelType.TwoFaCtSms:
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

        internal static Tuple<ITwoFactorChannelInfo[], Action> TwoFactorValidatePrepare(
            this IAuth auth,
            Action<ByteString> onLoginToken,
            ByteString loginToken,
            IEnumerable<TwoFactorChannelInfo> channels)
        {
            var resumeWithToken = loginToken;

            ITwoFactorPushInfo lastUsedChannel = null;

            TwoFactorPushActionDelegate GetActionDelegate(ITwoFactorPushInfo channel, TwoFactorChannelInfo info)
            {
                return async action =>
                {
                    var duration = channel is ITwoFactorDurationInfo dur ? dur.Duration : TwoFactorDuration.EveryLogin;

                    var rq = new TwoFactorSendPushRequest
                    {
                        ChannelUid = info.ChannelUid,
                        ExpireIn = SdkExpirationToKeeper(duration),
                        EncryptedLoginToken = loginToken,
                        PushType = SdkPushActionToKeeper(action)
                    };
                    await auth.ExecutePushAction(rq);
                    lastUsedChannel = channel;
                };
            }

            TwoFactorCodeActionDelegate GetCodeDelegate(ITwoFactorAppCodeInfo channel, TwoFactorChannelInfo info)
            {
                return async code =>
                {
                    var duration = channel is ITwoFactorDurationInfo dur ? dur.Duration : TwoFactorDuration.EveryLogin;

                    var request = new TwoFactorValidateRequest
                    {
                        EncryptedLoginToken = loginToken,
                        ExpireIn = SdkExpirationToKeeper(duration),
                        ValueType = TwoFactorChannelToValue(info.ChannelType),
                        Value = code,
                    };
                    var validateRs = await auth.ExecuteTwoFactorValidateCode(request);
                    onLoginToken(validateRs.EncryptedLoginToken);
                };
            }

            var availableChannels = new List<ITwoFactorChannelInfo>();
            foreach (var ch in channels)
            {
                switch (ch.ChannelType)
                {
                    case TwoFactorChannelType.TwoFaCtTotp:
                    {
                        var totp = new AuthenticatorTwoFactorChannel();
                        totp.InvokeTwoFactorCodeAction = GetCodeDelegate(totp, ch);
                        availableChannels.Add(totp);
                    }
                        break;

                    case TwoFactorChannelType.TwoFaCtRsa:
                    {
                        var rsa = new RsaSecurIdTwoFactorChannel();
                        rsa.InvokeTwoFactorCodeAction = GetCodeDelegate(rsa, ch);
                        availableChannels.Add(rsa);
                    }
                        break;

                    case TwoFactorChannelType.TwoFaCtSms:
                    {
                        var sms = new TwoFactorSmsChannel
                        {
                            PhoneNumber = ch.PhoneNumber,
                        };
                        sms.InvokeTwoFactorPushAction = GetActionDelegate(sms, ch);
                        sms.InvokeTwoFactorCodeAction = GetCodeDelegate(sms, ch);
                        availableChannels.Add(sms);
                    }
                        break;

                    case TwoFactorChannelType.TwoFaCtDuo:
                    {
                        var duoTfa = new TwoFactorDuoChannel
                        {
                            PhoneNumber = ch.PhoneNumber,
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
                        duoTfa.InvokeTwoFactorPushAction = GetActionDelegate(duoTfa, ch);
                        duoTfa.InvokeTwoFactorCodeAction = GetCodeDelegate(duoTfa, ch);
                        availableChannels.Add(duoTfa);
                    }
                        break;

                    case TwoFactorChannelType.TwoFaCtDna:
                    {
                        var dna2Fa = new TwoFactorKeeperDnaChannel
                        {
                            PhoneNumber = ch.PhoneNumber
                        };
                        dna2Fa.InvokeTwoFactorPushAction = GetActionDelegate(dna2Fa, ch);
                        dna2Fa.InvokeTwoFactorCodeAction = GetCodeDelegate(dna2Fa, ch);
                        availableChannels.Add(dna2Fa);
                    }
                        break;

                    case TwoFactorChannelType.TwoFaCtU2F:
                        if (auth.AuthCallback is IAuthSecurityKeyUI keyUi)
                        {
                            try
                            {
                                var rqs = JsonUtils.ParseJson<SecurityKeyRequest>(Encoding.UTF8.GetBytes(ch.Challenge));
                                var key2Fa = new TwoFactorSecurityKeyChannel();
                                key2Fa.InvokeTwoFactorPushAction = (action) =>
                                {
                                    return Task.Run(async () =>
                                    {
                                        var signature = await keyUi.AuthenticateRequests(rqs.authenticateRequests);
                                        var request = new TwoFactorValidateRequest
                                        {
                                            EncryptedLoginToken = loginToken,
                                            ExpireIn = TwoFactorExpiration.TwoFaExpImmediately,
                                            ValueType = ch.ChannelType == TwoFactorChannelType.TwoFaCtWebauthn ? TwoFactorValueType.TwoFaRespWebauthn : TwoFactorValueType.TwoFaRespU2F,
                                            Value = signature,
                                        };
                                        var validateRs = await auth.ExecuteTwoFactorValidateCode(request);
                                        onLoginToken(validateRs.EncryptedLoginToken);
                                    });
                                };
                                availableChannels.Add(key2Fa);
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e.Message);
                            }
                        }

                        break;
                    case TwoFactorChannelType.TwoFaCtWebauthn:
                    case TwoFactorChannelType.TwoFaCtKeeper:
                        break;
                }
            }

            bool NotificationCallback(NotificationEvent message)
            {
                if (message.Event != "received_totp") return false;
                if (!string.IsNullOrEmpty(message.EncryptedLoginToken))
                {
                    resumeWithToken = ByteString.CopyFrom(message.EncryptedLoginToken.Base64UrlDecode());
                    onLoginToken(resumeWithToken);
                    return true;
                }

                if (!string.IsNullOrEmpty(message.Passcode) && lastUsedChannel is ITwoFactorAppCodeInfo codeInfo)
                {
                    Task.Run(async () =>
                    {
                        try
                        {
                            await codeInfo.InvokeTwoFactorCodeAction(message.Passcode);
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message);
                        }
                    });
                }

                return false;
            }

            auth.PushNotifications?.RegisterCallback(NotificationCallback);

            return Tuple.Create<ITwoFactorChannelInfo[], Action>(availableChannels.ToArray(),
                () => { auth.PushNotifications?.RemoveCallback(NotificationCallback); });
        }

        internal static void StoreConfigurationIfChangedV3(this IAuth auth, LoginContext v3)
        {
            if (string.CompareOrdinal(auth.Storage.LastLogin ?? "", auth.Username) != 0)
            {
                auth.Storage.LastLogin = auth.Username;
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

            var existingUser = auth.Storage.Users.Get(auth.Username);
            var deviceToken = auth.DeviceToken.Base64UrlEncode();
            if (existingUser?.LastDevice?.DeviceToken != deviceToken ||
                string.IsNullOrEmpty(existingUser?.Server))
            {
                var uc = existingUser != null
                    ? new UserConfiguration(existingUser)
                    : new UserConfiguration(auth.Username);
                uc.Server = auth.Endpoint.Server;

                var lastDevice = new UserDeviceConfiguration(deviceToken);
                uc.LastDevice = lastDevice;
                auth.Storage.Users.Put(uc);
            }

            var deviceConf = auth.Storage.Devices.Get(deviceToken);
            if (deviceConf != null && v3.CloneCode != null)
            {
                var dc = new DeviceConfiguration(deviceConf);
                var serverInfo = dc.ServerInfo.Get(auth.Endpoint.Server);
                var si = serverInfo != null ? new DeviceServerConfiguration(serverInfo) : new DeviceServerConfiguration(auth.Endpoint.Server);
                si.CloneCode = v3.CloneCode.Base64UrlEncode();
                dc.ServerInfo.Put(si);
                auth.Storage.Devices.Put(dc);
            }

            if (auth.Storage is IConfigurationFlush hasFlush)
            {
                hasFlush.Flush();
            }
        }

        internal static GetSsoTokenActionInfo AuthorizeUsingOnsiteSsoPrepare(
            this IAuth auth,
            LoginContext v3,
            Action onSsoToken,
            string ssoBaseUrl,
            bool forceLogin)
        {
            var queryString = System.Web.HttpUtility.ParseQueryString("");
            CryptoUtils.GenerateRsaKey(out var privateKey, out var publicKey);
            queryString.Add("key", publicKey.Base64UrlEncode());
            queryString.Add("embedded", "");
            if (forceLogin)
            {
                queryString.Add("relogin", "");
            }

            var builder = new UriBuilder(new Uri(ssoBaseUrl))
            {
                Query = queryString.ToString()
            };
            var ssoAction = new GetSsoTokenActionInfo(builder.Uri.AbsoluteUri, false)
            {
                InvokeSsoTokenAction = async tokenStr =>
                {
                    var token = JsonUtils.ParseJson<SsoToken>(Encoding.UTF8.GetBytes(tokenStr));
                    var pk = CryptoUtils.LoadPrivateKey(privateKey);

                    auth.Username = token.Email;
                    await auth.EnsureDeviceTokenIsRegistered(v3, auth.Username);

                    if (!string.IsNullOrEmpty(token.Password))
                    {
                        var password = Encoding.UTF8.GetString(CryptoUtils.DecryptRsa(token.Password.Base64UrlDecode(), pk));
                        v3.PasswordQueue.Enqueue(password);
                    }

                    if (!string.IsNullOrEmpty(token.NewPassword))
                    {
                        var password = Encoding.UTF8.GetString(CryptoUtils.DecryptRsa(token.NewPassword.Base64UrlDecode(), pk));
                        v3.PasswordQueue.Enqueue(password);
                    }

                    v3.SsoLoginInfo = new SsoLoginInfo
                    {
                        SsoProvider = token.ProviderName,
                        SpBaseUrl = ssoBaseUrl,
                        IdpSessionId = token.SessionId
                    };

                    onSsoToken();
                }
            };

            return ssoAction;
        }

        internal static GetSsoTokenActionInfo AuthorizeUsingCloudSsoPrepare(
            this IAuth auth,
            LoginContext v3,
            Action<ByteString> onSsoLogin,
            string ssoBaseUrl,
            bool forceLogin)
        {
            var rq = new SsoCloudRequest
            {
                ClientVersion = auth.Endpoint.ClientVersion,
                Embedded = true,
                ForceLogin = forceLogin
            };
            var transmissionKey = CryptoUtils.GenerateEncryptionKey();
            var apiRequest = auth.Endpoint.PrepareApiRequest(rq, transmissionKey);

            var queryString = System.Web.HttpUtility.ParseQueryString("");
            queryString.Add("payload", apiRequest.ToByteArray().Base64UrlEncode());
            var builder = new UriBuilder(new Uri(ssoBaseUrl))
            {
                Query = queryString.ToString()
            };

            var ssoAction = new GetSsoTokenActionInfo(builder.Uri.AbsoluteUri, true)
            {
                InvokeSsoTokenAction = async (tokenStr) =>
                {
                    var rsBytes = tokenStr.Base64UrlDecode();
                    rsBytes = CryptoUtils.DecryptAesV2(rsBytes, transmissionKey);
                    var rs = SsoCloudResponse.Parser.ParseFrom(rsBytes);

                    auth.Username = rs.Email;
                    await auth.EnsureDeviceTokenIsRegistered(v3, auth.Username);

                    v3.SsoLoginInfo = new SsoLoginInfo
                    {
                        SsoProvider = rs.ProviderName,
                        SpBaseUrl = ssoBaseUrl,
                        IdpSessionId = rs.IdpSessionId
                    };

                    onSsoLogin(rs.EncryptedLoginToken);
                }
            };
            return ssoAction;
        }

        public static async Task RequestCreateUser(this IAuth auth, LoginContext v3, string password)
        {
            var dataKey = CryptoUtils.GenerateEncryptionKey();
            var clientKey = CryptoUtils.GenerateEncryptionKey();
            CryptoUtils.GenerateRsaKey(out var rsaPrivate, out var rsaPublic);
            CryptoUtils.GenerateEcKey(out var ecPrivate, out var ecPublic);
            var devicePublicKey = CryptoUtils.GetPublicEcKey(v3.DeviceKey);
            var request = new CreateUserRequest
            {
                ClientVersion = auth.Endpoint.ClientVersion,
                Username = auth.Username,
                AuthVerifier = ByteString.CopyFrom(CryptoUtils.CreateAuthVerifier(password, CryptoUtils.GetRandomBytes(16), 100000)),
                EncryptionParams = ByteString.CopyFrom(CryptoUtils.CreateEncryptionParams(password, CryptoUtils.GetRandomBytes(16), 100000, dataKey)),
                RsaPublicKey = ByteString.CopyFrom(rsaPublic),
                RsaEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(rsaPrivate, dataKey)),
                EccPublicKey = ByteString.CopyFrom(CryptoUtils.UnloadEcPublicKey(ecPublic)),
                EccEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(CryptoUtils.UnloadEcPrivateKey(ecPrivate), dataKey)),
                EncryptedClientKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(clientKey, dataKey)),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                EncryptedDeviceDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(dataKey, devicePublicKey))
            };
            var apiRequest = new ApiRequestPayload
            {
                Payload = request.ToByteString()
            };
            
            Debug.WriteLine($"REST Request: endpoint \"request_create_user\": {request}");
            await auth.Endpoint.ExecuteRest("authentication/request_create_user", apiRequest);
        }

        internal static async Task CreateSsoUser(this IAuth auth, LoginContext v3, ByteString loginToken)
        {
            var dataKey = CryptoUtils.GenerateEncryptionKey();
            var clientKey = CryptoUtils.GenerateEncryptionKey();
            CryptoUtils.GenerateEcKey(out var ecPrivateKey, out var ecPublicKey);
            CryptoUtils.GenerateRsaKey(out var rsaPrivateKey, out var rsaPublicKey);
            var devicePublicKey = CryptoUtils.GetPublicEcKey(v3.DeviceKey);
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
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
            };
            var apiRequest = new ApiRequestPayload
            {
                Payload = request.ToByteString()
            };

            Debug.WriteLine($"REST Request: endpoint \"create_user_sso\": {request}");
            await auth.Endpoint.ExecuteRest("authentication/create_user_sso", apiRequest);
        }

        private static async Task<DeviceVerificationResponse> RequestDeviceAdminApproval(this IAuth auth, LoginContext v3)
        {
            var request = new DeviceVerificationRequest
            {
                Username = auth.Username,
                ClientVersion = auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken),
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"request_device_admin_approval\": {request}");
#endif
            var payload = new ApiRequestPayload {Payload = request.ToByteString()};
            var rs = await auth.Endpoint.ExecuteRest("authentication/request_device_admin_approval", payload);
            DeviceVerificationResponse response = null;
            if (rs?.Length > 0)
            {
                response = DeviceVerificationResponse.Parser.ParseFrom(rs);
            }

            return response;
        }

        internal static Tuple<IDataKeyChannelInfo[], Action> RequestDataKeyPrepare(
            this IAuth auth,
            LoginContext v3,
            Action<bool> onApproved,
            ByteString loginToken)
        {
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
                    var rs = await auth.RequestDeviceAdminApproval(v3);
                    if (rs != null && rs.DeviceStatus == DeviceStatus.DeviceOk)
                    {
                        onApproved(true);
                    }
                }
            };

            bool ProcessDataKeyRequest(NotificationEvent message)
            {
                if (string.CompareOrdinal(message.Message, "device_approved") == 0)
                {
                    onApproved(message.Approved);
                    return true;
                }

                if (string.CompareOrdinal(message.Command, "device_verified") == 0)
                {
                    onApproved(true);
                    return true;
                }

                return false;
            }

            auth.PushNotifications?.RegisterCallback(ProcessDataKeyRequest);

            return Tuple.Create<IDataKeyChannelInfo[], Action>(
                new IDataKeyChannelInfo[] {pushChannel, adminChannel},
                () => { auth.PushNotifications?.RemoveCallback(ProcessDataKeyRequest); }
            );
        }

        internal static async Task<SsoServiceProviderResponse> GetSsoServiceProvider(this IAuth auth, LoginContext v3, string providerName)
        {
            var payload = new ApiRequestPayload
            {
                ApiVersion = 3,
                Payload = new SsoServiceProviderRequest
                {
                    ClientVersion = auth.Endpoint.ClientVersion,
                    Locale = auth.Endpoint.Locale,
                    Name = providerName
                }.ToByteString()
            };

#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"get_sso_service_provider\": {payload}");
#endif
            byte[] rsBytes;
            try
            {
                rsBytes = await auth.Endpoint.ExecuteRest("enterprise/get_sso_service_provider", payload);
            }
            catch (KeeperRegionRedirect krr)
            {
                await auth.RedirectToRegionV3(krr.RegionHost);
                rsBytes = await auth.Endpoint.ExecuteRest("enterprise/get_sso_service_provider", payload);
            }

            if (!(rsBytes?.Length > 0))
                throw new KeeperInvalidParameter("enterprise/get_sso_service_provider", "provider_name", providerName, "SSO provider not found");

            var rs = SsoServiceProviderResponse.Parser.ParseFrom(rsBytes);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"get_sso_service_provider\": {rs}");
#endif
            return rs;
        }


        internal static void SsoLogout(this IAuthentication auth)
        {
            if (auth.AuthContext.SsoLoginInfo == null || !(auth.AuthCallback is ISsoLogoutCallback ssoLogout)) return;

            var queryString = System.Web.HttpUtility.ParseQueryString("");
            if (auth.AuthContext.AccountAuthType == AccountAuthType.CloudSso)
            {
                var rq = new SsoCloudRequest
                {
                    ClientVersion = auth.Endpoint.ClientVersion,
                    Embedded = true,
                    IdpSessionId = auth.AuthContext.SsoLoginInfo.IdpSessionId,
                    Username = auth.Username
                };
                var transmissionKey = CryptoUtils.GenerateEncryptionKey();
                var apiRequest = auth.Endpoint.PrepareApiRequest(rq, transmissionKey);
                queryString.Add("payload", apiRequest.ToByteArray().Base64UrlEncode());
            }
            else
            {
                queryString.Add("embedded", "");
            }

            var builder = new UriBuilder(new Uri(auth.AuthContext.SsoLoginInfo.SpBaseUrl.Replace("/login", "/logout")))
            {
                Query = queryString.ToString()
            };
            ssoLogout.SsoLogoutUrl(builder.Uri.AbsoluteUri);
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
