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
    internal enum AccountAuthType
    {
        Regular = 1,
        CloudSso = 2,
        OnsiteSso = 3
    }

    internal class AuthV3Wrapper
    {
        public readonly Auth Auth;

        public AuthV3Wrapper(Auth auth)
        {
            Auth = auth;
            MessageSessionUid = CryptoUtils.GetRandomBytes(16);
            AccountAuthType = AccountAuthType.Regular;
        }

        public AccountAuthType AccountAuthType { get; set; }

        public byte[] CloneCode { get; set; }

        public string V2TwoFactorToken { get; set; }

        internal ECPrivateKeyParameters DeviceKey { get; set; }

        internal byte[] MessageSessionUid { get; }
        internal Queue<string> PasswordQueue { get; } = new Queue<string>();

        internal SsoLoginInfo SsoLoginInfo { get; set; }
    }

    internal static class LoginV3Extensions
    {
        internal static async Task EnsureDeviceTokenIsRegistered(this AuthV3Wrapper v3, string username)
        {
            if (string.Compare(v3.Auth.Username, username, StringComparison.InvariantCultureIgnoreCase) != 0)
            {
                v3.Auth.Username = username;
                v3.Auth.DeviceToken = null;
                v3.DeviceKey = null;
                v3.CloneCode = null;
            }

            IDeviceConfiguration deviceConf = null;
            if (v3.Auth.DeviceToken != null)
            {
                var token = v3.Auth.DeviceToken.Base64UrlEncode();
                deviceConf = v3.Auth.Storage.Devices.Get(token);
                if (deviceConf == null)
                {
                    v3.Auth.DeviceToken = null;
                    v3.DeviceKey = null;
                    v3.CloneCode = null;
                }
            }

            var userConf = v3.Auth.Storage.Users.Get(v3.Auth.Username);
            var lastDevice = userConf?.LastDevice;
            var attempt = 0;
            while (v3.Auth.DeviceToken == null || v3.DeviceKey == null)
            {
                attempt++;
                if (attempt > 10) throw new KeeperInvalidDeviceToken("too many attempts");

                v3.Auth.DeviceToken = null;
                v3.DeviceKey = null;
                v3.CloneCode = null;

                if (lastDevice != null)
                {
                    deviceConf = v3.Auth.Storage.Devices.Get(lastDevice.DeviceToken);
                    if (deviceConf != null)
                    {
                        var serverInfo = deviceConf.ServerInfo?.Get(v3.Auth.Endpoint.Server);
                        if (serverInfo != null)
                        {
                            v3.CloneCode = serverInfo.CloneCode.Base64UrlDecode();
                        }
                    }
                    lastDevice = null;
                }

                if (deviceConf == null)
                {
                    deviceConf = v3.Auth.Storage.Devices.List.FirstOrDefault();
                }

                if (deviceConf == null)
                {
                    deviceConf = await v3.Auth.RegisterDevice();
                }

                try
                {
                    if (!(deviceConf.DeviceKey?.Length > 0)) throw new KeeperInvalidDeviceToken("invalid configuration");
                    v3.Auth.DeviceToken = deviceConf.DeviceToken.Base64UrlDecode();
                    v3.DeviceKey = CryptoUtils.LoadPrivateEcKey(deviceConf.DeviceKey);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    v3.Auth.Storage.Devices.Delete(deviceConf.DeviceToken);
                    deviceConf = null;
                }
            }

            {
                var token = v3.Auth.DeviceToken.Base64UrlEncode();
                deviceConf = v3.Auth.Storage.Devices.Get(token);
                if (deviceConf == null) throw new KeeperInvalidDeviceToken("invalid configuration");
                if (deviceConf.ServerInfo?.Get(v3.Auth.Endpoint.Server) == null)
                {
                    await v3.Auth.RegisterDeviceInRegion(deviceConf);
                }
            }

            {
                if (attempt > 0 && v3.Auth.PushNotifications != null)
                {
                    try
                    {
                        v3.Auth.PushNotifications.Dispose();
                        v3.Auth.PushNotifications = null;
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }

                if (v3.Auth.PushNotifications == null)
                {
                    var cancellationTokenSource = new CancellationTokenSource();
                    try
                    {
                        var connectRequest = new WssConnectionRequest
                        {
                            EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                            MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                            DeviceTimeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                        };
                        v3.Auth.PushNotifications = await v3.Auth.ConnectToPushServer(connectRequest, cancellationTokenSource.Token);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }
            }
        }

        internal static async Task<AuthContext> LoginSsoV3(this AuthV3Wrapper v3, string providerName, bool forceLogin)
        {
            if (v3.Auth.Ui != null && v3.Auth.Ui is IAuthSsoUI)
            {
                var payload = new ApiRequestPayload
                {
                    ApiVersion = 3,
                    Payload = new SsoServiceProviderRequest
                    {
                        ClientVersion = v3.Auth.Endpoint.ClientVersion,
                        Locale = v3.Auth.Endpoint.Locale,
                        Name = providerName
                    }.ToByteString()
                };

                var rsBytes = await v3.Auth.Endpoint.ExecuteRest("enterprise/get_sso_service_provider", payload);
                if (rsBytes?.Length > 0)
                {
                    var rs = SsoServiceProviderResponse.Parser.ParseFrom(rsBytes);

                    v3.AccountAuthType = rs.IsCloud ? AccountAuthType.CloudSso : AccountAuthType.OnsiteSso;
                    if (rs.IsCloud)
                    {
                        return await v3.AuthorizeUsingCloudSso(rs.SpUrl, forceLogin);
                    }

                    return await v3.AuthorizeUsingOnsiteSso(rs.SpUrl, forceLogin);
                }

                throw new KeeperInvalidParameter("enterprise/get_sso_service_provider", "provider_name", providerName, "SSO provider not found");
            }

            throw new KeeperAuthFailed();
        }


        internal static async Task<AuthContext> LoginV3(this AuthV3Wrapper v3, params string[] passwords)
        {
            foreach (var p in passwords)
            {
                if (string.IsNullOrEmpty(p)) continue;
                v3.PasswordQueue.Enqueue(p);
            }

            try
            {
                var loginMethod = v3.AccountAuthType == AccountAuthType.Regular || v3.PasswordQueue.Count == 0
                    ? LoginMethod.ExistingAccount 
                    : LoginMethod.AfterSso;
                return await v3.StartLogin(false, loginMethod);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                throw;
            }
        }

        internal static async Task RedirectToRegionV3(this IAuth auth, string newRegion)
        {
            auth.Endpoint.Server = newRegion;
            if (auth.Ui is IAuthInfoUI infoUi)
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
            var rs = await auth.Endpoint.ExecuteRest("authentication/register_device", new ApiRequestPayload { Payload = request.ToByteString() });
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

        private static async Task RequestDeviceVerification(this AuthV3Wrapper v3, string channel)
        {
            var request = new DeviceVerificationRequest
            {
                Username = v3.Auth.Username,
                ClientVersion = v3.Auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                VerificationChannel = channel
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"request_device_verification\": {request}");
#endif
            await v3.Auth.Endpoint.ExecuteRest("authentication/request_device_verification",
                new ApiRequestPayload {Payload = request.ToByteString()});
        }

        internal static async Task ValidateDeviceVerificationCode(this AuthV3Wrapper v3, string code)
        {
            var request = new ValidateDeviceVerificationCodeRequest
            {
                Username = v3.Auth.Username,
                ClientVersion = v3.Auth.Endpoint.ClientVersion,
                EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                VerificationCode = code
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"validate_device_verification_code\": {request}");
#endif
            await v3.Auth.Endpoint.ExecuteRest("authentication/validate_device_verification_code",
                new ApiRequestPayload {Payload = request.ToByteString()});
        }

        private static async Task<AuthContext> ExecuteStartLogin(this AuthV3Wrapper v3, StartLoginRequest request)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"start_login\": {request}");
#endif

            var rs = await v3.Auth.Endpoint.ExecuteRest("authentication/start_login", new ApiRequestPayload {Payload = request.ToByteString()});
            var response = LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"start_login\": {response}");
#endif
            switch (response.LoginState)
            {
                case LoginState.LoggedIn:
                    v3.Auth.Username = response.PrimaryUsername;
                    v3.CloneCode = response.CloneCode.ToByteArray();
                    var authContext = new AuthContext
                    {
                        SessionToken = response.EncryptedSessionToken.ToByteArray(),
                        SessionTokenRestriction = GetSessionTokenScope(response.SessionTokenType),
                        SsoLoginInfo = v3.SsoLoginInfo,
                    };
                    var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
                    switch (response.EncryptedDataKeyType)
                    {
                        case EncryptedDataKeyType.ByDevicePublicKey:
                            authContext.DataKey = CryptoUtils.DecryptEc(encryptedDataKey, v3.DeviceKey);
                            break;
                    }

                    return authContext;

                case LoginState.RequiresUsername:
                    return await v3.ResumeLogin(response.EncryptedLoginToken);

                case LoginState.Requires2Fa:
                    if (v3.Auth.Ui != null)
                    {
                        return await v3.TwoFactorValidate(response.EncryptedLoginToken, response.Channels);
                    }

                    break;
                case LoginState.RequiresAuthHash:
                    if (v3.Auth.Ui != null)
                    {
                        return await v3.ValidateAuthHash(response.EncryptedLoginToken, response.Salt);
                    }

                    break;

                case LoginState.DeviceApprovalRequired:
                    if (v3.Auth.Ui != null)
                    {
                        return await v3.ApproveDevice(response.EncryptedLoginToken);
                    }

                    break;

                case LoginState.RedirectCloudSso:
                    v3.AccountAuthType = AccountAuthType.CloudSso;
                    return await v3.AuthorizeUsingCloudSso(response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

                case LoginState.RedirectOnsiteSso:
                    v3.AccountAuthType = AccountAuthType.OnsiteSso;
                    return await v3.AuthorizeUsingOnsiteSso(response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

                case LoginState.RequiresDeviceEncryptedDataKey:
                {
                    if (v3.Auth.Ui != null)
                    {
                        v3.CloneCode = null;
                        if (v3.AccountAuthType == AccountAuthType.CloudSso)
                        {
                            return await v3.RequestDataKey(response.EncryptedLoginToken);
                        }

                        v3.Auth.ResumeSession = false;
                        var newRequest = new StartLoginRequest
                        {
                            Username = v3.Auth.Username,
                            ClientVersion = v3.Auth.Endpoint.ClientVersion,
                            EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                            LoginType = LoginType.Normal,
                            LoginMethod = LoginMethod.ExistingAccount,
                            MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                        };
                        return await v3.ExecuteStartLogin(newRequest);
                    }

                    break;
                }

                case LoginState.RequiresAccountCreation:
                    if (v3.AccountAuthType == AccountAuthType.CloudSso)
                    {
                        return await v3.CreateSsoUser(response.EncryptedLoginToken);
                    }

                    break;

                case LoginState.RegionRedirect:
                    throw new KeeperRegionRedirect(response.StateSpecificValue)
                    {
                        Username = request.Username
                    };

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

        private static async Task<AuthContext> ResumeLogin(this AuthV3Wrapper v3, ByteString loginToken, LoginMethod method = LoginMethod.ExistingAccount)
        {
            var request = new StartLoginRequest
            {
                ClientVersion = v3.Auth.Endpoint.ClientVersion,
                EncryptedLoginToken = loginToken,
                EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                Username = v3.Auth.Username,
                LoginMethod = method,
            };
            if (v3.Auth.ResumeSession && v3.CloneCode != null)
            {
                request.CloneCode = ByteString.CopyFrom(v3.CloneCode);
            }

            return await v3.ExecuteStartLogin(request);
        }

        internal static async Task<AuthContext> StartLogin(this AuthV3Wrapper v3, bool forceNewLogin = false, LoginMethod loginMethod = LoginMethod.ExistingAccount)
        {
            var attempt = 0;

            while (true)
            {
                attempt++;
                await v3.EnsureDeviceTokenIsRegistered(v3.Auth.Username);
                if (v3.Auth.Ui is IAuthInfoUI infoUi)
                {
                    infoUi.SelectedDevice(v3.Auth.DeviceToken.Base64UrlEncode());
                }

                if (v3.Auth.ResumeSession && v3.CloneCode == null)
                {
                    v3.CloneCode = new byte[0];
                }

                try
                {
                    var request = new StartLoginRequest
                    {
                        ClientVersion = v3.Auth.Endpoint.ClientVersion,
                        EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                        LoginType = v3.Auth.AlternatePassword ? LoginType.Alternate : LoginType.Normal,
                        LoginMethod = loginMethod,
                        MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                        ForceNewLogin = forceNewLogin,
                    };
                    if (!forceNewLogin && v3.Auth.ResumeSession && loginMethod == LoginMethod.ExistingAccount && v3.CloneCode != null)
                    {
                        request.CloneCode = ByteString.CopyFrom(v3.CloneCode);
                    }
                    else
                    {
                        request.Username = v3.Auth.Username;
                        if (!string.IsNullOrEmpty(v3.V2TwoFactorToken))
                        {
                            request.V2TwoFactorToken = v3.V2TwoFactorToken;
                        }
                    }

                    var context = await v3.ExecuteStartLogin(request);
                    if (context.SessionTokenRestriction == 0 && v3.Auth.PushNotifications is IPushNotificationChannel push)
                    {
                        await push.SendToWebSocket(context.SessionToken, false);
                    }

                    return context;
                }
                catch (Exception e)
                {
                    v3.Auth.PushNotifications?.Dispose();
                    v3.Auth.PushNotifications = null;
                    if (attempt < 3 && e is KeeperInvalidDeviceToken)
                    {
                        v3.Auth.Storage.Devices.Delete(v3.Auth.DeviceToken.Base64UrlEncode());
                        v3.Auth.DeviceToken = null;
                        v3.DeviceKey = null;
                        continue;
                    }

                    Debug.WriteLine(e.Message);
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
                case SessionTokenType.Restrict:
                case SessionTokenType.Purchase:
                    result |= SessionTokenRestriction.AccountExpired;
                    break;
            }

            return result;
        }

        private static async Task<AuthContext> ExecuteValidateAuthHash(this AuthV3Wrapper v3, ByteString loginToken, string password, Salt salt)
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
            var rs = await v3.Auth.Endpoint.ExecuteRest("authentication/validate_auth_hash",
                new ApiRequestPayload {Payload = request.ToByteString()});
            var response = LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST response: endpoint \"validate_auth_hash\": {response}");
#endif
            v3.Auth.Username = response.PrimaryUsername;
            v3.CloneCode = response.CloneCode.ToByteArray();
            var authContext = new AuthContext
            {
                SessionToken = response.EncryptedSessionToken.ToByteArray(),
                SessionTokenRestriction = GetSessionTokenScope(response.SessionTokenType),
                SsoLoginInfo = v3.SsoLoginInfo,
            };
            
            var validatorSalt = CryptoUtils.GetRandomBytes(16);
            authContext.PasswordValidator = 
                CryptoUtils.CreateEncryptionParams(password, validatorSalt, 100000, CryptoUtils.GetRandomBytes(32));
            
            var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
            switch (response.EncryptedDataKeyType)
            {
                case EncryptedDataKeyType.ByAlternate:
                    var key = CryptoUtils.DeriveKeyV2("data_key", password, salt.Salt_.ToByteArray(), salt.Iterations);
                    authContext.DataKey = CryptoUtils.DecryptAesV2(encryptedDataKey, key);
                    break;
                case EncryptedDataKeyType.ByPassword:
                    authContext.DataKey = CryptoUtils.DecryptEncryptionParams(password, encryptedDataKey);
                    break;
                case EncryptedDataKeyType.ByDevicePublicKey:
                    authContext.DataKey = CryptoUtils.DecryptEc(encryptedDataKey, v3.DeviceKey);
                    break;
            }

            return authContext;
        }

        private static async Task<AuthContext> ValidateAuthHash(this AuthV3Wrapper v3, ByteString loginToken, IEnumerable<Salt> salts)
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
                throw new KeeperStartLoginException(LoginState.RequiresAuthHash, "Master Password has not been created.");
            }

            while (v3.PasswordQueue.Count > 0)
            {
                var password = v3.PasswordQueue.Dequeue();
                try
                {
                    return await v3.ExecuteValidateAuthHash(loginToken, password, saltInfo);
                }
                catch (KeeperAuthFailed)
                {
                }
                catch
                {
                    v3.PasswordQueue.Enqueue(password);
                    throw;
                }
            }

            using (var cancellationToken = new CancellationTokenSource())
            {
                var contextTask = new TaskCompletionSource<AuthContext>();
                var passwordInfo = new MasterPasswordInfo(v3.Auth.Username)
                {
                    InvokePasswordActionDelegate = async password =>
                    {
                        try
                        {
                            var context = await v3.ExecuteValidateAuthHash(loginToken, password, saltInfo);
                            contextTask.TrySetResult(context);
                        }
                        catch (KeeperCanceled kc)
                        {
                            contextTask.SetException(kc);
                        }
                    }
                };

                var uiTask = v3.Auth.Ui.WaitForUserPassword(passwordInfo, cancellationToken.Token);
                var index = Task.WaitAny(uiTask, contextTask.Task);
                if (index == 1) return await contextTask.Task;
                var result = await uiTask;
                if (result)
                {
                    return await v3.ResumeLogin(loginToken);
                }

                throw new KeeperCanceled();
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
                Debug.WriteLine(e.Message);
            }
        }

        private static async Task ExecuteDeviceApproveOtpAction(
            this AuthV3Wrapper v3,
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
                var validateRs = await v3.Auth.ExecuteTwoFactorValidateCode(request);
                var resumeToken = validateRs.EncryptedLoginToken.ToByteArray();
                var notification = new NotificationEvent
                {
                    Event = "received_totp",
                    EncryptedLoginToken = resumeToken.Base64UrlEncode(),
                };
                v3.Auth.PushNotifications.Push(notification);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
        }

        private static async Task<AuthContext> ApproveDevice(this AuthV3Wrapper v3, ByteString loginToken)
        {
            var resumeLoginToken = loginToken;
            var loginTokenTaskSource = new TaskCompletionSource<bool>();

            var email = new DeviceApprovalEmailResend();
            email.InvokeDeviceApprovalPushAction = async () =>
            {
                try
                {
                    await v3.RequestDeviceVerification(email.Resend ? "email_resend" : "email");
                    email.Resend = true;
                }
                catch (KeeperCanceled kc)
                {
                    loginTokenTaskSource.SetException(kc);   
                }
            };
            email.InvokeDeviceApprovalOtpAction = async (code) =>
            {
                try
                {
                    await v3.ValidateDeviceVerificationCode(code);
                    loginTokenTaskSource.TrySetResult(true);
                }
                catch (KeeperCanceled kc)
                {
                    loginTokenTaskSource.SetException(kc);   
                }
            };

            var push = new DeviceApprovalKeeperPushAction();
            push.InvokeDeviceApprovalPushAction = async () =>
            {
                try
                {
                    await v3.Auth.ExecuteDeviceApprovePushAction(TwoFactorPushType.TwoFaPushKeeper, loginToken);
                }
                catch (KeeperCanceled kc)
                {
                    loginTokenTaskSource.SetException(kc);   
                }
            };

            var otp = new TwoFactorTwoFactorAuth();
            otp.InvokeDeviceApprovalPushAction = async () =>
            {
                try
                {
                    await v3.Auth.ExecuteDeviceApprovePushAction(TwoFactorPushType.TwoFaPushNone, loginToken, SdkExpirationToKeeper(otp.Duration));
                }
                catch (KeeperCanceled kc)
                {
                    loginTokenTaskSource.SetException(kc);   
                }
            };
            otp.InvokeDeviceApprovalOtpAction = async (oneTimePassword) =>
            {
                try
                {
                    await v3.ExecuteDeviceApproveOtpAction(TwoFactorValueType.TwoFaCodeNone, loginToken, oneTimePassword, SdkExpirationToKeeper(otp.Duration));
                }
                catch (KeeperCanceled kc)
                {
                    loginTokenTaskSource.SetException(kc);   
                }
            };

            bool NotificationCallback(NotificationEvent message)
            {
                if (loginTokenTaskSource.Task.IsCompleted) return true;
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

            v3.Auth.PushNotifications?.RegisterCallback(NotificationCallback);

            var sdkCancellation = new CancellationTokenSource();
            var uiTask = v3.Auth.Ui.WaitForDeviceApproval(new IDeviceApprovalChannelInfo[] {email, push, otp}, sdkCancellation.Token);
            var tokenTask = loginTokenTaskSource.Task;

            var index = Task.WaitAny(uiTask, tokenTask);
            if (index == 0)
            {
                v3.Auth.PushNotifications?.RemoveCallback(NotificationCallback);
                var resume = await uiTask;
                if (!resume) throw new KeeperCanceled();
            }
            else
            {
                await tokenTask;
                sdkCancellation.Cancel();
            }

            return await v3.ResumeLogin(resumeLoginToken);
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

        private static async Task<AuthContext> TwoFactorValidate(this AuthV3Wrapper v3,
            ByteString loginToken,
            IEnumerable<TwoFactorChannelInfo> channels)
        {
            var resumeWithToken = loginToken;

            ITwoFactorPushInfo lastUsedChannel = null;

            var loginTaskSource = new TaskCompletionSource<bool>();

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
                    try
                    {
                        await v3.Auth.ExecutePushAction(rq);
                        lastUsedChannel = channel;
                    }
                    catch (KeeperCanceled kc)
                    {
                        loginTaskSource.SetException(kc);
                    }
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
                    try
                    {
                        var validateRs = await v3.Auth.ExecuteTwoFactorValidateCode(request);
                        resumeWithToken = validateRs.EncryptedLoginToken;
                        loginTaskSource.TrySetResult(true);
                        return true;
                    }
                    catch (KeeperCanceled kc)
                    {
                        loginTaskSource.SetException(kc);
                    }
                    catch (KeeperAuthFailed)
                    {
                    }
                    return false;
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
                        if (v3.Auth.Ui is IAuthSecurityKeyUI keyUi)
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
                                        try
                                        {
                                            var validateRs = await v3.Auth.ExecuteTwoFactorValidateCode(request);
                                            resumeWithToken = validateRs.EncryptedLoginToken;
                                            loginTaskSource.TrySetResult(true);
                                        }
                                        catch (KeeperCanceled kc)
                                        {
                                            loginTaskSource.SetException(kc);
                                        }
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
                if (loginTaskSource.Task.IsCompleted) return true;
                if (message.Event != "received_totp") return false;
                if (!string.IsNullOrEmpty(message.EncryptedLoginToken))
                {
                    resumeWithToken = ByteString.CopyFrom(message.EncryptedLoginToken.Base64UrlDecode());
                    loginTaskSource.TrySetResult(true);
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

            v3.Auth.PushNotifications?.RegisterCallback(NotificationCallback);
            using (var tokenSource = new CancellationTokenSource())
            {
                var userTask = v3.Auth.Ui.WaitForTwoFactorCode(availableChannels.ToArray(), tokenSource.Token);
                int index = Task.WaitAny(userTask, loginTaskSource.Task);
                v3.Auth.PushNotifications?.RemoveCallback(NotificationCallback);
                if (index == 0)
                {
                    if (!await userTask) throw new KeeperCanceled();
                }
                else
                {
                    tokenSource.Cancel();
                    await loginTaskSource.Task;
                }
            }

            return await v3.ResumeLogin(resumeWithToken);
        }

        internal static void StoreConfigurationIfChangedV3(this Auth auth, byte[] cloneCode)
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
            if (existingUser?.LastDevice?.DeviceToken != deviceToken)
            {
                var uc = existingUser != null
                    ? new UserConfiguration(existingUser)
                    : new UserConfiguration(auth.Username)
                    {
                        Server = auth.Endpoint.Server
                    };
                var lastDevice = existingUser?.LastDevice != null
                    ? new UserDeviceConfiguration(existingUser.LastDevice)
                    {
                        DeviceToken = deviceToken
                    }
                    : new UserDeviceConfiguration(deviceToken);
                uc.LastDevice = lastDevice;
                auth.Storage.Users.Put(uc);
            }

            var deviceConf = auth.Storage.Devices.Get(deviceToken);
            if (deviceConf != null && cloneCode != null)
            {
                var dc = new DeviceConfiguration(deviceConf);
                var serverInfo = dc.ServerInfo.Get(auth.Endpoint.Server);
                var si = serverInfo != null ? new DeviceServerConfiguration(serverInfo) : new DeviceServerConfiguration(auth.Endpoint.Server);
                si.CloneCode = cloneCode.Base64UrlEncode();
                dc.ServerInfo.Put(si);
                auth.Storage.Devices.Put(dc);
            }

            if (auth.Storage is JsonConfigurationStorage jcs)
            {
                jcs.Cache.Flush();
            }
        }

        private static async Task<AuthContext> AuthorizeUsingOnsiteSso(this AuthV3Wrapper v3, string ssoBaseUrl, bool forceLogin, ByteString loginToken = null)
        {
            if (v3.Auth.Ui != null && v3.Auth.Ui is IAuthSsoUI ssoUi)
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
                var tokenSource = new TaskCompletionSource<bool>();
                var ssoAction = new GetSsoTokenActionInfo(builder.Uri.AbsoluteUri, false)
                {
                    InvokeSsoTokenAction = tokenStr =>
                    {
                        var token = JsonUtils.ParseJson<SsoToken>(Encoding.UTF8.GetBytes(tokenStr));
                        var pk = CryptoUtils.LoadPrivateKey(privateKey);
                        v3.Auth.Username = token.Email;
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
                        var result = await userTask;
                        if (result && loginToken != null)
                        {
                            return await v3.ResumeLogin(loginToken);
                        }

                        throw new KeeperCanceled();
                    }

                    await tokenSource.Task;
                    cancellationSource.Cancel();
                    if (loginToken != null)
                    {
                        return await v3.ResumeLogin(loginToken, LoginMethod.AfterSso);
                    }

                    await v3.EnsureDeviceTokenIsRegistered(v3.Auth.Username);
                    return await v3.StartLogin(false, LoginMethod.AfterSso);
                }
            }

            throw new KeeperAuthFailed();
        }

        private static async Task<AuthContext> AuthorizeUsingCloudSso(this AuthV3Wrapper v3, string ssoBaseUrl, bool forceLogin, ByteString loginToken = null)
        {
            if (v3.Auth.Ui != null && v3.Auth.Ui is IAuthSsoUI ssoUi)
            {
                var rq = new SsoCloudRequest
                {
                    ClientVersion = v3.Auth.Endpoint.ClientVersion,
                    Embedded = true,
                    ForceLogin = forceLogin
                };
                var transmissionKey = CryptoUtils.GenerateEncryptionKey();
                var apiRequest = v3.Auth.Endpoint.PrepareApiRequest(rq, transmissionKey);

                var queryString = System.Web.HttpUtility.ParseQueryString("");
                queryString.Add("payload", apiRequest.ToByteArray().Base64UrlEncode());
                var builder = new UriBuilder(new Uri(ssoBaseUrl))
                {
                    Query = queryString.ToString()
                };

                var tokenSource = new TaskCompletionSource<bool>();
                var ssoAction = new GetSsoTokenActionInfo(builder.Uri.AbsoluteUri, true)
                {
                    InvokeSsoTokenAction = (tokenStr) =>
                    {
                        var rsBytes = tokenStr.Base64UrlDecode();
                        rsBytes = CryptoUtils.DecryptAesV2(rsBytes, transmissionKey);
                        var rs = SsoCloudResponse.Parser.ParseFrom(rsBytes);
                        v3.Auth.Username = rs.Email;
                        v3.SsoLoginInfo = new SsoLoginInfo
                        {
                            SsoProvider = rs.ProviderName,
                            SpBaseUrl = ssoBaseUrl,
                            IdpSessionId = rs.IdpSessionId
                        };
                        loginToken = rs.EncryptedLoginToken;
                        
                        tokenSource.TrySetResult(true);
                        return (Task) Task.FromResult(true);
                    }
                };

                using (var cancellationSource = new CancellationTokenSource())
                {
                    var tokenTask = ssoUi.WaitForSsoToken(ssoAction, cancellationSource.Token);
                    var index = Task.WaitAny(tokenTask, tokenSource.Task);
                    if (index == 0)
                    {
                        var result = await tokenTask;
                        if (result && loginToken != null)
                        {
                            return await v3.ResumeLogin(loginToken);
                        }

                        throw new KeeperCanceled();
                    }
                    await tokenSource.Task;
                    cancellationSource.Cancel();
                    await v3.EnsureDeviceTokenIsRegistered(v3.Auth.Username);
                    return await v3.ResumeLogin(loginToken, LoginMethod.AfterSso);
                }
            }

            throw new KeeperAuthFailed();
        }

        private static async Task<AuthContext> CreateSsoUser(this AuthV3Wrapper v3, ByteString loginToken)
        {
            var dataKey = CryptoUtils.GenerateEncryptionKey();
            var clientKey = CryptoUtils.GenerateEncryptionKey();
            CryptoUtils.GenerateEcKey(out var ecPrivateKey, out var ecPublicKey);
            CryptoUtils.GenerateRsaKey(out var rsaPrivateKey, out var rsaPublicKey);
            var devicePublicKey = CryptoUtils.GetPublicEcKey(v3.DeviceKey);
            var request = new CreateUserRequest
            {
                Username = v3.Auth.Username,
                RsaPublicKey = ByteString.CopyFrom(rsaPublicKey),
                RsaEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(rsaPrivateKey, dataKey)),
                EccPublicKey = ByteString.CopyFrom(CryptoUtils.UnloadEcPublicKey(ecPublicKey)),
                EccEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(CryptoUtils.UnloadEcPrivateKey(ecPrivateKey), dataKey)),
                EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
                EncryptedClientKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(clientKey, dataKey)),
                ClientVersion = v3.Auth.Endpoint.ClientVersion,
                EncryptedDeviceDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(dataKey, devicePublicKey)),
                EncryptedLoginToken = loginToken,
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
            };
            var apiRequest = new ApiRequestPayload
            {
                Payload = request.ToByteString()
            };
            await v3.Auth.Endpoint.ExecuteRest("authentication/create_user_sso", apiRequest);

            return await v3.ResumeLogin(loginToken);
        }

        private static async Task RequestDeviceAdminApproval(this AuthV3Wrapper v3)
        {
            var request = new DeviceVerificationRequest
            {
                Username = v3.Auth.Username,
                ClientVersion = v3.Auth.Endpoint.ClientVersion,
                MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                EncryptedDeviceToken = ByteString.CopyFrom(v3.Auth.DeviceToken),
            };
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"request_device_admin_approval\": {request}");
#endif
            await v3.Auth.Endpoint.ExecuteRest("authentication/request_device_admin_approval",
                new ApiRequestPayload { Payload = request.ToByteString() });
        }


        private static async Task<AuthContext> RequestDataKey(this AuthV3Wrapper v3, ByteString loginToken)
        {
            if (!(v3.Auth.Ui is IAuthSsoUI ssoUi)) throw new KeeperCanceled();

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
                    try
                    {
                        await v3.Auth.ExecutePushAction(rq);
                    }
                    catch (KeeperCanceled kc)
                    {
                        completeTask.SetException(kc);
                    }
                }
            };

            var adminChannel = new GetDataKeyActionInfo(DataKeyShareChannel.AdminApproval)
            {
                InvokeGetDataKeyAction = async () =>
                {
                    try
                    {
                        await v3.RequestDeviceAdminApproval();
                    }
                    catch (KeeperCanceled kc)
                    {
                        completeTask.SetException(kc);
                    }
                }
            };

            bool ProcessDataKeyRequest(NotificationEvent message)
            {
                if (completeTask.Task.IsCompleted) return true;
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

            v3.Auth.PushNotifications.RegisterCallback(ProcessDataKeyRequest);
            var uiTask = ssoUi.WaitForDataKey(new IDataKeyChannelInfo[] {pushChannel, adminChannel}, completeToken.Token);
            var index = Task.WaitAny(uiTask, completeTask.Task);
            v3.Auth.PushNotifications.RemoveCallback(ProcessDataKeyRequest);
            if (index == 0)
            {
                var result = await uiTask;
                if (!result) throw new KeeperCanceled();
            }
            else
            {
                await completeTask.Task;
                completeToken.Cancel();
            }

            return await v3.ResumeLogin(loginToken);
        }
        
        internal static void SsoLogout(this Auth auth)
        {
            if (auth.AuthContext is AuthContext context)
            {
                if (context.SsoLoginInfo != null && auth.Ui is IAuthSsoUI ssoUi)
                {
                    var queryString = System.Web.HttpUtility.ParseQueryString("");

                    if (context.AccountAuthType == AccountAuthType.CloudSso)
                    {
                        var rq = new SsoCloudRequest
                        {
                            ClientVersion = auth.Endpoint.ClientVersion,
                            Embedded = true,
                            IdpSessionId = context.SsoLoginInfo.IdpSessionId,
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

                    var builder = new UriBuilder(new Uri(context.SsoLoginInfo.SpBaseUrl.Replace("/login", "/logout")))
                    {
                        Query = queryString.ToString()
                    };
                    ssoUi.SsoLogoutUrl(builder.Uri.AbsoluteUri);
                }
            }
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
