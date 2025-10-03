using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using Push;

[assembly: InternalsVisibleTo("Tests")]

namespace KeeperSecurity.Authentication.Sync
{
    /// <summary>
    /// Defines the user interface methods required for authentication with Keeper (sync).
    /// </summary>
    /// <seealso cref="ISsoLogoutCallback"/>
    /// <seealso cref="IPostLoginTaskUI"/>
    public interface IAuthSyncCallback
    {
        void OnNextStep();
    }

    /// <summary>
    /// Represents Keeper authentication. (sync)
    /// </summary>
    /// <seealso cref="IAuth"/>
    /// <seealso cref="IAuthentication"/>
    public class AuthSync : AuthCommon, IAuth
    {
        /// <summary>
        /// Gets User interaction interface.
        /// </summary>
        public IAuthSyncCallback UiCallback { get; set; }

        /// <exclude/>
        public override object AuthCallback => UiCallback;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="storage">Configuration storage.</param>
        /// <param name="endpoint">Keeper Endpoint.</param>
        public AuthSync(IConfigurationStorage storage, IKeeperEndpoint endpoint = null) 
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage);

            Cancel();
        }

        /// <inheritdoc/>>
        public IConfigurationStorage Storage { get; }

        /// <inheritdoc/>>
        public bool ResumeSession { get; set; }

        /// <inheritdoc/>>
        public bool AlternatePassword { get; set; }

        /// <inheritdoc cref="IAuth.Username" />>
        public new string Username
        {
            get => base.Username;
            set => base.Username = value;
        }

        /// <inheritdoc cref="IAuth.DeviceToken" />>
        public new byte[] DeviceToken
        {
            get => base.DeviceToken;
            set => base.DeviceToken = value;
        }

        /// <summary>
        /// Gets a value that indicates whether login to Keeper has completed.
        /// </summary>
        public bool IsCompleted => Step.State is AuthState.Connected or AuthState.Error or AuthState.Restricted;

        private AuthStep _step;

        /// <summary>
        /// Gets a current login step.
        /// </summary>
        public AuthStep Step
        {
            get => _step;
            protected set
            {
                if (value == null) return;
                _step?.Dispose();
                _step = value;
                Task.Run(() =>
                {
                    UiCallback?.OnNextStep();
                });
            }
        }

        /// <summary>
        /// Cancels Keeper login
        /// </summary>
        public void Cancel()
        {
            SetPushNotifications(null);
            Step = new ReadyToLoginStep();
        }

        private LoginContext _loginContext;

        private async Task DoLogin(string username)
        {
            Username = username.ToLowerInvariant();
            try
            {
                try
                {
                    await this.EnsureDeviceTokenIsRegistered(_loginContext, Username);
                    Step = await this.StartLogin(_loginContext, StartLoginSync);
                }
                catch (KeeperRegionRedirect krr)
                {
                    this.RedirectToRegionV3(krr.RegionHost);
                    await this.EnsureDeviceTokenIsRegistered(_loginContext, Username);
                    Step = await this.StartLogin(_loginContext, StartLoginSync);
                }
            }
            catch (Exception e)
            {
                SetPushNotifications(null);
                var code = e is KeeperApiException kae ? kae.Code : "unknown_error";
                Step = new ErrorStep(code, e.Message);
            }
        }

        /// <inheritdoc/>>
        public async Task Login(string username, params string[] passwords)
        {
            Cancel();
            if (string.IsNullOrEmpty(username))
            {
                throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
            }

            _loginContext = new LoginContext();
            foreach (var password in passwords)
            {
                if (string.IsNullOrEmpty(password)) continue;
                _loginContext.PasswordQueue.Enqueue(password);
            }
            var configuration = Storage.Get();
            var uc = configuration.Users.Get(username);
            if (!string.IsNullOrEmpty(uc?.Password))
            {
                _loginContext.PasswordQueue.Enqueue(uc.Password);
            }

            await DoLogin(username);
        }

        private async Task DoLoginSso(string providerName, bool forceLogin)
        {
            var serviceProvider = await this.GetSsoServiceProvider(_loginContext, providerName);
            var step = AuthorizeUsingSso(serviceProvider.IsCloud, serviceProvider.SpUrl, forceLogin, null);
            step.LoginAsUser = providerName;
            step.LoginAsProvider = true;
            Step = step;
        }

        /// <inheritdoc/>>
        public async Task LoginSso(string providerName, bool forceLogin = false)
        {
            Cancel();
            _loginContext = new LoginContext();
            await DoLoginSso(providerName, forceLogin);
        }

        /// <inheritdoc/>>
        public override async Task Logout()
        {
            await base.Logout();
            Cancel();
        }

        private async Task<AuthStep> StartLoginSync(StartLoginRequest request)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"start_login\": {request}");
#endif

            var rs = await Endpoint.ExecuteRest("authentication/start_login", new ApiRequestPayload {Payload = request.ToByteString()});
            var response = LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"start_login\": {response}");
#endif
            switch (response.LoginState)
            {
                case LoginState.LoggedIn:
                    Username = response.PrimaryUsername;
                    _loginContext.CloneCode = response.CloneCode.ToByteArray();
                    var context = new AuthContext
                    {
                        SessionToken = response.EncryptedSessionToken.ToByteArray(),
                        SessionTokenRestriction = LoginV3Extensions.GetSessionTokenScope(response.SessionTokenType),
                        SsoLoginInfo = _loginContext.SsoLoginInfo,
                    };
                    var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
                    switch (response.EncryptedDataKeyType)
                    {
                        case EncryptedDataKeyType.ByDevicePublicKey:
                            context.DataKey = CryptoUtils.DecryptEc(encryptedDataKey, _loginContext.DeviceKey);
                            break;
                    }

                    return await OnConnected(context);

                case LoginState.RequiresUsername:
                    if (!string.IsNullOrEmpty(Username))
                    {
                        return await this.ResumeLogin(_loginContext, StartLoginSync, response.EncryptedLoginToken);
                    }
                    break;

                case LoginState.Requires2Fa:
                    return TwoFactorValidate(response.EncryptedLoginToken, response.Channels.ToArray());

                case LoginState.RequiresAuthHash:
                    return await ValidateAuthHash(response.EncryptedLoginToken, response.Salt.ToArray());

                case LoginState.DeviceApprovalRequired:
                    return ApproveDevice(response.EncryptedLoginToken);

                case LoginState.RedirectCloudSso:
                {
                    var step = AuthorizeUsingSso(true, response.Url, request.ForceNewLogin, response.EncryptedLoginToken);
                    step.LoginAsUser = Username;
                    step.LoginAsProvider = false;
                    return step;
                }

                case LoginState.RedirectOnsiteSso:
                {
                    var step = AuthorizeUsingSso(false, response.Url, request.ForceNewLogin, response.EncryptedLoginToken);
                    step.LoginAsUser = Username;
                    step.LoginAsProvider = false;
                    return step;
                }

                case LoginState.RequiresDeviceEncryptedDataKey:
                {
                    _loginContext.CloneCode = null;
                    if (_loginContext.AccountAuthType == AccountAuthType.CloudSso)
                    {
                        return RequestDataKey(response.EncryptedLoginToken);
                    }

                    break;
                }

                case LoginState.RequiresAccountCreation:
                    switch (_loginContext.AccountAuthType)
                    {
                        case AccountAuthType.CloudSso:
                            await this.CreateSsoUser(_loginContext, response.EncryptedLoginToken);
                            return await this.ResumeLogin(_loginContext, StartLoginSync, response.EncryptedLoginToken);
                        case AccountAuthType.OnsiteSso:
                            if (_loginContext.PasswordQueue.Count > 0)
                            {
                                await this.RequestCreateUser(_loginContext, _loginContext.PasswordQueue.Peek());
                                return await this.ResumeLogin(_loginContext, StartLoginSync, response.EncryptedLoginToken);
                            }
                            break;
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

        private async Task<AuthStep> OnConnected(AuthContext context)
        {
            authContext = context;

            this.StoreConfigurationIfChangedV3(_loginContext);
            SetPushNotifications(null);

            if (authContext.SessionTokenRestriction == 0)
            {
                var pushNotifications = new KeeperPushNotifications(Endpoint.WebProxy);
                var messageSessionUid = _loginContext.MessageSessionUid;

                async Task<Uri> PrepareWssUrl(byte[] transmissionKey)
                {
                    await ExecuteAuthRest("keep_alive", null);
                    var connectionRequest = new WssConnectionRequest
                    {
                        EncryptedDeviceToken = ByteString.CopyFrom(DeviceToken),
                        MessageSessionUid = ByteString.CopyFrom(messageSessionUid),
                        DeviceTimeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    var apiRequest = Endpoint.PrepareApiRequest(connectionRequest, transmissionKey);
                    var builder = new UriBuilder
                    {
                        Scheme = "wss",
                        Host = Endpoint.PushServer(),
                        Path = "wss_open_connection/" + apiRequest.ToByteArray().Base64UrlEncode()
                    };
                    return builder.Uri;
                }

                pushNotifications.ConnectToPushServer(PrepareWssUrl, context.SessionToken);
                SetPushNotifications(pushNotifications);
            }

            try
            {
                await PostLogin();
                return authContext.SessionTokenRestriction == 0
                    ? new ConnectedStep()
                    : new RestrictedConnectionStep();
            }
            catch (KeeperApiException kae)
            {
                SetPushNotifications(null);
                return new ErrorStep(kae.Code, kae.Message);
            }
            catch (Exception e)
            {
                SetPushNotifications(null);
                return new ErrorStep("unknown_error", e.Message);
            }
        }

        private TwoFactorStep TwoFactorValidate(ByteString loginToken, IEnumerable<TwoFactorChannelInfo> channels)
        {
            this.EnsurePushNotification(_loginContext);
            
            var tfaStep = new TwoFactorStep();
            var t = this.TwoFactorValidatePrepare(
                async (token) =>
                {
                    if (ReferenceEquals(Step, tfaStep))
                    {
                        Step = await this.ResumeLogin(_loginContext, StartLoginSync, token);
                    }
                },
                loginToken,
                channels);
            var channelInfo = t.Item1;
            var onDone = t.Item2;

            tfaStep.Channels = channelInfo.Select(x => x.Channel).ToArray();
            tfaStep.Duration = TwoFactorDuration.EveryLogin;
            tfaStep.DefaultChannel = channelInfo[0].Channel;
            tfaStep.OnGetChannelPushActions = (channel) =>
            {
                return channelInfo
                    .Where(x => x.Channel == channel)
                    .OfType<ITwoFactorPushInfo>()
                    .SelectMany(x => x.SupportedActions,
                        (x, y) => y)
                    .ToArray();
            };
            tfaStep.OnIsCodeChannel = (channel) =>
            {
                return channelInfo
                    .Where(x => x.Channel == channel)
                    .OfType<ITwoFactorAppCodeInfo>()
                    .Any();
            };
            tfaStep.OnGetPhoneNumber = (channel) =>
            {
                return channelInfo
                    .Where(x => x.Channel == channel)
                    .OfType<ITwoFactorAppCodeInfo>()
                    .Select(x => x.PhoneNumber)
                    .FirstOrDefault();
            };
            tfaStep.OnDispose = onDone;

            tfaStep.OnSendPush = async (action) =>
            {
                var channel = channelInfo
                    .OfType<ITwoFactorPushInfo>()
                    .FirstOrDefault(x => x.SupportedActions.Contains(action));
                if (channel != null)
                {
                    if (channel is ITwoFactorDurationInfo dur)
                    {
                        dur.Duration = tfaStep.Duration;
                    }

                    await channel.InvokeTwoFactorPushAction(action);
                }
            };
            tfaStep.OnSendCode = async (channel, code) =>
            {
                var otp = channelInfo
                    .OfType<ITwoFactorAppCodeInfo>()
                    .FirstOrDefault(x => x.Channel == channel);
                if (otp != null)
                {
                    if (otp is ITwoFactorDurationInfo dur)
                    {
                        dur.Duration = tfaStep.Duration;
                    }

                    await otp.InvokeTwoFactorCodeAction.Invoke(code);
                }
            };
            tfaStep.OnResume = async () =>
            {
                Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken);
            };
            return tfaStep;
        }

        private async Task<PasswordStep> ValidateAuthHash(ByteString loginToken, Salt[] salts)
        {
            var passwordInfo = this.ValidateAuthHashPrepare(_loginContext,
                async context => { Step = await OnConnected(context); },
                loginToken,
                salts
            );

            while (_loginContext.PasswordQueue.Count > 0)
            {
                var password = _loginContext.PasswordQueue.Dequeue();
                try
                {
                    await passwordInfo.InvokePasswordActionDelegate.Invoke(password);
                    if (Step.State == AuthState.Connected)
                    {
                        return null;
                    }
                }
                catch (KeeperAuthFailed)
                {
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            }

            var step = new PasswordStep
            {
                OnPassword = async password =>
                {
                    await passwordInfo.InvokePasswordActionDelegate.Invoke(password);
                },
                OnBiometricKey = async bioKey =>
                {
                    await passwordInfo.InvokeBiometricsActionDelegate.Invoke(bioKey);
                }
            };

            return step;
        }

        private DeviceApprovalStep ApproveDevice(ByteString loginToken)
        {
            this.EnsurePushNotification(_loginContext);
            
            var deviceApprovalStep = new DeviceApprovalStep();
            var t = this.ApproveDevicePrepare(
                _loginContext,
                async (token) =>
                {
                    if (ReferenceEquals(Step, deviceApprovalStep))
                    {
                        Step = await this.ResumeLogin(_loginContext, StartLoginSync, token);
                    }
                },
                loginToken);
            var channelInfo = t.Item1;
            var onDone = t.Item2;

            deviceApprovalStep.DefaultChannel = channelInfo[0].Channel;
            deviceApprovalStep.Channels = channelInfo.Select(x => x.Channel).ToArray();
            deviceApprovalStep.OnSendPush = async (channel) =>
            {
                var push = channelInfo
                    .OfType<IDeviceApprovalPushInfo>()
                    .FirstOrDefault(x => x.Channel == channel);
                if (push != null)
                {
                    await push.InvokeDeviceApprovalPushAction();
                }
            };
            deviceApprovalStep.OnSendCode = async (channel, code) =>
            {
                var otp = channelInfo
                    .OfType<IDeviceApprovalOtpInfo>()
                    .FirstOrDefault(x => x.Channel == channel);
                if (otp != null)
                {
                    await otp.InvokeDeviceApprovalOtpAction.Invoke(code);
                }
            };
            deviceApprovalStep.OnResume = async () => 
            {
                Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken);
            };
            deviceApprovalStep.OnDispose = onDone;
            return deviceApprovalStep;
        }

        private SsoTokenStep AuthorizeUsingSso(bool isCloudSso, string ssoBaseUrl, bool forceLogin, ByteString loginToken)
        {
            Task<AuthStep> ResumeAfterSso(ByteString ssoLoginToken)
            {
                return ssoLoginToken == null
                    ? this.StartLogin(_loginContext, StartLoginSync, false, LoginMethod.AfterSso)
                    : this.ResumeLogin(_loginContext, StartLoginSync, ssoLoginToken, LoginMethod.AfterSso);
            }

            _loginContext.AccountAuthType = isCloudSso ? AccountAuthType.CloudSso : AccountAuthType.OnsiteSso;

            var ssoAction = isCloudSso
                ? this.AuthorizeUsingCloudSsoPrepare(_loginContext,
                    async (token) => 
                    {
                        Step = await ResumeAfterSso(token);
                    },
                    ssoBaseUrl,
                    forceLogin)
                : this.AuthorizeUsingOnsiteSsoPrepare(_loginContext,
                    async () =>
                    {
                        Step = await ResumeAfterSso(loginToken);
                    },
                    ssoBaseUrl,
                    forceLogin);

            var ssoTokenStep = new SsoTokenStep
            {
                SsoLoginUrl = ssoAction.SsoLoginUrl,
                IsCloudSso = ssoAction.IsCloudSso,
                OnSetSsoToken = ssoToken => ssoAction.InvokeSsoTokenAction.Invoke(ssoToken),
                OnLoginWithPassword = async () =>
                {
                    AlternatePassword = true;
                    _loginContext.AccountAuthType = AccountAuthType.Regular;
                    Step = await this.StartLogin(_loginContext, StartLoginSync);
                }
            };
            return ssoTokenStep;
        }

        private SsoDataKeyStep RequestDataKey(ByteString loginToken)
        {
            this.EnsurePushNotification(_loginContext);
            var dataKeyStep = new SsoDataKeyStep();
            var t = this.RequestDataKeyPrepare(
                _loginContext,
                (approved) =>
                {
                    Task.Run(async () =>
                    {
                        if (ReferenceEquals(Step, dataKeyStep))
                        {
                            Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken);
                        }
                    });
                },
                loginToken);
            var channels = t.Item1;

            dataKeyStep.Channels = channels.Select(x => x.Channel).ToArray();
            dataKeyStep.OnRequestDataKey = async (channel) =>
            {
                var info = channels.FirstOrDefault(x => x.Channel == channel);
                if (info != null)
                {
                    await info.InvokeGetDataKeyAction();
                }
            };
            dataKeyStep.OnResume = async () =>
            {
                Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken);
            };
            return dataKeyStep;
        }

        /// <summary>
        /// Resume login with an encrypted login token recieved from biometric authentication
        /// </summary>
        /// <param name="encryptedLoginToken">The encrypted login token from biometric authentication</param>
        /// <returns>Task representing the async operation</returns>
        public async Task ResumeLoginWithToken(ByteString encryptedLoginToken)
        {
            Step = await this.ResumeLogin(_loginContext, StartLoginSync, encryptedLoginToken);
        }
    }
}
