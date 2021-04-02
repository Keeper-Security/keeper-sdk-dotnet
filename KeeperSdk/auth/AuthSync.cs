using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Authentication.Sync
{
    /// <summary>
    /// Defines the user interface methods required for authentication with Keeper (sync).
    /// </summary>
    /// <seealso cref="ISsoLogoutCallback"/>
    /// <seealso cref="IPostLoginTaskUI"/>
    public interface IAuthSyncCallback : IAuthCallback
    {
        void OnNextStep();
    }

    /// <summary>
    /// Represents Keeper authentication. (sync)
    /// </summary>
    /// <seealso cref="Async.Auth"/>
    /// <seealso cref="IAuth"/>
    /// <seealso cref="IAuthentication"/>
    public class AuthSync : AuthCommon, IAuth
    {
        /// <summary>
        /// Gets User interaction interface.
        /// </summary>
        public IAuthSyncCallback UiCallback { get; set; }

        /// <exclude/>
        public override IAuthCallback AuthCallback => UiCallback;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="storage">Configuration storage.</param>
        /// <param name="endpoint">Keeper Endpoint.</param>
        public AuthSync(IConfigurationStorage storage, IKeeperEndpoint endpoint = null) 
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage.LastServer, Storage.Servers);

            Cancel();
        }

        /// <summary>
        /// Gets configuration storage.
        /// </summary>
        public IConfigurationStorage Storage { get; }

        /// <summary>
        /// Gets or sets session resumption flag
        /// </summary>
        public bool ResumeSession { get; set; }

        /// <summary>
        /// Forces master password login for SSO accounts.
        /// </summary>
        public bool AlternatePassword { get; set; }

        /// <summary>
        /// Gets or sets username.
        /// </summary>
        public new string Username
        {
            get => base.Username;
            set => base.Username = value;
        }

        /// <exclude />
        public void SetPushNotifications(IFanOut<NotificationEvent> pushNotifications)
        {
            PushNotifications = pushNotifications;
        }

        /// <summary>
        /// Gets or sets device token
        /// </summary>
        public new byte[] DeviceToken
        {
            get => base.DeviceToken;
            set => base.DeviceToken = value;
        }


        /// <summary>
        /// Gets a value that indicates whether login to Keeper has completed.
        /// </summary>
        public bool IsCompleted => 
            Step.State == AuthState.Connected || 
            Step.State == AuthState.Error || 
            Step.State == AuthState.Restricted;

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
            Step = new ReadyToLoginStep();
        }

        private LoginContext _loginContext;

        private async Task DetectProxySync(Func<Task> resumeWhenDone)
        {
            var keeperUri = new Uri($"https://{Endpoint.Server}/api/rest/ping");
            var proxyStep = await DetectProxy(keeperUri,
                (proxyUri, proxyAuth) =>
                {
                    return new HttpProxyStep
                    {
                        ProxyUri = proxyUri,
                        OnSetProxyCredentials = async (proxyUsername, proxyPassword) =>
                        {
                            var proxy = AuthUIExtensions.GetWebProxyForCredentials(proxyUri, proxyAuth, proxyUsername, proxyPassword);
                            await PingKeeperServer(keeperUri, proxy);
                            Endpoint.WebProxy = proxy;
                            await resumeWhenDone.Invoke();
                        },
                    };
                });
            if (proxyStep != null)
            {
                Step = proxyStep;
            }
            else
            {
                await resumeWhenDone.Invoke();
            }
        }

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
                    await this.RedirectToRegionV3(krr.RegionHost);
                    await this.EnsureDeviceTokenIsRegistered(_loginContext, Username);
                    Step = await this.StartLogin(_loginContext, StartLoginSync);
                }
            }
            catch (Exception e)
            {
                var code = e is KeeperApiException kae ? kae.Code : "unknown_error";
                Step = new ErrorStep(code, e.Message);
            }
        }

        /// <summary>
        /// Login to Keeper account with email.
        /// </summary>
        /// <param name="username">Keeper account email address.</param>
        /// <param name="passwords">Master password(s)</param>
        /// <returns>Awaitable task</returns>
        /// <seealso cref="LoginSso(string, bool)"/>
        public async Task Login(string username, params string[] passwords)
        {
            await DetectProxySync(async () =>
            {
                if (Step.State != AuthState.NotConnected)
                {
                    Cancel();
                }

                if (string.IsNullOrEmpty(username))
                {
                    throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
                }

                _loginContext = new LoginContext();
                foreach (var password in passwords)
                {
                    _loginContext.PasswordQueue.Enqueue(password);
                }

                await DoLogin(username);
            });
        }

        private async Task DoLoginSso(string providerName, bool forceLogin)
        {
            var serviceProvider = await this.GetSsoServiceProvider(_loginContext, providerName);
            var step = AuthorizeUsingSso(serviceProvider.IsCloud, serviceProvider.SpUrl, forceLogin, null);
            step.LoginAsUser = providerName;
            step.LoginAsProvider = true;
            Step = step;
        }

        /// <summary>
        /// Login to Keeper account with SSO provider.
        /// </summary>
        /// <param name="providerName">SSO provider name.</param>
        /// <param name="forceLogin">Force new login with SSO IdP.</param>
        /// <returns>Awaitable task.</returns>
        /// <seealso cref="Login(string, string[])"/>
        public async Task LoginSso(string providerName, bool forceLogin = false)
        {
            await DetectProxySync(async () =>
            {
                Cancel();
                _loginContext = new LoginContext();
                await DoLoginSso(providerName, forceLogin);
            });
        }

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
                    return await this.ResumeLogin(_loginContext, StartLoginSync, response.EncryptedLoginToken);

                case LoginState.Requires2Fa:
                    return TwoFactorValidate(response.EncryptedLoginToken, response.Channels.ToArray());

                case LoginState.RequiresAuthHash:
                    return ValidateAuthHash(response.EncryptedLoginToken, response.Salt.ToArray());

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
            if (authContext.SessionTokenRestriction == 0 && PushNotifications is IPushNotificationChannel push)
            {
                await push.SendToWebSocket(authContext.SessionToken, false);
            }

            this.StoreConfigurationIfChangedV3(_loginContext);
            try
            {
                await PostLogin();
                return authContext.SessionTokenRestriction == 0 
                    ? (AuthStep) new ConnectedStep() 
                    : (AuthStep) new RestrictedConnectionStep();
            }
            catch (KeeperApiException kae)
            {
                return new ErrorStep(kae.Code, kae.Message);
            }
            catch (Exception e)
            {
                return new ErrorStep("unknown_error", e.Message);
            }
        }

        private TwoFactorStep TwoFactorValidate(ByteString loginToken, IEnumerable<TwoFactorChannelInfo> channels)
        {
            var tfaStep = new TwoFactorStep();
            var t = this.TwoFactorValidatePrepare(
                token =>
                {
                    if (ReferenceEquals(Step, tfaStep))
                    {
                        Step = this.ResumeLogin(_loginContext, StartLoginSync, token).Result;
                    }
                },
                loginToken,
                channels);
            var channelInfo = t.Item1;
            var onDone = t.Item2;

            tfaStep.Channels = channelInfo.Select(x => x.Channel).ToArray();
            tfaStep.Duration = TwoFactorDuration.Every30Days;
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
            return tfaStep;
        }

        private PasswordStep ValidateAuthHash(ByteString loginToken, Salt[] salts)
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
                    passwordInfo.InvokePasswordActionDelegate.Invoke(password).GetAwaiter().GetResult();
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
                onPassword = async password =>
                {
                    await passwordInfo.InvokePasswordActionDelegate.Invoke(password);
                },
                onBiometricKey = async bioKey =>
                {
                    await passwordInfo.InvokeBiometricsActionDelegate.Invoke(bioKey);
                }
            };

            return step;
        }

        private DeviceApprovalStep ApproveDevice(ByteString loginToken)
        {
            var deviceApprovalStep = new DeviceApprovalStep();

            var t = this.ApproveDevicePrepare(
                _loginContext,
                (token) =>
                {
                    if (ReferenceEquals(Step, deviceApprovalStep))
                    {
                        Step = this.ResumeLogin(_loginContext, StartLoginSync, token).Result;
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
            deviceApprovalStep.onDispose = onDone;
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
                    (token) => { Step = ResumeAfterSso(token).GetAwaiter().GetResult(); },
                    ssoBaseUrl,
                    forceLogin)
                : this.AuthorizeUsingOnsiteSsoPrepare(_loginContext,
                    () => { Step = ResumeAfterSso(loginToken).GetAwaiter().GetResult(); },
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
            var dataKeyStep = new SsoDataKeyStep();

            var t = this.RequestDataKeyPrepare(
                _loginContext,
                (approved) =>
                {
                    Task.Run(async () =>
                    {
                        if (ReferenceEquals(Step, dataKeyStep))
                        {
                            Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken, LoginMethod.AfterSso);
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
            return dataKeyStep;
        }
    }
}
