using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using static System.Diagnostics.Debug;

namespace KeeperSecurity.Authentication
{
    public enum AuthState
    {
        Login,
        ProxyAuth,
        DeviceApproval,
        TwoFactor,
        Password,
        SsoToken,
        SsoDataKey,
        Connected,
        Error,
    }

    public abstract class AuthStep : IDisposable
    {
        protected AuthStep(AuthState state)
        {
            State = state;
        }

        public AuthState State { get; }

        protected virtual void Dispose(bool disposing)
        {
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    public class LoginStep : AuthStep
    {
        public LoginStep() : base(AuthState.Login)
        {
        }
    }

    public class DeviceApprovalStep : AuthStep
    {
        public DeviceApprovalStep() : base(AuthState.DeviceApproval)
        {
        }

        public DeviceApprovalChannel DefaultChannel { get; set; }
        public DeviceApprovalChannel[] Channels { get; internal set; }

        internal Func<DeviceApprovalChannel, Task> OnSendPush;

        public Task SendPush(DeviceApprovalChannel channel)
        {
            return OnSendPush?.Invoke(channel);
        }

        internal Func<DeviceApprovalChannel, string, Task> OnSendCode;

        public Task SendCode(DeviceApprovalChannel channel, string code)
        {
            return OnSendCode?.Invoke(channel, code);
        }

        internal Action onDispose;

        protected override void Dispose(bool disposing)
        {
            onDispose?.Invoke();
            base.Dispose(disposing);
        }
    }

    public class TwoFactorStep : AuthStep
    {
        public TwoFactorStep() : base(AuthState.TwoFactor)
        {
        }

        public TwoFactorChannel DefaultChannel { get; set; }

        public TwoFactorChannel[] Channels { get; internal set; }

        public TwoFactorDuration Duration { get; set; }

        internal Func<TwoFactorChannel, TwoFactorPushAction[]> OnGetChannelPushActions;

        public TwoFactorPushAction[] GetChannelPushActions(TwoFactorChannel channel)
        {
            return OnGetChannelPushActions != null ? OnGetChannelPushActions(channel) : new TwoFactorPushAction[] { };
        }

        internal Func<TwoFactorChannel, bool> OnIsCodeChannel;

        public bool IsCodeChannel(TwoFactorChannel channel)
        {
            return OnIsCodeChannel?.Invoke(channel) ?? false;
        }

        internal Func<TwoFactorChannel, string> OnGetPhoneNumber;

        public string GetPhoneNumber(TwoFactorChannel channel)
        {
            return OnGetPhoneNumber?.Invoke(channel);
        }

        internal Func<TwoFactorPushAction, Task> OnSendPush;

        public Task SendPush(TwoFactorPushAction action)
        {
            return OnSendPush?.Invoke(action);
        }

        internal Func<TwoFactorChannel, string, Task> OnSendCode;

        public Task SendCode(TwoFactorChannel channel, string code)
        {
            return OnSendCode?.Invoke(channel, code);
        }

        internal Action OnDispose;

        protected override void Dispose(bool disposing)
        {
            OnDispose?.Invoke();
            base.Dispose(disposing);
        }
    }

    public class PasswordStep : AuthStep
    {
        public PasswordStep() : base(AuthState.Password)
        {
        }

        internal Func<string, Task> OnPassword;

        public Task VerifyPassword(string password)
        {
            return OnPassword?.Invoke(password);
        }
    }

    public class HttpProxyStep : AuthStep
    {
        public HttpProxyStep() : base(AuthState.ProxyAuth)
        {
        }

        public Uri ProxyUri { get; internal set; }

        internal Action<string, string> OnSetProxyCredentials;

        public void SetProxyCredentials(string username, string password)
        {
            OnSetProxyCredentials?.Invoke(username, password);
        }
    }

    public class SsoTokenStep : AuthStep
    {
        public SsoTokenStep() : base(AuthState.SsoToken)
        {
        }

        public string SsoLoginUrl { get; internal set; }
        public bool IsCloudSso { get; internal set; }

        internal Func<string, Task> OnSetSsoToken;

        public Task SetSsoToken(string ssoToken)
        {
            return OnSetSsoToken?.Invoke(ssoToken);
        }
    }

    public class SsoDataKeyStep : AuthStep
    {
        public SsoDataKeyStep() : base(AuthState.SsoDataKey)
        {
        }

        public DataKeyShareChannel[] Channels { get; internal set; }

        internal Func<DataKeyShareChannel, Task> OnRequestDataKey { get; set; }

        public Task RequestDataKey(DataKeyShareChannel channel)
        {
            return OnRequestDataKey?.Invoke(channel);
        }
    }

    public class ConnectedStep : AuthStep
    {
        public ConnectedStep() : base(AuthState.Connected)
        {
        }
    }

    public class ErrorStep : AuthStep
    {
        public ErrorStep(string code, string message) : base(AuthState.Error)
        {
            Code = code;
            Message = message;
        }

        public string Code { get; }
        public string Message { get; }
    }

    public interface IAuthSyncCallback : IAuthUi
    {
        void OnNextStep();
    }

    public class AuthSync : AuthCommon, IHttpProxyCredentialUi
    {
        public IAuthSyncCallback UiCallback { get; set; }
        public override IAuthUi AuthUi => UiCallback;

        public AuthSync(IConfigurationStorage storage, IKeeperEndpoint endpoint = null) : base(storage, endpoint)
        {
            if (endpoint is KeeperEndpoint ke && ke.ProxyUi == null)
            {
                ke.ProxyUi = this;
            }

            Cancel();
        }

        public Task<bool> WaitForHttpProxyCredentials(IHttpProxyInfo proxyInfo)
        {
            return Task.FromResult(false);
        }

        public bool IsCompleted => Step.State == AuthState.Connected || Step.State == AuthState.Error;

        private AuthStep _step;

        public AuthStep Step
        {
            get => _step;
            private set
            {
                var notifyStateChanged = _step != null;
                _step?.Dispose();
                _step = value;
                if (notifyStateChanged)
                {
                    Task.Run(() => { UiCallback?.OnNextStep(); });
                }
            }
        }

        public void Cancel()
        {
            Step = new LoginStep();
        }

        private V3LoginContext _loginContext;

        public override async Task Login(string username, params string[] passwords)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
            }

            Cancel();
            Username = username.ToLowerInvariant();
            _loginContext = new V3LoginContext();
            await this.EnsureDeviceTokenIsRegistered(_loginContext, Username);

            foreach (var password in passwords)
            {
                _loginContext.PasswordQueue.Enqueue(password);
            }

            try
            {
                Step = await this.StartLogin(_loginContext, StartLoginSync);
            }
            catch (KeeperRegionRedirect krr)
            {
                await this.RedirectToRegionV3(krr.RegionHost);
                Step = await this.StartLogin(_loginContext, StartLoginSync);
            }
        }

        // TODO
        public override async Task LoginSso(string providerName, bool forceLogin = false)
        {
            Cancel();
            _loginContext = new V3LoginContext();
        }

        private async Task<AuthStep> StartLoginSync(StartLoginRequest request)
        {
#if DEBUG
            WriteLine($"REST Request: endpoint \"start_login\": {request}");
#endif

            var rs = await Endpoint.ExecuteRest("authentication/start_login", new ApiRequestPayload {Payload = request.ToByteString()});
            var response = LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            WriteLine($"REST Response: endpoint \"start_login\": {response}");
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
                    _loginContext.AccountAuthType = AccountAuthType.CloudSso;
                    return AuthorizeUsingCloudSso(response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

                case LoginState.RedirectOnsiteSso:
                    _loginContext.AccountAuthType = AccountAuthType.OnsiteSso;
                    return AuthorizeUsingOnsiteSso(response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

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
                    if (_loginContext.AccountAuthType == AccountAuthType.CloudSso)
                    {
                        await this.CreateSsoUser(_loginContext, response.EncryptedLoginToken);
                        return await this.ResumeLogin(_loginContext, StartLoginSync, response.EncryptedLoginToken);
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

        private async Task<ConnectedStep> OnConnected(AuthContext context)
        {
            authContext = context;
            if (authContext.SessionTokenRestriction == 0 && PushNotifications is IPushNotificationChannel push)
            {
                await push.SendToWebSocket(authContext.SessionToken, false);
            }

            this.StoreConfigurationIfChangedV3(_loginContext.CloneCode);
            await PostLogin();

            return new ConnectedStep();
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
                    Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken);
                }
            };
            return tfaStep;
        }

        private PasswordStep ValidateAuthHash(ByteString loginToken, Salt[] salts)
        {
            var passwordInfo = this.ValidateAuthHashPrepare(_loginContext,
                context => { Step = OnConnected(context).GetAwaiter().GetResult(); },
                loginToken,
                salts
            );
            var step = new PasswordStep
            {
                OnPassword = async password => { await passwordInfo.InvokePasswordActionDelegate.Invoke(password); }
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

        private SsoTokenStep AuthorizeUsingCloudSso(string ssoBaseUrl, bool forceLogin, ByteString loginToken)
        {
            var ssoAction = this.AuthorizeUsingCloudSsoPrepare(_loginContext,
                (token) => { Task.Run(async () => { Step = await this.ResumeLogin(_loginContext, StartLoginSync, token); }); },
                ssoBaseUrl,
                forceLogin,
                loginToken);

            var ssoTokenStep = new SsoTokenStep
            {
                SsoLoginUrl = ssoAction.SsoLoginUrl,
                IsCloudSso = ssoAction.IsCloudSso,
                OnSetSsoToken = (ssoToken) => ssoAction.InvokeSsoTokenAction.Invoke(ssoToken)
            };
            return ssoTokenStep;
        }

        SsoTokenStep AuthorizeUsingOnsiteSso(string ssoBaseUrl, bool forceLogin, ByteString loginToken)
        {
            var ssoAction = this.AuthorizeUsingOnsiteSsoPrepare(_loginContext,
                () =>
                {
                    Task.Run(async () =>
                    {
                        if (loginToken != null)
                        {
                            Step = await this.ResumeLogin(_loginContext, StartLoginSync, loginToken, LoginMethod.AfterSso);
                        }
                        else
                        {
                            await this.EnsureDeviceTokenIsRegistered(_loginContext, Username);
                            Step = await this.StartLogin(_loginContext, StartLoginSync, false, LoginMethod.AfterSso);
                        }
                    });
                },
                ssoBaseUrl,
                forceLogin,
                loginToken);

            return new SsoTokenStep
            {
                SsoLoginUrl = ssoAction.SsoLoginUrl,
                IsCloudSso = ssoAction.IsCloudSso,
                OnSetSsoToken = (ssoToken) => ssoAction.InvokeSsoTokenAction.Invoke(ssoToken)
            };
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
            var onApproved = t.Item2;

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

        public void SsoLogoutUrl(string url)
        {
            // TODO
        }
    }
}
