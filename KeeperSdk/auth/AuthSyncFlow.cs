using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Configuration;

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
            ResumeSession = false;
        }

        public bool ResumeSession { get; set; }
        public bool UseAlternatePassword { get; set; }

        internal Func<string, string[], Task> onLogin;

        public Task Login(string username, params string[] passwords)
        {
            return onLogin?.Invoke(username, passwords);
        }

        internal Func<string, Task> onLoginSso;

        public Task LoginSSO(string providerName)
        {
            return onLoginSso?.Invoke(providerName);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            onLogin = null;
            onLoginSso = null;
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

    public class SsoDataKey : AuthStep
    {
        public SsoDataKey() : base(AuthState.SsoDataKey)
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
        public ErrorStep(string message) : base(AuthState.Error)
        {
            Message = message;
        }

        public string Message { get; }
    }

    public interface IAuthFlowCallback
    {
        void OnNextStep();
        void OnMessage(string message);
    }

    public class AuthSyncFlow : IAuthUI, IHttpProxyCredentialUi, IAuthSsoUI
    {
        public Auth Auth { get; private set; }
        public IAuthFlowCallback UiCallback { get; set; }
        private IConfigurationStorage Storage { get; }
        private IKeeperEndpoint Endpoint { get; }

        public AuthSyncFlow(IConfigurationStorage storage, IKeeperEndpoint endpoint = null)
        {
            Storage = storage;
            Endpoint = endpoint;
            Cancel();
        }

        public bool IsCompleted => Step.State == AuthState.Connected || Step.State == AuthState.Error;

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
            StepTask = null;

            Auth?.Dispose();
            Auth = null;

            Step = new LoginStep
            {
                onLogin = LoginAction,
                onLoginSso = LoginSSOAction,
            };
        }

        private int _loginAttempt = 0;
        private TaskCompletionSource<bool> _stateChangeTask;

        private TaskCompletionSource<bool> StateChangeTask
        {
            get => _stateChangeTask;
            set
            {
                var task = _stateChangeTask;
                if (task != null && !task.Task.IsCompleted)
                {
                    Task.Run(() =>
                    {
                        task.TrySetResult(false);
                    });
                }

                _stateChangeTask = value;
            }
        }

        private async Task LoginAction(string username, string[] passwords)
        {
            if (Step.State != AuthState.Login)
            {
                Cancel();
            }

            var loginStep = Step as LoginStep;
            var resumeSession = loginStep?.ResumeSession ?? false;
            var alternatePassword = loginStep?.UseAlternatePassword ?? false;

            StateChangeTask = new TaskCompletionSource<bool>();
            _ = Task.Run(async () =>
            {
                var auth = new Auth(this, Storage, Endpoint)
                {
                    ResumeSession = resumeSession,
                    AlternatePassword = alternatePassword
                };

                var attempt = Interlocked.Increment(ref _loginAttempt);
                try
                {
                    await auth.Login(username, passwords);
                    Auth = auth;
                    Step = new ConnectedStep();
                    StateChangeTask?.TrySetResult(true);
                }
                catch (Exception e)
                {
                    if (attempt == _loginAttempt)
                    {
                        Step = new ErrorStep($"Login Error: {e.Message}");
                    }

                    StateChangeTask?.TrySetException(e);
                }
                finally
                {
                    StateChangeTask = null;
                }
            });
            await StateChangeTask.Task;
        }

        private async Task LoginSSOAction(string providerName)
        {
            if (Step.State != AuthState.Login)
            {
                Cancel();
            }

            StateChangeTask = new TaskCompletionSource<bool>();
            _ = Task.Run(async () =>
            {
                var auth = new Auth(this, Storage, Endpoint);
                var attempt = Interlocked.Increment(ref _loginAttempt);
                try
                {
                    UiCallback?.OnMessage($"Connected to \"{auth.Endpoint.Server}\"");
                    await auth.LoginSso(providerName);
                    Auth = auth;
                    Step = new ConnectedStep();
                    StateChangeTask = null;
                }
                catch (Exception e)
                {
                    if (attempt == _loginAttempt)
                    {
                        Step = new ErrorStep($"Login Error: {e.Message}");
                    }
                }
            });
            await StateChangeTask.Task;
        }

        private TaskCompletionSource<bool> StepTask
        {
            get => _stepTask;
            set
            {
                if (_stepTask != null && !_stepTask.Task.IsCompleted)
                {
                    _stepTask.TrySetResult(true);
                }

                _stepTask = value;
            }
        }

        private AuthStep _step;
        private TaskCompletionSource<bool> _stepTask;

        public Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        {
            var deviceApprovalStep = new DeviceApprovalStep
            {
                DefaultChannel = channels[0].Channel,
                Channels = channels.Select(x => x.Channel).ToArray(),
                OnSendPush = async (channel) =>
                {
                    var push = channels
                        .OfType<IDeviceApprovalPushInfo>()
                        .FirstOrDefault(x => x.Channel == channel);
                    if (push != null)
                    {
                        await push.InvokeDeviceApprovalPushAction();
                    }
                },
                OnSendCode = async (channel, code) =>
                {
                    var otp = channels
                        .OfType<IDeviceApprovalOtpInfo>()
                        .FirstOrDefault(x => x.Channel == channel);
                    if (otp != null)
                    {
                        await otp.InvokeDeviceApprovalOtpAction.Invoke(code);
                    }
                }
            };

            Step = deviceApprovalStep;
            StateChangeTask = null;

            StepTask = new TaskCompletionSource<bool>();
            return StepTask.Task;
        }

        public Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token)
        {
            var tfaStep = new TwoFactorStep
            {
                Duration = TwoFactorDuration.Every30Days,
                DefaultChannel = channels[0].Channel,
                Channels = channels.Select(x => x.Channel).ToArray(),
                OnGetChannelPushActions = (channel) =>
                {
                    return channels
                        .OfType<ITwoFactorPushInfo>()
                        .SelectMany(x => x.SupportedActions,
                            (x, y) => y)
                        .ToArray();
                },
            };
            tfaStep.OnSendPush = async (action) =>
            {
                var channel = channels
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
                var otp = channels
                    .OfType<ITwoFactorAppCodeInfo>()
                    .FirstOrDefault(x => x.Channel == channel);
                if (otp != null)
                {
                    if (otp is ITwoFactorDurationInfo dur)
                    {
                        dur.Duration = tfaStep.Duration;
                    }

                    var taskSource = new TaskCompletionSource<bool>();
                    try
                    {
                        StateChangeTask = taskSource;
                        await otp.InvokeTwoFactorCodeAction.Invoke(code);
                        await taskSource.Task;
                    }
                    finally
                    {
                        if (!taskSource.Task.IsCompleted)
                        {
                            taskSource.TrySetResult(false);
                        }
                    }
                }
            };

            Step = tfaStep;
            StateChangeTask = null;

            StepTask = new TaskCompletionSource<bool>();
            return StepTask.Task;
        }

        public Task<bool> WaitForUserPassword(IPasswordInfo passwordInfo, CancellationToken token)
        {
            var passwordStep = new PasswordStep
            {
                OnPassword = async (password) =>
                {
                    var taskSource = new TaskCompletionSource<bool>();
                    try
                    {
                        StateChangeTask = taskSource;
                        await passwordInfo.InvokePasswordActionDelegate(password);
                        await taskSource.Task;
                    }
                    finally
                    {
                        if (!taskSource.Task.IsCompleted)
                        {
                            taskSource.TrySetResult(false);
                        }
                    }
                }
            };

            Step = passwordStep;
            StateChangeTask = null;

            StepTask = new TaskCompletionSource<bool>();
            return StepTask.Task;
        }

        public Task<bool> WaitForHttpProxyCredentials(IHttpProxyInfo proxyInfo)
        {
            var proxyStep = new HttpProxyStep
            {
                ProxyUri = proxyInfo.ProxyUri,
                OnSetProxyCredentials = (username, password) => { proxyInfo.InvokeHttpProxyCredentialsDelegate.Invoke(username, password); },
            };

            Step = proxyStep;
            StateChangeTask = null;

            StepTask = new TaskCompletionSource<bool>();
            return StepTask.Task;
        }

        public Task<bool> WaitForSsoToken(ISsoTokenActionInfo actionInfo, CancellationToken token)
        {
            var ssoLoginStep = new SsoTokenStep
            {
                SsoLoginUrl = actionInfo.SsoLoginUrl,
                IsCloudSso = actionInfo.IsCloudSso,
                OnSetSsoToken = async (ssoToken) =>
                {
                    try
                    {
                        var taskSource = new TaskCompletionSource<bool>();
                        StateChangeTask = taskSource;
                        await actionInfo.InvokeSsoTokenAction.Invoke(ssoToken);
                        await taskSource.Task;
                    }
                    finally
                    {
                        StateChangeTask = null;
                    }
                }
            };

            Step = ssoLoginStep;
            StateChangeTask = null;

            StepTask = new TaskCompletionSource<bool>();
            return StepTask.Task;
        }

        public Task<bool> WaitForDataKey(IDataKeyChannelInfo[] channels, CancellationToken token)
        {
            var dataKeyStep = new SsoDataKey
            {
                Channels = channels.Select(x => x.Channel).ToArray(),
                OnRequestDataKey = async (channel) =>
                {
                    var info = channels.FirstOrDefault(x => x.Channel == channel);
                    if (info != null)
                    {
                        await info.InvokeGetDataKeyAction();
                    }
                },
            };

            Step = dataKeyStep;
            StateChangeTask = null;

            StepTask = new TaskCompletionSource<bool>();
            return StepTask.Task;
        }

        public void SsoLogoutUrl(string url)
        {
            // TODO
        }
    }
}
