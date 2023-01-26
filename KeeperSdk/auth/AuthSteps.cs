using System;
using System.Threading.Tasks;

namespace KeeperSecurity.Authentication.Sync
{
    /// <summary>
    /// Specifies authentication states.
    /// </summary>
    public enum AuthState
    {
        /// <summary>
        /// Ready to login
        /// </summary>
        NotConnected,
        /// <summary>
        /// Device Approval
        /// </summary>
        DeviceApproval,
        /// <summary>
        /// Two Factor Authentication
        /// </summary>
        TwoFactor,
        /// <summary>
        /// Master Password
        /// </summary>
        Password,
        /// <summary>
        /// SSO Login
        /// </summary>
        SsoToken,
        /// <summary>
        /// SSO Approval
        /// </summary>
        SsoDataKey,
        /// <summary>
        /// Login success
        /// </summary>
        Connected,
        /// <summary>
        /// Login failure
        /// </summary>
        Error,
        /// <summary>
        /// Restricted Connection
        /// </summary>
        Restricted,
    }

    /// <summary>
    /// Represents base Keeper authentication step
    /// </summary>
    /// <seealso cref="ReadyToLoginStep"/>
    /// <seealso cref="DeviceApprovalStep"/>
    /// <seealso cref="TwoFactorStep"/>
    /// <seealso cref="PasswordStep"/>
    /// <seealso cref="SsoTokenStep"/>
    /// <seealso cref="SsoDataKeyStep"/>
    /// <seealso cref="ConnectedStep"/>
    /// <seealso cref="ErrorStep"/>
    public abstract class AuthStep : IDisposable
    {
        protected AuthStep(AuthState state)
        {
            State = state;
        }

        /// <summary>
        /// Gets Keeper login state
        /// </summary>
        public AuthState State { get; }

        protected virtual void Dispose(bool disposing)
        {
        }
        /// <exclude/>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Represents initial Login step
    /// </summary>
    public class ReadyToLoginStep : AuthStep
    {
        internal ReadyToLoginStep() : base(AuthState.NotConnected)
        {
        }
    }

    /// <summary>
    /// Represents device approval step
    /// </summary>
    public class DeviceApprovalStep : AuthStep
    {
        internal DeviceApprovalStep() : base(AuthState.DeviceApproval)
        {
        }

        /// <summary>
        /// Gets or sets default device approval channel
        /// </summary>
        public DeviceApprovalChannel DefaultChannel { get; set; }

        /// <summary>
        /// Gets available device approval channels
        /// </summary>
        public DeviceApprovalChannel[] Channels { get; internal set; }

        internal Func<DeviceApprovalChannel, Task> OnSendPush;

        /// <summary>
        /// Sends push notification to the channel
        /// </summary>
        /// <param name="channel">Device approval channel</param>
        /// <returns>Awaitable task</returns>
        public Task SendPush(DeviceApprovalChannel channel)
        {
            return OnSendPush?.Invoke(channel);
        }

        internal Func<DeviceApprovalChannel, string, Task> OnSendCode;

        /// <summary>
        /// Sends verification code to the channel
        /// </summary>
        /// <param name="channel">Device approval channel</param>
        /// <param name="code">Verification code</param>
        /// <returns>Awaitable task</returns>
        public Task SendCode(DeviceApprovalChannel channel, string code)
        {
            return OnSendCode?.Invoke(channel, code);
        }

        internal Func<Task> OnResume;

        /// <summary>
        /// Resumes login flow
        /// </summary>
        /// <returns>Awaitable task</returns>
        public Task Resume()
        {
            return OnResume?.Invoke();
        }


        internal Action onDispose;

        protected override void Dispose(bool disposing)
        {
            onDispose?.Invoke();
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Represents Two Factor Authentication step
    /// </summary>
    public class TwoFactorStep : AuthStep
    {
        internal TwoFactorStep() : base(AuthState.TwoFactor)
        {
        }

        /// <summary>
        /// Gets or sets default two factor authentication channel
        /// </summary>
        public TwoFactorChannel DefaultChannel { get; set; }

        /// <summary>
        /// Gets available two factor authentication channels
        /// </summary>
        public TwoFactorChannel[] Channels { get; internal set; }

        /// <summary>
        /// Gets / sets two factor authentication duration / expiration
        /// </summary>
        public TwoFactorDuration Duration { get; set; }

        internal Func<TwoFactorChannel, TwoFactorPushAction[]> OnGetChannelPushActions;

        /// <summary>
        /// Gets available push actions for the channel
        /// </summary>
        /// <param name="channel">Two factor authentication channel</param>
        /// <returns>List of available push actions</returns>
        public TwoFactorPushAction[] GetChannelPushActions(TwoFactorChannel channel)
        {
            return OnGetChannelPushActions != null ? OnGetChannelPushActions(channel) : new TwoFactorPushAction[] { };
        }

        internal Func<TwoFactorChannel, bool> OnIsCodeChannel;

        /// <summary>
        /// Gets flag if channel accepts verification codes
        /// </summary>
        /// <param name="channel">Two factor authentication channel</param>
        /// <returns><c>True</c> if the channel supports verification codes</returns>
        public bool IsCodeChannel(TwoFactorChannel channel)
        {
            return OnIsCodeChannel?.Invoke(channel) ?? false;
        }

        internal Func<TwoFactorChannel, string> OnGetPhoneNumber;

        /// <summary>
        /// Gets phone number for the channel
        /// </summary>
        /// <param name="channel">Two factor authentication channel</param>
        /// <returns>Phone number registered to the channel.</returns>
        public string GetPhoneNumber(TwoFactorChannel channel)
        {
            return OnGetPhoneNumber?.Invoke(channel);
        }

        internal Func<TwoFactorPushAction, Task> OnSendPush;

        /// <summary>
        /// Sends push action to the channel
        /// </summary>
        /// <param name="action">Push action</param>
        public Task SendPush(TwoFactorPushAction action)
        {
            return OnSendPush?.Invoke(action);
        }

        internal Func<TwoFactorChannel, string, Task> OnSendCode;

        /// <summary>
        /// Sends verification code
        /// </summary>
        /// <param name="channel"></param>
        /// <param name="code"></param>
        public Task SendCode(TwoFactorChannel channel, string code)
        {
            return OnSendCode?.Invoke(channel, code);
        }

        internal Func<Task> OnResume;

        /// <summary>
        /// Resumes login
        /// </summary>
        public Task Resume()
        {
            return OnResume?.Invoke();
        }

        internal Action OnDispose;

        protected override void Dispose(bool disposing)
        {
            OnDispose?.Invoke();
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Represents Master Password step
    /// </summary>
    public class PasswordStep : AuthStep
    {
        internal PasswordStep() : base(AuthState.Password)
        {
        }

        internal Func<string, Task> onPassword;

        /// <summary>
        /// Verifies master password
        /// </summary>
        /// <param name="password">Master password</param>
        /// <returns>Awaitable task</returns>
        public Task VerifyPassword(string password)
        {
            return onPassword?.Invoke(password);
        }

        internal Func<byte[], Task> onBiometricKey;
        /// <summary>
        /// Verifies biometric key
        /// </summary>
        /// <param name="biometricKey">Biometric key</param>
        /// <returns>Awaitable task</returns>
        public Task VerifyBiometricKey(byte[] biometricKey)
        {
            return onBiometricKey?.Invoke(biometricKey);
        }
    }

    /// <summary>
    /// Represents SSO Login step
    /// </summary>
    public class SsoTokenStep : AuthStep
    {
        internal SsoTokenStep() : base(AuthState.SsoToken)
        {
        }

        /// <summary>
        /// Gets username used to login
        /// </summary>
        public string LoginAsUser { get; internal set; }

        /// <summary>
        /// Gets SSO provider used to login
        /// </summary>
        public bool LoginAsProvider { get; internal set; }

        /// <summary>
        /// Gets SSO login URL
        /// </summary>
        public string SsoLoginUrl { get; internal set; }

        /// <summary>
        /// Gets cloud SSO flag
        /// </summary>
        public bool IsCloudSso { get; internal set; }

        internal Func<string, Task> OnSetSsoToken;
        /// <summary>
        /// Sets SSO login token
        /// </summary>
        /// <param name="ssoToken">SSO token</param>
        /// <returns></returns>
        public Task SetSsoToken(string ssoToken)
        {
            return OnSetSsoToken?.Invoke(ssoToken);
        }

        internal Func<Task> OnLoginWithPassword;
        /// <summary>
        /// Login with alternate Keeper password
        /// </summary>
        /// <returns></returns>
        public Task LoginWithPassword()
        {
            return OnLoginWithPassword?.Invoke();
        }
    }

    /// <summary>
    /// Represents SSO Approval step
    /// </summary>
    public class SsoDataKeyStep : AuthStep
    {
        internal SsoDataKeyStep() : base(AuthState.SsoDataKey)
        {
        }

        /// <summary>
        /// Gets available SSO approval channels
        /// </summary>
        public DataKeyShareChannel[] Channels { get; internal set; }

        internal Func<DataKeyShareChannel, Task> OnRequestDataKey { get; set; }

        /// <summary>
        /// Requests SSO Approval
        /// </summary>
        /// <param name="channel">SSO approval channel</param>
        public Task RequestDataKey(DataKeyShareChannel channel)
        {
            return OnRequestDataKey?.Invoke(channel);
        }

        internal Func<Task> onResume;
        /// <summary>
        /// Resumes login flow
        /// </summary>
        public Task Resume()
        {
            return onResume?.Invoke();
        }
    }

    /// <summary>
    /// Represents Connected step. Final step. Successfully connected to Keeper.
    /// </summary>
    public class ConnectedStep : AuthStep
    {
        internal ConnectedStep() : base(AuthState.Connected)
        {
        }
    }

    /// <summary>
    /// Represents Error step. Final step. Failed to connect to Keeper.
    /// </summary>
    public class ErrorStep : AuthStep
    {
        internal ErrorStep(string code, string message) : base(AuthState.Error)
        {
            Code = code;
            Message = message;
        }

        /// <summary>
        /// Gets error code
        /// </summary>
        public string Code { get; }

        /// <summary>
        /// Get error message
        /// </summary>
        public string Message { get; }
    }

    /// <summary>
    /// Represents Restricted Connection step. Final step. The connection is limited only to certain commands.
    /// </summary>
    public class RestrictedConnectionStep : AuthStep
    {
        public RestrictedConnectionStep() : base(AuthState.Restricted)
        {
        }
    }
}
