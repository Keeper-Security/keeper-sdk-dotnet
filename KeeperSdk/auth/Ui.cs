using System;
using System.Threading.Tasks;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Specifies supported device approval channels.
    /// </summary>
    public enum DeviceApprovalChannel
    {
        /// <summary>
        /// Device approval by email.
        /// </summary>
        Email,
        /// <summary>
        /// Device approval by 2FA.
        /// </summary>
        TwoFactorAuth,
        /// <summary>
        /// Device approval by Keeper Push.
        /// </summary>
        KeeperPush,
    }

    /// <summary>
    /// Specifies supported 2FA channels.
    /// </summary>
    public enum TwoFactorChannel
    {
        /// <summary>
        /// Google / Microsoft Authenticator
        /// </summary>
        Authenticator,
        /// <summary>
        /// SMS 
        /// </summary>
        TextMessage,
        /// <summary>
        /// DUO Security
        /// </summary>
        DuoSecurity,
        /// <summary>
        /// RSA SecurID
        /// </summary>
        RSASecurID,
        /// <summary>
        /// Keeper DNA. Smart watches.
        /// </summary>
        KeeperDNA,
        /// <summary>
        /// U2F Security Key
        /// </summary>
        SecurityKey,
        /// <summary>
        /// Other
        /// </summary>
        Other,
    }

    /// <summary>
    /// Specifies 2FA expiration.
    /// </summary>
    /// <see cref="ITwoFactorDurationInfo" />
    public enum TwoFactorDuration
    {
        /// <summary>
        /// Requires 2FA every login
        /// </summary>
        EveryLogin = 0,
        /// <summary>
        /// Requires 2FA every 30 days
        /// </summary>
        Every30Days = 30,
        /// <summary>
        /// Stores 2FA forever.
        /// </summary>
        Forever = 9999,
    }

    /// <summary>
    /// Specifies supported data key share channels.
    /// </summary>
    public enum DataKeyShareChannel
    {
        /// <summary>
        /// Keeper Push
        /// </summary>
        KeeperPush = 1,
        /// <summary>
        /// Enterprise admin approval
        /// </summary>
        AdminApproval = 2,
    }

    /// <summary>
    /// Specifies available 2FA actions.
    /// </summary>
    public enum TwoFactorPushAction
    {
        None,
        /// <summary>
        /// DUO Push.
        /// </summary>
        DuoPush,
        /// <summary>
        /// DUO SMS.
        /// </summary>
        DuoTextMessage,
        /// <summary>
        /// DOU Voice Call.
        /// </summary>
        DuoVoiceCall,
        /// <summary>
        /// Text Message / SMS.
        /// </summary>
        TextMessage,
        /// <summary>
        /// Push to a smart watch.
        /// </summary>
        KeeperDna,
        Email,
        /// <summary>
        /// U2F Security Key.
        /// </summary>
        SecurityKey,
    }


    /// <summary>
    /// Defines methods that notify client about IAuth object state changes. Optional.
    /// </summary>
    public interface IAuthInfoUI
    {
        /// <summary>
        /// Notifies the client about Keeper region changes
        /// </summary>
        /// <param name="newRegion">Keeper region.</param>
        void RegionChanged(string newRegion);

        /// <summary>
        /// Notifies the client about device token changes
        /// </summary>
        /// <param name="deviceToken">Device Token</param>
        void SelectedDevice(string deviceToken);
    }

    /// <summary>
    /// Defines the methods required to logout from SSO IdP. Optional.
    /// </summary>
    public interface ISsoLogoutCallback
    {
        /// <summary>
        /// Notifies the client that SSO user logged out.
        /// </summary>
        /// <param name="url">SSO Logout URL</param>
        /// <remarks>
        /// Client opens the browser windows and navigates to SSO Logout URL.
        /// </remarks>
        void SsoLogoutUrl(string url);
    }


    /// <summary>
    /// Defines the methods required to complete post login tasks. Optional.
    /// </summary>
    /// <remarks>
    /// Enterprise users may require to complete some post login tasks to complete login to Keeper.
    /// <list type="bullet">
    /// <item><description>Change expired master password.</description></item>
    /// <item><description>Accept Account Transfer Consent.</description></item>
    /// </list>
    /// </remarks>
    public interface IPostLoginTaskUI 
    {
        /// <summary>
        /// Display a dialog
        /// </summary>
        /// <param name="information">Information.</param>
        /// <returns><c>True</c> Yes/Continue/Accept <c>False</c> No/Cancel/Decline</returns>
        /// <remarks>
        /// Present a dialog with the provided information. Dialog has Yes/No buttons.
        /// </remarks>
        Task<bool> Confirmation(string information);

        /// <summary>
        /// Change master password.
        /// </summary>
        /// <param name="matcher">Password complexity rule matcher.</param>
        /// <returns>A task returning a new password.</returns>
        Task<string> GetNewPassword(PasswordRuleMatcher matcher);
    }

    /// <summary>
    /// Base 2FA channel interface 
    /// </summary>
    public interface ITwoFactorChannelInfo
    {
        /// <summary>
        /// 2FA Channel Type
        /// </summary>
        TwoFactorChannel Channel { get; }
    }

    /// <summary>
    /// Base interface for device approval channel.
    /// </summary>
    public interface IDeviceApprovalChannelInfo
    {
        /// <summary>
        /// Device approval channel.
        /// </summary>
        DeviceApprovalChannel Channel { get; }
    }

    /// <summary>
    /// Validate master password delegate.
    /// </summary>
    /// <param name="password">Master Password</param>
    /// <returns>Awaitable task.</returns>
    /// <exception cref="KeeperAuthFailed">Invalid username or password.</exception>
    /// <exception cref="KeeperStartLoginException">Unrecoverable login error.</exception>
    /// <exception cref="KeeperCanceled">Login cancelled.</exception>
    /// <exception cref="Exception">Other exceptions.</exception>
    public delegate Task PasswordActionDelegate(string password);

    /// <summary>
    /// Validate biometrics key delegate.
    /// </summary>
    /// <param name="biometricsKey">Biometrics key.</param>
    /// <returns>Awaitable task.</returns>
    /// <exception cref="KeeperAuthFailed">Invalid username or password.</exception>
    /// <exception cref="KeeperStartLoginException">Unrecoverable login error.</exception>
    /// <exception cref="KeeperCanceled">Login cancelled.</exception>
    /// <exception cref="Exception">Other exceptions.</exception>
    public delegate Task BiometricsActionDelegate(byte[] biometricsKey);

    /// <summary>
    /// Base interface for password validation.
    /// </summary>
    public interface IPasswordInfo
    {
        /// <summary>
        /// Username.
        /// </summary>
        string Username { get; }
        /// <summary>
        /// Master password validation delegate.
        /// </summary>
        PasswordActionDelegate InvokePasswordActionDelegate { get; }
        /// <summary>
        /// Biometric Key validation delegate
        /// </summary>
        BiometricsActionDelegate InvokeBiometricsActionDelegate { get; }
    }

    /// <summary>
    /// Data key share push action.
    /// </summary>
    /// <returns>Awaitable task</returns>
    /// <exception cref="Exception">Other exceptions.</exception>
    public delegate Task GetDataKeyActionDelegate();

    /// <summary>
    /// Base interface for sharing data key.
    /// </summary>
    public interface IDataKeyChannelInfo
    {
        /// <summary>
        /// Data key share channel.
        /// </summary>
        DataKeyShareChannel Channel { get; }

        /// <summary>
        /// Data key share action endpoint.
        /// </summary>
        GetDataKeyActionDelegate InvokeGetDataKeyAction { get; }
    }

    /// <summary>
    /// SSO login token delegate.
    /// </summary>
    /// <param name="token">SSO login token.</param>
    /// <returns>Awaitable task.</returns>
    /// <exception cref="Exception">Other exceptions.</exception>
    public delegate Task SsoTokenActionDelegate(string token);

    /// <summary>
    /// Base interface for SSO login
    /// </summary>
    public interface ISsoTokenActionInfo
    {
        /// <summary>
        /// Gets SSO login URL.
        /// </summary>
        string SsoLoginUrl { get; }

        /// <summary>
        /// Gets Cloud SSO flag
        /// </summary>
        /// <remarks>
        /// <c>True</c> - Cloud SSO
        /// <c>False</c> - On-Premises SSO
        /// </remarks>
        bool IsCloudSso { get; }

        /// <summary>
        /// Gets SSO Login token action endpoint.
        /// </summary>
        SsoTokenActionDelegate InvokeSsoTokenAction { get; }
    }

    /// <summary>
    /// Defines 2FA duration property.
    /// </summary>
    public interface ITwoFactorDurationInfo
    {
        /// <summary>
        /// 2FA duration.
        /// </summary>
        TwoFactorDuration Duration { get; set; }
    }

    /// <summary>
    /// Device approval push delegate.
    /// </summary>
    /// <returns>Awaitable task.</returns>
    public delegate Task DeviceApprovalPushActionDelegate();

    /// <summary>
    /// Defines a property for device approval push actions.
    /// </summary>
    public interface IDeviceApprovalPushInfo : IDeviceApprovalChannelInfo
    {
        /// <summary>
        /// Gets device approval push action endpoint.
        /// </summary>
        DeviceApprovalPushActionDelegate InvokeDeviceApprovalPushAction { get; }
    }

    /// <summary>
    /// Device approval by 2FA code delegate.
    /// </summary>
    /// <param name="code">2FA code</param>
    /// <returns>Awaitable task.</returns>
    public delegate Task DeviceApprovalOtpDelegate(string code);

    /// <summary>
    /// Defines a property for device approval by code actions.
    /// </summary>
    public interface IDeviceApprovalOtpInfo : IDeviceApprovalChannelInfo
    {
        /// <summary>
        /// Gets device approval by 2FA code action endpoint.
        /// </summary>
        DeviceApprovalOtpDelegate InvokeDeviceApprovalOtpAction { get; }
    }

    /// <summary>
    /// Two Factor Authorization by code delegate.
    /// </summary>
    /// <param name="code">2FA code</param>
    /// <returns>Awaitable task.</returns>
    public delegate Task TwoFactorCodeActionDelegate(string code);

    /// <summary>
    /// Defines properties for 2FA by code action.
    /// </summary>
    public interface ITwoFactorAppCodeInfo: ITwoFactorChannelInfo, ITwoFactorDurationInfo
    {
        /// <summary>
        /// 2FA channel name.
        /// </summary>
        string ChannelName { get; }
        /// <summary>
        /// 2FA application name.
        /// </summary>
        string ApplicationName { get; }
        /// <summary>
        /// Phone number associated with this 2FA method. Optional.
        /// </summary>
        string PhoneNumber { get; }
        /// <summary>
        /// Gets 2FA by code action endpoint.
        /// </summary>
        TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; }
    }

    /// <summary>
    /// Two Factor Authorization action delegate.
    /// </summary>
    /// <param name="pushAction">Action.</param>
    /// <returns>Awaitable task.</returns>
    public delegate Task TwoFactorPushActionDelegate(TwoFactorPushAction pushAction);

    /// <summary>
    /// Defines properties for 2FA push action.
    /// </summary>
    public interface ITwoFactorPushInfo : ITwoFactorChannelInfo
    {
        /// <summary>
        /// Gets a list of available push actions.
        /// </summary>
        TwoFactorPushAction[] SupportedActions { get; }
        /// <summary>
        /// Gets 2FA push action endpoint.
        /// </summary>
        TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; }
    }

    /// <summary>
    /// Defines the method that starts U2F Security Key 2FA. Optional.
    /// </summary>
    /// <remarks>
    /// Implement this interface along with <see cref="Async.IAuthUI">Auth UI</see>
    /// if you plan to support Security Key (Yubikey and any other U2F compatible keys).
    /// </remarks>
    /// <seealso cref="Async.IAuthUI"/>
    public interface IAuthSecurityKeyUI
    {
        /// <summary>
        /// U2F key authentications required.
        /// </summary>
        /// <param name="request">Public Key Credential request.</param>
        /// <returns>A task that returns WebAuthn signature.</returns>
        Task<string> AuthenticatePublicKeyRequest(PublicKeyCredentialRequestOptions request);
    }
}