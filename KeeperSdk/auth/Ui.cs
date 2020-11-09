//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Net;
using System.Threading;
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
    /// Defines the user interface methods required for authentication with Keeper.
    /// </summary>
    /// <seealso cref="IAuthSsoUI"/>
    /// <seealso cref="IHttpProxyCredentialUI"/>
    /// <seealso cref="IAuthSecurityKeyUI"/>
    /// <seealso cref="IPostLoginTaskUI"/>
    public interface IAuthUI
    {
        /// <summary>
        /// Device Approval is required.
        /// </summary>
        /// <param name="channels">List of available device approval channels.</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client when device is successfully approved.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// Clients to display the list of available device approval channels.
        /// When user picks one clients to check if channel implements <see cref="IDeviceApprovalPushInfo">push interface</see>
        /// then invoke <see cref="IDeviceApprovalPushInfo.InvokeDeviceApprovalPushAction">push action</see>
        /// If channel implements <see cref="ITwoFactorDurationInfo">2FA duration interface</see> clients may show 2FA expiration picker.
        /// </remarks>
        Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token);

        /// <summary>
        /// Two Factor Authentication is required.
        /// </summary>
        /// <param name="channels">List of available 2FA channels.</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client passed 2FA.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// Clients to display the list of available 2FA channels.
        /// When user picks one clients to check
        /// <list type="number">
        /// <item><description>
        /// if channel implements <see cref="ITwoFactorPushInfo">push interface</see> clients displays an button for each <see cref="ITwoFactorPushInfo.SupportedActions">push action</see>
        /// </description></item>
        /// <item><description>
        /// If channel implements <see cref="ITwoFactorDurationInfo">2FA duration interface</see> clients may show 2FA expiration picker.
        /// </description></item>
        /// <item><description>
        /// If channel implements <see cref="ITwoFactorAppCodeInfo">2FA code interface</see> clients displays 2FA code input.
        /// </description></item>
        /// </list>
        /// When customer enters the code and click Next clients returns the code to <see cref="ITwoFactorAppCodeInfo.InvokeTwoFactorCodeAction">the SDK</see>.
        /// </remarks>
        Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token);

        /// <summary>
        /// Master Password is required.
        /// </summary>
        /// <param name="passwordInfo">Enter Password interface</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client successfully authorized. Can be ignored.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resumes login, <c>False</c> cancels.</returns>
        /// <remarks>
        /// Client displays Enter password dialog.
        /// When customer clicks Next client returns the password to <see cref="IPasswordInfo.InvokePasswordActionDelegate">the SDK</see>.
        /// </remarks>
        Task<bool> WaitForUserPassword(IPasswordInfo passwordInfo, CancellationToken token);
    }

    /// <summary>
    /// Various methods that notify client about IAuth object state changes. Optional.
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
    /// Defines the methods required completing SSO Login. Optional.
    /// </summary>
    /// <remarks>If client supports SSO Login this interface needs to be implemented
    /// along with <see cref="IAuthUI">Auth UI</see>
    /// </remarks>
    /// <seealso cref="IAuthUI"/>
    /// <remarks>
    /// Client implements this interface to support SSO login. This interface will be called in response
    /// of <see cref="IAuth.Login"/> if username is SSO user or <see cref="IAuth.LoginSso"/>
    /// </remarks>
    public interface IAuthSsoUI
    {
        /// <summary>
        /// SSO Login is required.
        /// </summary>
        /// <param name="actionInfo"></param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client successfully logged in with SSO.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// When this method is called client opens embedded web browser and navigates to URL specified in
        /// <see cref="ISsoTokenActionInfo.SsoLoginUrl">actionInfo.SsoLoginUrl</see>
        /// then monitors embedded web browser navigation.
        /// When it finds the page that contains <c>window.token</c> object it passes this object to
        /// <see cref="ISsoTokenActionInfo.InvokeSsoTokenAction">actionInfo.InvokeSsoTokenAction</see>
        /// </remarks>
        Task<bool> WaitForSsoToken(ISsoTokenActionInfo actionInfo, CancellationToken token);

        /// <summary>
        /// Data Key needs to be shared. 
        /// </summary>
        /// <param name="channels">List of available data key sharing channels.</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client that data key is shared.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// Cloud SSO login may require user data key to be shared if the device is used for the first time.
        /// Client displays the list of available data key sharing channels.
        /// When user picks a channel, client invokes channel's action <see cref="IDataKeyChannelInfo.InvokeGetDataKeyAction">channels.InvokeGetDataKeyAction</see>
        /// </remarks>
        Task<bool> WaitForDataKey(IDataKeyChannelInfo[] channels, CancellationToken token);

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
    /// Defines the method that starts U2F Security Key 2FA. Optional.
    /// </summary>
    /// <remarks>
    /// Implement this interface along with <see cref="IAuthUI">Auth UI</see>
    /// if you plan to support Security Key (Yubikey and any other U2F compatible keys).
    /// </remarks>
    /// <seealso cref="IAuthUI"/>
    public interface IAuthSecurityKeyUI
    {
        /// <summary>
        /// U2F key authentications required.
        /// </summary>
        /// <param name="requests">a list of registered U2F key requests.</param>
        /// <returns>A task that returns U2F signature.</returns>
        Task<string> AuthenticateRequests(SecurityKeyAuthenticateRequest[] requests);
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
    /// Defines a method that returns HTTP Web proxy credentials. Optional.
    /// </summary>
    /// <remarks>
    /// Keeper SDK calls this interface if it detects that access to the Internet is protected with HTTP Proxy.
    /// Clients requests HTTP proxy credentials from the user and return them to the library.
    /// </remarks>
    /// <seealso cref="IAuthUI"/>
    public interface IHttpProxyCredentialUI
    {
        /// <summary>
        /// Requests HTTP Proxy credentials.
        /// </summary>
        /// <param name="proxyUri">HTTP Proxy URL</param>
        /// <param name="proxyAuthentication">Proxy-Authentication header.</param>
        /// <returns>A task that returns HTTP proxy credentials. </returns>
        Task<IWebProxy> GetHttpProxyCredentials(Uri proxyUri, string proxyAuthentication);
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
    public delegate Task<bool> TwoFactorCodeActionDelegate(string code);

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
}