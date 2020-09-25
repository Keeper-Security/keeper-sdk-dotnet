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

namespace KeeperSecurity.Sdk.UI
{
    public enum TwoFactorChannel
    {
        Authenticator,
        TextMessage,
        DuoSecurity,
        RSASecurID,
        KeeperDNA,
        SecurityKey,
        Other,
    }

    public enum TwoFactorDuration
    {
        EveryLogin = 0,
        Every30Days = 30,
        Forever = 9999,
    }

    public interface ITwoFactorChannelInfo
    {
        TwoFactorChannel Channel { get; }
    }

    public enum DeviceApprovalChannel
    {
        Email,
        TwoFactorAuth,
        KeeperPush,
    }

    public interface IDeviceApprovalChannelInfo
    {
        DeviceApprovalChannel Channel { get; }
    }

    public interface IAuthUI
    {
        Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token);
        Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token);
        Task<string> GetMasterPassword(string username);
    }

    public interface IAuthInfoUI
    {
        void RegionChanged(string newRegion);
        void SelectedDevice(string deviceToken);
    }

    public enum DataKeyShareChannel
    {
        KeeperPush = 1,
        AdminApproval = 2,
    }

    public interface IGetDataKeyChannelInfo
    {
        DataKeyShareChannel Channel { get; }
    }

    public delegate Task GetDataKeyActionDelegate();

    public interface IGetDataKeyActionInfo : IGetDataKeyChannelInfo
    {
        GetDataKeyActionDelegate InvokeGetDataKeyAction { get; }
    }

    public interface IAuthSsoUI
    {
        Task<string> GetSsoToken(string url, bool isCloudSso);
        Task<bool> WaitForDataKey(IGetDataKeyChannelInfo[] channels, CancellationToken token);
        void SsoLogoutUrl(string url);
    }

    public interface IAuthSecurityKeyUI
    {
        Task<string> AuthenticateRequests(SecurityKeyAuthenticateRequest[] requests);
    }

    public interface IPostLoginTaskUI 
    {
        Task<bool> Confirmation(string information);
        Task<string> GetNewPassword(PasswordRuleMatcher matcher);
    }

    public interface ITwoFactorDurationInfo
    {
        TwoFactorDuration Duration { get; set; }
    }

    public delegate Task DeviceApprovalPushActionDelegate();
    public interface IDeviceApprovalPushInfo : IDeviceApprovalChannelInfo
    {
        DeviceApprovalPushActionDelegate InvokeDeviceApprovalPushAction { get; }
    }

    public delegate Task DeviceApprovalOtpDelegate(string code);
    public interface IDeviceApprovalOtpInfo : IDeviceApprovalChannelInfo
    {
        DeviceApprovalOtpDelegate InvokeDeviceApprovalOtpAction { get; }
    }

    public delegate Task TwoFactorCodeActionDelegate(string code);
    public interface ITwoFactorAppCodeInfo: ITwoFactorChannelInfo, ITwoFactorDurationInfo
    {
        string ChannelName { get; }
        string ApplicationName { get; }
        string PhoneNumber { get; }
        TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; }
    }

    public enum TwoFactorPushAction
    {
        None,
        DuoPush,
        DuoTextMessage,
        DuoVoiceCall,
        TextMessage,
        KeeperDna,
        Email,
        SecurityKey,
    }
    public delegate Task TwoFactorPushActionDelegate(TwoFactorPushAction pushAction);
    public interface ITwoFactorPushInfo : ITwoFactorChannelInfo
    {
        TwoFactorPushAction[] SupportedActions { get; }
        TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; }
    }

    public interface IHttpProxyCredentialUI
    {
        Task<IWebProxy> GetHttpProxyCredentials(Uri proxyUri, string proxyAuthentication);
    }
}