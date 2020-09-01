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
        Other,
    }

    public enum TwoFactorDuration
    {
        EveryLogin = 0,
        Every30Days = 30,
        Forever = 9999,
    }

    public class TwoFactorCode
    {
        public TwoFactorCode(TwoFactorChannel channel, string code, TwoFactorDuration duration)
        {
            Channel = channel;
            Code = code;
            Duration = duration;
        }

        public TwoFactorChannel Channel { get; }
        public string Code { get; }
        public TwoFactorDuration Duration { get; }
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
        Task<string> GetMasterPassword(string username);
        Task<TwoFactorCode> GetTwoFactorCode(TwoFactorChannel defaultChannel, ITwoFactorChannelInfo[] channels, CancellationToken token);
        Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token);
    }

    public interface IAuthInfoUI
    {
        void RegionChanged(string newRegion);
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

    public interface IPostLoginTaskUI 
    {
        Task<bool> Confirmation(string information);
        Task<string> GetNewPassword(PasswordRuleMatcher matcher);
    }

    public interface IDeviceApprovalDuration
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

    public interface ITwoFactorAppCodeInfo: ITwoFactorChannelInfo
    {
        string ChannelName { get; }
        string ApplicationName { get; }
        string PhoneNumber { get; }
    }

    public delegate Task<bool> TwoFactorPushActionDelegate(TwoFactorPushAction pushAction, TwoFactorDuration duration);

    public interface ITwoFactorPushInfo : ITwoFactorChannelInfo
    {
        TwoFactorPushAction[] SupportedActions { get; }
        TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; }
    }


    public enum TwoFactorPushAction
    {
        None,
        DuoPush,
        DuoTextMessage,
        DuoVoiceCall,
        TextMessage,
        KeeperPush,
        Email,
    }

    public interface IHttpProxyCredentialUI
    {
        Task<IWebProxy> GetHttpProxyCredentials(Uri proxyUri, string proxyAuthentication);
    }
}