using System;
using System.Collections.Generic;
using System.Net;

namespace KeeperSecurity.Authentication
{

    internal class GetSsoTokenActionInfo : ISsoTokenActionInfo
    {
        public GetSsoTokenActionInfo(string url, bool isCloudSso)
        {
            SsoLoginUrl = url;
            IsCloudSso = isCloudSso;
        }

        public string SsoLoginUrl { get; }
        public bool IsCloudSso { get; }
        public SsoTokenActionDelegate InvokeSsoTokenAction { get; internal set; }
    }

    internal class GetDataKeyActionInfo : IDataKeyChannelInfo
    {
        public GetDataKeyActionInfo(DataKeyShareChannel channel)
        {
            Channel = channel;
        }

        public DataKeyShareChannel Channel { get; }
        public GetDataKeyActionDelegate InvokeGetDataKeyAction { get; internal set; }
    }

    internal class DeviceApprovalEmailResend : IDeviceApprovalPushInfo, IDeviceApprovalOtpInfo
    {
        public DeviceApprovalChannel Channel => DeviceApprovalChannel.Email;

        public DeviceApprovalPushActionDelegate InvokeDeviceApprovalPushAction { get; internal set; }
        public DeviceApprovalOtpDelegate InvokeDeviceApprovalOtpAction { get; internal set; }
        public bool Resend { get; internal set; }
    }

    internal class DeviceApprovalKeeperPushAction : IDeviceApprovalPushInfo
    {
        public DeviceApprovalChannel Channel => DeviceApprovalChannel.KeeperPush;

        public DeviceApprovalPushActionDelegate InvokeDeviceApprovalPushAction { get; internal set; }
    }

    internal class TwoFactorTwoFactorAuth : IDeviceApprovalPushInfo, IDeviceApprovalOtpInfo, ITwoFactorDurationInfo
    {
        public DeviceApprovalChannel Channel => DeviceApprovalChannel.TwoFactorAuth;
        public TwoFactorDuration Duration { get; set; }

        public DeviceApprovalPushActionDelegate InvokeDeviceApprovalPushAction { get; internal set; }
        public DeviceApprovalOtpDelegate InvokeDeviceApprovalOtpAction { get; internal set; }
    }

    internal class AuthenticatorTwoFactorChannel : ITwoFactorAppCodeInfo
    {
        internal AuthenticatorTwoFactorChannel()
        {
            Channel = TwoFactorChannel.Authenticator;
            ChannelName = "totp";
            ApplicationName = "TOTP (Google/Microsoft Authenticator)";
            Duration = TwoFactorDuration.EveryLogin;
        }

        public TwoFactorChannel Channel { get; }
        public string ApplicationName { get; }
        public string PhoneNumber { get; internal set; }
        public string ChannelName { get; }
        public TwoFactorDuration Duration { get; set; }
        public TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; internal set; }
    }
    
    internal class RsaSecurIdTwoFactorChannel : ITwoFactorAppCodeInfo
    {
        internal RsaSecurIdTwoFactorChannel()
        {
            Channel = TwoFactorChannel.RSASecurID;
            ChannelName = "rsa";
            ApplicationName = "RSA SecurID";
            Duration = TwoFactorDuration.EveryLogin;
        }

        public TwoFactorChannel Channel { get; }
        public string ChannelName { get; }
        public string ApplicationName { get; }
        public string PhoneNumber { get; internal set; }
        public TwoFactorDuration Duration { get; set; }
        public TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; internal set; }
    }

    internal class TwoFactorDuoChannel : ITwoFactorAppCodeInfo, ITwoFactorPushInfo
    {
        public TwoFactorChannel Channel => TwoFactorChannel.DuoSecurity;
        public string ChannelName => "duo";
        public string ApplicationName => "Duo Mobile App";
        public string PhoneNumber { get; internal set; }
        public TwoFactorPushAction[] SupportedActions { get; set; }
        public TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; internal set; }
        public TwoFactorDuration Duration { get; set; } = TwoFactorDuration.EveryLogin;
        public TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; internal set; }
    }

    internal class TwoFactorSmsChannel : ITwoFactorAppCodeInfo, ITwoFactorPushInfo
    {
        internal TwoFactorSmsChannel()
        {
            Channel = TwoFactorChannel.TextMessage;
            ChannelName = "sms";
            ApplicationName = "Mobile SMS App";
            SupportedActions = new[] {TwoFactorPushAction.TextMessage};
            Duration = TwoFactorDuration.EveryLogin;
        }

        public TwoFactorChannel Channel { get; }
        public string ChannelName { get; }
        public string ApplicationName { get; }
        public TwoFactorPushAction[] SupportedActions { get; }
        public string PhoneNumber { get; internal set; }
        public TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; internal set; }
        public TwoFactorDuration Duration { get; set; }
        public TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; internal set; }
    }

    internal class TwoFactorKeeperDnaChannel : ITwoFactorAppCodeInfo, ITwoFactorPushInfo
    {
        internal TwoFactorKeeperDnaChannel()
        {
            Channel = TwoFactorChannel.KeeperDNA;
            ChannelName = "dna";
            ApplicationName = "Keeper for Mobile";
            SupportedActions = new[] {TwoFactorPushAction.KeeperDna};
            Duration = TwoFactorDuration.EveryLogin;
        }

        public TwoFactorChannel Channel { get; }
        public string ChannelName { get; }
        public string ApplicationName { get; }
        public string PhoneNumber { get; internal set; }
        public TwoFactorPushAction[] SupportedActions { get; }
        public TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; internal set; }
        public TwoFactorDuration Duration { get; set; }
        public TwoFactorCodeActionDelegate InvokeTwoFactorCodeAction { get; internal set; }
    }

    internal class TwoFactorSecurityKeyChannel : ITwoFactorPushInfo
    {
        public TwoFactorChannel Channel => TwoFactorChannel.SecurityKey;
        public TwoFactorPushAction[] SupportedActions { get; } = {TwoFactorPushAction.SecurityKey};
        public TwoFactorPushActionDelegate InvokeTwoFactorPushAction { get; internal set; }
    }

    internal class MasterPasswordInfo : IPasswordInfo
    {
        internal MasterPasswordInfo(string username)
        {
            Username = username;
        }

        public string Username { get; }
        public PasswordActionDelegate InvokePasswordActionDelegate { get; internal set; }
        public BiometricsActionDelegate InvokeBiometricsActionDelegate { get; internal set; }
    }

    /// <exclude/>
    public static class AuthUIExtensions
    {
        /// <summary>
        /// Creates IWebProxy instance for provided credentials.
        /// </summary>
        /// <param name="proxyUri">Proxy URI</param>
        /// <param name="proxyMethods">Proxy Authentication Methods</param>
        /// <param name="proxyUsername">Proxy Username</param>
        /// <param name="proxyPassword">Proxy Password</param>
        /// <returns></returns>
        public static IWebProxy GetWebProxyForCredentials(
            Uri proxyUri, 
            string[] proxyMethods, 
            string proxyUsername, 
            string proxyPassword)
        {
            var cred = new NetworkCredential(proxyUsername, proxyPassword);
            var myCache = new CredentialCache();
            foreach (var method in proxyMethods)
            {
                myCache.Add(proxyUri, method.TrimEnd(), cred);
            }

            return new WebProxy(proxyUri.DnsSafeHost, proxyUri.Port)
            {
                UseDefaultCredentials = false,
                Credentials = myCache
            };
        }

        public static string GetPushActionText(this TwoFactorPushAction pushAction)
        {
            return PushActions.TryGetValue(pushAction, out var text) ? text : pushAction.ToString();
        }

        public static bool TryParsePushAction(string text, out TwoFactorPushAction pushAction)
        {
            foreach (var pair in PushActions)
            {
                if (string.Compare(text, pair.Value, StringComparison.OrdinalIgnoreCase) != 0) continue;

                pushAction = pair.Key;
                return true;
            }

            pushAction = TwoFactorPushAction.None;
            return false;
        }

        private static readonly IDictionary<TwoFactorPushAction, string> PushActions = new Dictionary<TwoFactorPushAction, string>
        {
            {TwoFactorPushAction.DuoPush, "duo_push"},
            {TwoFactorPushAction.DuoTextMessage, "duo_sms"},
            {TwoFactorPushAction.DuoVoiceCall, "duo_call"},
            {TwoFactorPushAction.TextMessage, "sms"},
            {TwoFactorPushAction.KeeperDna, "dna"},
            {TwoFactorPushAction.Email, "email"},
            {TwoFactorPushAction.SecurityKey, "key"},
        };

        public static string GetTwoFactorChannelText(this TwoFactorChannel channel)
        {
            return TwoFactorChannels.TryGetValue(channel, out var text) ? text : channel.ToString();
        }

        public static bool TryParseTwoFactorChannel(string text, out TwoFactorChannel channel)
        {
            if (!string.IsNullOrEmpty(text))
            {
                foreach (var pair in TwoFactorChannels)
                {
                    if (pair.Value.Equals(text))
                    {
                        channel = pair.Key;
                        return true;
                    }
                }
            }

            channel = TwoFactorChannel.Other;
            return false;
        }

        private static readonly IDictionary<TwoFactorChannel, string> TwoFactorChannels =
            new Dictionary<TwoFactorChannel, string>
            {
                {TwoFactorChannel.Authenticator, "totp"},
                {TwoFactorChannel.TextMessage, "sms"},
                {TwoFactorChannel.DuoSecurity, "duo"},
                {TwoFactorChannel.RSASecurID, "rsa"},
                {TwoFactorChannel.KeeperDNA, "dna"},
                {TwoFactorChannel.SecurityKey, "key"},
            };

        public static string DeviceApprovalChannelText(this DeviceApprovalChannel channel)
        {
            return DeviceApproveChannels.TryGetValue(channel, out var text) ? text : channel.ToString();
        }

        public static bool TryParseDeviceApprovalChannel(string text, out DeviceApprovalChannel channel)
        {
            foreach (var pair in DeviceApproveChannels)
            {
                if (string.Compare(pair.Value, text, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    channel = pair.Key;
                    return true;
                }
            }

            channel = DeviceApprovalChannel.Email;
            return false;
        }

        private static readonly IDictionary<DeviceApprovalChannel, string> DeviceApproveChannels = new Dictionary<DeviceApprovalChannel, string>
        {
            {DeviceApprovalChannel.Email, "email"},
            {DeviceApprovalChannel.KeeperPush, "keeper_push"},
            {DeviceApprovalChannel.TwoFactorAuth, "2fa"},
        };

        public static string SsoDataKeyShareChannelText(this DataKeyShareChannel channel)
        {
            return DataKeyShareChannels[channel];
        }

        public static bool TryParseDataKeyShareChannel(string text, out DataKeyShareChannel channel)
        {
            if (!string.IsNullOrEmpty(text))
            {
                foreach (var pair in DataKeyShareChannels)
                {
                    if (pair.Value.Equals(text))
                    {
                        channel = pair.Key;
                        return true;
                    }
                }
            }

            channel = DataKeyShareChannel.KeeperPush;
            return false;
        }

        private static readonly IDictionary<DataKeyShareChannel, string> DataKeyShareChannels = new Dictionary<DataKeyShareChannel, string>
        {
            {DataKeyShareChannel.KeeperPush, "keeper_push"},
            {DataKeyShareChannel.AdminApproval, "request_admin"},
        };

        private static readonly IDictionary<TwoFactorDuration, string> Durations = new Dictionary<TwoFactorDuration, string>
        {
            {TwoFactorDuration.EveryLogin, "never"},
            {TwoFactorDuration.Forever, "forever"},
            {TwoFactorDuration.Every12Hours, "12 hours"},
            {TwoFactorDuration.Every24Hours, "24 hours"},
            {TwoFactorDuration.Every30Days, "30 days"},
        };

        public static string DurationToText(TwoFactorDuration duration)
        {
            if (Durations.TryGetValue(duration, out var text))
            {
                return text;
            }
            return "";
        }

        public static bool TryParseTextToDuration(string text, out TwoFactorDuration duration)
        {
            foreach (var pair in Durations) {
                if (string.Equals(pair.Value, text, StringComparison.InvariantCultureIgnoreCase)) { 
                    duration = pair.Key;
                    return true;
                }
            }
            duration = TwoFactorDuration.EveryLogin;
            return false;
        }
    }
}
