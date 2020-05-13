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
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk.UI
{
    public enum TwoFactorCodeChannel
    {
        Authenticator,
        TextMessage,
        DuoSecurity,
        RSASecurID,
        Other,
    }

    public enum TwoFactorCodeDuration: int
    {
        EveryLogin = 0,
        Every30Days = 30,
        Forever = 9999,
    }

    public class TwoFactorCode
    {
        public TwoFactorCode(string code, TwoFactorCodeDuration duration)
        {
            Code = code;
            Duration = duration;
        }

        public string Code { get; }
        public TwoFactorCodeDuration Duration { get; }
    }

    public interface IAuthUI
    {
        Task<bool> Confirmation(string information);
        Task<string> GetNewPassword(PasswordRuleMatcher matcher);
        Task<TwoFactorCode> GetTwoFactorCode(TwoFactorCodeChannel provider);
    }

    public interface IDuoResult
    {
        TwoFactorCodeDuration Duration { get; }
    }

    public class DuoCodeResult : TwoFactorCode, IDuoResult
    {
        public DuoCodeResult(string code, TwoFactorCodeDuration duration) : base(code, duration)
        {
        }
    }

    public enum DuoAction
    {
        DuoPush,
        TextMessage,
        VoiceCall,
    }

    public static class AuthUIExtensions
    {
        public static string GetDuoActionText(this DuoAction action)
        {
            return DuoActions[action];
        }

        public static bool TryParseDuoAction(string text, out DuoAction action)
        {
            foreach (var pair in DuoActions)
            {
                if (string.Compare(text, pair.Value, StringComparison.OrdinalIgnoreCase) != 0) continue;

                action = pair.Key;
                return true;
            }

            action = DuoAction.DuoPush;
            return false;
        }

        public static string GetTwoFactorChannelText(this TwoFactorCodeChannel channel)
        {
            return TwoFactorChannels.TryGetValue(channel, out var ch) ? ch : "";
        }

        public static TwoFactorCodeChannel GetTwoFactorChannel(string channel)
        {
            if (!string.IsNullOrEmpty(channel))
            {
                foreach (var pair in TwoFactorChannels)
                {
                    if (pair.Value.Equals(channel))
                    {
                        return pair.Key;
                    }
                }
            }

            return TwoFactorCodeChannel.Other;
        }

        private static readonly IDictionary<TwoFactorCodeChannel, string> TwoFactorChannels =
            new Dictionary<TwoFactorCodeChannel, string>
            {
                {TwoFactorCodeChannel.Authenticator, "two_factor_channel_google"},
                {TwoFactorCodeChannel.TextMessage, "two_factor_channel_sms"},
                {TwoFactorCodeChannel.DuoSecurity, "two_factor_channel_duo"},
                {TwoFactorCodeChannel.RSASecurID, "two_factor_channel_rsa"},
            };

        internal static readonly IDictionary<DuoAction, string> DuoActions = new Dictionary<DuoAction, string>
        {
            {DuoAction.DuoPush, "push"},
            {DuoAction.TextMessage, "sms"},
            {DuoAction.VoiceCall, "phone"},
        };
    }

    public sealed class DuoAccount
    {
        public string PushNotificationUrl { get; internal set; }

        public string ParseDuoPasscodeNotification(byte[] notification)
        {
            if (notification != null)
            {
                var evt = JsonUtils.ParseJson<NotificationEvent>(notification);
                return evt.passcode;
            }

            return null;
        }

        public DuoAction[] Capabilities { get; internal set; }
        public string Phone { get; internal set; } // Phone number associated the account
    }

    public interface IDuoTwoFactorUI
    {
        void DuoRequireEnrollment(string enrollmentUrl);
        Task<TwoFactorCode> GetDuoTwoFactorResult(DuoAccount account, CancellationToken token);
    }

    public interface IHttpProxyCredentialUI
    {
        Task<IWebProxy> GetHttpProxyCredentials(string proxyAuthenticate);
    }
}