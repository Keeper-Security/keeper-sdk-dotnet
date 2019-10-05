using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace KeeperSecurity.Sdk.UI
{
    public enum TwoFactorCodeChannel
    {
        Authenticator,
        TextMessage,
        DuoSecurity,
        Other,
    }

    public enum TwoFactorCodeDuration
    {
        EveryLogin,
        Every30Days,
        Forever,
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
        TaskCompletionSource<TwoFactorCode> GetTwoFactorCode(TwoFactorCodeChannel provider);
    }

    public interface IDuoResult
    {
        TwoFactorCodeDuration Duration { get; }
    }

    public class DuoCodeResult : TwoFactorCode, IDuoResult
    {
        public DuoCodeResult(string code, TwoFactorCodeDuration duration) : base(code, duration) {}
    }

    public enum DuoAction
    {
        DuoPush,
        TextMessage,
        VoiceCall,
    }

    public static class DuoActionExtensions
    {
        public static string GetDuoActionText(this DuoAction action)
        {
            return DuoActions[action];
        }

        public static bool TryParseDuoAction(string text, out DuoAction action)
        {
            lock (DuoActions)
            {
                foreach (var pair in DuoActions)
                {
                    if (string.Compare(text, pair.Value, true) == 0)
                    {
                        action = pair.Key;
                        return true;
                    }
                }
            }
            action = DuoAction.DuoPush;
            return false;
        }

        private static readonly IDictionary<DuoAction, string> DuoActions = new Dictionary<DuoAction, string>
        {
            { DuoAction.DuoPush, "push" },
            { DuoAction.TextMessage, "sms" },
            { DuoAction.VoiceCall, "voice" },
        };
    }

    public sealed class DuoAccount
    {
        public DuoAction[] Capabilities { get; internal set; }
        public string Phone { get; internal set; }    // Phone number associated the account
        public string EnrollmentUrl { get; internal set; }   // Account requires Enrollment with DUO
    }

    public interface IDuoTwoFactorUI
    {
        TaskCompletionSource<TwoFactorCode> GetDuoTwoFactorResult(DuoAccount account, Func<DuoAction, Task> onAction);
    }

    public interface IHttpProxyCredentialUI
    {
        Task<IWebProxy> GetHttpProxyCredentials(string proxyAuthenticate);
    }

}
