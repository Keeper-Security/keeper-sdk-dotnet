#if NET472_OR_GREATER || NET8_0_OR_GREATER
using System;
using System.Linq;
using KeeperSecurity.Utils;

namespace KeeperBiometrics
{
    internal enum LoginMethod
    {
        Biometric,
        YubiKey,
    }

    internal static class AuthenticationOptionsBuilder
    {
        public static AuthenticationOptions Build(
            LoginMethod method,
            string rpId,
            string challenge,
            string[] allowedCredentialIds = null,
            string userVerification = null,
            string authenticatorAttachment = null,
            string origin = null,
            int? timeoutMs = null)
        {
            if (string.IsNullOrWhiteSpace(challenge))
            {
                throw new ArgumentException("Challenge is required.", nameof(challenge));
            }

            return new AuthenticationOptions
            {
                RpId = rpId,
                Challenge = challenge.Base64UrlDecode(),
                RawChallengeString = challenge,
                AllowedCredentialIds = allowedCredentialIds?
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .ToArray(),
                UserVerification = NormalizeValue(
                    userVerification,
                    method == LoginMethod.YubiKey ? "any" : "required"),
                AuthenticatorAttachment = NormalizeValue(
                    authenticatorAttachment,
                    method == LoginMethod.YubiKey ? "any" : "platform"),
                Origin = origin,
                TimeoutMs = timeoutMs ?? (int) TimeSpan.FromMinutes(1).TotalMilliseconds,
            };
        }

        private static string NormalizeValue(string value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
#endif

