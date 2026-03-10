#if NET472_OR_GREATER
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Utils;

namespace KeeperBiometrics
{
    /// <summary>
    /// <see cref="IAuthSyncCallback"/> + <see cref="IAuthSecurityKeyUI"/> implementation
    /// that delegates YubiKey / WebAuthn 2FA to the existing
    /// <see cref="WindowsHelloApi.AuthenticateAsync"/> native WebAuthn infrastructure.
    /// </summary>
    public sealed class SecurityKeyAuthCallback : IAuthSyncCallback, IAuthSecurityKeyUI
    {
        private readonly Action _onNextStep;

        public SecurityKeyAuthCallback() : this(null) { }

        public SecurityKeyAuthCallback(Action onNextStep)
        {
            _onNextStep = onNextStep; 
        }

        public void OnNextStep()
        {
            _onNextStep?.Invoke();
        }

        public async Task<string> AuthenticatePublicKeyRequest(
            KeeperSecurity.Authentication.PublicKeyCredentialRequestOptions request)
        {
            if (request == null || string.IsNullOrEmpty(request.challenge))
            {
                throw new Exception("Security key challenge is empty. Try another 2FA method.");
            }

            var authOptions = new AuthenticationOptions
            {
                RpId = request.rpId,
                Challenge = request.challenge.Base64UrlDecode(),
                RawChallengeString = request.challenge,
                Origin = request.extensions?.appid,
                AuthenticatorAttachment = "cross-platform-u2f-v2",
                UserVerification = "required",
                TimeoutMs = (int) TimeSpan.FromMinutes(2).TotalMilliseconds,
            };

            authOptions.AllowedCredentialIds = request.allowCredentials?
                .Where(x => x != null
                            && string.Equals(x.type, "public-key", StringComparison.OrdinalIgnoreCase)
                            && !string.IsNullOrWhiteSpace(x.id))
                .Select(x => x.id)
                .ToArray();

            var result = await WindowsHelloApi.AuthenticateAsync(authOptions).ConfigureAwait(false);

            if (!result.Success)
            {
                throw new Exception($"Security key authentication failed: {result.ErrorMessage}");
            }

            var signature = new KeeperWebAuthnSignature
            {
                id = result.CredentialId,
                rawId = result.CredentialId,
                response = new SignatureResponse
                {
                    authenticatorData = result.AuthenticatorData,
                    clientDataJSON = result.ClientDataJSON,
                    signature = result.Signature,
                },
                type = "public-key",
                clientExtensionResults = new ClientExtensionResults(),
            };
            return Encoding.UTF8.GetString(JsonUtils.DumpJson(signature, false));
        }
    }
}
#endif
