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
    /// Handles security key authentication by routing YubiKey and WebAuthn
    /// two-factor requests through the existing native Windows WebAuthn flow.
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
                throw new Exception("security challenge is missing, try another authentication method.");
            }

            var authOptions = AuthenticationOptionsBuilder.Build(
                LoginMethod.YubiKey,
                request.rpId,
                request.challenge,
                request.allowCredentials?
                    .Where(x => x != null
                                && string.Equals(x.type, "public-key", StringComparison.OrdinalIgnoreCase))
                    .Select(x => x.id)
                    .ToArray(),
                request.userVerification,
                request.authenticatorAttachment,
                request.extensions?.appid,
                (int) TimeSpan.FromMinutes(2).TotalMilliseconds);

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
