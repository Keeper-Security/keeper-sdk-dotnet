#if NET472_OR_GREATER
using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace KeeperBiometric
{
    /// <summary>
    /// Implements <see cref="IBiometricLoginProvider"/> using Windows Hello passkeys.
    /// Use this when referencing KeeperBiometrics and set <see cref="KeeperLoginFlow.BiometricLoginProvider"/> to enable biometric login in KeeperCli.
    /// </summary>
    public sealed class BiometricLoginProviderAdapter : IBiometricLoginProvider
    {
        /// <inheritdoc />
        public bool IsAvailable() => PasskeyManager.IsAvailable();

        /// <inheritdoc />
        public bool HasCredential(string username) => CredentialStorage.HasCredential(username);

        /// <inheritdoc />
        public async Task<IBiometricLoginResult> TryAuthenticateAsync(IAuthEndpoint auth, string username)
        {
            var result = await PasskeyManager.AuthenticatePasskeyAsync(auth, username, PasskeyManager.Purpose.Login).ConfigureAwait(false);
            return new ResultAdapter(result);
        }

        private sealed class ResultAdapter : IBiometricLoginResult
        {
            private readonly PasskeyAuthenticationResult _inner;

            internal ResultAdapter(PasskeyAuthenticationResult inner) => _inner = inner;

            public bool Success => _inner.Success;
            public bool IsValid => _inner.IsValid;
            public byte[] EncryptedLoginToken => _inner.EncryptedLoginToken?.ToByteArray();
            public string ErrorMessage => _inner.ErrorMessage;
        }
    }
}
#endif
