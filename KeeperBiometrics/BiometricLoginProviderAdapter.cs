#if NET472_OR_GREATER
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace KeeperBiometrics
{
    /// <summary>
    /// Implements <see cref="IBiometricLoginProvider"/> using Windows Hello passkeys.
    /// </summary>
    public sealed class BiometricLoginProviderAdapter : IBiometricLoginProvider, IBiometricPasskeySync
    {
        /// <inheritdoc />
        public bool IsAvailable() => PasskeyManager.IsAvailable();

        /// <inheritdoc />
        public bool HasCredential(string username) => CredentialStorage.HasCredential(username);

        /// <inheritdoc />
        public async Task<IBiometricLoginResult> TryAuthenticateAsync(IAuthEndpoint auth, string username)
        {
            var result = await PasskeyManager.AuthenticatePasskeyAsync(auth, username, PasskeyManager.Purpose.Login);
            return new ResultAdapter(result);
        }

        /// <inheritdoc />
        public async Task SyncAccountPasskeyStatusAsync(IAuthentication auth)
        {
            var username = auth?.Username;
            if (string.IsNullOrEmpty(username) || !PasskeyManager.IsAvailable()) return;

            List<PasskeyInfo> passkeys;
            try
            {
                passkeys = await PasskeyManager.ListPasskeysOrThrowAsync(auth);
            }
            catch (Exception ex)
            {
                // Lookup failed: keep the cached state and retry on the next login.
                System.Diagnostics.Debug.WriteLine($"Passkey sync skipped, could not list passkeys: {ex.Message}");
                return;
            }

            if (!passkeys.Any(p => !p.IsDisabled))
            {
                CredentialStorage.RemoveCredentialId(username);
                return;
            }

            try
            {
                var deviceToken = auth.DeviceToken;
                var summary = await auth.LoadAccountSummary();
                var device = deviceToken == null ? null : summary?.Devices
                    .FirstOrDefault(x => x.EncryptedDeviceToken.ToByteArray().SequenceEqual(deviceToken));
                if (device == null)
                {
                    return;
                }

                if (!device.EncryptedDataKeyPresent)
                {
                    // Idempotent: "device_data_key_exists" is treated as success.
                    await auth.RegisterDataKeyForDevice(device);
                }
            }
            catch (Exception ex)
            {
                // Only cache availability if the device data key is registered.
                System.Diagnostics.Debug.WriteLine($"Passkey sync skipped, device data key registration failed: {ex.Message}");
                return;
            }

            CredentialStorage.SetBiometricFlag(username);
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
