using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Extension methods to set up and manage Account Recovery via a Recovery Phrase.
    /// Replaces the legacy security question / answer recovery and the v2 <c>set_data_key_backup</c> API.
    /// </summary>
    public static class AccountRecoveryExtensions
    {
        private const string AccountRecoverySetupEndpoint = "authentication/account_recovery_setup";

        /// <summary>
        /// Sets the account recovery phrase for the currently logged in user. Invalidates any
        /// previously configured recovery phrase or security question / answer.
        /// </summary>
        /// <param name="auth">Authenticated Keeper connection.</param>
        /// <param name="recoveryPhrase">A 24-word recovery phrase. See <see cref="RecoveryPhrase.Generate"/>.</param>
        public static async Task SetupAccountRecovery(this IAuthentication auth, string recoveryPhrase)
        {
            var normalizedPhrase = RecoveryPhrase.Normalize(recoveryPhrase);
            var recoveryKey = RecoveryPhrase.DeriveRecoveryKey(normalizedPhrase);
            var recoveryAuthToken = RecoveryPhrase.DeriveRecoveryAuthToken(normalizedPhrase);

            var request = new AccountRecoverySetupRequest
            {
                RecoveryEncryptedDataKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(auth.AuthContext.DataKey, recoveryKey)),
                RecoveryAuthHash = ByteString.CopyFrom(recoveryAuthToken),
            };

            await auth.ExecuteAuthRest(AccountRecoverySetupEndpoint, request);
        }

        /// <summary>
        /// Delays the account recovery setup prompt for 30 days without changing the current
        /// recovery configuration.
        /// </summary>
        /// <param name="auth">Authenticated Keeper connection.</param>
        public static async Task SnoozeAccountRecoverySetup(this IAuthentication auth)
        {
            await auth.ExecuteAuthRest(AccountRecoverySetupEndpoint, new AccountRecoverySetupRequest());
        }

        /// <summary>
        /// Verifies that the recovery phrase entered by the user matches the one on file for the
        /// currently logged in account.
        /// </summary>
        /// <param name="auth">Authenticated Keeper connection.</param>
        /// <param name="recoveryPhrase">Recovery phrase to verify.</param>
        /// <returns><c>true</c> if the recovery phrase matches; otherwise <c>false</c>.</returns>
        public static async Task<bool> VerifyAccountRecoveryPhrase(this IAuthentication auth, string recoveryPhrase)
        {
            var normalizedPhrase = RecoveryPhrase.Normalize(recoveryPhrase);
            var recoveryAuthToken = RecoveryPhrase.DeriveRecoveryAuthToken(normalizedPhrase);

            var request = new AccountRecoverySetupRequest
            {
                RecoveryAuthHash = ByteString.CopyFrom(recoveryAuthToken),
            };

            try
            {
                await auth.ExecuteAuthRest("authentication/account_recovery_verify_phrase", request);
                return true;
            }
            catch (KeeperApiException e) when (!e.IsThrottleError())
            {
                return false;
            }
        }
    }
}
