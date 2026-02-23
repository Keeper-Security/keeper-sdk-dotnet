using System.Threading.Tasks;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Biometric Authentication Result.
    /// </summary>
    public interface IBiometricLoginResult
    {
        /// <summary>true if the local biometric step succeeded.</summary>
        bool Success { get; }

        /// <summary>true if the server accepted the authentication.</summary>
        bool IsValid { get; }

        /// <summary>Encrypted login token to resume login; null if not available.</summary>
        byte[] EncryptedLoginToken { get; }

        /// <summary>Error or status message when not successful.</summary>
        string ErrorMessage { get; }
    }

    /// <summary>
    /// Optional provider for biometric login.
    /// </summary>
    public interface IBiometricLoginProvider
    {
        /// <summary>Returns true if biometric login is available on this device.</summary>
        bool IsAvailable();

        /// <summary>Returns true if a credential is stored for the given username.</summary>
        bool HasCredential(string username);

        /// <summary>
        /// Attempts to authenticate the user via biometric login and obtain an encrypted login token.
        /// </summary>
        /// <param name="auth">Authentication endpoint used for REST calls.</param>
        /// <param name="username">Username to authenticate.</param>
        /// <returns>Result with EncryptedLoginToken on success; otherwise Success/IsValid may be false with an ErrorMessage set.</returns>
        Task<IBiometricLoginResult> TryAuthenticateAsync(IAuthEndpoint auth, string username);
    }
}
