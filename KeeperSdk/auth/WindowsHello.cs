using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

#if NET472_OR_GREATER

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Windows Hello verification result
    /// </summary>
    public enum BiometricVerificationResult
    {
        Verified = 0,
        DeviceNotPresent = 1,
        NotConfiguredForUser = 2,
        DisabledByPolicy = 3,
        DeviceBusy = 4,
        RetriesExhausted = 5,
        Canceled = 6
    }

    /// <summary>
    /// Credential storage for biometric authentication
    /// </summary>
    public class BiometricCredential
    {
        public string Username { get; set; }
        public string Server { get; set; }
        public byte[] EncryptedPassword { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastUsedAt { get; set; }
    }

    /// <summary>
    /// Windows Hello biometric authentication provider
    /// </summary>
    public static class WindowsHelloProvider
    {
        private const string CREDENTIAL_REGISTRY_KEY = @"SOFTWARE\Keeper Security\PowerCommander\Biometric";

        /// <summary>
        /// Check if Windows Hello is available on this system
        /// </summary>
        public static async Task<bool> IsAvailableAsync()
        {
            try
            {
                var result = await RequestVerificationAsync("Windows Hello availability check", false);
                return result != BiometricVerificationResult.DeviceNotPresent && 
                       result != BiometricVerificationResult.NotConfiguredForUser &&
                       result != BiometricVerificationResult.DisabledByPolicy;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Request biometric verification from the user
        /// </summary>
        /// <param name="message">Message to display to the user</param>
        /// <param name="actualVerification">Whether to perform actual verification or just check availability</param>
        /// <returns>Verification result</returns>
        public static async Task<BiometricVerificationResult> RequestVerificationAsync(string message, bool actualVerification = true)
        {
            try
            {
                // Use Windows Runtime UserConsentVerifier
                var userConsentVerifierType = Type.GetType("Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime");
                if (userConsentVerifierType == null)
                {
                    return BiometricVerificationResult.DeviceNotPresent;
                }

                var checkAvailabilityMethod = userConsentVerifierType.GetMethod("CheckAvailabilityAsync");
                var requestVerificationMethod = userConsentVerifierType.GetMethod("RequestVerificationAsync", new Type[] { typeof(string) });

                if (checkAvailabilityMethod == null || requestVerificationMethod == null)
                {
                    return BiometricVerificationResult.DeviceNotPresent;
                }

                // Check availability first
                var availabilityTask = (dynamic)checkAvailabilityMethod.Invoke(null, null);
                var availability = await availabilityTask;
                
                // Map Windows availability result to our enum
                var availabilityResult = MapAvailabilityToBiometricResult(availability);
                if (availabilityResult != BiometricVerificationResult.Verified)
                {
                    return availabilityResult;
                }

                if (!actualVerification)
                {
                    return BiometricVerificationResult.Verified;
                }

                // Request verification
                var verificationTask = (dynamic)requestVerificationMethod.Invoke(null, new object[] { message ?? "Verify your identity" });
                var verificationResult = await verificationTask;
                
                return MapVerificationToBiometricResult(verificationResult);
            }
            catch (Exception)
            {
                return BiometricVerificationResult.DeviceNotPresent;
            }
        }

        /// <summary>
        /// Store biometric credential securely using DPAPI
        /// </summary>
        public static bool StoreBiometricCredential(string username, string password, string server = "keepersecurity.com")
        {
            try
            {
                var credential = new BiometricCredential
                {
                    Username = username,
                    Server = server,
                    EncryptedPassword = ProtectedData.Protect(
                        Encoding.UTF8.GetBytes(password),
                        GetEntropy(username, server),
                        DataProtectionScope.CurrentUser
                    ),
                    CreatedAt = DateTime.UtcNow,
                    LastUsedAt = DateTime.UtcNow
                };

                return StoreCredentialInRegistry(credential);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Retrieve biometric credential
        /// </summary>
        public static BiometricCredential GetBiometricCredential(string username, string server = "keepersecurity.com")
        {
            try
            {
                return RetrieveCredentialFromRegistry(username, server);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Remove biometric credential
        /// </summary>
        public static bool RemoveBiometricCredential(string username, string server = "keepersecurity.com")
        {
            try
            {
                return RemoveCredentialFromRegistry(username, server);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Decrypt stored password after biometric verification
        /// </summary>
        public static string DecryptPassword(BiometricCredential credential)
        {
            try
            {
                var decryptedBytes = ProtectedData.Unprotect(
                    credential.EncryptedPassword,
                    GetEntropy(credential.Username, credential.Server),
                    DataProtectionScope.CurrentUser
                );
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch
            {
                return null;
            }
        }

        #region Private Helper Methods

        private static BiometricVerificationResult MapAvailabilityToBiometricResult(dynamic availability)
        {
            // Map Windows UserConsentVerifierAvailability to our enum
            var availabilityValue = (int)availability;
            switch (availabilityValue)
            {
                case 0: return BiometricVerificationResult.Verified; // Available
                case 1: return BiometricVerificationResult.DeviceNotPresent; // DeviceNotPresent
                case 2: return BiometricVerificationResult.NotConfiguredForUser; // NotConfiguredForUser
                case 3: return BiometricVerificationResult.DisabledByPolicy; // DisabledByPolicy
                default: return BiometricVerificationResult.DeviceNotPresent;
            }
        }

        private static BiometricVerificationResult MapVerificationToBiometricResult(dynamic verificationResult)
        {
            // Map Windows UserConsentVerificationResult to our enum
            var resultValue = (int)verificationResult;
            switch (resultValue)
            {
                case 0: return BiometricVerificationResult.Verified; // Verified
                case 1: return BiometricVerificationResult.DeviceNotPresent; // DeviceNotPresent
                case 2: return BiometricVerificationResult.NotConfiguredForUser; // NotConfiguredForUser
                case 3: return BiometricVerificationResult.DisabledByPolicy; // DisabledByPolicy
                case 4: return BiometricVerificationResult.DeviceBusy; // DeviceBusy
                case 5: return BiometricVerificationResult.RetriesExhausted; // RetriesExhausted
                case 6: return BiometricVerificationResult.Canceled; // Canceled
                default: return BiometricVerificationResult.Canceled;
            }
        }

        private static byte[] GetEntropy(string username, string server)
        {
            var entropy = $"Keeper-{username}-{server}-{Environment.MachineName}";
            return SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(entropy));
        }

        private static string GetRegistryKeyName(string username, string server)
        {
            return $"{username}@{server}";
        }

        private static bool StoreCredentialInRegistry(BiometricCredential credential)
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(CREDENTIAL_REGISTRY_KEY))
                {
                    var credentialKey = GetRegistryKeyName(credential.Username, credential.Server);
                    using (var subKey = key.CreateSubKey(credentialKey))
                    {
                        subKey.SetValue("Username", credential.Username);
                        subKey.SetValue("Server", credential.Server);
                        subKey.SetValue("EncryptedPassword", credential.EncryptedPassword);
                        subKey.SetValue("CreatedAt", credential.CreatedAt.ToBinary());
                        subKey.SetValue("LastUsedAt", credential.LastUsedAt.ToBinary());
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        private static BiometricCredential RetrieveCredentialFromRegistry(string username, string server)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(CREDENTIAL_REGISTRY_KEY))
                {
                    if (key == null) return null;

                    var credentialKey = GetRegistryKeyName(username, server);
                    using (var subKey = key.OpenSubKey(credentialKey))
                    {
                        if (subKey == null) return null;

                        var credential = new BiometricCredential
                        {
                            Username = subKey.GetValue("Username")?.ToString(),
                            Server = subKey.GetValue("Server")?.ToString(),
                            EncryptedPassword = (byte[])subKey.GetValue("EncryptedPassword"),
                            CreatedAt = DateTime.FromBinary((long)subKey.GetValue("CreatedAt")),
                            LastUsedAt = DateTime.FromBinary((long)subKey.GetValue("LastUsedAt"))
                        };

                        // Update last used time
                        credential.LastUsedAt = DateTime.UtcNow;
                        StoreCredentialInRegistry(credential);

                        return credential;
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private static bool RemoveCredentialFromRegistry(string username, string server)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(CREDENTIAL_REGISTRY_KEY, true))
                {
                    if (key == null) return true;

                    var credentialKey = GetRegistryKeyName(username, server);
                    key.DeleteSubKey(credentialKey, false);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        #endregion
    }

    /// <summary>
    /// Interface for UI callbacks during biometric authentication
    /// </summary>
    public interface IBiometricAuthUI
    {
        Task<string> PromptForUsernameAsync();
        Task<string> PromptForPasswordAsync(string message);
        Task ShowMessageAsync(string message);
        Task ShowErrorAsync(string message);
    }

    /// <summary>
    /// Biometric authentication flow manager
    /// </summary>
    public class BiometricAuthenticator
    {
        private readonly IBiometricAuthUI _ui;

        public BiometricAuthenticator(IBiometricAuthUI ui)
        {
            _ui = ui;
        }

        /// <summary>
        /// Set up biometric authentication for a user
        /// </summary>
        public async Task<bool> SetupBiometricAsync(string username, string password, string server = "keepersecurity.com")
        {
            if (!await WindowsHelloProvider.IsAvailableAsync())
            {
                await _ui.ShowErrorAsync("Windows Hello is not available on this system. Please configure Windows Hello in Windows Settings.");
                return false;
            }

            // Verify biometric access first
            var verificationResult = await WindowsHelloProvider.RequestVerificationAsync($"Set up biometric login for {username}");
            if (verificationResult != BiometricVerificationResult.Verified)
            {
                await _ui.ShowErrorAsync($"Biometric verification failed: {verificationResult}");
                return false;
            }

            // Store the credential
            var stored = WindowsHelloProvider.StoreBiometricCredential(username, password, server);
            if (stored)
            {
                await _ui.ShowMessageAsync($"✓ Biometric authentication setup complete for {username}");
                return true;
            }
            else
            {
                await _ui.ShowErrorAsync("Failed to store biometric credentials");
                return false;
            }
        }

        /// <summary>
        /// Authenticate using biometrics
        /// </summary>
        public async Task<string> AuthenticateAsync(string username, string server = "keepersecurity.com")
        {
            if (!await WindowsHelloProvider.IsAvailableAsync())
            {
                await _ui.ShowErrorAsync("Windows Hello is not available on this system.");
                return null;
            }

            // Check if credential exists
            var credential = WindowsHelloProvider.GetBiometricCredential(username, server);
            if (credential == null)
            {
                await _ui.ShowErrorAsync($"No biometric credentials found for {username} on {server}. Please set up biometric authentication first.");
                return null;
            }

            // Request biometric verification
            await _ui.ShowMessageAsync($"🔐 Biometric authentication required for {username}");
            var verificationResult = await WindowsHelloProvider.RequestVerificationAsync($"Verify your identity to access Keeper vault for {username}");

            if (verificationResult != BiometricVerificationResult.Verified)
            {
                await _ui.ShowErrorAsync($"Biometric verification failed: {verificationResult}");
                return null;
            }

            // Decrypt and return password
            var password = WindowsHelloProvider.DecryptPassword(credential);
            if (password == null)
            {
                await _ui.ShowErrorAsync("Failed to decrypt stored password. Please set up biometric authentication again.");
                return null;
            }

            await _ui.ShowMessageAsync("✅ Biometric authentication successful");
            return password;
        }
    }
}

#endif
