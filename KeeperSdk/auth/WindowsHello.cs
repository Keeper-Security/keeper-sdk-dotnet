using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Utils;

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
        public byte[] CredentialId { get; set; }
        public byte[] PublicKey { get; set; }
        public uint SignatureCounter { get; set; }
        public string CredType { get; set; }
        public Guid AaGuid { get; set; }
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
            // Check if we're running on Windows
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return false;
            }

            try
            {
                // Try to load Windows Runtime UserConsentVerifier using reflection (same as PowerShell implementation)
                var userConsentVerifierType = Type.GetType("Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime");
                if (userConsentVerifierType == null)
                {
                    // Fallback: try loading from WinRT assemblies
                    try
                    {
                        var winrtAssembly = System.Reflection.Assembly.Load("Windows.Security.Credentials.UI");
                        userConsentVerifierType = winrtAssembly.GetType("Windows.Security.Credentials.UI.UserConsentVerifier");
                    }
                    catch
                    {
                        return false;
                    }
                }

                if (userConsentVerifierType == null)
                {
                    return false;
                }

                var checkAvailabilityMethod = userConsentVerifierType.GetMethod("CheckAvailabilityAsync");
                if (checkAvailabilityMethod == null)
                {
                    return false;
                }

                // Check availability
                var availabilityTask = checkAvailabilityMethod.Invoke(null, null);
                if (availabilityTask is Task<object> task)
                {
                    var availability = await task;
                    var availabilityValue = Convert.ToInt32(availability);
                    // Return true if Available (0), false for other states
                    return availabilityValue == 0;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Request biometric verification from the user using Windows Hello
        /// </summary>
        /// <param name="message">Message to display to the user</param>
        /// <param name="actualVerification">Whether to perform actual verification or just check availability</param>
        /// <returns>Verification result</returns>
        public static async Task<BiometricVerificationResult> RequestVerificationAsync(string message, bool actualVerification = true)
        {
            // Check if we're running on Windows
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return BiometricVerificationResult.DeviceNotPresent;
            }

            try
            {
                // Try to load Windows Runtime UserConsentVerifier using reflection
                var userConsentVerifierType = Type.GetType("Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime");
                if (userConsentVerifierType == null)
                {
                    // Fallback: try loading from WinRT assemblies
                    try
                    {
                        var winrtAssembly = System.Reflection.Assembly.Load("Windows.Security.Credentials.UI");
                        userConsentVerifierType = winrtAssembly.GetType("Windows.Security.Credentials.UI.UserConsentVerifier");
                    }
                    catch
                    {
                        return BiometricVerificationResult.DeviceNotPresent;
                    }
                }

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
                var availabilityTask = checkAvailabilityMethod.Invoke(null, null);
                if (availabilityTask is Task<object> task)
                {
                    var availability = await task;
                    var availabilityResult = MapAvailabilityToBiometricResult(availability);
                    if (availabilityResult != BiometricVerificationResult.Verified)
                    {
                        return availabilityResult;
                    }
                }
                else
                {
                    return BiometricVerificationResult.DeviceNotPresent;
                }

                if (!actualVerification)
                {
                    return BiometricVerificationResult.Verified;
                }

                // Request verification
                var verificationTask = requestVerificationMethod.Invoke(null, new object[] { message ?? "Verify your identity" });
                if (verificationTask is Task<object> verifyTask)
                {
                    var verificationResult = await verifyTask;
                    return MapVerificationToBiometricResult(verificationResult);
                }
                
                return BiometricVerificationResult.DeviceNotPresent;
            }
            catch (Exception)
            {
                return BiometricVerificationResult.DeviceNotPresent;
            }
        }
        
        private static BiometricVerificationResult MapAvailabilityToBiometricResult(object availability)
        {
            // Map Windows UserConsentVerifierAvailability to our enum
            var availabilityValue = Convert.ToInt32(availability);
            switch (availabilityValue)
            {
                case 0: return BiometricVerificationResult.Verified; // Available
                case 1: return BiometricVerificationResult.DeviceNotPresent; // DeviceNotPresent
                case 2: return BiometricVerificationResult.NotConfiguredForUser; // NotConfiguredForUser
                case 3: return BiometricVerificationResult.DisabledByPolicy; // DisabledByPolicy
                default: return BiometricVerificationResult.DeviceNotPresent;
            }
        }

        private static BiometricVerificationResult MapVerificationToBiometricResult(object verificationResult)
        {
            // Map Windows UserConsentVerificationResult to our enum
            var resultValue = Convert.ToInt32(verificationResult);
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


        /// <summary>
        /// Store biometric credential securely
        /// </summary>
        public static async Task<bool> StoreBiometricCredentialAsync(string username, string password, string server = "keepersecurity.com")
        {
            try
            {
                // Verify Windows Hello is available and user can authenticate
                var verificationResult = await RequestVerificationAsync($"Set up biometric authentication for {username}", true);
                if (verificationResult != BiometricVerificationResult.Verified)
                {
                    return false;
                }
                
                var credential = new BiometricCredential
                {
                    Username = username,
                    Server = server,
                    EncryptedPassword = ProtectPassword(password, username, server),
                    CredentialId = CryptoUtils.GetRandomBytes(32), // Use random credential ID for tracking
                    CreatedAt = DateTime.UtcNow,
                    LastUsedAt = DateTime.UtcNow
                };

                return StoreCredentialSecurely(credential);
            }
            catch (Exception)
            {
                return false;
            }
        }
        
        /// <summary>
        /// Store biometric credential securely (backward compatibility - synchronous wrapper)
        /// </summary>
        [Obsolete("Use StoreBiometricCredentialAsync for better async support")]
        public static bool StoreBiometricCredential(string username, string password, string server = "keepersecurity.com")
        {
            try
            {
                return StoreBiometricCredentialAsync(username, password, server).GetAwaiter().GetResult();
            }
            catch
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
                return RetrieveCredentialSecurely(username, server);
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
                return RemoveCredentialSecurely(username, server);
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
                return UnprotectPassword(credential.EncryptedPassword, credential.Username, credential.Server);
            }
            catch
            {
                return null;
            }
        }

        #region Private Helper Methods

        private static byte[] ProtectPassword(string password, string username, string server)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var entropy = GetEntropy(username, server);

            // Try Windows DPAPI first if available
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var protectedDataType = Type.GetType("System.Security.Cryptography.ProtectedData, System.Security.Cryptography.ProtectedData");
                    if (protectedDataType != null)
                    {
                        var protectMethod = protectedDataType.GetMethod("Protect", new Type[] { typeof(byte[]), typeof(byte[]), typeof(object) });
                        if (protectMethod != null)
                        {
                            // DataProtectionScope.CurrentUser = 0
                            var result = protectMethod.Invoke(null, new object[] { passwordBytes, entropy, 0 });
                            return (byte[])result;
                        }
                    }
                }
                catch
                {
                    // Fall through to cross-platform encryption
                }
            }

            // Cross-platform encryption using AES (less secure than DPAPI)
            using (var aes = Aes.Create())
            {
                aes.Key = entropy.Take(32).ToArray(); // 256-bit key
                aes.IV = entropy.Skip(16).Take(16).ToArray(); // 128-bit IV
                
                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
                }
            }
        }

        private static string UnprotectPassword(byte[] encryptedPassword, string username, string server)
        {
            var entropy = GetEntropy(username, server);

            // Try Windows DPAPI first if available
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var protectedDataType = Type.GetType("System.Security.Cryptography.ProtectedData, System.Security.Cryptography.ProtectedData");
                    if (protectedDataType != null)
                    {
                        var unprotectMethod = protectedDataType.GetMethod("Unprotect", new Type[] { typeof(byte[]), typeof(byte[]), typeof(object) });
                        if (unprotectMethod != null)
                        {
                            // DataProtectionScope.CurrentUser = 0
                            var result = unprotectMethod.Invoke(null, new object[] { encryptedPassword, entropy, 0 });
                            return Encoding.UTF8.GetString((byte[])result);
                        }
                    }
                }
                catch
                {
                    // Fall through to cross-platform decryption
                }
            }

            // Cross-platform decryption using AES
            using (var aes = Aes.Create())
            {
                aes.Key = entropy.Take(32).ToArray(); // 256-bit key
                aes.IV = entropy.Skip(16).Take(16).ToArray(); // 128-bit IV
                
                using (var decryptor = aes.CreateDecryptor())
                {
                    var decryptedBytes = decryptor.TransformFinalBlock(encryptedPassword, 0, encryptedPassword.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }

        private static byte[] GetEntropy(string username, string server)
        {
            var entropy = $"Keeper-{username}-{server}-{Environment.MachineName}-BiometricAuth-2024";
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(entropy));
            }
        }

        private static string GetCredentialFileName(string username, string server)
        {
            var safe = $"{username}@{server}".Replace(":", "_").Replace("/", "_").Replace("\\", "_");
            return $"keeper_biometric_{safe}.dat";
        }

        private static string GetCredentialDirectory()
        {
            var userFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var credentialDir = Path.Combine(userFolder, ".keeper", "biometric");
            
            if (!Directory.Exists(credentialDir))
            {
                Directory.CreateDirectory(credentialDir);
            }
            
            return credentialDir;
        }

        private static bool StoreCredentialSecurely(BiometricCredential credential)
        {
            try
            {
                var credentialDir = GetCredentialDirectory();
                var fileName = GetCredentialFileName(credential.Username, credential.Server);
                var filePath = Path.Combine(credentialDir, fileName);

                var data = new
                {
                    Username = credential.Username,
                    Server = credential.Server,
                    EncryptedPassword = Convert.ToBase64String(credential.EncryptedPassword),
                    CredentialId = credential.CredentialId != null ? Convert.ToBase64String(credential.CredentialId) : null,
                    PublicKey = credential.PublicKey != null ? Convert.ToBase64String(credential.PublicKey) : null,
                    SignatureCounter = credential.SignatureCounter,
                    CredType = credential.CredType,
                    AaGuid = credential.AaGuid.ToString(),
                    CreatedAt = credential.CreatedAt.ToBinary(),
                    LastUsedAt = credential.LastUsedAt.ToBinary()
                };

                var json = JsonUtils.DumpJson(data);
                File.WriteAllText(filePath, Encoding.UTF8.GetString(json));
                
                // Set file permissions to be readable only by current user
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Unix/Linux file permissions - owner read/write only
                    try
                    {
                        var chmod = System.Diagnostics.Process.Start("chmod", $"600 \"{filePath}\"");
                        chmod?.WaitForExit();
                    }
                    catch
                    {
                        // Ignore if chmod fails
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        private class CredentialData
        {
            public string Username { get; set; }
            public string Server { get; set; }
            public string EncryptedPassword { get; set; }
            public string CredentialId { get; set; }
            public string PublicKey { get; set; }
            public uint SignatureCounter { get; set; }
            public string CredType { get; set; }
            public string AaGuid { get; set; }
            public long CreatedAt { get; set; }
            public long LastUsedAt { get; set; }
        }

        private static BiometricCredential RetrieveCredentialSecurely(string username, string server)
        {
            try
            {
                var credentialDir = GetCredentialDirectory();
                var fileName = GetCredentialFileName(username, server);
                var filePath = Path.Combine(credentialDir, fileName);

                if (!File.Exists(filePath))
                    return null;

                var json = File.ReadAllText(filePath);
                var data = JsonUtils.ParseJson<CredentialData>(Encoding.UTF8.GetBytes(json));
                
                var credential = new BiometricCredential
                {
                    Username = data.Username,
                    Server = data.Server,
                    EncryptedPassword = Convert.FromBase64String(data.EncryptedPassword),
                    CredentialId = !string.IsNullOrEmpty(data.CredentialId) ? Convert.FromBase64String(data.CredentialId) : null,
                    PublicKey = !string.IsNullOrEmpty(data.PublicKey) ? Convert.FromBase64String(data.PublicKey) : null,
                    SignatureCounter = data.SignatureCounter,
                    CredType = data.CredType,
                    AaGuid = !string.IsNullOrEmpty(data.AaGuid) ? Guid.Parse(data.AaGuid) : Guid.Empty,
                    CreatedAt = DateTime.FromBinary(data.CreatedAt),
                    LastUsedAt = DateTime.FromBinary(data.LastUsedAt)
                };

                // Update last used time
                credential.LastUsedAt = DateTime.UtcNow;
                StoreCredentialSecurely(credential);

                return credential;
            }
            catch
            {
                return null;
            }
        }

        private static bool RemoveCredentialSecurely(string username, string server)
        {
            try
            {
                var credentialDir = GetCredentialDirectory();
                var fileName = GetCredentialFileName(username, server);
                var filePath = Path.Combine(credentialDir, fileName);

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
                
                return true;
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
        /// Set up biometric authentication for a user using FIDO2
        /// </summary>
        public async Task<bool> SetupBiometricAsync(string username, string password, string server = "keepersecurity.com")
        {
            if (!await WindowsHelloProvider.IsAvailableAsync())
            {
                await _ui.ShowErrorAsync("Windows Hello is not available on this system. Please configure Windows Hello in Windows Settings.");
                return false;
            }

            await _ui.ShowMessageAsync($"Setting up biometric authentication for {username}...");
            
            // Store the credential
            var stored = await WindowsHelloProvider.StoreBiometricCredentialAsync(username, password, server);
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
