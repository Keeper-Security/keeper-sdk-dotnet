using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Utils;

// Available for all targets including netstandard2.0

#if FIDO2_AVAILABLE
using Fido2NetLib;
using Fido2NetLib.Objects;
#endif

#if WINDOWS_HELLO_AVAILABLE
using Windows.Security.Credentials;
using Windows.Security.Credentials.UI;
using Windows.Storage.Streams;
using System.Runtime.InteropServices.WindowsRuntime;
#endif

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
        
#if FIDO2_AVAILABLE
        // FIDO2-specific properties (only available when FIDO2 library is included)
        public byte[] UserHandle { get; set; }
        public string AttestationFormat { get; set; }
        public PublicKeyCredentialType CredentialType { get; set; }
        public AuthenticatorTransport[] Transports { get; set; }
        public byte[] AttestationObject { get; set; }
        public byte[] ClientDataJson { get; set; }
#endif
    }

    /// <summary>
    /// Windows Hello biometric authentication provider with FIDO2 support (.NET 8.0+) or basic Windows Hello
    /// </summary>
    public static class WindowsHelloProvider
    {
#if FIDO2_AVAILABLE
        private static readonly IFido2 _fido2;
        private static readonly string _origin = "https://keepersecurity.com";
        private static readonly string _rpId = "keepersecurity.com";

        static WindowsHelloProvider()
        {
            var config = new Fido2Configuration()
            {
                ServerDomain = _rpId,
                ServerName = "Keeper Security",
                Origins = new HashSet<string> { _origin },
                TimestampDriftTolerance = 300000
            };
            
            _fido2 = new Fido2(config);
        }
#endif

        /// <summary>
        /// Check if Windows Hello is available on this system
        /// Following Microsoft's official documentation approach:
        /// https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello
        /// </summary>
        public static async Task<bool> IsAvailableAsync()
        {
            // Check if we're running on Windows
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return false;
            }
            else{
                try
                {
#if WINDOWS_HELLO_AVAILABLE
                    var keyCredentialAvailable = await KeyCredentialManager.IsSupportedAsync();
                    return keyCredentialAvailable;
#else
                    // For netstandard2.0, Windows Hello is not available
                    return false;
#endif
                }
                catch (Exception)
                {
                    // If Windows Runtime API fails, Windows Hello is not available
                    return false;
                }
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
                if (!actualVerification)
                {
                    return await IsAvailableAsync() ? BiometricVerificationResult.Verified : BiometricVerificationResult.DeviceNotPresent;
                }

                // Use Windows Runtime APIs for Windows targets
                try
                {
#if WINDOWS_HELLO_AVAILABLE
                    var result = await UserConsentVerifier.RequestVerificationAsync(message ?? "Verify your identity");
                    return MapUserConsentResultToBiometricResult(result);
#else
                    // For netstandard2.0, just check availability
                    return await IsAvailableAsync() ? BiometricVerificationResult.Verified : BiometricVerificationResult.DeviceNotPresent;
#endif
                }
                catch (Exception)
                {
                    // Fall back to availability check if verification fails
                    return await IsAvailableAsync() ? BiometricVerificationResult.DeviceNotPresent : BiometricVerificationResult.DeviceNotPresent;
                }
            }
            catch (Exception)
            {
                return BiometricVerificationResult.DeviceNotPresent;
            }
        }
        
        /// <summary>
        /// Map Windows UserConsentVerificationResult to our BiometricVerificationResult
        /// </summary>
#if WINDOWS_HELLO_AVAILABLE
        private static BiometricVerificationResult MapUserConsentResultToBiometricResult(UserConsentVerificationResult result)
        {
            switch (result)
            {
                case UserConsentVerificationResult.Verified:
                    return BiometricVerificationResult.Verified;
                case UserConsentVerificationResult.DeviceNotPresent:
                    return BiometricVerificationResult.DeviceNotPresent;
                case UserConsentVerificationResult.NotConfiguredForUser:
                    return BiometricVerificationResult.NotConfiguredForUser;
                case UserConsentVerificationResult.DisabledByPolicy:
                    return BiometricVerificationResult.DisabledByPolicy;
                case UserConsentVerificationResult.DeviceBusy:
                    return BiometricVerificationResult.DeviceBusy;
                case UserConsentVerificationResult.RetriesExhausted:
                    return BiometricVerificationResult.RetriesExhausted;
                case UserConsentVerificationResult.Canceled:
                    return BiometricVerificationResult.Canceled;
                default:
                    return BiometricVerificationResult.DeviceNotPresent;
            }
        }
#endif

        /// <summary>
        /// Test Windows Hello authentication by showing the popup dialog
        /// </summary>
        /// <param name="message">Custom message to display (optional)</param>
        /// <returns>Verification result</returns>
        public static async Task<BiometricVerificationResult> TestWindowsHelloPopupAsync(string message = null)
        {
            // Always force actual verification (show popup)
            return await RequestVerificationAsync(message ?? "🔐 Test Windows Hello Authentication", actualVerification: true);
        }

        /// <summary>
        /// Create a Windows Hello-protected cryptographic key for the given account
        /// </summary>
        /// <param name="accountId">Unique identifier for the account (e.g., username@server)</param>
        /// <returns>Result indicating success/failure and key information</returns>
        public static async Task<WindowsHelloKeyResult> CreateProtectedKeyAsync(string accountId)
        {
#if WINDOWS_HELLO_AVAILABLE
            try
            {
                // Check if Windows Hello is supported
                var isSupported = await KeyCredentialManager.IsSupportedAsync();
                if (!isSupported)
                {
                    return new WindowsHelloKeyResult
                    {
                        Success = false,
                        ErrorMessage = "Windows Hello is not supported on this device"
                    };
                }

                // Create a new key credential protected by Windows Hello
                var keyCreationResult = await KeyCredentialManager.RequestCreateAsync(
                    accountId, 
                    KeyCredentialCreationOption.ReplaceExisting);

                switch (keyCreationResult.Status)
                {
                    case KeyCredentialStatus.Success:
                        var userKey = keyCreationResult.Credential;
                        var publicKey = userKey.RetrievePublicKey();
                        
                        // Get attestation information
                        var keyAttestationResult = await userKey.GetAttestationAsync();
                        
                        return new WindowsHelloKeyResult
                        {
                            Success = true,
#if WINDOWS_HELLO_AVAILABLE
                            KeyCredential = userKey,
                            AttestationStatus = keyAttestationResult.Status,
#endif
                            PublicKey = publicKey?.ToArray(),
                            AttestationBuffer = keyAttestationResult.AttestationBuffer?.ToArray(),
                            CertificateChain = keyAttestationResult.CertificateChainBuffer?.ToArray()
                        };

                    case KeyCredentialStatus.UserCanceled:
                        return new WindowsHelloKeyResult
                        {
                            Success = false,
                            ErrorMessage = "User canceled Windows Hello setup"
                        };

                    case KeyCredentialStatus.UserPrefersPassword:
                        return new WindowsHelloKeyResult
                        {
                            Success = false,
                            ErrorMessage = "User prefers password authentication"
                        };

                    default:
                        return new WindowsHelloKeyResult
                        {
                            Success = false,
                            ErrorMessage = $"Key creation failed: {keyCreationResult.Status}"
                        };
                }
            }
            catch (Exception ex)
            {
                return new WindowsHelloKeyResult
                {
                    Success = false,
                    ErrorMessage = $"Exception during key creation: {ex.Message}"
                };
            }
#else
            // For netstandard2.0, Windows Hello key creation is not available
            return new WindowsHelloKeyResult
            {
                Success = false,
                ErrorMessage = "Windows Hello key creation requires Windows Runtime APIs (not available in netstandard2.0)"
            };
#endif
        }

        /// <summary>
        /// Result of Windows Hello key creation
        /// </summary>
        public class WindowsHelloKeyResult
        {
            public bool Success { get; set; }
            public string ErrorMessage { get; set; }
#if WINDOWS_HELLO_AVAILABLE
            public KeyCredential KeyCredential { get; set; }
            public KeyCredentialAttestationStatus AttestationStatus { get; set; }
#endif
            public byte[] PublicKey { get; set; }
            public byte[] AttestationBuffer { get; set; }
            public byte[] CertificateChain { get; set; }
        }

#if FIDO2_AVAILABLE
        /// <summary>
        /// Create FIDO2 credential options for registration (.NET 8.0+ only)
        /// </summary>
        public static CredentialCreateOptions CreateRegistrationOptions(string username, string displayName, string server = "keepersecurity.com")
        {
            var user = new Fido2User
            {
                Name = username,
                Id = Encoding.UTF8.GetBytes(username),
                DisplayName = displayName ?? username
            };

            var options = _fido2.RequestNewCredential(
                user, 
                new List<PublicKeyCredentialDescriptor>(), // No existing credentials to exclude
                AuthenticatorSelection.Default,
                AttestationConveyancePreference.Direct
            );

            return options;
        }

        /// <summary>
        /// Create FIDO2 assertion options for authentication (.NET 8.0+ only)
        /// </summary>
        public static AssertionOptions CreateAuthenticationOptions(BiometricCredential credential)
        {
            var allowedCredentials = new List<PublicKeyCredentialDescriptor>
            {
                new PublicKeyCredentialDescriptor(credential.CredentialId)
            };

            var options = _fido2.GetAssertionOptions(
                allowedCredentials,
                UserVerificationRequirement.Required
            );

            return options;
        }
#endif

        /// <summary>
        /// Store biometric credential securely
        /// </summary>
        public static async Task<bool> StoreBiometricCredentialAsync(string username, string password, string server = "keepersecurity.com")
        {
            try
            {
                // First verify Windows Hello is available
                if (!await IsAvailableAsync())
                {
                    return false;
                }

                // Verify user can authenticate before setting up
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
                    CredentialId = CryptoUtils.GetRandomBytes(32),
                    CreatedAt = DateTime.UtcNow,
                    LastUsedAt = DateTime.UtcNow,
                    CredType = "platform"
                };

#if FIDO2_AVAILABLE
                // Add FIDO2-specific properties for .NET 8.0+
                var options = CreateRegistrationOptions(username, username, server);
                credential.UserHandle = options.User.Id;
                credential.CredentialType = PublicKeyCredentialType.PublicKey;
                credential.AttestationFormat = "packed";
#endif

                return StoreCredentialSecurely(credential);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Authenticate using stored biometric credential
        /// </summary>
        public static async Task<string> AuthenticateWithBiometricAsync(string username, string server = "keepersecurity.com")
        {
            try
            {
                // Check if Windows Hello is available
                if (!await IsAvailableAsync())
                {
                    return null;
                }

                // Retrieve stored credential
                var credential = GetBiometricCredential(username, server);
                if (credential == null)
                {
                    return null;
                }

                // Request biometric verification
                var verificationResult = await RequestVerificationAsync($"Verify your identity to access Keeper vault for {username}");
                if (verificationResult != BiometricVerificationResult.Verified)
                {
                    return null;
                }

                // Decrypt the password
                var password = DecryptPassword(credential);
                if (password != null)
                {
                    // Update last used time
                    credential.LastUsedAt = DateTime.UtcNow;
                    StoreCredentialSecurely(credential);
                }

                return password;
            }
            catch
            {
                return null;
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
                    // Use System.Security.Cryptography.ProtectedData directly - it's available in .NET Standard 2.0 on Windows
                    return ProtectedData.Protect(passwordBytes, entropy, DataProtectionScope.CurrentUser);
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
                    // Use System.Security.Cryptography.ProtectedData directly - it's available in .NET Standard 2.0 on Windows
                    var result = ProtectedData.Unprotect(encryptedPassword, entropy, DataProtectionScope.CurrentUser);
                    return Encoding.UTF8.GetString(result);
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
#if FIDO2_AVAILABLE
            var entropy = $"Keeper-{username}-{server}-{Environment.MachineName}-FIDO2Auth-2024";
#else
            var entropy = $"Keeper-{username}-{server}-{Environment.MachineName}-BiometricAuth-2024";
#endif
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(entropy));
            }
        }

        private static string GetCredentialFileName(string username, string server)
        {
            var safe = $"{username}@{server}".Replace(":", "_").Replace("/", "_").Replace("\\", "_");
#if FIDO2_AVAILABLE
            return $"keeper_fido2_{safe}.dat";
#else
            return $"keeper_biometric_{safe}.dat";
#endif
        }

        private static string GetCredentialDirectory()
        {
            var userFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
#if FIDO2_AVAILABLE
            var credentialDir = Path.Combine(userFolder, ".keeper", "fido2");
#else
            var credentialDir = Path.Combine(userFolder, ".keeper", "biometric");
#endif
            
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
                    LastUsedAt = credential.LastUsedAt.ToBinary(),
#if FIDO2_AVAILABLE
                    UserHandle = credential.UserHandle != null ? Convert.ToBase64String(credential.UserHandle) : null,
                    AttestationFormat = credential.AttestationFormat,
                    CredentialType = credential.CredentialType.ToString(),
                    Transports = credential.Transports?.Select(t => t.ToString()).ToArray(),
                    AttestationObject = credential.AttestationObject != null ? Convert.ToBase64String(credential.AttestationObject) : null,
                    ClientDataJson = credential.ClientDataJson != null ? Convert.ToBase64String(credential.ClientDataJson) : null
#endif
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
#if FIDO2_AVAILABLE
            public string UserHandle { get; set; }
            public string AttestationFormat { get; set; }
            public string CredentialType { get; set; }
            public string[] Transports { get; set; }
            public string AttestationObject { get; set; }
            public string ClientDataJson { get; set; }
#endif
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

#if FIDO2_AVAILABLE
                credential.UserHandle = !string.IsNullOrEmpty(data.UserHandle) ? Convert.FromBase64String(data.UserHandle) : null;
                credential.AttestationFormat = data.AttestationFormat;
                credential.AttestationObject = !string.IsNullOrEmpty(data.AttestationObject) ? Convert.FromBase64String(data.AttestationObject) : null;
                credential.ClientDataJson = !string.IsNullOrEmpty(data.ClientDataJson) ? Convert.FromBase64String(data.ClientDataJson) : null;

                // Parse CredentialType
                if (!string.IsNullOrEmpty(data.CredentialType) && Enum.TryParse<PublicKeyCredentialType>(data.CredentialType, out var credType))
                {
                    credential.CredentialType = credType;
                }

                // Parse Transports
                if (data.Transports != null)
                {
                    credential.Transports = data.Transports
                        .Where(t => Enum.TryParse<AuthenticatorTransport>(t, out _))
                        .Select(t => Enum.Parse<AuthenticatorTransport>(t))
                        .ToArray();
                }
#endif

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
        /// Set up biometric authentication for a user
        /// </summary>
        public async Task<bool> SetupBiometricAsync(string username, string password, string server = "keepersecurity.com")
        {
            if (!await WindowsHelloProvider.IsAvailableAsync())
            {
                await _ui.ShowErrorAsync("Windows Hello is not available on this system. Please configure Windows Hello in Windows Settings.");
                return false;
            }

#if FIDO2_AVAILABLE
            await _ui.ShowMessageAsync($"Setting up FIDO2 biometric authentication for {username}...");
#else
            await _ui.ShowMessageAsync($"Setting up biometric authentication for {username}...");
#endif
            
            // Store the credential
            var stored = await WindowsHelloProvider.StoreBiometricCredentialAsync(username, password, server);
            if (stored)
            {
#if FIDO2_AVAILABLE
                await _ui.ShowMessageAsync($"✓ FIDO2 biometric authentication setup complete for {username}");
#else
                await _ui.ShowMessageAsync($"✓ Biometric authentication setup complete for {username}");
#endif
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
#if FIDO2_AVAILABLE
                await _ui.ShowErrorAsync($"No FIDO2 biometric credentials found for {username} on {server}. Please set up biometric authentication first.");
#else
                await _ui.ShowErrorAsync($"No biometric credentials found for {username} on {server}. Please set up biometric authentication first.");
#endif
                return null;
            }

            // Request biometric verification
#if FIDO2_AVAILABLE
            await _ui.ShowMessageAsync($"🔐 FIDO2 biometric authentication required for {username}");
#else
            await _ui.ShowMessageAsync($"🔐 Biometric authentication required for {username}");
#endif
            
            var password = await WindowsHelloProvider.AuthenticateWithBiometricAsync(username, server);

            if (password == null)
            {
#if FIDO2_AVAILABLE
                await _ui.ShowErrorAsync("FIDO2 biometric authentication failed");
#else
                await _ui.ShowErrorAsync("Biometric authentication failed");
#endif
                return null;
            }

#if FIDO2_AVAILABLE
            await _ui.ShowMessageAsync("✅ FIDO2 biometric authentication successful");
#else
            await _ui.ShowMessageAsync("✅ Biometric authentication successful");
#endif
            return password;
        }
    }
}

// End of file - available for all targets