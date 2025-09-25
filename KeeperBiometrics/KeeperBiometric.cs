#if NET472_OR_GREATER || NET8_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PeterO.Cbor;
using Newtonsoft.Json;

namespace KeeperBiometric
{
    /// <summary>
    /// Lightweight, self-contained Windows Hello WebAuthn implementation for PowerShell
    /// This provides native Windows WebAuthn API access specifically designed for PowerShell integration
    /// with no external dependencies.
    /// </summary>
    public static class WindowsHelloApi
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
        
        [DllImport("user32.dll")]
        public static extern IntPtr GetActiveWindow();
        
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
        
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        
        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);
        
        private const int SW_RESTORE = 9;
        private const int SW_SHOW = 5;

        /// <summary>
        /// Gets the best window handle for Windows Hello dialogs
        /// This helps with dialog positioning and interaction issues
        /// </summary>
        private static IntPtr GetBestWindowHandle()
        {
            var foregroundWnd = GetForegroundWindow();
            if (foregroundWnd != IntPtr.Zero && IsWindowVisible(foregroundWnd))
            {
                return foregroundWnd;
            }
            
            var activeWnd = GetActiveWindow();
            if (activeWnd != IntPtr.Zero && IsWindowVisible(activeWnd))
            {
                return activeWnd;
            }
            
            var consoleWnd = GetConsoleWindow();
            if (consoleWnd != IntPtr.Zero)
            {
                SetForegroundWindow(consoleWnd);
                ShowWindow(consoleWnd, SW_RESTORE);
                return consoleWnd;
            }
            
            return IntPtr.Zero;
        }

        /// <summary>
        /// Comprehensive Windows Hello information for PowerShell scripts
        /// </summary>
        public static WindowsHelloCapabilities GetCapabilities()
        {
            try
            {
                var result = NativeWebAuthn.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool isAvailable);
                var apiVersion = NativeWebAuthn.WebAuthNGetApiVersionNumber();
                
                return new WindowsHelloCapabilities
                {
                    IsAvailable = result == NativeWebAuthn.HRESULT.S_OK && isAvailable,
                    ApiVersion = apiVersion,
                    Platform = GetWindowsVersion(),
                    SupportedMethods = DetectSupportedBiometricMethods(),
                    CanCreateCredentials = result == NativeWebAuthn.HRESULT.S_OK && isAvailable && apiVersion >= 2,
                    CanPerformAuthentication = result == NativeWebAuthn.HRESULT.S_OK && isAvailable,
                    WebAuthnDllAvailable = true,
                    LastChecked = DateTime.UtcNow,
                    RecommendedIntegration = result == NativeWebAuthn.HRESULT.S_OK && isAvailable 
                        ? "Use Connect-KeeperWithBiometricsAdvanced" 
                        : "Use regular Connect-Keeper"
                };
            }
            catch (DllNotFoundException)
            {
                return new WindowsHelloCapabilities
                {
                    IsAvailable = false,
                    ErrorMessage = "webauthn.dll not available (requires Windows 10 1903+)",
                    WebAuthnDllAvailable = false,
                    Platform = GetWindowsVersion(),
                    LastChecked = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                return new WindowsHelloCapabilities
                {
                    IsAvailable = false,
                    ErrorMessage = ex.Message,
                    WebAuthnDllAvailable = false,
                    Platform = GetWindowsVersion(),
                    LastChecked = DateTime.UtcNow
                };
            }
        }

        /// <summary>
        /// Simple PowerShell-friendly test for Windows Hello availability
        /// </summary>
        public static bool IsAvailable()
        {
            try
            {
                var result = NativeWebAuthn.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool isAvailable);
                return result == NativeWebAuthn.HRESULT.S_OK && isAvailable;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get formatted information for PowerShell display
        /// </summary>
        public static object GetFormattedInfo()
        {
            var caps = GetCapabilities();
            return new
            {
                WindowsHello = new {
                    Available = caps.IsAvailable,
                    Status = caps.IsAvailable ? "Ready" : "Not Available",
                    ApiVersion = caps.ApiVersion,
                    Platform = caps.Platform,
                    Methods = caps.SupportedMethods,
                    Error = caps.ErrorMessage,
                    LastChecked = caps.LastChecked.ToString("yyyy-MM-dd HH:mm:ss UTC")
                },
                PowerShellIntegration = new {
                    CanCreateCredentials = caps.CanCreateCredentials,
                    CanAuthenticate = caps.CanPerformAuthentication,
                    RecommendedCommand = caps.RecommendedIntegration,
                    WebAuthnDllStatus = caps.WebAuthnDllAvailable ? "Available" : "Missing"
                },
                SystemInfo = new {
                    DllAvailable = caps.WebAuthnDllAvailable,
                    BiometricMethodCount = caps.SupportedMethods?.Length ?? 0,
                    ProductionReady = caps.IsAvailable && caps.CanCreateCredentials,
                    RuntimeVersion = Environment.Version.ToString(),
                    Is64BitProcess = Environment.Is64BitProcess
                }
            };
        }

        /// <summary>
        /// Perform Windows Hello authentication (WebAuthn GetAssertion)
        /// </summary>
        public static async Task<AuthenticationResult> AuthenticateAsync(AuthenticationOptions options)
        {
            try
            {
                var hWnd = GetBestWindowHandle();
                var result = await GetAssertionAsync(hWnd, options);
                
                return new AuthenticationResult
                {
                    Success = true,
                    CredentialId = ToBase64Url(result.CredentialId),
                    Signature = ToBase64Url(result.Signature),
                    AuthenticatorData = ToBase64Url(result.AuthenticatorData),
                    ClientDataJSON = ToBase64Url(result.ClientDataJSON),
                    UserHandle = result.UserHandle != null ? ToBase64Url(result.UserHandle) : null,
                    Method = "Native WebAuthn GetAssertion",
                    Timestamp = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = ex.Message,
                    ErrorType = ex.GetType().Name,
                    Timestamp = DateTime.UtcNow
                };
            }
        }

         /// <summary>
         /// Create a new Windows Hello credential (WebAuthn MakeCredential)
         /// </summary>
        public static async Task<CredentialCreationResult> CreateCredentialAsync(RegistrationOptions options, ExcludeCredential[] excludeCredentials = null)
        {
            try
            {
                var hWnd = GetBestWindowHandle();
                var result = await MakeCredentialAsync(hWnd, options, excludeCredentials);
                 
                return new CredentialCreationResult
                {
                    Success = true,
                    CredentialId = ToBase64Url(result.CredentialId),
                    AttestationObject = ToBase64Url(result.AttestationObject),
                    ClientDataJSON = ToBase64Url(result.ClientDataJSON),
                    PublicKey = result.PublicKey != null ? ToBase64Url(result.PublicKey) : null,
                    Method = "Native WebAuthn MakeCredential",
                    SignatureCount = result.SignatureCount,
                    Timestamp = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                return new CredentialCreationResult
                {
                    Success = false,
                    ErrorMessage = ex.Message,
                    ErrorType = ex.GetType().Name,
                    Timestamp = DateTime.UtcNow
                };
            }
        }

        #region Private Implementation

        private static string GetWindowsVersion()
        {
            try
            {
                var version = Environment.OSVersion;
                return $"Windows {version.Version.Major}.{version.Version.Minor} Build {version.Version.Build}";
            }
            catch
            {
                return "Windows (Version Unknown)";
            }
        }

        private static string[] DetectSupportedBiometricMethods()
        {
            var methods = new List<string>();      
            methods.Add("PIN");
            // TODO: Add platform-specific detection for:
            // - Fingerprint readers (WinBio API)
            // - Face recognition cameras (Windows.Devices.Enumeration)
            // - Security keys (additional WebAuthn calls)
            return methods.ToArray();
        }

        private static async Task<InternalAuthenticationResult> GetAssertionAsync(IntPtr hWnd, AuthenticationOptions options)
        {
            var taskSource = new TaskCompletionSource<InternalAuthenticationResult>();
            
            await Task.Run(() =>
            {
                var ptrList = new List<IntPtr>();
                try
                {
                    // Create client data with Base64Url encoding (WebAuthn standard)
                    var clientData = new SecurityKeyClientData
                    {
                        dataType = SecurityKeyClientData.GET_ASSERTION,
                        challenge = ToBase64Url(options.Challenge),
                        origin = $"https://{options.RpId ?? "keepersecurity.com"}",
                    };
                    
                    var clientDataJson = SerializeClientData(clientData);
                    var clientDataBytes = System.Text.Encoding.UTF8.GetBytes(clientDataJson);
                    var clientDataPtr = Marshal.AllocHGlobal(clientDataBytes.Length);
                    ptrList.Add(clientDataPtr);
                    Marshal.Copy(clientDataBytes, 0, clientDataPtr, clientDataBytes.Length);

                    var data = new NativeWebAuthn.WEBAUTHN_CLIENT_DATA
                    {
                        dwVersion = NativeWebAuthn.WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                        cbClientDataJSON = clientDataBytes.Length,
                        pbClientDataJSON = clientDataPtr,
                        pwszHashAlgId = NativeWebAuthn.WEBAUTHN_HASH_ALGORITHM_SHA_256,
                    };

                    // Set up credentials (if any allowed credentials specified)
                    var credentialSize = Marshal.SizeOf(typeof(NativeWebAuthn.WEBAUTHN_CREDENTIAL));
                    var credentialsPtr = IntPtr.Zero;
                    var credentialCount = 0;
                    
                    if (options.AllowedCredentialIds != null && options.AllowedCredentialIds.Length > 0)
                    {
                        var credentials = options.AllowedCredentialIds
                            .Select(x => FromBase64Url(x))
                            .ToArray();
                        
                        credentialCount = credentials.Length;
                        credentialsPtr = Marshal.AllocHGlobal(credentialCount * credentialSize);
                        ptrList.Add(credentialsPtr);
                        
                        var pubKeyPtr = Marshal.StringToHGlobalUni(NativeWebAuthn.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY);
                        ptrList.Add(pubKeyPtr);
                        
                        for (var i = 0; i < credentials.Length; i++)
                        {
                            var credLength = credentials[i].Length;
                            var credPtr = Marshal.AllocHGlobal(credLength);
                            ptrList.Add(credPtr);
                            Marshal.Copy(credentials[i], 0, credPtr, credLength);
                            
                            var cred = new NativeWebAuthn.WEBAUTHN_CREDENTIAL
                            {
                                dwVersion = NativeWebAuthn.WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                                cbId = credLength,
                                pbId = credPtr,
                                pwszCredentialType = pubKeyPtr
                            };
                            Marshal.StructureToPtr(cred, credentialsPtr + (i * credentialSize), false);
                        }
                    }

                    var assertionOptions = new NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
                    {
                        dwVersion = 4,
                        dwTimeoutMilliseconds = (uint)options.TimeoutMs,
                        CredentialList = new NativeWebAuthn.WEBAUTHN_CREDENTIALS
                        {
                            cCredentials = credentialCount,
                            pCredentials = credentialsPtr
                        },
                        Extensions = new NativeWebAuthn.WEBAUTHN_EXTENSIONS
                        {
                            cExtensions = 0,
                            pExtensions = IntPtr.Zero
                        },
                        dwAuthenticatorAttachment = NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                        dwUserVerificationRequirement = options.UserVerification == "required" ? 1u : 0u,
                        dwFlags = 0,
                        pwszU2fAppId = IntPtr.Zero,
                        pbU2fAppId = IntPtr.Zero,
                        pCancellationId = IntPtr.Zero,
                        pAllowCredentialList = IntPtr.Zero,
                    };

                    // Ensure window is focused and visible before calling WebAuthn API
                    if (hWnd != IntPtr.Zero)
                    {
                        SetForegroundWindow(hWnd);
                        ShowWindow(hWnd, SW_SHOW);
                        // Small delay to ensure window is ready
                        System.Threading.Thread.Sleep(100);
                    }
                    
                    // Call WebAuthn API
                    var hr = NativeWebAuthn.WebAuthNAuthenticatorGetAssertion(
                        hWnd, 
                        options.RpId ?? "keepersecurity.com", 
                        ref data, 
                        ref assertionOptions, 
                        out var assertionPtr);

                    if (hr == NativeWebAuthn.HRESULT.S_OK)
                    {
                        var assertion = (NativeWebAuthn.WEBAUTHN_ASSERTION)Marshal.PtrToStructure(
                            assertionPtr, typeof(NativeWebAuthn.WEBAUTHN_ASSERTION));

                        byte[] credentialId = new byte[assertion.Credential.cbId];
                        if (assertion.Credential.pbId != IntPtr.Zero)
                        {
                            Marshal.Copy(assertion.Credential.pbId, credentialId, 0, assertion.Credential.cbId);
                        }

                        byte[] authenticatorData = new byte[assertion.cbAuthenticatorData];
                        if (assertion.pbAuthenticatorData != IntPtr.Zero)
                        {
                            Marshal.Copy(assertion.pbAuthenticatorData, authenticatorData, 0, assertion.cbAuthenticatorData);
                        }

                        byte[] signatureData = new byte[assertion.cbSignature];
                        if (assertion.pbSignature != IntPtr.Zero)
                        {
                            Marshal.Copy(assertion.pbSignature, signatureData, 0, assertion.cbSignature);
                        }

                        byte[] userId = null;
                        if (assertion.cbUserId > 0 && assertion.pbUserId != IntPtr.Zero)
                        {
                            userId = new byte[assertion.cbUserId];
                            Marshal.Copy(assertion.pbUserId, userId, 0, assertion.cbUserId);
                        }

                        NativeWebAuthn.WebAuthNFreeAssertion(assertionPtr);
                        
                        taskSource.TrySetResult(new InternalAuthenticationResult
                        {
                            CredentialId = credentialId,
                            AuthenticatorData = authenticatorData,
                            Signature = signatureData,
                            ClientDataJSON = clientDataBytes,
                            UserHandle = userId
                        });
                    }
                    else
                    {
                        var ptr = NativeWebAuthn.WebAuthNGetErrorName(hr);
                        var error = Marshal.PtrToStringUni(ptr);
                        taskSource.SetException(new Exception($"WebAuthn GetAssertion error: {error} (HRESULT: 0x{hr:X8})"));
                    }
                }
                catch (Exception ex)
                {
                    taskSource.SetException(ex);
                }
                finally
                {
                    foreach (var ptr in ptrList)
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                    ptrList.Clear();
                }
            });

            return await taskSource.Task;
        }

        private static Task<InternalCredentialCreationResult> MakeCredentialAsync(IntPtr hWnd, RegistrationOptions options, ExcludeCredential[] excludeCredentials = null)
        {
            var taskSource = new TaskCompletionSource<InternalCredentialCreationResult>();
            var ptrList = new List<IntPtr>();
            Task.Run(() =>
            {
                try
                {
                    var clientData = new SecurityKeyClientData
                    {
                        dataType = "webauthn.create",
                        challenge = ToBase64Url(options.Challenge),
                        origin = $"https://{options.RpId}"
                    };

                    var clientDataJson = SerializeClientData(clientData);
                    var clientDataBytes = Encoding.UTF8.GetBytes(clientDataJson);
                    var clientDataPtr = Marshal.AllocHGlobal(clientDataBytes.Length);
                    Marshal.Copy(clientDataBytes, 0, clientDataPtr, clientDataBytes.Length);
                    ptrList.Add(clientDataPtr);

                    var webAuthNClientData = new NativeWebAuthn.WEBAUTHN_CLIENT_DATA
                    {
                        dwVersion = NativeWebAuthn.WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                        cbClientDataJSON = clientDataBytes.Length,
                        pbClientDataJSON = clientDataPtr,
                        pwszHashAlgId = NativeWebAuthn.WEBAUTHN_HASH_ALGORITHM_SHA_256
                    };

                    var rpInfo = new NativeWebAuthn.WEBAUTHN_RP_ENTITY_INFORMATION
                    {
                        dwVersion = NativeWebAuthn.WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                        pwszId = options.RpId,
                        pwszName = options.RpName ?? options.RpId,
                        pwszIcon = null
                    };

=                    var userIdPtr = Marshal.AllocHGlobal(options.UserId.Length);
                    Marshal.Copy(options.UserId, 0, userIdPtr, options.UserId.Length);
                    ptrList.Add(userIdPtr);

                    var userInfo = new NativeWebAuthn.WEBAUTHN_USER_ENTITY_INFORMATION
                    {
                        dwVersion = NativeWebAuthn.WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                        cbId = options.UserId.Length,
                        pbId = userIdPtr,
                        pwszName = options.UserName,
                        pwszDisplayName = options.UserDisplayName ?? options.UserName,
                        pwszIcon = null
                    };

                    var credParam = new NativeWebAuthn.WEBAUTHN_COSE_CREDENTIAL_PARAMETER
                    {
                        dwVersion = NativeWebAuthn.WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                        pwszCredentialType = NativeWebAuthn.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                        lAlg = -7 // ES256
                    };

                    var credParamPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeWebAuthn.WEBAUTHN_COSE_CREDENTIAL_PARAMETER>());
                    Marshal.StructureToPtr(credParam, credParamPtr, false);
                    ptrList.Add(credParamPtr);

                    var credParams = new NativeWebAuthn.WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
                    {
                        cCredentialParameters = 1,
                        pCredentialParameters = credParamPtr
                    };

                    IntPtr excludeCredentialListPtr = IntPtr.Zero;
                    IntPtr pubKeyPtr = IntPtr.Zero; 
                    
                    if (excludeCredentials != null && excludeCredentials.Length > 0)
                    {   
                        try
                        {
                            var excludeCredentialsCbor = EncodeExcludeCredentialsAsCbor(excludeCredentials);
                            var excludeCborPtr = Marshal.AllocHGlobal(excludeCredentialsCbor.Length);
                            ptrList.Add(excludeCborPtr);
                            Marshal.Copy(excludeCredentialsCbor, 0, excludeCborPtr, excludeCredentialsCbor.Length);
                            
                            var excludeList = new NativeWebAuthn.WEBAUTHN_CREDENTIAL_LIST
                            {
                                cCredentials = excludeCredentials.Length,
                                ppCredentials = excludeCborPtr 
                            };

                            IntPtr excludeListPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeWebAuthn.WEBAUTHN_CREDENTIAL_LIST)));
                            ptrList.Add(excludeListPtr);
                            Marshal.StructureToPtr(excludeList, excludeListPtr, false);

                            excludeCredentialListPtr = excludeListPtr;
                            
                            var excludeListCheck = Marshal.PtrToStructure<NativeWebAuthn.WEBAUTHN_CREDENTIAL_LIST>(excludeListPtr);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error encoding exclude credentials as CBOR: {ex.Message}");
                            throw;
                        }
                        
                    }

                    // Create make credential options
                    var makeCredOptions = new NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
                    {
                        dwVersion = NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
                        dwTimeoutMilliseconds = (uint)options.TimeoutMs,
                        CredentialList = new NativeWebAuthn.WEBAUTHN_CREDENTIAL_LIST
                        {
                            cCredentials = 0,
                            ppCredentials = IntPtr.Zero
                        },
                        Extensions = new NativeWebAuthn.WEBAUTHN_EXTENSIONS
                        {
                            cExtensions = 0,
                            pExtensions = IntPtr.Zero
                        },
                        dwAuthenticatorAttachment = options.AuthenticatorAttachment == "platform" 
                            ? NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM 
                            : NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                        bRequireResidentKey = options.ResidentKeyRequirement == "required",
                        dwUserVerificationRequirement = options.UserVerification == "required" ? 1u : 0u,
                        dwAttestationConveyancePreference = options.AttestationConveyancePreference == "direct" ? 1u : 0u,
                        dwFlags = 0,
                        pwszCancellationId = null,
                        pExcludeCredentialList = excludeCredentialListPtr,
                        dwEnterpriseAttestation = 0,
                        bPreferResidentKey = false,
                        dwLargeBlobSupport = 0,
                        bPreferPlatformAttachment = false,
                        bBrowserInPrivateMode = false,
                        bEnablePrf = false,
                        pLinkedDevice = IntPtr.Zero,
                        cbJsonExt = 0,
                        pbJsonExt = IntPtr.Zero,
                        pPRFGlobalEval = IntPtr.Zero,
                        cCredentialHints = 0,
                        ppwszCredentialHints = IntPtr.Zero,
                        bThirdPartyPayment = false
                    };

                    // Call native WebAuthn MakeCredential API
                    var hr = NativeWebAuthn.WebAuthNAuthenticatorMakeCredential(
                        hWnd,
                        ref rpInfo,
                        ref userInfo,
                        ref credParams,
                        ref webAuthNClientData,
                        ref makeCredOptions,
                        out var credentialAttestationPtr);

                    if (hr == NativeWebAuthn.HRESULT.S_OK && credentialAttestationPtr != IntPtr.Zero)
                    {
                        var credentialAttestation = Marshal.PtrToStructure<NativeWebAuthn.WEBAUTHN_CREDENTIAL_ATTESTATION>(credentialAttestationPtr);

                        var credentialId = new byte[credentialAttestation.cbCredentialId];
                        Marshal.Copy(credentialAttestation.pbCredentialId, credentialId, 0, credentialAttestation.cbCredentialId);
                        
                        var createdCredIdBase64Url = ToBase64Url(credentialId);
                        var attestationObject = new byte[credentialAttestation.cbAttestationObject];
                        Marshal.Copy(credentialAttestation.pbAttestationObject, attestationObject, 0, credentialAttestation.cbAttestationObject);

                        var authenticatorData = new byte[credentialAttestation.cbAuthenticatorData];
                        Marshal.Copy(credentialAttestation.pbAuthenticatorData, authenticatorData, 0, credentialAttestation.cbAuthenticatorData);

                        NativeWebAuthn.WebAuthNFreeCredentialAttestation(credentialAttestationPtr);

                        taskSource.TrySetResult(new InternalCredentialCreationResult
                        {
                            CredentialId = credentialId,
                            AttestationObject = attestationObject,
                            ClientDataJSON = clientDataBytes,
                            PublicKey = authenticatorData,
                            SignatureCount = 0
                        });
                    }
                    else
                    {
                        var ptr = NativeWebAuthn.WebAuthNGetErrorName(hr);
                        var error = Marshal.PtrToStringUni(ptr);
                        taskSource.SetException(new Exception($"WebAuthn MakeCredential error: {error} (HRESULT: 0x{hr:X8})"));
                    }

                    if (pubKeyPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pubKeyPtr);
                    }
                }
                catch (Exception ex)
                {
                    taskSource.SetException(ex);
                }
                finally
                {
                    foreach (var ptr in ptrList)
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                    ptrList.Clear();
                }
            });

            return taskSource.Task;
        }

        private static string SerializeClientData(SecurityKeyClientData clientData)
        {
        return $"{{\"type\":\"{clientData.dataType}\",\"challenge\":\"{clientData.challenge}\",\"origin\":\"{clientData.origin}\",\"crossOrigin\":false}}";
        }

        /// <summary>
        /// Converts byte array to Base64Url string
        /// </summary>
        private static string ToBase64Url(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')          
                .Replace('+', '-')  
                .Replace('/', '_');     
        }

         /// <summary>
         /// Converts Base64Url string back to byte array
         /// </summary>
        private static byte[] FromBase64Url(string base64Url)
        {
            try
            {
                if (string.IsNullOrEmpty(base64Url))
                {
                    throw new ArgumentException("Base64Url string cannot be null or empty");
                }

                string base64 = base64Url.Replace('-', '+').Replace('_', '/');
                
                switch (base64.Length % 4)
                {
                    case 2: base64 += "=="; break;
                    case 3: base64 += "="; break;
                }
                
                return Convert.FromBase64String(base64);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decoding Base64Url: '{base64Url}' (Length: {base64Url?.Length ?? 0})");
                Console.WriteLine($"Exception: {ex.Message}");
                throw new ArgumentException($"Invalid Base64Url format: {ex.Message}", ex);
            }
         }

         /// <summary>
         /// Encodes exclude credentials as CBOR (matching Yubico python-fido2 approach)
         /// </summary>
         private static byte[] EncodeExcludeCredentialsAsCbor(ExcludeCredential[] excludeCredentials)
         {
             if (excludeCredentials == null || excludeCredentials.Length == 0)
                 return new byte[0];

             var cborArray = CBORObject.NewArray();
             
             foreach (var cred in excludeCredentials)
             {
                 var credObj = CBORObject.NewMap();
                 credObj["type"] = CBORObject.FromObject(cred.Type ?? "public-key");
                 credObj["id"] = CBORObject.FromObject(FromBase64Url(cred.Id));
                 
                 if (cred.Transports != null && cred.Transports.Length > 0)
                 {
                     var transportsArray = CBORObject.NewArray();
                     foreach (var transport in cred.Transports)
                     {
                         transportsArray.Add(CBORObject.FromObject(transport));
                     }
                     credObj["transports"] = transportsArray;
                 }
                 
                 cborArray.Add(credObj);
             }
             
             return cborArray.EncodeToBytes();
         }

         /// <summary>
         /// Helper method to read bytes from unmanaged memory
         /// </summary>
         private static byte[] ReadBytes(IntPtr ptr, int count)
         {
             var bytes = new byte[count];
             Marshal.Copy(ptr, bytes, 0, count);
             return bytes;
         }

         /// <summary>
         /// Helper to reverse bytes for big-endian conversion
         /// </summary>
         private static uint ReverseBytes(uint value)
         {
             return (value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |
                    (value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;
         }


         /// <summary>
         /// Extract public key coordinates from authenticator data
         /// </summary>
         private static (byte[] XCoord, byte[] YCoord) ExtractPublicKeyFromAuthenticatorData(byte[] authenticatorData)
         {
            try
            {
                
                if (authenticatorData.Length < 37)
                {
                    throw new Exception("Authenticator data too short");
                }

                
                var flags = authenticatorData[32];
                if ((flags & 0x40) == 0)
                {
                    throw new Exception("No attested credential data present");
                }

                var offset = 37;
                
                offset += 16;
                
                if (authenticatorData.Length < offset + 2)
                    throw new Exception("Invalid authenticator data structure");
                    
                var credIdLen = (authenticatorData[offset] << 8) | authenticatorData[offset + 1];
                offset += 2;
                
                offset += credIdLen;
                
                if (authenticatorData.Length <= offset)
                    throw new Exception("No COSE key data found");
                    
                var coseKeyBytes = new byte[authenticatorData.Length - offset];
                Array.Copy(authenticatorData, offset, coseKeyBytes, 0, coseKeyBytes.Length);
                
                var coseKey = CBORObject.DecodeFromBytes(coseKeyBytes);
                
                var xCoord = coseKey[-2].GetByteString(); // x coordinate
                var yCoord = coseKey[-3].GetByteString(); // y coordinate
                
                return (xCoord, yCoord);
            }
            catch
            {
            throw new Exception("Failed to extract public key from authenticator data");
            }
         }

        /// <summary>
        /// Discover existing Windows Hello credentials (lists all, optionally filtered by RP ID and username)
        /// This method uses the WebAuthn API to enumerate platform credentials directly
        /// </summary>
        public static CredentialDiscoveryResult DiscoverCredentials(string rpId = null, string username = null)
        {
            return DiscoverCredentials(rpId, username, null);
        }

        /// <summary>
        /// Discover existing Windows Hello credentials with specific credential IDs to check
        /// This method uses the WebAuthn API to check which of the provided credential IDs are valid
        /// </summary>
        public static CredentialDiscoveryResult DiscoverCredentials(string rpId = null, string username = null, string[] credentialIdsToCheck = null)
        {
            var result = new CredentialDiscoveryResult
            {
                Username = username,
                RpId = rpId,
                Method = credentialIdsToCheck != null && credentialIdsToCheck.Length > 0 ? 
                    "WebAuthn Platform Credential List + Specific ID Check" : 
                    "WebAuthn Platform Credential List",
                Timestamp = DateTime.UtcNow,
                DiscoveredCredentials = new List<DiscoveredCredential>()
            };

            IntPtr pList = IntPtr.Zero;
            try
            {
                IntPtr hWnd = GetBestWindowHandle();
                
                int hr = NativeWebAuthn.WebAuthNGetPlatformCredentialList(IntPtr.Zero, out pList);
                if (hr != 0 || pList == IntPtr.Zero)
                {
                    // 0x80090027 = NTE_NOT_FOUND - no credentials found, this is not an error
                    if (hr == unchecked((int)0x80090027))
                    {
                        result.Success = true;
                        result.ErrorMessage = "No Windows Hello credentials found matching the criteria";
                        result.ErrorType = null;
                        return result;
                    }
                    
                    result.Success = false;
                    result.ErrorMessage = $"WebAuthNGetPlatformCredentialList failed: 0x{hr:X8}";
                    result.ErrorType = "WebAuthnApiError";
                    return result;
                }

                var list = Marshal.PtrToStructure<NativeWebAuthn.WEBAUTHN_CREDENTIAL_DETAILS_LIST>(pList);
                IntPtr ppArray = list.ppCredentialDetails;
                int count = (int)list.cCredentialDetails;

                for (int i = 0; i < count; i++)
                {
                    try
                    {
                        IntPtr pDetailPtr = Marshal.ReadIntPtr(ppArray, i * IntPtr.Size);
                        if (pDetailPtr == IntPtr.Zero) continue;

                        var detail = Marshal.PtrToStructure<NativeWebAuthn.WEBAUTHN_CREDENTIAL_DETAILS>(pDetailPtr);

                        byte[] credentialIdBytes = Array.Empty<byte>();
                        int idLen = (int)detail.cbCredentialID;
                        if (idLen > 0 && detail.pbCredentialID != IntPtr.Zero)
                        {
                            credentialIdBytes = new byte[idLen];
                            Marshal.Copy(detail.pbCredentialID, credentialIdBytes, 0, idLen);
                        }

                        string credentialRpId = null;
                        if (detail.pRpInformation != IntPtr.Zero)
                        {
                            var rpInfo = Marshal.PtrToStructure<NativeWebAuthn.WEBAUTHN_RP_ENTITY_INFORMATION_READ>(detail.pRpInformation);
                            credentialRpId = rpInfo.pwszId != IntPtr.Zero ? Marshal.PtrToStringUni(rpInfo.pwszId) : null;
                        }

                        string credentialUserName = null;
                        string credentialUserDisplayName = null;
                        string credentialUserHandleBase64Url = null;
                        if (detail.pUserInformation != IntPtr.Zero)
                        {
                            var userInfo = Marshal.PtrToStructure<NativeWebAuthn.WEBAUTHN_USER_ENTITY_INFORMATION_READ>(detail.pUserInformation);
                            credentialUserName = userInfo.pwszName != IntPtr.Zero ? Marshal.PtrToStringUni(userInfo.pwszName) : null;
                            credentialUserDisplayName = userInfo.pwszDisplayName != IntPtr.Zero ? Marshal.PtrToStringUni(userInfo.pwszDisplayName) : null;

                            if (userInfo.cbId > 0 && userInfo.pbId != IntPtr.Zero)
                            {
                                var userIdBytes = new byte[userInfo.cbId];
                                Marshal.Copy(userInfo.pbId, userIdBytes, 0, (int)userInfo.cbId);
                                credentialUserHandleBase64Url = ToBase64Url(userIdBytes);
                            }
                        }

                        bool rpIdMatch = string.IsNullOrEmpty(rpId) ||
                                         string.Equals(credentialRpId, rpId, StringComparison.OrdinalIgnoreCase);
                        bool userMatch = string.IsNullOrEmpty(username) ||
                                         string.Equals(credentialUserName, username, StringComparison.OrdinalIgnoreCase) ||
                                         string.Equals(credentialUserDisplayName, username, StringComparison.OrdinalIgnoreCase);

                        if (rpIdMatch && userMatch)
                        {
                            result.DiscoveredCredentials.Add(new DiscoveredCredential
                            {
                                CredentialId = ToBase64Url(credentialIdBytes),
                                Source = "WebAuthn Platform Credential List",
                                IsAvailable = true,
                                UserHandle = credentialUserName ?? credentialUserDisplayName ?? credentialUserHandleBase64Url,
                                RpId = credentialRpId
                            });
                        }
                    }
                    catch (Exception exEntry)
                    {
                        Console.WriteLine($"Error processing credential {i}: {exEntry}");
                    }
                }

                if (credentialIdsToCheck != null && credentialIdsToCheck.Length > 0)
                {
                    var validCredentials = new List<DiscoveredCredential>();
                    var invalidCredentialIds = new List<string>();
                    
                    foreach (var credIdToCheck in credentialIdsToCheck)
                    {
                        var found = result.DiscoveredCredentials.FirstOrDefault(c => 
                            string.Equals(c.CredentialId, credIdToCheck, StringComparison.OrdinalIgnoreCase));
                        
                        if (found != null)
                        {
                            validCredentials.Add(found);
                        }
                        else
                        {
                            invalidCredentialIds.Add(credIdToCheck);
                        }
                    }
                    
                    result.DiscoveredCredentials = validCredentials;
                    result.HasCredentials = validCredentials.Count > 0;
                    result.StatusMessage = $"Found {validCredentials.Count} of {credentialIdsToCheck.Length} specified credentials";
                    
                    result.AllowCredentialsAnalysis = new
                    {
                        TotalAllowed = credentialIdsToCheck.Length,
                        Present = validCredentials.Count,
                        Missing = invalidCredentialIds.Count,
                        ValidCredentialIds = validCredentials.Select(c => c.CredentialId).ToArray(),
                        InvalidCredentialIds = invalidCredentialIds.ToArray()
                    };
                }
                else
                {
                    result.Success = true;
                    result.HasCredentials = result.DiscoveredCredentials.Count > 0;
                    result.StatusMessage = result.HasCredentials
                        ? $"Found {result.DiscoveredCredentials.Count} credential(s) for {username ?? "any user"}@{rpId ?? "any rp"}"
                        : $"No credentials found for {username ?? "any user"}@{rpId ?? "any rp"}";
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                result.ErrorType = ex.GetType().Name;
                return result;
            }
            finally
            {
                if (pList != IntPtr.Zero)
                {
                    NativeWebAuthn.WebAuthNFreePlatformCredentialList(pList);
                }
            }
        }
        #endregion
    }

    #region Data Classes

    /// <summary>
    /// Windows Hello capabilities information for PowerShell
    /// </summary>
    public class WindowsHelloCapabilities
    {
        public bool IsAvailable { get; set; }
        public int ApiVersion { get; set; }
        public string Platform { get; set; }
        public string[] SupportedMethods { get; set; }
        public bool CanCreateCredentials { get; set; }
        public bool CanPerformAuthentication { get; set; }
        public bool WebAuthnDllAvailable { get; set; }
        public string RecommendedIntegration { get; set; }
        public string ErrorMessage { get; set; }
        public DateTime LastChecked { get; set; }
    }

    /// <summary>
    /// PowerShell-friendly authentication options
    /// </summary>
    public class AuthenticationOptions
    {
        public string RpId { get; set; }
        public byte[] Challenge { get; set; }
        public string[] AllowedCredentialIds { get; set; }
        public int TimeoutMs { get; set; } = 60000; // 1 minute default
        public string UserVerification { get; set; } = "required";
    }

    /// <summary>
    /// PowerShell-friendly authentication result
    /// </summary>
    public class AuthenticationResult
    {
        public bool Success { get; set; }
        public string CredentialId { get; set; }
        public string Signature { get; set; }
        public string AuthenticatorData { get; set; }
        public string ClientDataJSON { get; set; }
        public string UserHandle { get; set; }
        public string Method { get; set; }
        public DateTime Timestamp { get; set; }
        public string ErrorMessage { get; set; }
        public string ErrorType { get; set; }
    }

    /// <summary>
    /// Internal authentication result (before base64 encoding)
    /// </summary>
    internal class InternalAuthenticationResult
    {
        public byte[] CredentialId { get; set; }
        public byte[] Signature { get; set; }
        public byte[] AuthenticatorData { get; set; }
        public byte[] ClientDataJSON { get; set; }
        public byte[] UserHandle { get; set; }
    }

    /// <summary>
    /// PowerShell-friendly registration options for credential creation
    /// </summary>
    public class RegistrationOptions
    {
        public string RpId { get; set; }
        public string RpName { get; set; }
        public byte[] Challenge { get; set; }
        public byte[] UserId { get; set; }
        public string UserName { get; set; }
        public string UserDisplayName { get; set; }
        public int TimeoutMs { get; set; } = 60000; // 1 minute default
        public string UserVerification { get; set; } = "required";
        public string AttestationConveyancePreference { get; set; } = "direct";
        public string ResidentKeyRequirement { get; set; } = "discouraged";
        public string AuthenticatorAttachment { get; set; } = "platform";
    }

    /// <summary>
    /// Exclude credential for WebAuthn registration
    /// </summary>
    public class ExcludeCredential
    {
        public string Type { get; set; } = "public-key";
        public string Id { get; set; }
        public string[] Transports { get; set; }
    }

    /// <summary>
    /// PowerShell-friendly credential creation result
    /// </summary>
    public class CredentialCreationResult
    {
        public bool Success { get; set; }
        public string CredentialId { get; set; }
        public string AttestationObject { get; set; }
        public string ClientDataJSON { get; set; }
        public string PublicKey { get; set; }
        public string Method { get; set; }
        public uint SignatureCount { get; set; }
        public DateTime Timestamp { get; set; }
        public string ErrorMessage { get; set; }
        public string ErrorType { get; set; }
    }

    /// <summary>
    /// Internal credential creation result (before base64 encoding)
    /// </summary>
    internal class InternalCredentialCreationResult
    {
        public byte[] CredentialId { get; set; }
        public byte[] AttestationObject { get; set; }
        public byte[] ClientDataJSON { get; set; }
        public byte[] PublicKey { get; set; }
        public uint SignatureCount { get; set; }
    }

    /// <summary>
    /// Result from credential discovery operations
    /// </summary>
    public class CredentialDiscoveryResult
    {
        public bool Success { get; set; }
        public string Username { get; set; }
        public string RpId { get; set; }
        public bool HasCredentials { get; set; }
        public List<DiscoveredCredential> DiscoveredCredentials { get; set; } = new List<DiscoveredCredential>();
        public string StatusMessage { get; set; }
        public string Method { get; set; }
        public DateTime Timestamp { get; set; }
        public string ErrorMessage { get; set; }
        public string ErrorType { get; set; }
        public object AllowCredentialsAnalysis { get; set; }
    }

    /// <summary>
    /// Information about a discovered credential
    /// </summary>
    public class DiscoveredCredential
    {
        public string CredentialId { get; set; }
        public string Source { get; set; } 
        public bool IsAvailable { get; set; }
        public string UserHandle { get; set; }
        public string RpId { get; set; }
    }

     /// <summary>
     /// Client data for WebAuthn operations
     /// </summary>
     internal class SecurityKeyClientData
     {
         public const string GET_ASSERTION = "webauthn.get";
         public const string CREATE_CREDENTIAL = "webauthn.create";
         
         public string dataType { get; set; }
         public string challenge { get; set; }
         public string origin { get; set; }
     }


    #endregion

    #region Native WebAuthn Interop

    internal static class NativeWebAuthn
    {
        internal const int WEBAUTHN_API_VERSION_1 = 1;
        internal const int WEBAUTHN_API_VERSION_2 = 2;
        internal const uint WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1;
        internal const string WEBAUTHN_HASH_ALGORITHM_SHA_256 = "SHA-256";
        internal const uint WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1;
        internal const uint WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION = 1;
        internal const string WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = "public-key";
        
        internal const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
        internal const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
        internal const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
        internal const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2 = 3;

        internal enum HRESULT : uint
        {
            S_FALSE = 0x0001,
            S_OK = 0x0000,
            E_INVALIDARG = 0x80070057,
            E_OUTOFMEMORY = 0x8007000E
        }

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetApiVersionNumber", CharSet = CharSet.Unicode)]
        internal static extern int WebAuthNGetApiVersionNumber();

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable", CharSet = CharSet.Unicode)]
        internal static extern HRESULT WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
            out bool pbIsUserVerifyingPlatformAuthenticatorAvailable);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
        internal static extern HRESULT WebAuthNAuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [MarshalAs(UnmanagedType.LPWStr)][In] string pwszRpId,
            [In] ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In] ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
            [Out] out IntPtr ppWebAuthNAssertion);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeAssertion", CharSet = CharSet.Unicode)]
        internal static extern void WebAuthNFreeAssertion([In] IntPtr pWebAuthNAssertion);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern int WebAuthNGetPlatformCredentialList(
            IntPtr pGetCredentialsOptions, 
            out IntPtr ppCredentialDetailsList);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern void WebAuthNFreePlatformCredentialList(
            IntPtr pCredentialDetailsList);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorMakeCredential", CharSet = CharSet.Unicode)]
        internal static extern HRESULT WebAuthNAuthenticatorMakeCredential(
            [In] IntPtr hWnd,
            [In] ref WEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
            [In] ref WEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
            [In] ref WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pPubKeyCredParams,
            [In] ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In] ref WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pWebAuthNMakeCredentialOptions,
            [Out] out IntPtr ppWebAuthNCredentialAttestation);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeCredentialAttestation", CharSet = CharSet.Unicode)]
        internal static extern void WebAuthNFreeCredentialAttestation([In] IntPtr pWebAuthNCredentialAttestation);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetErrorName", CharSet = CharSet.Unicode)]
        internal static extern IntPtr WebAuthNGetErrorName([In] HRESULT hr);

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CLIENT_DATA
        {
            public uint dwVersion;
            public int cbClientDataJSON;
            public IntPtr pbClientDataJSON;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszHashAlgId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL
        {
            public uint dwVersion;
            public int cbId;
            public IntPtr pbId;
            public IntPtr pwszCredentialType;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIALS
        {
            public int cCredentials;
            public IntPtr pCredentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_LIST
        {
            public int cCredentials;
            public IntPtr ppCredentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_EX
        {
            public uint dwVersion;
            public uint cbId;
            public IntPtr pbId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCredentialType;
            public uint dwTransports;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_EXTENSIONS
        {
            public uint cExtensions;
            public IntPtr pExtensions;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            public uint dwVersion;
            public uint dwTimeoutMilliseconds;
            public WEBAUTHN_CREDENTIALS CredentialList;
            public WEBAUTHN_EXTENSIONS Extensions;
            public uint dwAuthenticatorAttachment;
            public uint dwUserVerificationRequirement;
            public uint dwFlags;
            public IntPtr pwszU2fAppId;
            public IntPtr pbU2fAppId;
            public IntPtr pCancellationId;
            public IntPtr pAllowCredentialList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_ASSERTION
        {
            public uint dwVersion;
            public int cbAuthenticatorData;
            public IntPtr pbAuthenticatorData;
            public int cbSignature;
            public IntPtr pbSignature;
            public WEBAUTHN_CREDENTIAL Credential;
            public int cbUserId;
            public IntPtr pbUserId;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_RP_ENTITY_INFORMATION
        {
            public uint dwVersion;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszIcon;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_USER_ENTITY_INFORMATION
        {
            public uint dwVersion;
            public int cbId;
            public IntPtr pbId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszIcon;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszDisplayName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER
        {
            public uint dwVersion;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCredentialType;
            public int lAlg;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
        {
            public int cCredentialParameters;
            public IntPtr pCredentialParameters;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
        {
            public uint dwVersion;
            public uint dwTimeoutMilliseconds;
            public WEBAUTHN_CREDENTIAL_LIST CredentialList;
            public WEBAUTHN_EXTENSIONS Extensions;
            public uint dwAuthenticatorAttachment;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRequireResidentKey;
            public uint dwUserVerificationRequirement;
            public uint dwAttestationConveyancePreference;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCancellationId;
            public IntPtr pExcludeCredentialList;  
            public uint dwEnterpriseAttestation;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bPreferResidentKey;
            public uint dwLargeBlobSupport;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bPreferPlatformAttachment;
            public bool bBrowserInPrivateMode;
            public bool bEnablePrf;
            public IntPtr pLinkedDevice;  
            public uint cbJsonExt;
            public IntPtr pbJsonExt;  
            public IntPtr pPRFGlobalEval;  // PWEBAUTHN_HMAC_SECRET_SALT
            public uint cCredentialHints;
            public IntPtr ppwszCredentialHints;  
            public bool bThirdPartyPayment;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_ATTESTATION
        {
            public uint dwVersion;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszFormatType;
            public int cbAuthenticatorData;
            public IntPtr pbAuthenticatorData;
            public int cbAttestation;
            public IntPtr pbAttestation;
            public uint dwAttestationDecodeType;
            public IntPtr pvAttestationDecode;
            public int cbAttestationObject;
            public IntPtr pbAttestationObject;
            public int cbCredentialId;
            public IntPtr pbCredentialId;
            public IntPtr Extensions;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIALS_LIST
        {
            public int cCredentials;
            public IntPtr ppCredentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_DETAILS
        {
            public uint dwVersion;
            public uint cbCredentialID;                
            public IntPtr pbCredentialID;              
            public IntPtr pRpInformation;              
            public IntPtr pUserInformation;            
            public IntPtr pCredBlob;                   
            public uint cbCredBlob;                   
            public IntPtr pHmacSecretSalt;            
            public uint dwCredProtect;          
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRemovable;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bBackedUp;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bHasLargeBlob;                 
            [MarshalAs(UnmanagedType.Bool)]
            public bool bHasCredBlob;                  
            [MarshalAs(UnmanagedType.Bool)]
            public bool bHasHmacSecret;                
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_DETAILS_LIST
        {
            public uint cCredentialDetails;            
            public IntPtr ppCredentialDetails;         
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WEBAUTHN_RP_ENTITY_INFORMATION_READ
        {
            public uint dwVersion;
            public IntPtr pwszId;      
            public IntPtr pwszName;
            public IntPtr pwszIcon;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WEBAUTHN_USER_ENTITY_INFORMATION_READ
        {
            public uint dwVersion;
            public uint cbId;          
            public IntPtr pbId;        
            public IntPtr pwszName;    
            public IntPtr pwszIcon;
            public IntPtr pwszDisplayName;
        }

    }

    #endregion
}
#endif
