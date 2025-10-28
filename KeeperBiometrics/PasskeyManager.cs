#if NET472_OR_GREATER || NET8_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Newtonsoft.Json;
using KeeperSecurity.Vault;

namespace KeeperBiometric
{
    /// <summary>
    /// High-level manager for Windows Hello passkey operations with Keeper
    /// Provides complete registration, authentication, and management workflows
    /// </summary>
    public static class PasskeyManager
    {
        private const string DefaultRpId = "keepersecurity.com";
        
        /// <summary>
        /// Checks if Windows Hello is available on this system
        /// </summary>
        public static bool IsAvailable()
        {
            return WindowsHelloApi.IsAvailable();
        }
        
        /// <summary>
        /// Gets detailed Windows Hello capabilities
        /// </summary>
        public static WindowsHelloCapabilities GetCapabilities()
        {
            return WindowsHelloApi.GetCapabilities();
        }
        
        /// <summary>
        /// Registers a new Windows Hello passkey credential for Keeper
        /// </summary>
        /// <param name="auth">Authentication object (IAuthentication)</param>
        /// <param name="friendlyName">Optional friendly name for the credential</param>
        /// <param name="force">Force creation even if credential exists</param>
        /// <returns>Registration result</returns>
        public static async Task<PasskeyRegistrationResult> RegisterPasskeyAsync(IAuthentication auth, string friendlyName = null, bool force = false)
        {
            try
            {
                if (!IsAvailable())
                {
                    return new PasskeyRegistrationResult
                    {
                        Success = false,
                        ErrorMessage = "Windows Hello is not available on this system"
                    };
                }
                
                var request = new PasskeyRegistrationRequest
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.Platform
                };
                
                var response = await auth.ExecuteAuthRest<PasskeyRegistrationRequest, PasskeyRegistrationResponse>(
                    "authentication/passkey/generate_registration", 
                    request);
                
                if (response == null)
                {
                    return new PasskeyRegistrationResult
                    {
                        Success = false,
                        ErrorMessage = "Failed to get registration options from Keeper"
                    };
                }
                
                var creationOptions = JsonConvert.DeserializeObject<PublicKeyCredentialCreationOptions>(
                    response.PkCreationOptions);
                
                if (creationOptions == null)
                {
                    return new PasskeyRegistrationResult
                    {
                        Success = false,
                        ErrorMessage = "Failed to parse registration options"
                    };
                }
                
                var username = creationOptions.user.name;
                
                if (!force && CredentialStorage.HasCredential(username))
                {
                    var existingCredId = CredentialStorage.GetCredentialId(username);
                    
                    if (creationOptions.excludeCredentials != null)
                    {
                        foreach (var excluded in creationOptions.excludeCredentials)
                        {
                            if (excluded.id == existingCredId)
                            {
                                return new PasskeyRegistrationResult
                                {
                                    Success = false,
                                    ErrorMessage = "Credential already registered for this user. Use -Force to override.",
                                    CredentialId = existingCredId
                                };
                            }
                        }
                    }
                }
                
                var excludeCredentials = ConvertExcludeCredentials(creationOptions.excludeCredentials);
                
                var regOptions = new RegistrationOptions
                {
                    Challenge = FromBase64Url(creationOptions.challenge),
                    RpId = creationOptions.rp.id,
                    RpName = creationOptions.rp.name,
                    UserId = FromBase64Url(creationOptions.user.id),
                    UserName = username,
                    UserDisplayName = friendlyName ?? creationOptions.user.displayName ?? username
                };
                
                var credResult = await WindowsHelloApi.CreateCredentialAsync(regOptions, excludeCredentials);
                
                if (!credResult.Success)
                {
                    return new PasskeyRegistrationResult
                    {
                        Success = false,
                        ErrorMessage = $"Windows Hello credential creation failed: {credResult.ErrorMessage}"
                    };
                }
                
                var finalizationRequest = new PasskeyRegistrationFinalization
                {
                    ChallengeToken = response.ChallengeToken,
                    AuthenticatorResponse = CreateAuthenticatorResponse(
                        credResult.CredentialId,
                        credResult.AttestationObject,
                        credResult.ClientDataJSON
                    )
                };
                
                if (!string.IsNullOrEmpty(friendlyName))
                {
                    finalizationRequest.FriendlyName = friendlyName;
                }
                
                await auth.ExecuteAuthRest("authentication/passkey/verify_registration", finalizationRequest);
                
                CredentialStorage.SetCredentialId(username, credResult.CredentialId);
                
                return new PasskeyRegistrationResult
                {
                    Success = true,
                    CredentialId = credResult.CredentialId,
                    Username = username,
                    AAGUID = credResult.AAGUID,
                    Provider = credResult.Provider,
                    Message = "Windows Hello credential registered successfully"
                };
            }
            catch (Exception ex)
            {
                return new PasskeyRegistrationResult
                {
                    Success = false,
                    ErrorMessage = $"Registration failed: {ex.Message}"
                };
            }
        }
        
        /// <summary>
        /// Authenticates using Windows Hello passkey
        /// </summary>
        /// <param name="auth">Authentication object (IAuth or IAuthentication)</param>
        /// <param name="username">Username to authenticate</param>
        /// <param name="purpose">Purpose: 'login' or 'vault'</param>
        /// <returns>Authentication result</returns>
        public static async Task<PasskeyAuthenticationResult> AuthenticatePasskeyAsync(
            IAuthEndpoint auth, 
            string username, 
            string purpose = "login")
        {
            try
            {
                if (!IsAvailable())
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Windows Hello is not available"
                    };
                }
                
                var storedCredId = CredentialStorage.GetCredentialId(username);
                if (string.IsNullOrEmpty(storedCredId))
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "No Windows Hello credential found for this user"
                    };
                }
                
                var request = new PasskeyAuthenticationRequest
                {
                    AuthenticatorAttachment = AuthenticatorAttachment.Platform,
                    ClientVersion = auth.Endpoint.ClientVersion,
                    Username = username,
                    PasskeyPurpose = purpose == "vault" ? PasskeyPurpose.PkReauth : PasskeyPurpose.PkLogin
                };
                
                if (auth.DeviceToken != null)
                {
                    request.EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken);
                }
                
                PasskeyAuthenticationResponse response;
                var authenticatedAuth = auth as IAuthentication;
                bool isAuthenticated = authenticatedAuth?.AuthContext?.SessionToken != null;
                
                if (isAuthenticated)
                {
                    response = await authenticatedAuth.ExecuteAuthRest<PasskeyAuthenticationRequest, PasskeyAuthenticationResponse>(
                        "authentication/passkey/generate_authentication",
                        request);
                }
                else
                {
                    var requestBytes = request.ToByteArray();
                    var apiRequest = new ApiRequestPayload
                    {
                        Payload = ByteString.CopyFrom(requestBytes)
                    };
                    var responseBytes = await auth.Endpoint.ExecuteRest("authentication/passkey/generate_authentication", apiRequest);
                    response = PasskeyAuthenticationResponse.Parser.ParseFrom(responseBytes);
                }
                
                if (response == null)
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Failed to get authentication options from Keeper"
                    };
                }
                
                var authOptionsResponse = JsonConvert.DeserializeObject<AuthenticationOptionsResponse>(
                    response.PkRequestOptions);
                
                if (authOptionsResponse?.publicKeyCredentialRequestOptions == null)
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Failed to parse authentication options"
                    };
                }
                
                var requestOptions = authOptionsResponse.publicKeyCredentialRequestOptions;
                
                if (string.IsNullOrEmpty(requestOptions.challenge))
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Authentication options missing challenge"
                    };
                }
                
                if (string.IsNullOrEmpty(requestOptions.rpId))
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Authentication options missing RP ID"
                    };
                }
                
                var authOptions = new AuthenticationOptions
                {
                    Challenge = FromBase64Url(requestOptions.challenge),
                    RpId = requestOptions.rpId,
                    AllowedCredentialIds = requestOptions.allowCredentials?
                        .Where(c => !string.IsNullOrEmpty(c.id))
                        .Select(c => c.id)
                        .ToArray(),
                    UserVerification = requestOptions.userVerification ?? "required"
                };
                
                var assertion = await WindowsHelloApi.AuthenticateAsync(authOptions);
                
                if (!assertion.Success)
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = $"Windows Hello authentication failed: {assertion.ErrorMessage}"
                    };
                }
                
                var validationRequest = new PasskeyValidationRequest
                {
                    ChallengeToken = response.ChallengeToken,
                    PasskeyPurpose = request.PasskeyPurpose,
                    AssertionResponse = ByteString.CopyFrom(
                        Encoding.UTF8.GetBytes(CreateAssertionResponse(assertion))
                    )
                };
                
                if (response.EncryptedLoginToken != null && response.EncryptedLoginToken.Length > 0)
                {
                    validationRequest.EncryptedLoginToken = response.EncryptedLoginToken;
                }
                
                PasskeyValidationResponse validationResponse;
                if (isAuthenticated)
                {
                    validationResponse = await authenticatedAuth.ExecuteAuthRest<PasskeyValidationRequest, PasskeyValidationResponse>(
                        "authentication/passkey/verify_authentication",
                        validationRequest);
                }
                else
                {
                    var validationBytes = validationRequest.ToByteArray();
                    var apiRequest = new ApiRequestPayload
                    {
                        Payload = ByteString.CopyFrom(validationBytes)
                    };
                    var responseBytes = await auth.Endpoint.ExecuteRest("authentication/passkey/verify_authentication", apiRequest);
                    validationResponse = PasskeyValidationResponse.Parser.ParseFrom(responseBytes);
                }
                
                if (validationResponse == null)
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Keeper validation failed: No response from server"
                    };
                }
                
                if (!validationResponse.IsValid)
                {
                    return new PasskeyAuthenticationResult
                    {
                        Success = false,
                        ErrorMessage = "Keeper validation failed: Authentication was not accepted by the server"
                    };
                }
                
                return new PasskeyAuthenticationResult
                {
                    Success = true,
                    IsValid = validationResponse.IsValid,
                    EncryptedLoginToken = validationResponse.EncryptedLoginToken?.ToByteArray(),
                    Username = username,
                    Message = "Authentication successful"
                };
            }
            catch (Exception ex)
            {
                return new PasskeyAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = $"Authentication failed: {ex.Message}"
                };
            }
        }
        
        /// <summary>
        /// Lists available passkey credentials from Keeper
        /// </summary>
        /// <param name="auth">Authentication object (IAuth)</param>
        /// <param name="includeDisabled">Include disabled credentials</param>
        /// <returns>List of passkey info</returns>
        public static async Task<List<PasskeyInfo>> ListPasskeysAsync(IAuthentication auth, bool includeDisabled = false)
        {
            try
            {
                var request = new PasskeyListRequest
                {
                    IncludeDisabled = includeDisabled
                };
                
                var response = await auth.ExecuteAuthRest<PasskeyListRequest, PasskeyListResponse>(
                    "authentication/passkey/get_available_keys",
                    request);
                
                if (response == null)
                {
                    return new List<PasskeyInfo>();
                }
                
                return response.PasskeyInfo.Select(pk =>
                {
                    var aaguid = pk.AAGUID;
                    var provider = WindowsHelloApi.GetProviderNameFromAaguid(aaguid);
                    
                    return new PasskeyInfo
                    {
                        UserId = pk.UserId,
                        FriendlyName = string.IsNullOrEmpty(pk.FriendlyName) ? "Windows Hello" : pk.FriendlyName,
                        CredentialId = ToBase64Url(pk.CredentialId.ToByteArray()),
                        AAGUID = aaguid,
                        Provider = provider,
                        CreatedAt = pk.CreatedAtMillis > 0 
                            ? DateTimeOffset.FromUnixTimeMilliseconds(pk.CreatedAtMillis).DateTime 
                            : DateTime.MinValue,
                        LastUsed = pk.LastUsedMillis > 0
                            ? DateTimeOffset.FromUnixTimeMilliseconds(pk.LastUsedMillis).DateTime
                            : DateTime.MinValue,
                        IsDisabled = pk.DisabledAtMillis > 0
                    };
                }).ToList();
            }
            catch (Exception)
            {
                return new List<PasskeyInfo>();
            }
        }
        
        /// <summary>
        /// Removes a passkey from both Keeper and local storage
        /// </summary>
        /// <param name="auth">Authentication object (IAuth)</param>
        /// <param name="username">Username to remove credential for</param>
        /// <returns>True if successful</returns>
        public static async Task<bool> RemovePasskeyAsync(IAuthentication auth, string username)
        {
            try
            {
                var credentialId = CredentialStorage.GetCredentialId(username);
                if (string.IsNullOrEmpty(credentialId))
                {
                    return false;
                }
                
                var credentials = await ListPasskeysAsync(auth);
                var matchingCred = credentials.FirstOrDefault(c => c.CredentialId == credentialId);
                
                if (matchingCred != null)
                {
                    var request = new UpdatePasskeyRequest
                    {
                        UserId = matchingCred.UserId,
                        CredentialId = ByteString.CopyFrom(FromBase64Url(matchingCred.CredentialId))
                    };
                    
                    await auth.ExecuteAuthRest("authentication/passkey/disable", request);
                }
                
                CredentialStorage.SetCredentialId(username, null);
                
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
        
        
        #region Helper Methods
        
        private static byte[] FromBase64Url(string base64Url)
        {
            if (string.IsNullOrEmpty(base64Url))
            {
                return Array.Empty<byte>();
            }
            
            var base64 = base64Url.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            
            return Convert.FromBase64String(base64);
        }
        
        private static string ToBase64Url(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return string.Empty;
            }
            
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
        
        private static ExcludeCredential[] ConvertExcludeCredentials(List<PublicKeyCredentialDescriptor> excludeList)
        {
            if (excludeList == null || excludeList.Count == 0)
            {
                return Array.Empty<ExcludeCredential>();
            }
            
            return excludeList.Select(ec => new ExcludeCredential
            {
                Type = ec.type,
                Id = ec.id,
                Transports = ec.transports?.ToArray()
            }).ToArray();
        }
        
        private static string CreateAuthenticatorResponse(string credentialId, string attestationObject, string clientDataJSON)
        {
            var response = new
            {
                id = credentialId,
                rawId = credentialId,
                response = new
                {
                    attestationObject = attestationObject,
                    clientDataJSON = clientDataJSON
                },
                type = "public-key",
                clientExtensionResults = new { }
            };
            
            return JsonConvert.SerializeObject(response);
        }
        
        private static string CreateAssertionResponse(AuthenticationResult assertion)
        {
            var response = new
            {
                id = assertion.CredentialId,
                rawId = assertion.CredentialId,
                response = new
                {
                    authenticatorData = assertion.AuthenticatorData,
                    clientDataJSON = assertion.ClientDataJSON,
                    signature = assertion.Signature,
                    userHandle = assertion.UserHandle
                },
                type = "public-key",
                clientExtensionResults = new { }
            };
            
            return JsonConvert.SerializeObject(response);
        }
        
        #endregion
    }
    
    #region Result Classes
    
    /// <summary>
    /// Result of passkey registration
    /// </summary>
    public class PasskeyRegistrationResult
    {
        public bool Success { get; set; }
        public string CredentialId { get; set; }
        public string Username { get; set; }
        public string AAGUID { get; set; }
        public string Provider { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    /// <summary>
    /// Result of passkey authentication
    /// </summary>
    public class PasskeyAuthenticationResult
    {
        public bool Success { get; set; }
        public bool IsValid { get; set; }
        public byte[] EncryptedLoginToken { get; set; }
        public string Username { get; set; }
        public string Message { get; set; }
        public string ErrorMessage { get; set; }
    }
    
    /// <summary>
    /// Information about a passkey
    /// </summary>
    public class PasskeyInfo
    {
        public int UserId { get; set; }
        public string FriendlyName { get; set; }
        public string CredentialId { get; set; }
        public string AAGUID { get; set; }
        public string Provider { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastUsed { get; set; }
        public bool IsDisabled { get; set; }
    }
    
    /// <summary>
    /// WebAuthn credential creation options
    /// </summary>
    internal class PublicKeyCredentialCreationOptions
    {
        public string challenge { get; set; }
        public RelyingParty rp { get; set; }
        public User user { get; set; }
        public List<PublicKeyCredentialDescriptor> excludeCredentials { get; set; }
    }
    
    /// <summary>
    /// WebAuthn authentication options response
    /// </summary>
    internal class AuthenticationOptionsResponse
    {
        public PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions { get; set; }
        public string username { get; set; }
    }
    
    /// <summary>
    /// WebAuthn credential request options
    /// </summary>
    internal class PublicKeyCredentialRequestOptions
    {
        public string challenge { get; set; }
        public string rpId { get; set; }
        public List<PublicKeyCredentialDescriptor> allowCredentials { get; set; }
        public string userVerification { get; set; }
        public int timeout { get; set; }
    }
    
    internal class RelyingParty
    {
        public string id { get; set; }
        public string name { get; set; }
    }
    
    internal class User
    {
        public string id { get; set; }
        public string name { get; set; }
        public string displayName { get; set; }
    }
    
    internal class PublicKeyCredentialDescriptor
    {
        public string type { get; set; }
        public string id { get; set; }
        public List<string> transports { get; set; }
    }
    
    #endregion
}
#endif

