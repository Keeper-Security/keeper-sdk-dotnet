#if NET472_OR_GREATER
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace WinWebAuthn
{
    public static class Authenticate
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();

        [StructLayout(LayoutKind.Sequential)]
        public class GuidClass
        {
            public Guid TheGuid;
        }

        /// <summary>
        /// Check if Windows Hello (platform authenticator) is available
        /// </summary>
        public static bool IsWindowsHelloAvailable()
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

        public static Task<WebAuthnSignature> GetAssertion(IntPtr hWnd, PublicKeyCredentialRequestOptions options)
        {
            return GetAssertion(hWnd, options, CancellationToken.None);
        }

        public static Task<WebAuthnSignature> GetAssertion(IntPtr hWnd, PublicKeyCredentialRequestOptions options, CancellationToken token)
        {
            var taskSource = new TaskCompletionSource<WebAuthnSignature>();
            Task.Run(() =>
               {
                   var ptrList = new List<IntPtr>();
                   try
                   {
                       var clientData = new SecurityKeyClientData
                       {
                           dataType = SecurityKeyClientData.GET_ASSERTION,
                           challenge = options.challenge,
                           origin = options.extensions.appid,
                       };
                       var clientDataBytes = JsonUtils.DumpJson(clientData, false);
                       var clientDataPtr = Marshal.AllocHGlobal(clientDataBytes.Length);
                       ptrList.Add(clientDataPtr);
                       Marshal.Copy(clientDataBytes, 0, clientDataPtr, clientDataBytes.Length);

                       var data = new NativeWebAuthn.WEBAUTHN_CLIENT_DATA
                       {
                           dwVersion = NativeWebAuthn.WEBAUTHN_API_VERSION_2,
                           cbClientDataJSON = clientDataBytes.Length,
                           pbClientDataJSON = clientDataPtr,
                           pwszHashAlgId = NativeWebAuthn.WEBAUTHN_HASH_ALGORITHM_SHA_256,
                       };

                       var credentials = options.allowCredentials
                       .Where(x => x.type == NativeWebAuthn.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY)
                       .Select(x => x.id.Base64UrlDecode())
                       .ToArray();
                       var credentialSize = Marshal.SizeOf(typeof(NativeWebAuthn.WEBAUTHN_CREDENTIAL));
                       var credentialsPtr = Marshal.AllocHGlobal(options.allowCredentials.Length * credentialSize);
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

                       var opts = new NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
                       {
                           dwVersion = 4,
                           dwTimeoutMilliseconds = (uint) TimeSpan.FromMinutes(2).TotalMilliseconds,
                           CredentialList = new NativeWebAuthn.WEBAUTHN_CREDENTIALS
                           {
                               cCredentials = credentials.Length,
                               pCredentials = credentialsPtr
                           },
                           Extensions = new NativeWebAuthn.WEBAUTHN_EXTENSIONS
                           {
                               cExtensions = 0,
                               pExtensions = IntPtr.Zero
                           },
                           dwAuthenticatorAttachment = NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2,
                           dwUserVerificationRequirement = 0,
                           dwFlags = 0,
                           pwszU2fAppId = IntPtr.Zero,
                           pbU2fAppId = IntPtr.Zero,
                           pCancellationId = IntPtr.Zero,
                           pAllowCredentialList = IntPtr.Zero,
                       };

                       IDisposable cancelToken = null;
                       if (token != CancellationToken.None)
                       {
                           var guidPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(GuidClass)));
                           ptrList.Add(guidPtr);
                           if (NativeWebAuthn.WebAuthNGetCancellationId(guidPtr) == NativeWebAuthn.HRESULT.S_OK)
                           {
                               opts.pCancellationId = guidPtr;
                               cancelToken = token.Register(() => { NativeWebAuthn.WebAuthNCancelCurrentOperation(guidPtr); });
                           }
                       }

                       var hr = NativeWebAuthn.WebAuthNAuthenticatorGetAssertion(hWnd, options.rpId, ref data, ref opts, out var assertionPtr);
                       cancelToken?.Dispose();

                       if (hr == NativeWebAuthn.HRESULT.S_OK)
                       {
                           var assertion = (NativeWebAuthn.WEBAUTHN_ASSERTION) Marshal.PtrToStructure(assertionPtr, typeof(NativeWebAuthn.WEBAUTHN_ASSERTION));

                           byte[] credentialId;
                           if (assertion.Credential.cbId > 0)
                           {
                               credentialId = new byte[assertion.Credential.cbId];
                               if (assertion.Credential.pbId != IntPtr.Zero)
                               {
                                   Marshal.Copy(assertion.Credential.pbId, credentialId, 0, assertion.Credential.cbId);
                               }
                           }
                           else
                           {
                               credentialId = Array.Empty<byte>();
                           }

                           byte[] authenticatorData;
                           if (assertion.cbAuthenticatorData > 0)
                           {
                               authenticatorData = new byte[assertion.cbAuthenticatorData];
                               if (assertion.pbAuthenticatorData != IntPtr.Zero)
                               {
                                   Marshal.Copy(assertion.pbAuthenticatorData, authenticatorData, 0, assertion.cbAuthenticatorData);
                               }
                           }
                           else
                           {
                               authenticatorData = Array.Empty<byte>();
                           }

                           byte[] signatureData;
                           if (assertion.cbSignature > 0)
                           {
                               signatureData = new byte[assertion.cbSignature];
                               if (assertion.pbSignature != IntPtr.Zero)
                               {
                                   Marshal.Copy(assertion.pbSignature, signatureData, 0, assertion.cbSignature);
                               }
                           }
                           else
                           {
                               signatureData = Array.Empty<byte>();
                           }

                           NativeWebAuthn.WebAuthNFreeAssertion(assertionPtr);
                           taskSource.TrySetResult(new WebAuthnSignature
                           {
                               clientData = clientDataBytes,
                               authenticatorData = authenticatorData,
                               credentialId = credentialId,
                               signatureData = signatureData,
                           });
                       }
                       else
                       {
                           var ptr = NativeWebAuthn.WebAuthNGetErrorName(hr);
                           var error = Marshal.PtrToStringUni(ptr);
                           taskSource.SetException(new Exception($"WebauthN GetAssertion error: {error}"));
                       }
                   }
                   finally
                   {
                       foreach (var ptr in ptrList)
                       {
                           Marshal.FreeHGlobal(ptr);
                       }

                       ptrList.Clear();

                   }
               },
                token);

            return taskSource.Task;
        }
    }

    internal static class NativeWebAuthn
    {
        internal const int WEBAUTHN_API_VERSION_1 = 1;
        internal const int WEBAUTHN_API_VERSION_2 = 2;
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
        internal static extern HRESULT WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool pbIsUserVerifyingPlatformAuthenticatorAvailable);

        internal const uint WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1;
        internal const string WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = "public-key";
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL
        {
            // Version of this structure, to allow for modifications in the future.
            public uint dwVersion;

            // Size of pbID.
            public int cbId;
            // Unique ID for this particular credential.
            public IntPtr pbId;

            // Well-known credential type specifying what this particular credential is.
            public IntPtr pwszCredentialType;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIALS
        {
            public int cCredentials;
            public IntPtr pCredentials;  // PWEBAUTHN_CREDENTIALS
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _WEBAUTHN_EXTENSION
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszExtensionIdentifier;
            public uint cbExtension;
            public IntPtr pvExtension;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_EXTENSIONS
        {
            public uint cExtensions;
            public IntPtr pExtensions;  // PWEBAUTHN_EXTENSION
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_EX
        {
            // Version of this structure, to allow for modifications in the future.
            public uint dwVersion;

            // Size of pbID.
            public uint cbId;
            // Unique ID for this particular credential.
            public byte[] pbId;

            // Well-known credential type specifying what this particular credential is.
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCredentialType;

            // Transports. 0 implies no transport restrictions.
            public uint dwTransports;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_LIST
        {
            public uint cCredentials;
            public IntPtr ppCredentials;  //PWEBAUTHN_CREDENTIAL_EX*
        }

        public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
        public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
        public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
        public const uint WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2 = 3;


        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            // Version of this structure, to allow for modifications in the future.
            public uint dwVersion;

            // Time that the operation is expected to complete within.
            // This is used as guidance, and can be overridden by the platform.
            public uint dwTimeoutMilliseconds;

            // Allowed Credentials List.
            public WEBAUTHN_CREDENTIALS CredentialList;

            // Optional extensions to parse when performing the operation.
            public WEBAUTHN_EXTENSIONS Extensions;

            // Optional. Platform vs Cross-Platform Authenticators.
            public uint dwAuthenticatorAttachment;

            // User Verification Requirement.
            public uint dwUserVerificationRequirement;

            // Reserved for future Use
            public uint dwFlags;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2
            //

            // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
            public IntPtr pwszU2fAppId;

            // If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
            // PCWSTR pwszRpId;
            public IntPtr pbU2fAppId;    // BOOL* pbU2fAppId;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3
            //

            // Cancellation Id - Optional - See WebAuthNGetCancellationId
            public IntPtr pCancellationId;   //GUID *pCancellationId;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4
            //

            // Allow Credential List. If present, "CredentialList" will be ignored.
            public IntPtr pAllowCredentialList;  // PWEBAUTHN_CREDENTIAL_LIST

        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CLIENT_DATA
        {
            // Version of this structure, to allow for modifications in the future.
            // This field is required and should be set to CURRENT_VERSION above.
            public uint dwVersion;

            // Size of the pbClientDataJSON field.
            public int cbClientDataJSON;

            // UTF-8 encoded JSON serialization of the client data.
            public IntPtr pbClientDataJSON;

            // Hash algorithm ID used to hash the pbClientDataJSON field.
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszHashAlgId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_ASSERTION
        {
            // Version of this structure, to allow for modifications in the future.
            public uint dwVersion;

            // Size of cbAuthenticatorData.
            public int cbAuthenticatorData;
            // Authenticator data that was created for this assertion.
            public IntPtr pbAuthenticatorData;

            // Size of pbSignature.
            public int cbSignature;
            // Signature that was generated for this assertion.
            public IntPtr pbSignature;

            // Credential that was used for this assertion.
            public WEBAUTHN_CREDENTIAL Credential;

            // Size of User Id
            public int cbUserId;
            // UserId
            public IntPtr pbUserId;
        }
        internal const string WEBAUTHN_HASH_ALGORITHM_SHA_256 = "SHA-256";
        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
        internal static extern HRESULT WebAuthNAuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [MarshalAs(UnmanagedType.LPWStr)]
            [In] string pwszRpId,
            [In] ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In] ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
            [Out] out IntPtr ppWebAuthNAssertion);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeAssertion", CharSet = CharSet.Unicode)]
        internal static extern void WebAuthNFreeAssertion([In] IntPtr pWebAuthNAssertion);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetCancellationId", CharSet = CharSet.Unicode)]
        internal static extern HRESULT WebAuthNGetCancellationId([Out] IntPtr pCancellationId);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNCancelCurrentOperation", CharSet = CharSet.Unicode)]
        internal static extern HRESULT WebAuthNCancelCurrentOperation([In] IntPtr pCancellationId);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetErrorName", CharSet = CharSet.Unicode)]
        internal static extern IntPtr WebAuthNGetErrorName([In] HRESULT hr);
    }
}
#endif