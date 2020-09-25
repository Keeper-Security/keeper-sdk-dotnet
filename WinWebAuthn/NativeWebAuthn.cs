using System;
using System.Runtime.InteropServices;

namespace WinWebAuthn
{
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
