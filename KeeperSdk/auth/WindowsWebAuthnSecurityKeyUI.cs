using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Authenticates WebAuthn security keys using the native Windows WebAuthn dialog.
    /// Windows owns PIN prompting, PIN validation, and touch prompts.
    /// </summary>
    public static class WindowsWebAuthnSecurityKeyUI
    {
        // Version of WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS used by this code (the pAllowCredentialList layout).
        private const uint GetAssertionOptionsVersion = 4;
        // WEBAUTHN_API_VERSION_1 is the baseline API and already includes GET_ASSERTION_OPTIONS version 4
        // (webauthn.h). This is an API version, not a structure version, so do not compare it with the constant above.
        private const uint MinimumWebAuthnApiVersion = 1;
        private const uint CredentialVersion = 1;
        private const uint ClientDataVersion = 1;
        private const uint UserVerificationRequired = 1;
        private const uint UserVerificationPreferred = 2;
        private const uint UserVerificationDiscouraged = 3;
        private const uint CredentialTransportAny = 0;
        private const string PublicKeyCredentialType = "public-key";
        private const string HashAlgorithmSha256 = "SHA-256";
        private const int MaxAllowedCredentialCount = 1024;
        private const int MaxCredentialIdLength = 1024;
        private const int MaxChallengeLength = 1024;
        private const int MaxNativeBufferLength = 1024 * 1024;

        public static Task<string> AuthenticatePublicKeyRequest(object request, string trustedServer)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new PlatformNotSupportedException(
                    "Windows WebAuthn security-key authentication is available on Windows only.");
            }
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            var origin = NormalizeOrigin(trustedServer);
            var rpIdValue = GetStringMember(request, "rpId");
            var challengeValue = GetStringMember(request, "challenge");
            if (string.IsNullOrWhiteSpace(rpIdValue) || string.IsNullOrWhiteSpace(challengeValue))
            {
                throw new ArgumentException("The security-key request is missing its RP ID or challenge.", "request");
            }
            var rpId = ValidateRelyingParty(rpIdValue, origin);
            var challenge = DecodeBase64Url(challengeValue, MaxChallengeLength, "challenge");
            var extensions = GetMember(request, "extensions");
            var appId = extensions == null ? null : GetStringMember(extensions, "appid");
            ValidateAppId(appId);
            var userVerification = NormalizeUserVerification(GetStringMember(request, "userVerification"));
            var credentialIds = DecodeAllowedCredentials(GetMember(request, "allowCredentials"));

            // The native Windows API is synchronous; do not block the authentication UI.
            return Task.Run<string>(() => AuthenticateNative(
                origin, rpId, challenge, credentialIds, appId, userVerification));
        }

        private static string AuthenticateNative(string origin, string rpId,
            byte[] challenge, byte[][] credentialIds, string appId, string userVerification)
        {
            var allocated = new List<IntPtr>();
            var assertionPointer = IntPtr.Zero;
            try
            {
                uint apiVersion;
                try
                {
                    apiVersion = NativeMethods.WebAuthNGetApiVersionNumber();
                }
                catch (DllNotFoundException e)
                {
                    throw new PlatformNotSupportedException("The Windows WebAuthn API is unavailable.", e);
                }
                catch (EntryPointNotFoundException e)
                {
                    throw new PlatformNotSupportedException("The Windows WebAuthn API is unavailable.", e);
                }
                if (apiVersion < MinimumWebAuthnApiVersion)
                {
                    throw new PlatformNotSupportedException(
                        "The installed Windows WebAuthn API does not support the required security-key operation.");
                }

                var clientDataJson = "{\"type\":\"webauthn.get\",\"challenge\":" +
                    JsonQuote(EncodeBase64Url(challenge)) + ",\"origin\":" + JsonQuote(origin) +
                    ",\"crossOrigin\":false}";
                var clientDataBytes = Encoding.UTF8.GetBytes(clientDataJson);
                if (clientDataBytes == null || clientDataBytes.Length == 0 ||
                    clientDataBytes.Length > MaxNativeBufferLength)
                {
                    throw new ArgumentException("The WebAuthn client data has an invalid size.", "request");
                }

                var clientDataPointer = AllocateBytes(clientDataBytes, allocated);
                var hashAlgorithmPointer = Marshal.StringToHGlobalUni(HashAlgorithmSha256);
                allocated.Add(hashAlgorithmPointer);
                var nativeClientData = new NativeWebAuthnClientData
                {
                    dwVersion = ClientDataVersion,
                    cbClientDataJSON = checked((uint)clientDataBytes.Length),
                    pbClientDataJSON = clientDataPointer,
                    pwszHashAlgId = hashAlgorithmPointer,
                };

                var credentialPointers = BuildAllowedCredentialList(credentialIds, allocated);
                var nativeCredentialList = new NativeWebAuthnCredentialList
                {
                    cCredentials = checked((uint)credentialPointers.Length),
                    ppCredentials = credentialPointers.Length == 0
                        ? IntPtr.Zero
                        : AllocatePointerArray(credentialPointers, allocated),
                };
                var nativeCredentialListPointer =
                    Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeWebAuthnCredentialList)));
                allocated.Add(nativeCredentialListPointer);
                Marshal.StructureToPtr(nativeCredentialList, nativeCredentialListPointer, false);

                var appIdPointer = IntPtr.Zero;
                var appIdUsedPointer = IntPtr.Zero;
                if (!string.IsNullOrWhiteSpace(appId))
                {
                    appIdPointer = Marshal.StringToHGlobalUni(appId);
                    allocated.Add(appIdPointer);
                    appIdUsedPointer = Marshal.AllocHGlobal(sizeof(int));
                    Marshal.WriteInt32(appIdUsedPointer, 0);
                    allocated.Add(appIdUsedPointer);
                }

                var options = new NativeWebAuthnGetAssertionOptions
                {
                    dwVersion = GetAssertionOptionsVersion,
                    dwTimeoutMilliseconds = 120000,
                    CredentialList = new NativeWebAuthnCredentials
                    {
                        cCredentials = 0,
                        pCredentials = IntPtr.Zero,
                    },
                    Extensions = new NativeWebAuthnExtensions
                    {
                        cExtensions = 0,
                        pExtensions = IntPtr.Zero,
                    },
                    dwAuthenticatorAttachment = 0,
                    dwUserVerificationRequirement = MapUserVerification(userVerification),
                    dwFlags = 0,
                    pwszU2fAppId = appIdPointer,
                    pbU2fAppId = appIdUsedPointer,
                    pCancellationId = IntPtr.Zero,
                    pAllowCredentialList = nativeCredentialListPointer,
                };

                var result = NativeMethods.WebAuthNAuthenticatorGetAssertion(
                    GetSecurityKeyPromptOwnerWindow(), rpId, ref nativeClientData, ref options,
                    out assertionPointer);
                if (result != 0)
                {
                    string errorName = null;
                    try
                    {
                        var errorPointer = NativeMethods.WebAuthNGetErrorName(result);
                        if (errorPointer != IntPtr.Zero)
                        {
                            errorName = Marshal.PtrToStringUni(errorPointer);
                        }
                    }
                    catch
                    {
                        // Preserve the HRESULT if the OS cannot provide an error name.
                    }
                    throw new InvalidOperationException(string.IsNullOrWhiteSpace(errorName)
                        ? string.Format("Windows WebAuthn authentication failed (0x{0:X8}).", unchecked((uint)result))
                        : string.Format("Windows WebAuthn authentication failed: {0} (0x{1:X8}).",
                            errorName, unchecked((uint)result)));
                }
                if (assertionPointer == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Windows WebAuthn returned an empty assertion.");
                }

                var assertion = Marshal.PtrToStructure<NativeWebAuthnAssertion>(assertionPointer);
                var credentialId = CopyBytes(assertion.Credential.cbId, assertion.Credential.pbId,
                    1, MaxCredentialIdLength, "credential ID");
                var authenticatorData = CopyBytes(assertion.cbAuthenticatorData, assertion.pbAuthenticatorData,
                    37, MaxNativeBufferLength, "authenticator data");
                var signatureData = CopyBytes(assertion.cbSignature, assertion.pbSignature,
                    1, MaxNativeBufferLength, "signature");
                var userHandle = assertion.cbUserId == 0
                    ? null
                    : CopyBytes(assertion.cbUserId, assertion.pbUserId, 1, MaxCredentialIdLength, "user handle");
                EnsureAuthenticatorData(authenticatorData, userVerification);

                return BuildAssertionJson(credentialId, authenticatorData, clientDataBytes, signatureData,
                    userHandle, appIdUsedPointer);
            }
            finally
            {
                try
                {
                    if (assertionPointer != IntPtr.Zero)
                    {
                        NativeMethods.WebAuthNFreeAssertion(assertionPointer);
                    }
                }
                finally
                {
                    foreach (var pointer in allocated)
                    {
                        Marshal.FreeHGlobal(pointer);
                    }
                }
            }
        }

        private static byte[][] DecodeAllowedCredentials(object allowCredentials)
        {
            if (allowCredentials == null)
            {
                return new byte[0][];
            }
            var values = allowCredentials as IEnumerable;
            if (values == null)
            {
                throw new ArgumentException("The WebAuthn allowCredentials value is invalid.", "allowCredentials");
            }

            var descriptors = new List<object>();
            foreach (var item in values)
            {
                descriptors.Add(item);
                if (descriptors.Count > MaxAllowedCredentialCount)
                {
                    throw new ArgumentException("The WebAuthn request contains too many allowed credentials.",
                        "allowCredentials");
                }
            }

            var decoded = new byte[descriptors.Count][];
            for (var i = 0; i < descriptors.Count; i++)
            {
                var descriptor = descriptors[i];
                var type = descriptor == null ? null : GetStringMember(descriptor, "type");
                var id = descriptor == null ? null : GetStringMember(descriptor, "id");
                if (!string.Equals(type, PublicKeyCredentialType, StringComparison.Ordinal) ||
                    string.IsNullOrWhiteSpace(id))
                {
                    throw new ArgumentException("The WebAuthn request contains an invalid allowed credential.",
                        "allowCredentials");
                }
                decoded[i] = DecodeBase64Url(id, MaxCredentialIdLength, "allowed credential ID");
            }
            return decoded;
        }

        private static object GetMember(object instance, string name)
        {
            if (instance == null)
            {
                return null;
            }
            var flags = BindingFlags.Instance | BindingFlags.Public;
            var field = instance.GetType().GetField(name, flags);
            if (field != null)
            {
                return field.GetValue(instance);
            }
            var property = instance.GetType().GetProperty(name, flags);
            return property == null ? null : property.GetValue(instance, null);
        }

        private static string GetStringMember(object instance, string name)
        {
            return GetMember(instance, name) as string;
        }

        private static byte[] DecodeBase64Url(string value, int maximumLength, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("The WebAuthn " + name + " is empty.", name);
            }
            var maximumEncodedLength = checked(((maximumLength + 2) / 3) * 4 + 2);
            if (value.Length > maximumEncodedLength || value.IndexOfAny(new[] { '+', '/' }) >= 0)
            {
                throw new ArgumentException("The WebAuthn " + name + " is not valid Base64URL data.", name);
            }

            var firstPadding = value.IndexOf('=');
            var normalized = firstPadding < 0 ? value : value.Substring(0, firstPadding);
            var paddingLength = value.Length - normalized.Length;
            if (paddingLength > 2 || (firstPadding >= 0 && value.Substring(firstPadding).Trim('=').Length != 0))
            {
                throw new ArgumentException("The WebAuthn " + name + " is not valid Base64URL data.", name);
            }
            if (paddingLength > 0 &&
                (value.Length % 4 != 0 ||
                 (paddingLength == 1 && normalized.Length % 4 != 3) ||
                 (paddingLength == 2 && normalized.Length % 4 != 2)))
            {
                throw new ArgumentException("The WebAuthn " + name + " is not valid Base64URL data.", name);
            }

            for (var i = 0; i < normalized.Length; i++)
            {
                var ch = normalized[i];
                if (!(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') &&
                    !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_')
                {
                    throw new ArgumentException("The WebAuthn " + name + " is not valid Base64URL data.", name);
                }
            }

            normalized = normalized.Replace('-', '+').Replace('_', '/');
            switch (normalized.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    normalized += "==";
                    break;
                case 3:
                    normalized += "=";
                    break;
                default:
                    throw new ArgumentException("The WebAuthn " + name + " is not valid Base64URL data.", name);
            }

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(normalized);
            }
            catch (FormatException e)
            {
                throw new ArgumentException("The WebAuthn " + name + " is not valid Base64URL data.", name, e);
            }
            if (bytes.Length == 0 || bytes.Length > maximumLength)
            {
                throw new ArgumentException("The WebAuthn " + name + " has an invalid length.", name);
            }
            return bytes;
        }

        private static IntPtr[] BuildAllowedCredentialList(byte[][] credentialIds, IList<IntPtr> allocated)
        {
            var pointers = new List<IntPtr>(credentialIds.Length);
            foreach (var id in credentialIds)
            {
                var idPointer = AllocateBytes(id, allocated);
                var typePointer = Marshal.StringToHGlobalUni(PublicKeyCredentialType);
                allocated.Add(typePointer);
                var nativeCredential = new NativeWebAuthnCredentialEx
                {
                    dwVersion = CredentialVersion,
                    cbId = checked((uint)id.Length),
                    pbId = idPointer,
                    pwszCredentialType = typePointer,
                    dwTransports = CredentialTransportAny,
                };
                var credentialPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeWebAuthnCredentialEx)));
                allocated.Add(credentialPointer);
                Marshal.StructureToPtr(nativeCredential, credentialPointer, false);
                pointers.Add(credentialPointer);
            }
            return pointers.ToArray();
        }

        private static IntPtr AllocatePointerArray(IList<IntPtr> pointers, IList<IntPtr> allocated)
        {
            var allocationSize = checked(IntPtr.Size * pointers.Count);
            var pointer = Marshal.AllocHGlobal(allocationSize);
            allocated.Add(pointer);
            for (var i = 0; i < pointers.Count; i++)
            {
                Marshal.WriteIntPtr(pointer, checked(i * IntPtr.Size), pointers[i]);
            }
            return pointer;
        }

        private static IntPtr AllocateBytes(byte[] bytes, IList<IntPtr> allocated)
        {
            if (bytes == null || bytes.Length == 0)
            {
                throw new ArgumentException("A WebAuthn buffer cannot be empty.", "bytes");
            }
            var pointer = Marshal.AllocHGlobal(bytes.Length);
            allocated.Add(pointer);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        private static byte[] CopyBytes(uint length, IntPtr pointer, int minimumLength,
            int maximumLength, string name)
        {
            if (length < minimumLength || length > maximumLength || pointer == IntPtr.Zero)
            {
                throw new InvalidOperationException("Windows WebAuthn returned an invalid " + name + " buffer.");
            }
            var result = new byte[checked((int)length)];
            Marshal.Copy(pointer, result, 0, result.Length);
            return result;
        }

        private static string BuildAssertionJson(byte[] credentialId, byte[] authenticatorData,
            byte[] clientDataBytes, byte[] signatureData, byte[] userHandle, IntPtr appIdUsedPointer)
        {
            var encodedId = EncodeBase64Url(credentialId);
            var json = new StringBuilder();
            json.Append("{\"id\":").Append(JsonQuote(encodedId))
                .Append(",\"rawId\":").Append(JsonQuote(encodedId))
                .Append(",\"response\":{\"authenticatorData\":")
                .Append(JsonQuote(EncodeBase64Url(authenticatorData)))
                .Append(",\"clientDataJSON\":").Append(JsonQuote(EncodeBase64Url(clientDataBytes)))
                .Append(",\"signature\":").Append(JsonQuote(EncodeBase64Url(signatureData)));
            if (userHandle != null)
            {
                json.Append(",\"userHandle\":").Append(JsonQuote(EncodeBase64Url(userHandle)));
            }
            json.Append("},\"type\":").Append(JsonQuote(PublicKeyCredentialType))
                .Append(",\"clientExtensionResults\":{");
            if (appIdUsedPointer != IntPtr.Zero)
            {
                json.Append("\"appid\":").Append(Marshal.ReadInt32(appIdUsedPointer) != 0 ? "true" : "false");
            }
            return json.Append("}}").ToString();
        }

        private static string EncodeBase64Url(byte[] value)
        {
            return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string JsonQuote(string value)
        {
            var json = new StringBuilder(value.Length + 2);
            json.Append('"');
            foreach (var ch in value)
            {
                switch (ch)
                {
                    case '"':
                        json.Append("\\\"");
                        break;
                    case '\\':
                        json.Append("\\\\");
                        break;
                    case '\b':
                        json.Append("\\b");
                        break;
                    case '\f':
                        json.Append("\\f");
                        break;
                    case '\n':
                        json.Append("\\n");
                        break;
                    case '\r':
                        json.Append("\\r");
                        break;
                    case '\t':
                        json.Append("\\t");
                        break;
                    default:
                        if (ch < 0x20)
                        {
                            json.Append("\\u").Append(((int)ch).ToString("x4"));
                        }
                        else
                        {
                            json.Append(ch);
                        }
                        break;
                }
            }
            return json.Append('"').ToString();
        }

        private static uint MapUserVerification(string userVerification)
        {
            switch (userVerification)
            {
                case "required":
                    return UserVerificationRequired;
                case "discouraged":
                    return UserVerificationDiscouraged;
                default:
                    return UserVerificationPreferred;
            }
        }

        private static string NormalizeUserVerification(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "preferred";
            }
            switch (value.ToLowerInvariant())
            {
                case "required":
                case "preferred":
                case "discouraged":
                    return value.ToLowerInvariant();
                default:
                    throw new ArgumentException("The WebAuthn userVerification requirement is invalid.", "request");
            }
        }

        private static string NormalizeOrigin(string server)
        {
            if (string.IsNullOrWhiteSpace(server))
            {
                throw new ArgumentException("A trusted Keeper server is required.", "trustedServer");
            }

            var value = server.Trim();
            if (value.IndexOf("://", StringComparison.Ordinal) < 0)
            {
                value = "https://" + value;
            }
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                (!string.IsNullOrEmpty(uri.AbsolutePath) && uri.AbsolutePath != "/") ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new ArgumentException(
                    "The trusted Keeper origin must be HTTPS and cannot contain credentials, a path, query, or fragment.",
                    "trustedServer");
            }
            return uri.GetLeftPart(UriPartial.Authority);
        }

        private static string ValidateRelyingParty(string relyingPartyId, string origin)
        {
            var rpId = relyingPartyId.Trim().TrimEnd('.').ToLowerInvariant();
            if (Uri.CheckHostName(rpId) != UriHostNameType.Dns)
            {
                throw new ArgumentException("The WebAuthn relying-party ID must be a DNS host.", "request");
            }
            Uri rpUri;
            if (!Uri.TryCreate("https://" + rpId, UriKind.Absolute, out rpUri))
            {
                throw new ArgumentException("The WebAuthn relying-party ID is invalid.", "request");
            }
            rpId = rpUri.IdnHost.TrimEnd('.').ToLowerInvariant();
            var originHost = new Uri(origin).IdnHost.TrimEnd('.').ToLowerInvariant();
            if (!string.Equals(originHost, rpId, StringComparison.Ordinal) &&
                !originHost.EndsWith("." + rpId, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The WebAuthn relying-party ID does not match the configured Keeper origin.", "request");
            }
            return rpId;
        }

        private static void ValidateAppId(string appId)
        {
            if (string.IsNullOrWhiteSpace(appId))
            {
                return;
            }
            Uri uri;
            if (!Uri.TryCreate(appId, UriKind.Absolute, out uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(uri.UserInfo))
            {
                throw new ArgumentException("The WebAuthn AppID extension must be a valid HTTPS URL.", "request");
            }
        }

        private static void EnsureAuthenticatorData(byte[] authenticatorData, string userVerification)
        {
            const int flagsOffset = 32;
            const byte userPresent = 0x01;
            const byte userVerified = 0x04;
            if (authenticatorData == null || authenticatorData.Length < 37)
            {
                throw new InvalidOperationException("The security key returned invalid authenticator data.");
            }
            var flags = authenticatorData[flagsOffset];
            if ((flags & userPresent) == 0)
            {
                throw new InvalidOperationException("The security key did not confirm user presence.");
            }
            if (userVerification == "required" && (flags & userVerified) == 0)
            {
                throw new InvalidOperationException(
                    "The security key did not verify the user. Configure a FIDO2 PIN or choose another verification method.");
            }
        }

        private static IntPtr GetSecurityKeyPromptOwnerWindow()
        {
            // webauthn.dll requires a valid owner window handle; a null handle fails with
            // NTE_INVALID_PARAMETER (0x80090027). Prefer windows of this process, then the
            // foreground window (the terminal the user is typing in, e.g. Windows Terminal,
            // whose console window is hidden), and finally the desktop window.
            var consoleWindow = NativeMethods.GetConsoleWindow();
            if (consoleWindow != IntPtr.Zero && NativeMethods.IsWindowVisible(consoleWindow))
            {
                return consoleWindow;
            }
            try
            {
                using (var process = System.Diagnostics.Process.GetCurrentProcess())
                {
                    var mainWindow = process.MainWindowHandle;
                    if (mainWindow != IntPtr.Zero && NativeMethods.IsWindowVisible(mainWindow))
                    {
                        return mainWindow;
                    }
                }
            }
            catch (InvalidOperationException)
            {
            }
            var foregroundWindow = NativeMethods.GetForegroundWindow();
            if (foregroundWindow != IntPtr.Zero && NativeMethods.IsWindowVisible(foregroundWindow))
            {
                return foregroundWindow;
            }
            return NativeMethods.GetDesktopWindow();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnClientData
        {
            public uint dwVersion;
            public uint cbClientDataJSON;
            public IntPtr pbClientDataJSON;
            public IntPtr pwszHashAlgId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnCredentialEx
        {
            public uint dwVersion;
            public uint cbId;
            public IntPtr pbId;
            public IntPtr pwszCredentialType;
            public uint dwTransports;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnCredentialList
        {
            public uint cCredentials;
            public IntPtr ppCredentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnCredentials
        {
            public uint cCredentials;
            public IntPtr pCredentials;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnExtensions
        {
            public uint cExtensions;
            public IntPtr pExtensions;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnGetAssertionOptions
        {
            public uint dwVersion;
            public uint dwTimeoutMilliseconds;
            public NativeWebAuthnCredentials CredentialList;
            public NativeWebAuthnExtensions Extensions;
            public uint dwAuthenticatorAttachment;
            public uint dwUserVerificationRequirement;
            public uint dwFlags;
            public IntPtr pwszU2fAppId;
            public IntPtr pbU2fAppId;
            public IntPtr pCancellationId;
            public IntPtr pAllowCredentialList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnCredential
        {
            public uint dwVersion;
            public uint cbId;
            public IntPtr pbId;
            public IntPtr pwszCredentialType;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeWebAuthnAssertion
        {
            public uint dwVersion;
            public uint cbAuthenticatorData;
            public IntPtr pbAuthenticatorData;
            public uint cbSignature;
            public IntPtr pbSignature;
            public NativeWebAuthnCredential Credential;
            public uint cbUserId;
            public IntPtr pbUserId;
        }

        private static class NativeMethods
        {
            [DllImport("kernel32.dll")]
            internal static extern IntPtr GetConsoleWindow();

            [DllImport("user32.dll")]
            internal static extern IntPtr GetForegroundWindow();

            [DllImport("user32.dll")]
            internal static extern IntPtr GetDesktopWindow();

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsWindowVisible(IntPtr hWnd);

            [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetApiVersionNumber")]
            internal static extern uint WebAuthNGetApiVersionNumber();

            [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
            internal static extern int WebAuthNAuthenticatorGetAssertion(
                IntPtr hWnd,
                [MarshalAs(UnmanagedType.LPWStr)] string rpId,
                ref NativeWebAuthnClientData clientData,
                ref NativeWebAuthnGetAssertionOptions options,
                out IntPtr assertion);

            [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeAssertion")]
            internal static extern void WebAuthNFreeAssertion(IntPtr assertion);

            [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetErrorName")]
            internal static extern IntPtr WebAuthNGetErrorName(int error);
        }
    }
}
