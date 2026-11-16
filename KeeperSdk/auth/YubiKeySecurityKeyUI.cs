using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;
using Yubico.YubiKey.Fido2.Commands;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Provides WebAuthn security-key authentication in the Keeper SDK.
    /// Windows uses its native WebAuthn prompt; macOS and Linux use Yubico's
    /// YubiKey library and collect any FIDO2 PIN directly in the terminal.
    /// </summary>
    public sealed class YubiKeySecurityKeyUI : IAuthSecurityKeyUI
    {
        private static readonly object ConsolePromptLock = new object();
        private readonly string _trustedServer;

        /// <summary>
        /// Creates a security-key provider bound to the trusted Keeper server.
        /// </summary>
        /// <param name="trustedServer">Keeper host name or HTTPS origin.</param>
        public YubiKeySecurityKeyUI(string trustedServer)
        {
            _trustedServer = trustedServer;
        }

        /// <summary>
        /// True on Windows, macOS, or Linux where this provider can authenticate keys.
        /// </summary>
        public static bool IsSupportedPlatform =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        /// <inheritdoc/>
        public Task<string> AuthenticatePublicKeyRequest(PublicKeyCredentialRequestOptions request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }
            if (!IsSupportedPlatform)
            {
                throw new PlatformNotSupportedException(
                    "YubiKey security-key authentication is supported on Windows, macOS, and Linux.");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return WindowsWebAuthnSecurityKeyUI.AuthenticatePublicKeyRequest(request, _trustedServer);
            }

            return Task.Run(() => AuthenticateWithYubicoLibrary(request));
        }

        private string AuthenticateWithYubicoLibrary(PublicKeyCredentialRequestOptions request)
        {
            if (string.IsNullOrWhiteSpace(request.rpId))
            {
                throw new ArgumentException("The security-key request is missing its RP ID.", nameof(request));
            }
            var trustedOrigin = NormalizeOrigin(_trustedServer);
            var relyingPartyId = ValidateRelyingParty(request.rpId, trustedOrigin);
            var challenge = DecodeBase64Url(request.challenge, "challenge");
            var encodedChallenge = EncodeBase64Url(challenge);
            var clientData = new SecurityKeyClientData
            {
                dataType = SecurityKeyClientData.GET_ASSERTION,
                challenge = encodedChallenge,
                origin = trustedOrigin,
                crossOrigin = false,
            };
            var clientDataJson = JsonUtils.DumpJson(clientData, false);
            byte[] clientDataHash;
            using (var sha256 = SHA256.Create())
            {
                clientDataHash = sha256.ComputeHash(clientDataJson);
            }

            var parameters = new GetAssertionParameters(
                new RelyingParty(relyingPartyId),
                new ReadOnlyMemory<byte>(clientDataHash));
            var allowCredentials = request.allowCredentials ?? Array.Empty<AllowCredential>();
            foreach (var credential in allowCredentials)
            {
                if (credential == null ||
                    !string.Equals(credential.type, "public-key", StringComparison.Ordinal))
                {
                    throw new ArgumentException(
                        "The security-key request contains an invalid allowed credential.", nameof(request));
                }

                var id = DecodeBase64Url(credential.id, "allowed credential ID");
                var credentialId = new CredentialId
                {
                    Type = credential.type,
                    Id = new ReadOnlyMemory<byte>(id),
                };
                parameters.AllowCredential(credentialId);
            }

            var devices = YubiKeyDevice.FindByTransport(Transport.HidFido);
            using (var iterator = devices.GetEnumerator())
            {
                if (!iterator.MoveNext())
                {
                    throw new InvalidOperationException(
                        "No FIDO2 security key was found. Connect a YubiKey and try again.");
                }

                using (var fido2 = new Fido2Session(iterator.Current))
                {
                    fido2.KeyCollector = CollectKeyEntry;

                    // GetAssertionParameters does not expose the WebAuthn
                    // userVerification option. Verifying the PIN first makes a
                    // required-UV request produce an authenticator UV flag.
                    if (string.Equals(request.userVerification, "required", StringComparison.OrdinalIgnoreCase))
                    {
                        fido2.VerifyPin(PinUvAuthTokenPermissions.GetAssertion, relyingPartyId);
                    }

                    var assertions = fido2.GetAssertions(parameters);
                    if (assertions == null || assertions.Count == 0)
                    {
                        throw new InvalidOperationException(
                            "The connected YubiKey has no credential for this Keeper account.");
                    }

                    try
                    {
                        var assertion = assertions[0];
                        if (string.Equals(request.userVerification, "required", StringComparison.OrdinalIgnoreCase) &&
                            !assertion.AuthenticatorData.UserVerification)
                        {
                            throw new InvalidOperationException(
                                "The YubiKey did not verify the user. Configure and use a FIDO2 PIN, then retry.");
                        }
                        return BuildAssertionJson(
                            assertion,
                            clientDataJson,
                            !string.IsNullOrWhiteSpace(request.extensions?.appid));
                    }
                    finally
                    {
                        foreach (var assertion in assertions)
                        {
                            assertion?.Dispose();
                        }
                    }
                }
            }
        }

        private static bool CollectKeyEntry(KeyEntryData keyEntryData)
        {
            if (keyEntryData == null)
            {
                return false;
            }

            try
            {
                switch (keyEntryData.Request)
                {
                    case KeyEntryRequest.Release:
                        return true;

                    case KeyEntryRequest.TouchRequest:
                        lock (ConsolePromptLock)
                        {
                            Console.WriteLine(
                                "\nTouch your YubiKey to continue (Ctrl+C to cancel).\n");
                        }
                        return true;

                    case KeyEntryRequest.VerifyFido2Uv:
                        lock (ConsolePromptLock)
                        {
                            Console.WriteLine("User verification is required on the YubiKey.");
                        }
                        return true;

                    case KeyEntryRequest.VerifyFido2Pin:
                        return CollectPin(keyEntryData);

                    default:
                        return false;
                }
            }
            catch (OperationCanceledException)
            {
                keyEntryData.SignalUserCancel?.Invoke();
                return false;
            }
        }

        private static bool CollectPin(KeyEntryData keyEntryData)
        {
            if (Console.IsInputRedirected)
            {
                throw new InvalidOperationException(
                    "A terminal is required to enter the YubiKey PIN on macOS and Linux.");
            }

            lock (ConsolePromptLock)
            {
                if (keyEntryData.IsRetry)
                {
                    var retries = keyEntryData.RetriesRemaining;
                    Console.WriteLine(retries.HasValue
                        ? $"The YubiKey PIN was not accepted. {retries.Value} attempt(s) remaining."
                        : "The YubiKey PIN was not accepted. Please try again.");
                }
                Console.Write("Enter YubiKey PIN: ");

                var characters = ReadSecretCharacters();
                if (characters == null)
                {
                    Console.WriteLine();
                    return false;
                }

                var encodedPin = Encoding.UTF8.GetBytes(characters);
                Array.Clear(characters, 0, characters.Length);
                try
                {
                    keyEntryData.SubmitValue(encodedPin.AsSpan());
                }
                finally
                {
                    Array.Clear(encodedPin, 0, encodedPin.Length);
                }

                Console.WriteLine();
                return true;
            }
        }

        private static char[] ReadSecretCharacters()
        {
            var characters = new List<char>();
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    return characters.ToArray();
                }
                if (key.Key == ConsoleKey.C && (key.Modifiers & ConsoleModifiers.Control) != 0)
                {
                    return null;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (characters.Count > 0)
                    {
                        characters.RemoveAt(characters.Count - 1);
                    }
                    continue;
                }
                if (!char.IsControl(key.KeyChar))
                {
                    characters.Add(key.KeyChar);
                }
            }
        }

        private static string BuildAssertionJson(
            GetAssertionData assertion,
            byte[] clientDataJson,
            bool appIdExtensionRequested)
        {
            var credentialId = assertion.CredentialId.Id.ToArray();
            var authenticatorData = assertion.AuthenticatorData.EncodedAuthenticatorData.ToArray();
            var response = new SignatureResponse
            {
                authenticatorData = EncodeBase64Url(authenticatorData),
                clientDataJSON = EncodeBase64Url(clientDataJson),
                signature = EncodeBase64Url(assertion.Signature.ToArray()),
                userHandle = assertion.User == null
                    ? null
                    : EncodeBase64Url(assertion.User.Id.ToArray()),
            };
            var signature = new KeeperWebAuthnSignature
            {
                id = EncodeBase64Url(credentialId),
                rawId = EncodeBase64Url(credentialId),
                response = response,
                type = "public-key",
                clientExtensionResults = new ClientExtensionResults
                {
                    appid = appIdExtensionRequested ? false : (bool?)null,
                },
            };
            return Encoding.UTF8.GetString(JsonUtils.DumpJson(signature, false));
        }

        private static string NormalizeOrigin(string trustedServer)
        {
            if (string.IsNullOrWhiteSpace(trustedServer))
            {
                throw new ArgumentException("A trusted Keeper server is required.", nameof(trustedServer));
            }

            var value = trustedServer.Trim();
            if (value.IndexOf("://", StringComparison.Ordinal) < 0)
            {
                value = "https://" + value;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                (!string.IsNullOrEmpty(uri.AbsolutePath) && uri.AbsolutePath != "/") ||
                !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new ArgumentException(
                    "The trusted Keeper origin must be HTTPS and cannot contain credentials, a path, query, or fragment.",
                    nameof(trustedServer));
            }
            return uri.GetLeftPart(UriPartial.Authority);
        }

        private static string ValidateRelyingParty(string rpId, string trustedOrigin)
        {
            var normalizedId = rpId.Trim().TrimEnd('.').ToLowerInvariant();
            if (Uri.CheckHostName(normalizedId) != UriHostNameType.Dns ||
                !Uri.TryCreate("https://" + normalizedId, UriKind.Absolute, out var rpUri))
            {
                throw new ArgumentException("The security-key RP ID is invalid.", nameof(rpId));
            }

            normalizedId = rpUri.IdnHost.TrimEnd('.').ToLowerInvariant();
            var originHost = new Uri(trustedOrigin).IdnHost.TrimEnd('.').ToLowerInvariant();
            if (!string.Equals(originHost, normalizedId, StringComparison.Ordinal) &&
                !originHost.EndsWith("." + normalizedId, StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "The security-key RP ID does not match the configured Keeper server.", nameof(rpId));
            }
            return normalizedId;
        }

        private static byte[] DecodeBase64Url(string value, string name)
        {
            if (string.IsNullOrWhiteSpace(value) || value.IndexOfAny(new[] { '+', '/' }) >= 0)
            {
                throw new ArgumentException("The security-key " + name + " is invalid Base64URL data.", name);
            }

            var normalized = value.TrimEnd('=');
            foreach (var ch in normalized)
            {
                if (!(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') &&
                    !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_')
                {
                    throw new ArgumentException("The security-key " + name + " is invalid Base64URL data.", name);
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
                    throw new ArgumentException("The security-key " + name + " is invalid Base64URL data.", name);
            }

            try
            {
                var bytes = Convert.FromBase64String(normalized);
                if (bytes.Length == 0)
                {
                    throw new ArgumentException("The security-key " + name + " must not be empty.", name);
                }
                return bytes;
            }
            catch (FormatException exception)
            {
                throw new ArgumentException(
                    "The security-key " + name + " is invalid Base64URL data.", name, exception);
            }
        }

        private static string EncodeBase64Url(byte[] value)
        {
            return Convert.ToBase64String(value)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}
