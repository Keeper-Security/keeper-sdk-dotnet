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

        public static Task<U2FSignature> GetAssertion(IntPtr hWnd, SecurityKeyClientData clientData, IList<byte[]> keyHandles)
        {
            return GetAssertion(hWnd, clientData, keyHandles, CancellationToken.None);
        }

        public static Task<U2FSignature> GetAssertion(IntPtr hWnd, SecurityKeyClientData clientData, IList<byte[]> keyHandles, CancellationToken token)
        {
            var taskSource = new TaskCompletionSource<U2FSignature>();
            Task.Run(() =>
                {
                    var ptrList = new List<IntPtr>();
                    try
                    {
                        var clientDataBytes = JsonUtils.DumpJson(clientData);
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

                        var credentialSize = Marshal.SizeOf(typeof(NativeWebAuthn.WEBAUTHN_CREDENTIAL));
                        var credentialsPtr = Marshal.AllocHGlobal(keyHandles.Count * credentialSize);
                        ptrList.Add(credentialsPtr);
                        var pubKeyPtr = Marshal.StringToHGlobalUni(NativeWebAuthn.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY);
                        ptrList.Add(pubKeyPtr);
                        for (var i = 0; i < keyHandles.Count; i++)
                        {
                            var credLength = keyHandles[i].Length;
                            var credPtr = Marshal.AllocHGlobal(credLength);
                            ptrList.Add(credPtr);
                            Marshal.Copy(keyHandles[i], 0, credPtr, credLength);
                            var cred = new NativeWebAuthn.WEBAUTHN_CREDENTIAL
                            {
                                dwVersion = NativeWebAuthn.WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                                cbId = credLength,
                                pbId = credPtr,
                                pwszCredentialType = pubKeyPtr
                            };
                            Marshal.StructureToPtr(cred, credentialsPtr, false);
                        }

                        var opts = new NativeWebAuthn.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
                        {
                            dwVersion = 4,
                            dwTimeoutMilliseconds = (uint) TimeSpan.FromMinutes(2).TotalMilliseconds,
                            CredentialList = new NativeWebAuthn.WEBAUTHN_CREDENTIALS
                            {
                                cCredentials = keyHandles.Count,
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

                        var hr = NativeWebAuthn.WebAuthNAuthenticatorGetAssertion(hWnd, clientData.origin, ref data, ref opts, out var assertionPtr);
                        cancelToken?.Dispose();

                        if (hr == NativeWebAuthn.HRESULT.S_OK)
                        {
                            var assertion = (NativeWebAuthn.WEBAUTHN_ASSERTION) Marshal.PtrToStructure(assertionPtr, typeof(NativeWebAuthn.WEBAUTHN_ASSERTION));

                            byte[] keyHandleBytes;
                            if (assertion.Credential.cbId > 0)
                            {
                                keyHandleBytes = new byte[assertion.Credential.cbId];
                                if (assertion.Credential.pbId != IntPtr.Zero)
                                {
                                    Marshal.Copy(assertion.Credential.pbId, keyHandleBytes, 0, assertion.Credential.cbId);
                                }
                            }
                            else
                            {
                                keyHandleBytes = new byte[0];
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
                                authenticatorData = new byte[0];
                            }

                            byte[] signatureBytes;
                            if (assertion.cbSignature > 0)
                            {
                                signatureBytes = new byte[assertion.cbSignature];
                                if (assertion.pbSignature != IntPtr.Zero)
                                {
                                    Marshal.Copy(assertion.pbSignature, signatureBytes, 0, assertion.cbSignature);
                                }
                            }
                            else
                            {
                                signatureBytes = new byte[0];
                            }

                            NativeWebAuthn.WebAuthNFreeAssertion(assertionPtr);
                            taskSource.TrySetResult(new U2FSignature
                            {
                                clientData = clientDataBytes,
                                signatureData = authenticatorData.Skip(32).Take(5).Concat(signatureBytes).ToArray(),
                                keyHandle = keyHandleBytes
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
}
