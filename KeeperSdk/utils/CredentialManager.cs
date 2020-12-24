#if NET45
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
#endif

namespace KeeperSecurity.Utils
{
    /// <exclude />
    public static class CredentialManager
    {
        public static bool GetCredentials(string target, out string username, out string password)
        {
#if NET45
            try
            {
                var permissions = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
                permissions.Demand();

                var result = CredRead(target, 1, 0, out var credPointer);
                if (result)
                {
                    using (var credentialHandle = new CriticalCredentialHandle(credPointer))
                    {
                        var credential = credentialHandle.GetCredential();
                        username = credential.UserName;
                        if (credential.CredentialBlobSize > 0)
                        {
                            password = Marshal.PtrToStringUni(credential.CredentialBlob, credential.CredentialBlobSize / 2);
                            return true;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.ToString());
            }

#endif
            username = null;
            password = null;
            return false;
        }

#if NET45

        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredRead(string target, int credentialType, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWrite([In]
            ref CREDENTIAL userCredential,
            [In]
            uint flags);

        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        static extern bool CredFree([In]
            IntPtr cred);

        [StructLayout(LayoutKind.Sequential)]
        struct CREDENTIAL
        {
            public int Flags;
            public int Type;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string Comment;

            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetAlias;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserName;
        }

        sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
        {
            // Set the handle.
            internal CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            internal CREDENTIAL GetCredential()
            {
                if (!IsInvalid)
                {
                    return (CREDENTIAL) Marshal.PtrToStructure(handle, typeof(CREDENTIAL));
                }
                else
                {
                    throw new InvalidOperationException("Invalid CriticalHandle!");
                }
            }

            protected override bool ReleaseHandle()
            {
                if (IsInvalid) return false;

                CredFree(handle);
                SetHandleAsInvalid();
                return true;
            }
        }
#endif
    }
}
