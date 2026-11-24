using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace Commander
{
    /// <summary>
    /// Adapts the shared Windows WebAuthn implementation to Commander authentication.
    /// </summary>
    internal sealed class WindowsSecurityKeyUI : IAuthSecurityKeyUI
    {
        private readonly Func<string> _trustedServer;

        // The server can change after login starts (region redirect, "server" command),
        // so it is read when a security key is requested, not when the UI is created.
        internal WindowsSecurityKeyUI(Func<string> trustedServer)
        {
            _trustedServer = trustedServer;
        }

        public Task<string> AuthenticatePublicKeyRequest(PublicKeyCredentialRequestOptions request)
        {
            return WindowsWebAuthnSecurityKeyUI.AuthenticatePublicKeyRequest(request, _trustedServer());
        }
    }
}
