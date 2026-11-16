using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace Commander
{
    /// <summary>
    /// Adapts the shared Windows WebAuthn implementation to Commander authentication.
    /// </summary>
    internal sealed class WindowsSecurityKeyUI : IAuthSecurityKeyUI
    {
        private readonly string _trustedServer;

        internal WindowsSecurityKeyUI(string trustedServer)
        {
            _trustedServer = trustedServer;
        }

        public Task<string> AuthenticatePublicKeyRequest(PublicKeyCredentialRequestOptions request)
        {
            return WindowsWebAuthnSecurityKeyUI.AuthenticatePublicKeyRequest(request, _trustedServer);
        }
    }
}
