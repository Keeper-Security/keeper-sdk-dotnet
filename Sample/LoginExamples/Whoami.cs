using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.LoginExamples
{
    public static class WhoamiExample
    {
        public static async Task WhoamiAsync()
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                IAuthContext authContext = vault.Auth.AuthContext;
                string username = vault.Auth.Username;

                Console.WriteLine("=== Who Am I ===");
                Console.WriteLine($"Username: {username}");
                Console.WriteLine($"Account Auth Type: {authContext.AccountAuthType}");
                Console.WriteLine($"Is Enterprise Admin: {authContext.IsEnterpriseAdmin}");
                Console.WriteLine($"Expiration Date: {authContext.License.ExpirationDate}");
                Console.WriteLine($"Server: {vault.Auth.Endpoint.Server}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
