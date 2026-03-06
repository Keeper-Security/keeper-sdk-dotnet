using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.LoginExamples
{
    public static class LogoutExample
    {
        public static async Task LogoutAsync(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null)
            {
                Console.WriteLine("Not logged in.");
                return;
            }
            try
            {

                Console.WriteLine("Logging out...");
                await vault.Auth.Logout();
                Console.WriteLine("Logout successful!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}