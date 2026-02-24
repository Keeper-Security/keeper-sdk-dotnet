using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.LoginExamples
{
    public static class LogoutExample
    {
        public static async Task LogoutAsync()
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Not logged in.");
                    return;
                }

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