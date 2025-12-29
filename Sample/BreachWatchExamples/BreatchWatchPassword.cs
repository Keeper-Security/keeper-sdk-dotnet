using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections.Generic;
using System.Threading;
using Cli;
using BWService = KeeperSecurity.BreachWatch.BreachWatch;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchPasswordExample
    {
        public static async Task BreachWatchPassword(
            IEnumerable<(string Password, byte[] Euid)> passwordEntries,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                // Initialize BreachWatch with the vault's auth context
                await BWService.InitializeBreachWatch(vault.Auth);

                // Scan passwords
                var results = await BWService.ScanPasswordsAsync(passwordEntries, cancellationToken);

                if (results == null || results.Count == 0)
                {
                    Console.WriteLine("No scan results returned.");
                    return;
                }

                Console.WriteLine("======== BreachWatch Password Scan Results ========");
                foreach (var (password, status) in results)
                {
                    var masked = password.Length > 2
                        ? password[0] + new string('*', password.Length - 2) + password[^1]
                        : "***";
                    var breachStatus = status.BreachDetected ? "⚠ BREACHED" : "✓ Safe";
                    Console.WriteLine($"  {masked}: {breachStatus}");
                }
                Console.WriteLine("====================================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}