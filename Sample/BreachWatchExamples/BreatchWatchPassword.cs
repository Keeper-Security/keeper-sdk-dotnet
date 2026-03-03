using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Vault;
using BWService = KeeperSecurity.BreachWatch.BreachWatch;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchPasswordExample
    {
        public static async Task BreachWatchPassword(VaultOnline vault = null,
            IEnumerable<(string Password, byte[] Euid)> passwordEntries = null,
            CancellationToken cancellationToken = default)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {

                if (!vault.Auth.IsBreachWatchEnabled())
                {
                    Console.WriteLine("BreachWatch is not enabled for this account.");
                    return;
                }

                await BWService.InitializeBreachWatch(vault.Auth);

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
                    var breachStatus = status.BreachDetected ? "BREACHED" : "SAFE";
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