using System;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Vault;

namespace Sample.LoginExamples
{
    public static class WhoamiExample
    {
        public static async Task WhoamiAsync(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {
                var auth = vault.Auth;
                var license = auth.AuthContext.License;

                Console.WriteLine("=== Who Am I ===");
                Console.WriteLine($"User: {auth.Username}");
                Console.WriteLine($"Server: {auth.Endpoint.Server}");
                Console.WriteLine($"Data Center: {GetDataCenter(auth.Endpoint.Server)}");
                var environment = GetEnvironment(auth.Endpoint.Server);
                if (!string.IsNullOrEmpty(environment))
                {
                    Console.WriteLine($"Environment: {environment}");
                }
                Console.WriteLine($"Admin: {(auth.AuthContext.IsEnterpriseAdmin ? "Yes" : "No")}");
                Console.WriteLine($"Account Type: {license.AccountType}");
                Console.WriteLine($"Renewal Date: {license.ExpirationDate}");
                Console.WriteLine($"Storage Capacity: {license.BytesTotal / (1024 * 1024 * 1024)}GB");
                Console.WriteLine($"Storage Usage: {license.BytesUsed / (1024 * 1024 * 1024)}GB");
                Console.WriteLine($"Storage Expires: {license.StorageExpirationDate}");
                Console.WriteLine($"License Type: {license.ProductTypeName}");
                Console.WriteLine($"License Expires: {license.ExpirationDate}");
                Console.WriteLine($"BreachWatch: {(auth.IsBreachWatchEnabled() ? "Yes" : "No")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static string GetDataCenter(string hostname)
        {
            if (hostname.EndsWith(".com"))
            {
                return "US";
            }
            else if (hostname.EndsWith("eu"))
            {
                return "EU";
            }
            else if (hostname.EndsWith("govcloud.keepersecurity.us"))
            {
                return "US GOV";
            }
            else if (hostname.EndsWith(".au"))
            {
                return "AU";
            }
            else
            {
                return hostname;
            }
        }

        private static string GetEnvironment(string hostname)
        {
            if (hostname.StartsWith("dev."))
            {
                return "DEV";
            }
            else if (hostname.StartsWith("qa."))
            {
                return "QA";
            }
            else if (hostname.EndsWith("local"))
            {
                return "LOCAL";
            }
            return string.Empty;
        }
    }
}
