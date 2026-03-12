using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.SecretManagerExamples
{
    public static class AppListExample
    {
        public static async Task AppList(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var apps = vault.KeeperRecords.OfType<ApplicationRecord>().ToList();

            if (apps.Count == 0)
            {
                Console.WriteLine("No applications found in the vault.");
                return;
            }

            Console.WriteLine(
                $"{"#",4}  " +
                $"{"UID",-30}" +
                $"{"Title",-25}"
            );
            Console.WriteLine(new string('-', 65));

            int index = 1;
            foreach (var app in apps)
            {
                Console.WriteLine(
                    $"{index,4}  " +
                    $"{app.Uid,-30}  " +
                    $"{app.Title,-25}"
                );
                index++;
            }

            Console.WriteLine($"\nTotal: {apps.Count} application(s)");
        }
    }
}
