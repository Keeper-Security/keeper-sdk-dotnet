using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections;
using KeeperSecurity.Commands;
using System;
using System.Linq;

namespace Sample.SecretManagerExamples
{
    public static class AppListExample
    {
        public static async Task AppList()
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            Console.WriteLine(
                    $"{"#",4}  " +
                    $"{"UID",-30}" +
                    $"{"Title",-25}  "

                );
            Console.WriteLine(new string('-', 80));
            int index = 1;

            foreach (var app in vault.KeeperRecords.OfType<ApplicationRecord>())
            {
                Console.WriteLine(
                       $"{index,4}  " +
                       $"{app.Uid,-30}  " +
                       $"{app.Title,-25}  "
                   );
                index++;
            }

        }

    }
}
