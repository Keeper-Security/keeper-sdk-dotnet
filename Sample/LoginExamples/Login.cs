using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

namespace Sample.LoginExamples
{
    public static class LoginExample
    {
        public static async Task LoginAsync()
        {
            try
            {
                var configurationStorage = new JsonConfigurationStorage("config.json");

                Console.Write("Enter Email Address: ");
                var username = Console.ReadLine();
                if (string.IsNullOrEmpty(username))
                {
                    Console.WriteLine("Username is required.");
                    return;
                }

                Console.Write("Enter Password: ");
                var password = Console.ReadLine();
                if (string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("Password is required.");
                    return;
                }

                var auth = new AuthSync(configurationStorage);
              

                await auth.Login(username, password);

                if (auth.Step is ErrorStep es)
                {
                    Console.WriteLine($"Authentication error: {es.Message}");
                    return;
                }

                if (!auth.IsAuthenticated())
                {
                    Console.WriteLine("Authentication failed.");
                    return;
                }

                Console.WriteLine("Login successful!");

                // Optionally sync the vault
                var vault = new VaultOnline(auth);
                await vault.SyncDown();
                Console.WriteLine($"Vault synced. Records: {vault.KeeperRecords.Count()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}