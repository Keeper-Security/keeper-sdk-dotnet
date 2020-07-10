This folder is a sample Commander CLI application using the .NET SDK.  Below is a code sample that connects to Keeper and loads a vault.

### Sample C# application

```csharp
using System;
using System.Threading.Tasks;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;

namespace SimpleSdkConsoleApp
{
    class AuthUi : IAuthUI
    {
        public Task<bool> Confirmation(string information)
        {
            return Task.FromResult(false); // cancel any dialogs.
        }

        public Task<string> GetNewPassword(PasswordRuleMatcher matcher)
        {
            return Task.FromResult(""); // do not change expired password. 
        }

        public Task<TwoFactorCode> GetTwoFactorCode(TwoFactorCodeChannel provider)
        {
            // ask for second factor authorization code:
            // 1. Google / Microsoft Authenticator
            // 2. Backup code
            // 3. Code received in SMS

            return Task.Run(() =>
            {
                Console.Write("Enter 2FA Code: ");
                var code = Console.ReadLine();
                return new TwoFactorCode(code, TwoFactorCodeDuration.Forever);
            });
        }
    }

    internal class Program
    {
        private static async Task Main()
        {
            // Keeper SDK needs a storage to save some parameters 
            // such as: last login name, 2FA device token, etc
            // 
            //var configuration = new InMemoryConfigurationStorage();
            //
            IConfigurationStorage configuration = new JsonConfigurationStorage("test.json");
            var auth = new Auth(new AuthUi(), configuration);

            var prompt = "Enter Email Address: ";
            if (!string.IsNullOrEmpty(configuration.LastLogin))
            {
                Console.WriteLine($"Default Email Address: {configuration.LastLogin}");
            }

            Console.Write(prompt);
            var username = Console.ReadLine();
            if (string.IsNullOrEmpty(username))
            {
                if (string.IsNullOrEmpty(configuration.LastLogin))
                {
                    Console.WriteLine("Bye.");
                    return;
                }

                username = configuration.LastLogin;
            }

            var password = "";
            Console.Write("Enter Password: ");
            while (true)
            {
                var key = Console.ReadKey(true);

                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }

                if (char.IsControl(key.KeyChar))
                {
                    password = password.Remove(password.Length - 1);
                    Console.Write("\b \b");
                }
                else
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
            }

            if (string.IsNullOrEmpty(password))
            {
                Console.WriteLine("Bye.");
                return;
            }

            Console.WriteLine();

            // Login to Keeper
            Console.WriteLine("Logging in...");
            await auth.Login(username, password);

            var vault = new Vault(auth);
            Console.WriteLine("Retrieving records...");
            await vault.SyncDown();

            Console.WriteLine($"Hello {username}!");
            Console.WriteLine($"Vault has {vault.RecordCount} records.");
        }
    }
}
```
