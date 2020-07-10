### Password Management SDK for IT Admins & Developers

Keeper Security develops the world's most downloaded password manager and encrypted digital vault with millions of individual customers and thousands of enterprise customers worldwide.  Keeper is a zero-knowledge, native and cloud-based solution available on every mobile and desktop device platform. <a href="#about-keeper">Read more</a> about Keeper or visit the [Keeper Security](https://keepersecurity.com) website.

### .Net and PowerShell SDK for Keeper Password Manager

The Keeper .Net and PowerShell module ("PowerCommander") provides basic vault API access. The current features of the .Net and PowerShell library include the following:

* Access your Keeper vault (records, folders, shared folders)
* Manage records, folders and shared folders
* Customize integration into your backend systems
* Update/Rotate passwords in the vault

### PowerShell Module
To use the PowerShell modules, see the [PowerCommander library](https://github.com/Keeper-Security/keeper-sdk-dotnet/tree/master/PowerCommander).

### .Net SDK
For integration into your .Net systems, please utilize the [KeeperSDK library](https://github.com/Keeper-Security/Commander/tree/master/dotnet-keeper-sdk/KeeperSdk).

### Sample App
For help with implementation of SDK features, please see the [Commander CLI](https://github.com/Keeper-Security/Commander/tree/master/dotnet-keeper-sdk/Commander) sample application.  This application contains several basic operations such as logging in, authentication with two-factor, loading and decrypting the vault and updating passwords.

### Developer Requirements for KeeperSDK Library

* .Net Framework 4.6.1
* .Net Core 2.1
* .Net Standard 2.0

### Sample Commander application reference 

* ```login``` Login to Keeper

* ```logout``` Logout from Keeper

* ```sync-down``` or ```d``` Download, sync and decrypt vault

* ```list``` or ```ls``` List all records (try ```ls -l``` as well)

* ```tree``` Display entire folder structure as a tree

* ```cd``` Change current folder

* ```get``` Retrieve and display specified Keeper Record/Folder/Team in printable or JSON format.

* ```list-sf``` Display all shared folders

**Record Management Commands**

* ```add-record``` Add a record to the vault

* ```update-record``` Update a record contents such as the password

If you need any assistance or require specific functionality not supported in Commander yet, please contact us at commander@keepersecurity.com.

### Sample C# application.

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

### About Keeper Security

Keeper is a Zero Knowledge security provider. Zero Knowledge is a system architecture that guarantees the highest levels of security and privacy by adhering to the following principles:

- Data is encrypted and decrypted at the device level (not on the server)
- The application never stores plain text (human readable) data
- The server never receives data in plain text
- No Keeper employee or 3rd party can view the unencrypted data
- The keys to decrypt and encrypt data are derived from the user’s master password
- Multi-Layer encryption provides access control at the user, group and admin level
- Sharing of data uses Public Key Cryptography for secure key distribution

Data is encrypted locally on the user’s device before it is transmitted and stored in Keeper’s Cloud Security Vault. When data is synchronized to another device, the data remains encrypted until it is decrypted on the other device.

Keeper is the most secure, certified, tested and audited password security platform in the world. We are the only SOC 2 and ISO 27001 certified password management solution in the industry and Privacy Shield Compliant with the U.S. Department of Commerce's EU-U.S. Privacy Shield program, meeting the European Commission's Directive on Data Protection. Not only do we implement the most secure levels of encryption, we also adhere to very strict internal practices that are continually audited by third parties to help ensure that we continue to develop secure software and provide the world’s most secure cybersecurity platform.

If you have any questions, please email commander@keepersecurity.com.

