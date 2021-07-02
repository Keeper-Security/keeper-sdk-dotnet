This folder is a sample Commander CLI application using the .NET SDK.  Below is a code sample that connects to Keeper and loads a vault.

### Sample Commander application reference 

* ```login``` Login to Keeper

* ```logout``` Logout from Keeper

* ```sync-down``` or ```d``` Download, sync and decrypt vault

* ```list``` or ```ls``` List all records (try ```ls -l``` as well)

* ```tree``` Display entire folder structure as a tree

* ```cd``` Change current folder

* ```get``` Retrieve and display specified Keeper Record/Folder/Team in printable or JSON format

* ```mkdir``` Create a regular or shared folder in the vault

* ```rmdir``` Delete folder and its content

* ```mv``` Move record or folder to another location

* ```rm``` Remove record

** Shared Folder Commands **

* ```sf-list``` Display all shared folders

* ```sf-user``` Manage user or team access for shared folder

* ```sf-record``` Change record permissions. Use `mv` or `rm` commands to add/remove record to/from shared folder

** Device Management Commands **

* ```devices``` Manage device approval queue

* ```this-device``` Display or modify current device settings

** Record Management Commands **

* ```add-record``` Add a record to the vault

* ```update-record``` Update a record contents such as the password

** Enterprise Commands **

* ```enterprise-get-data``` Retrieve enterprise data structure

* ```enterprise-node``` Display enterprise node tree

* ```enterprise-user``` Display a list of enterprise users

* ```enterprise-team``` Display a list of enterprise users, manage team's users

* ```enterprise-role``` Display a list of enterprise roles, manage role's users and teams

* ```enterprise-device``` Manage admin approval queue. Cloud SSO only.

### Sample C# .Net Core application

```csharp
using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;

namespace SimpleSdkConsoleApp
{
    class AuthUi : IAuthUI
    {
        public Task<string> GetMasterPassword(string username)
        {
            string password = null;
            if (string.IsNullOrEmpty(password))
            {
                Console.Write("\nEnter Master Password: ");
                password = HelperUtils.ReadLineMasked();
            }

            return Task.FromResult(password);
        }

        public Task<TwoFactorCode> GetTwoFactorCode(TwoFactorChannel channel, ITwoFactorChannelInfo[] channels, CancellationToken token)
        {
            Console.Write("\nEnter 2FA Code: ");
            var code = Console.ReadLine();
            return Task.FromResult(new TwoFactorCode(channel, code, TwoFactorDuration.Forever));
        }

        public Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        {
            var tokenSource = new TaskCompletionSource<bool>();
            _ = Task.Run(async () => {
                var emailChannel = channels.FirstOrDefault(x => x.Channel == DeviceApprovalChannel.Email);
                if (emailChannel is IDeviceApprovalPushInfo pi)
                {
                    await pi.InvokeDeviceApprovalPushAction.Invoke(TwoFactorDuration.EveryLogin);
                }
                Console.WriteLine("\nDevice Approval\n\nCheck your email, approve your device by clicking verification link\n<Esc> to cancel");

                var complete = false;
                void onApprove()
                {
                    complete = true;
                }
                using (var reg = token.Register(onApprove))
                {
                    while (!complete)
                    {
                        while (Console.KeyAvailable)
                        {
                            var ch = Console.ReadKey(true);
                            if (ch.Key == ConsoleKey.Escape) {
                                complete = true;
                                tokenSource.TrySetResult(false);
                                break;
                            }
                        }
                        if (!complete) {
                            await Task.Delay(200);
                        }
                        var answer = Console.ReadLine();
                    }
                }
            });
            return tokenSource.Task;
        }
    }

    internal class Program
    {
        private static async Task Main()
        {
            // Keeper SDK needs a storage to save some parameters 
            // such as: last login name, device information, etc
            // 
            //
            IConfigurationStorage configuration = new JsonConfigurationStorage();
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


            Console.WriteLine();

            // Login to Keeper
            Console.WriteLine("Logging in...");
            await auth.Login(username);

            var vault = new Vault(auth);
            Console.WriteLine("Retrieving records...");
            await vault.SyncDown();

            Console.WriteLine($"Hello {username}!");
            Console.WriteLine($"Vault has {vault.RecordCount} records.");
        }
    }
    public static class HelperUtils
    {
        public static string ReadLineMasked(char mask = '*')
        {
            var sb = new StringBuilder();
            ConsoleKeyInfo keyInfo;
            while ((keyInfo = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                if (!char.IsControl(keyInfo.KeyChar))
                {
                    sb.Append(keyInfo.KeyChar);
                    Console.Write(mask);
                }
                else if (keyInfo.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);

                    if (Console.CursorLeft == 0)
                    {
                        Console.SetCursorPosition(Console.BufferWidth - 1, Console.CursorTop - 1);
                        Console.Write(' ');
                        Console.SetCursorPosition(Console.BufferWidth - 1, Console.CursorTop - 1);
                    }
                    else Console.Write("\b \b");
                }
            }

            Console.WriteLine();
            return sb.ToString();
        }
    }
}```
