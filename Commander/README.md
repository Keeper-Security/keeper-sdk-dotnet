This folder is a sample Commander CLI application using the .NET SDK.  Below is a code sample that connects to Keeper and loads a vault.

### Commander CLI Commands Reference

#### Authentication Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `sync-down` | `d` | Download & decrypt data |
| `logout` | | Logout |
| `whoami` | | Display information about the currently logged in user |

#### Vault Navigation & Search
| Command | Alias | Description |
|---------|-------|-------------|
| `search` | `list` | Search the vault. Can use a regular expression |
| `ls` | | List folder content |
| `cd` | | Change current folder |
| `tree` | | Display folder structure |

#### Record Management
| Command | Alias | Description |
|---------|-------|-------------|
| `get` | | Get information about any Keeper object (record, folder, team, etc.) |
| `add-record` | `add` | Add record |
| `update-record` | `edit` | Update record |
| `rm` | | Remove record(s) |
| `mv` | | Move record or folder |
| `record-history` | | Display record history |
| `record-type-info` | `rti` | Get record type info |
| `share-record` | | Change the sharing permissions of an individual record |

#### Attachment Management
| Command | Alias | Description |
|---------|-------|-------------|
| `download-attachment` | | Download Attachment(s) |
| `upload-attachment` | | Upload file attachment |
| `delete-attachment` | | Delete attachment |

#### Folder Management
| Command | Alias | Description |
|---------|-------|-------------|
| `mkdir` | | Make folder |
| `rmdir` | | Remove folder |
| `update-dir` | | Update folder |

#### Shared Folder Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `sf-list` | | List shared folders |
| `sf-user` | | Change shared folder user permissions |
| `sf-record` | | Change shared folder record permissions |

#### Trash Management
| Command | Alias | Description |
|---------|-------|-------------|
| `trash` | | Manage deleted records in trash |

#### Device Management
| Command | Alias | Description |
|---------|-------|-------------|
| `devices` | | Devices (other than current) commands |
| `this-device` | | Current device command |

#### Enterprise Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `enterprise-get-data` | `eget` | Retrieve enterprise data |
| `enterprise-node` | `en` | Manage Enterprise Nodes |
| `enterprise-user` | `eu` | Manage Enterprise Users |
| `enterprise-team` | `et` | Manage Enterprise Teams |
| `enterprise-role` | `er` | Manage Enterprise Roles |
| `enterprise-device` | `ed` | Manage User Devices |
| `transfer-user` | | Transfer User Account |
| `extend-account-share-expiration` | | Extend Account Share Expiration |
| `audit-report` | | Run an audit trail report |

#### Record Type Management
| Command | Alias | Description |
|---------|-------|-------------|
| `record-type-add` | | Add a new Record Type |
| `record-type-update` | | Updates a Record Type of given ID |
| `record-type-delete` | | Deletes a Record Type of given ID |
| `load-record-types` | | Loads Record Types to keeper from given file |
| `download-record-types` | | Downloads Record Types from keeper to given file |

#### Security & Reporting
| Command | Alias | Description |
|---------|-------|-------------|
| `password-report` | | Generate comprehensive password security report |
| `breachwatch` | | BreachWatch commands |

#### Other Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `ksm` | | Keeper Secret Manager commands |
| `one-time-share` | | Manage One Time Shares |
| `import` | | Imports records from JSON file |
| `clear` | `c` | Clears the screen |
| `quit` | `q` | Quit |

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
