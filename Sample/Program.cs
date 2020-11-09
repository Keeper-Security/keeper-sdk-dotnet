using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Configuration;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;

namespace Sample
{
    class AuthUi : IAuthUI
    {
        public async Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        {
            Console.WriteLine("Device Approval");
            foreach (var ci in channels)
            {
                switch (ci.Channel)
                {
                    case DeviceApprovalChannel.Email:
                        Console.WriteLine("'email' to send email");
                        break;
                    case DeviceApprovalChannel.KeeperPush:
                        Console.WriteLine("'push' to send Keeper Push notification");
                        break;
                    case DeviceApprovalChannel.TwoFactorAuth:
                        Console.WriteLine("'tfa' to send 2FA code");
                        Console.WriteLine("<code> provided by your 2FA application");
                        break;
                }
            }

            Console.WriteLine("<Enter> to resume, 'q' to cancel");

            var result = true;
            Console.Write("Device Approval Action: ");
            var action = Console.ReadLine();
            try
            {
                if (!string.IsNullOrEmpty(action))
                {
                    switch (action)
                    {
                        case "q":
                            result = false;
                            break;
                        case "email":
                        case "push":
                        case "tfa":
                        {
                            var channel = channels.FirstOrDefault(x =>
                            {
                                return x.Channel switch
                                {
                                    DeviceApprovalChannel.Email => action == "email",
                                    DeviceApprovalChannel.KeeperPush => action == "push",
                                    DeviceApprovalChannel.TwoFactorAuth => action == "tfa",
                                    _ => false,
                                };
                            });
                            if (channel != null)
                            {
                                if (channel is IDeviceApprovalPushInfo pi)
                                {
                                    if (channel is ITwoFactorDurationInfo dur)
                                    {
                                        dur.Duration = TwoFactorDuration.Every30Days;
                                    }

                                    await pi.InvokeDeviceApprovalPushAction();
                                }

                                if (channel is IDeviceApprovalOtpInfo)
                                {
                                    Console.WriteLine("'<code>' provide your code");
                                }

                                Console.Write("<Enter> when device is approved\n> ");
                                var code = Console.ReadLine();
                                if (channel is IDeviceApprovalOtpInfo oi && !string.IsNullOrEmpty(code))
                                {
                                    await oi.InvokeDeviceApprovalOtpAction(code);
                                }

                            }
                        }
                            break;
                        default:
                        {
                            var channel = channels.FirstOrDefault(x => x.Channel == DeviceApprovalChannel.TwoFactorAuth);
                            if (channel != null)
                            {
                                if (channel is IDeviceApprovalOtpInfo oi)
                                {
                                    if (channel is ITwoFactorDurationInfo dur)
                                    {
                                        dur.Duration = TwoFactorDuration.Every30Days;
                                    }

                                    await oi.InvokeDeviceApprovalOtpAction(action);
                                }
                            }
                        }
                            break;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        public Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token)
        {
            Console.WriteLine("\nTwo Factor Authentication\n");
            return Task.Run(async () =>
                {
                    Console.Write("Enter 2FA Code: ");
                    var code = Console.ReadLine();
                    if (!string.IsNullOrEmpty(code)) return false;
                    if (!(channels[0] is ITwoFactorAppCodeInfo ci)) return true;
                    try
                    {
                        await ci.InvokeTwoFactorCodeAction(code);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }

                    return true;

                },
                token);
        }

        public Task<bool> WaitForUserPassword(IPasswordInfo info, CancellationToken token)
        {
            Console.WriteLine("\nMaster Password\n");
            return Task.Run(async () =>
                {
                    while (true)
                    {
                        var password = "";
                        Console.Write("Enter Master Password: ");
                        while (true)
                        {
                            var key = Console.ReadKey(true);

                            if (key.Key == ConsoleKey.Enter) break;

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

                        if (string.IsNullOrEmpty(password)) break;
                        try
                        {
                            await info.InvokePasswordActionDelegate(password);
                            break;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }

                    return true;
                },
                token);
        }
    }

    internal static class Program
    {
        private static async Task Main()
        {
            // Keeper SDK needs a storage to save configuration
            // such as: last login name, device token, etc
            var jsonFile = new JsonConfigurationCache(new JsonConfigurationFileLoader("test.json"));
            IConfigurationStorage configuration = new JsonConfigurationStorage(jsonFile);
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

            // Login to Keeper
            Console.WriteLine("Logging in...");
            await auth.Login(username);
            if (auth.IsAuthenticated())
            {
                var vault = new VaultOnline(auth);
                Console.WriteLine("\nRetrieving records...");
                await vault.SyncDown();

                Console.WriteLine($"Hello {username}!");
                Console.WriteLine($"Vault has {vault.RecordCount} records.");

                // Find record with title "Google"
                var search = vault.Records.FirstOrDefault(x => string.Compare(x.Title, "Google", StringComparison.InvariantCultureIgnoreCase) == 0);
                // Create a record if it does not exist.
                if (search == null)
                {
                    search = new PasswordRecord
                    {
                        Title = "Google",
                        Login = "<Account Name>",
                        Password = "<Account Password>",
                        Link = "https://google.com",
                        Notes = "Stores google credentials"
                    };
                    search = await vault.CreateRecord(search);
                }

                // Update record.
                search.SetCustomField("Security Token", "11111111");
                search = await vault.UpdateRecord(search);

                // find file attachment.
                var attachment = search.Attachments
                    .FirstOrDefault(x => string.Compare(x.Title, "google", StringComparison.InvariantCultureIgnoreCase) == 0);

                if (attachment == null)
                {
                    // Upload local file "google.txt"
                    var uploadTask = new FileAttachmentUploadTask("google.txt")
                    {
                        Title = "Google",
                    };
                    await vault.UploadAttachment(search, uploadTask);
                }
                else
                {
                    // Download attachment into local file "google.txt"
                    await using var stream = File.OpenWrite("google.txt");
                    await vault.DownloadAttachment(search, attachment.Id, stream);

                    // Delete attachment. Remove it from the record 
                    search.Attachments.Remove(attachment);
                    await vault.UpdateRecord(search);
                }

                // Find shared folder with name "Google".
                var sharedFolder = vault.SharedFolders
                    .FirstOrDefault(x => string.Compare(x.Name, "Google", StringComparison.InvariantCultureIgnoreCase) == 0);
                if (sharedFolder == null)
                {
                    // Create shared folder.
                    var folder = await vault.CreateFolder("Google",
                        null,
                        new SharedFolderOptions
                        {
                            ManageRecords = true,
                            ManageUsers = false,
                            CanEdit = false,
                            CanShare = false,
                        });
                    vault.TryGetSharedFolder(folder.FolderUid, out sharedFolder);
                }

                // Add user to shared folder.
                await vault.PutUserToSharedFolder(sharedFolder.Uid,
                    "user@google.com",
                    UserType.User,
                    new SharedFolderUserOptions
                    {
                        ManageRecords = false,
                        ManageUsers = false,
                    });

                // Add record to shared folder.
                await vault.MoveRecords(new[] {new RecordPath {RecordUid = search.Uid}}, sharedFolder.Uid, true);

                if (auth.AuthContext.IsEnterpriseAdmin)
                {
                    // Load enterprise data.
                    var enterprise = new EnterpriseData(auth);

                    // Find team with name "Google".
                    var team = enterprise.Teams
                        .FirstOrDefault(x => string.Compare(x.Name, "Google", StringComparison.InvariantCultureIgnoreCase) == 0);
                    if (team == null)
                    {
                        // Create team.
                        team = await enterprise.CreateTeam(new EnterpriseTeam
                        {
                            Name = "Google",
                            RestrictEdit = false,
                            RestrictSharing = true,
                            RestrictView = false,
                        });
                    }

                    if (team != null)
                    {
                        // Add users to the "Google" team.
                        await enterprise.AddUsersToTeams(
                            new[] {"username@company.com", "username1@company.com"},
                            new[] {team.Uid},
                            Console.WriteLine);
                    }
                }

                Console.WriteLine("Press any key to quit");
                Console.ReadKey();
            }
        }
    }
}