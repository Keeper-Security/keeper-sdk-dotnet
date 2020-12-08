﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Configuration;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;

namespace Sample
{
    public class AuthFlowCallback : IAuthFlowCallback
    {
        private readonly Action _onNextStep;
        private readonly Action<string> _onMessage;
        public AuthFlowCallback(Action onNextStep, Action<string> onMessage)
        {
            _onNextStep = onNextStep;
            _onMessage = onMessage;
        }

        public void OnNextStep()
        {
            _onNextStep?.Invoke();
        }
        public void OnMessage(string message)
        {
            _onMessage?.Invoke(message);
        }
    }

    internal static class Program
    {
        private static string ChannelText(this DeviceApprovalChannel channel)
        {
            switch (channel)
            {
                case DeviceApprovalChannel.Email: return "email";
                case DeviceApprovalChannel.KeeperPush: return "keeper";
                case DeviceApprovalChannel.TwoFactorAuth: return "2fa";
                default: return channel.ToString();
            }
        }

        private static string ChannelText(this TwoFactorChannel channel)
        {
            switch (channel)
            {
                case TwoFactorChannel.Authenticator: return "authenticator";
                case TwoFactorChannel.TextMessage: return "sms";
                case TwoFactorChannel.DuoSecurity: return "duo";
                case TwoFactorChannel.RSASecurID: return "rsa";
                case TwoFactorChannel.KeeperDNA: return "dna";
                case TwoFactorChannel.SecurityKey: return "key";
                default: return channel.ToString().ToLowerInvariant();
            }
        }

        private static string ExpireText(this TwoFactorDuration duration)
        {
            switch (duration)
            {
                case TwoFactorDuration.EveryLogin: return "now";
                case TwoFactorDuration.Forever: return "never";
                default: return $"{(int) duration}_days";
            }
        }

        private const string PushCommand = "push";
        private const string ChannelCommand = "channel";
        private const string ExpireCommand = "expire";
        private static readonly TwoFactorDuration[] Expires = {TwoFactorDuration.EveryLogin, TwoFactorDuration.Every30Days, TwoFactorDuration.Forever};

        private static void PrintStepPrompt(AuthStep step)
        {
            var prompt = "";
            if (step is DeviceApprovalStep das)
            {
                prompt = $"Device Approval ({das.DefaultChannel.ChannelText()})";
            }
            else if (step is TwoFactorStep tfs)
            {
                prompt = $"2FA ({tfs.DefaultChannel.ChannelText()}) [{tfs.Duration.ExpireText()}]";
            }
            else if (step is PasswordStep)
            {
                prompt = "Master Password";
            }

            Console.Write($"\n{prompt} > ");
        }

        private static void PrintStepHelp(AuthStep step)
        {
            var commands = new List<string>();
            if (step is DeviceApprovalStep das)
            {
                commands.Add($"\"{ChannelCommand}=<{string.Join(" | ", das.Channels.Select(x => x.ChannelText()))}>\" to select default channel");
                commands.Add($"\"{PushCommand}\" to send a push to the channel");
                commands.Add("<code> to send a code to the channel");
            }
            else if (step is TwoFactorStep tfs)
            {
                var pushes = tfs.Channels
                    .SelectMany(x => tfs.GetChannelPushActions(x) ?? Enumerable.Empty<TwoFactorPushAction>())
                    .Select(x => x.GetPushActionText())
                    .ToArray();
                if (pushes.Length > 0)
                {
                    commands.Add($"\"{string.Join(" | ", pushes)}\" to send a push");
                }

                commands.Add($"\"{ExpireCommand}=<{string.Join(" | ", Expires.Select(x => x.ExpireText()))}>\" to set 2fa expiration");
                if (tfs.Channels.Length > 1)
                {
                    commands.Add($"\"{ChannelCommand}=<{string.Join(" | ", tfs.Channels.Select(x => x.ChannelText()))}>\" to select default channel.");
                }

                commands.Add("<code>");
            }
            else if (step is PasswordStep)
            {
                commands.Add("<password>");
            }
            else if (step is HttpProxyStep)
            {
                Console.WriteLine("Http Proxy login is not supported yet.");
            }
            else if (step is SsoTokenStep || step is SsoDataKey)
            {
                Console.WriteLine("SSO login is not supported yet.");
            }

            Console.WriteLine();
            if (commands.Count > 0)
            {
                Console.WriteLine("\nAvailable commands:");
                Console.WriteLine($"{string.Join("\n", commands)}");
                Console.WriteLine("<Enter> to resume");
            }

            Console.WriteLine("<Ctrl-C> to quit");

            _hideInput = step is PasswordStep;
        }

        private static void ProcessCommand(AuthSyncFlow authFlow, string command)
        {
            if (command == "?")
            {
                PrintStepHelp(authFlow.Step);
                return;
            }

            if (authFlow.Step is DeviceApprovalStep das)
            {
                if (command.StartsWith($"{ChannelCommand}=", StringComparison.InvariantCultureIgnoreCase))
                {
                    var channelText = command.Substring(ChannelCommand.Length + 1).ToLowerInvariant();
                    var channel = das.Channels.FirstOrDefault(x => x.ChannelText() == channelText);
                    if (channel != default)
                    {
                        das.DefaultChannel = channel;
                    }
                    else
                    {
                        Console.WriteLine($"Device Approval push channel {channelText} not found.");
                    }
                }
                else if (string.Compare(command, PushCommand, StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    das.SendPush(das.DefaultChannel);
                }
                else
                {
                    das.SendCode(das.DefaultChannel, command);
                }
            }

            else if (authFlow.Step is TwoFactorStep tfs)
            {
                if (command.StartsWith($"{ChannelCommand}=", StringComparison.InvariantCultureIgnoreCase))
                {
                    var channelText = command.Substring(ChannelCommand.Length + 1).ToLowerInvariant();
                    var channel = tfs.Channels.FirstOrDefault(x => x.ChannelText() == channelText);
                    if (channel != default)
                    {
                        tfs.DefaultChannel = channel;
                    }
                    else
                    {
                        Console.WriteLine($"2FA channel {channelText} not found.");
                    }
                }
                else if (command.StartsWith($"{ExpireCommand}=", StringComparison.InvariantCultureIgnoreCase))
                {
                    var expireText = command.Substring(ExpireCommand.Length + 1).ToLowerInvariant();
                    var duration = Expires.FirstOrDefault(x => x.ExpireText() == expireText);
                    if (duration != default)
                    {
                        tfs.Duration = duration;
                    }
                }
                else
                {
                    var push = tfs.Channels
                        .SelectMany(x => tfs.GetChannelPushActions(x) ?? Enumerable.Empty<TwoFactorPushAction>())
                        .FirstOrDefault(x => x.GetPushActionText() == command);
                    if (push != default)
                    {
                        tfs.SendPush(push);
                    }
                    else
                    {
                        tfs.SendCode(tfs.DefaultChannel, command);
                    }
                }
            }
            else if (authFlow.Step is PasswordStep ps)
            {
                ps.VerifyPassword(command);
            }
            else
            {
                Console.WriteLine($"Invalid command. Type \"?\" to list available commands.");
            }
        }

        private static bool _hideInput;

        private static string ReadInput()
        {
            var input = "";
            while (true)
            {
                var key = Console.ReadKey(true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (char.IsControl(key.KeyChar))
                {
                    if (input.Length > 0)
                    {
                        input = input.Remove(input.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    input += key.KeyChar;
                    Console.Write(_hideInput ? "*" : key.KeyChar.ToString());
                }
            }

            return input;
        }

        private static async Task Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(-1); };

            // Keeper SDK needs a storage to save configuration
            // such as: last login name, device token, etc
            var jsonFile = new JsonConfigurationCache(new JsonConfigurationFileLoader("test.json"));
            IConfigurationStorage configuration = new JsonConfigurationStorage(jsonFile);


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

            var inReadLine = false;

            var authFlow = new AuthSyncFlow(configuration);
            authFlow.UiCallback = new AuthFlowCallback(() =>
                {
                    if (!inReadLine) return;
                    if (authFlow.Step.State == AuthState.Connected || authFlow.Step.State == AuthState.Error)
                    {
                        Console.WriteLine("Press <Enter>");
                    }
                    else
                    {
                        PrintStepHelp(authFlow.Step);
                        PrintStepPrompt(authFlow.Step);
                    }
                },
                Console.WriteLine);

            // Login to Keeper
            if (authFlow.Step is LoginStep ls)
            {
                Console.WriteLine("Logging in...");
                ls.Login(username);
            }

            var lastState = AuthState.Login;
            while (authFlow.Step.State != AuthState.Connected)
            {
                if (authFlow.Step.State != lastState)
                {
                    PrintStepHelp(authFlow.Step);
                }

                lastState = authFlow.Step.State;
                PrintStepPrompt(authFlow.Step);
                inReadLine = true;
                var cmd = ReadInput();
                inReadLine = false;
                if (string.IsNullOrEmpty(cmd)) continue;

                try
                {
                    ProcessCommand(authFlow, cmd);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            var auth = authFlow.Auth;
            if (!auth.IsAuthenticated()) return;
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

            var nsd3 = vault.LoadNonSharedData<NonSharedData3>(search.Uid);
            nsd3.Data1 = "1";
            nsd3.Data3 = "3";
            await vault.StoreNonSharedData(search.Uid, nsd3);

            var nsd2 = vault.LoadNonSharedData<NonSharedData2>(search.Uid);
            nsd2.Data2 = "2";
            await vault.StoreNonSharedData(search.Uid, nsd2);

            // Update record.
            search.SetCustomField("Security Token", "11111111");
            search = await vault.UpdateRecord(search);

            // find file attachment.
            var attachment = search.Attachments
                .FirstOrDefault(x => string.Compare(x.Title, "google", StringComparison.InvariantCultureIgnoreCase) == 0);

            if (attachment == null)
            {
                // Upload local file "google.txt". 
                // var uploadTask = new FileAttachmentUploadTask("google.txt")
                var fileContent = Encoding.UTF8.GetBytes("Google");
                using (var stream = new MemoryStream(fileContent))
                {
                    var uploadTask = new AttachmentUploadTask(stream)
                    {
                        Title = "Google",
                        Name = "google.txt",
                        MimeType = "text/plain"
                    };
                    await vault.UploadAttachment(search, uploadTask);
                    await vault.UpdateRecord(search, false);
                }
            }
            else
            {
                // Download attachment into the stream
                // The stream could be a local file "google.txt"
                // using (var stream = File.OpenWrite("google.txt"))
                using (var stream = new MemoryStream())
                {
                    await vault.DownloadAttachment(search, attachment.Id, stream);
                }

                // Delete attachment. Remove it from the record 
                search.Attachments.Remove(attachment);
                await vault.UpdateRecord(search, false);
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
            try
            {
                await vault.PutUserToSharedFolder(sharedFolder.Uid,
                    "user@google.com",
                    UserType.User,
                    new SharedFolderUserOptions
                    {
                        ManageRecords = false,
                        ManageUsers = false,
                    });
            }
            catch (Exception e)
            {
                Console.WriteLine($"Add user to Shared Folder error: {e.Message}");
            }


            // Add record to shared folder.
            await vault.MoveRecords(new[] {new RecordPath {RecordUid = search.Uid}}, sharedFolder.Uid, true);

            if (auth.AuthContext.IsEnterpriseAdmin)
            {
                // Load enterprise data.
                var enterprise = new EnterpriseData(auth);
                await enterprise.GetEnterpriseData();

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

    public class NonSharedData1 : RecordNonSharedData
    {
        [DataMember(Name = "data1")]
        public string Data1 { get; set; }
    }

    public class NonSharedData2 : RecordNonSharedData
    {
        [DataMember(Name = "data2")]
        public string Data2 { get; set; }
    }

    public class NonSharedData3 : NonSharedData1
    {
        [DataMember(Name = "data3")]
        public string Data3 { get; set; }
    }

}