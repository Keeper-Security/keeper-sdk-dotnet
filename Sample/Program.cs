//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2021 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Commands;
using KeeperSecurity.Configuration;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;

namespace Sample
{
    internal static class Program
    {
        private static async Task Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(-1); };

            // Keeper SDK needs a storage to save configuration
            // such as: last login name, device token, etc
            var configuration = new JsonConfigurationStorage("config.json");
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

            var inputManager = new SimpleInputManager();

            // Login to Keeper
            Console.WriteLine("Logging in...");
            var authFlow = new AuthSync(configuration);
            await Utils.LoginToKeeper(authFlow, inputManager, username);

            if (authFlow.Step is ErrorStep es)
            {
                Console.WriteLine(es.Message);
                return;
            }
            if (!authFlow.IsAuthenticated()) return;

            var auth = authFlow;

            var vault = new VaultOnline(auth);
            Console.WriteLine("Retrieving records...");
            await vault.SyncDown();

            Console.WriteLine($"Hello {username}!");
            Console.WriteLine($"Vault has {vault.RecordCount} records.");

            // Find record with title "Google"
            var search = vault
                .KeeperRecords
                .Where(x => x.Version == 2 || x.Version == 3)
                .FirstOrDefault(x => string.Compare(x.Title, "Google", StringComparison.InvariantCultureIgnoreCase) == 0);
            // Create a record if it does not exist.
            if (search == null)
            {
                var loginRecord = new TypedRecordFacade<LoginRecordType>();
                loginRecord.Fields.Login = "<Account Name>";
                loginRecord.Fields.Password = "<Account Password>";
                loginRecord.Fields.Url = "https://google.com";

                var typed = loginRecord.TypedRecord;
                typed.Title = "Google";
                typed.Notes = "Stores google credentials";

                search = typed;
                search = await vault.CreateRecord(search);
            }

            var nsd3 = vault.LoadNonSharedData<NonSharedData3>(search.Uid);
            nsd3.Data1 = "1";
            nsd3.Data3 = "3";
            await vault.StoreNonSharedData(search.Uid, nsd3);

            var nsd2 = vault.LoadNonSharedData<NonSharedData2>(search.Uid);
            nsd2.Data2 = "2";
            await vault.StoreNonSharedData(search.Uid, nsd2);

            // Update record
            if (search is PasswordRecord password)
            {
                var cf = password.GetCustomField("Security Token");
                var tokenValue = cf?.Value ?? "1";
                password.SetCustomField("Security Token", tokenValue + "1");
            }
            else if (search is TypedRecord typed) 
            {
                var recordField = new RecordTypeField("text", "Security Token");
                if (!typed.FindTypedField(recordField, out var rf)) {

                    rf = recordField.CreateTypedField();
                    typed.Custom.Add(rf);
                }
                var tokenValue = rf.ObjectValue == null ? "1" : rf.ObjectValue.ToString();
                rf.ObjectValue = tokenValue + 1;
            }
            search = await vault.UpdateRecord(search);


            var attachment = vault.RecordAttachments(search)
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

                await vault.DeleteAttachment(search, attachment.Id);
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
                var enterprise = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(auth, new[] { enterprise });
                await enterpriseLoader.Load();

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