using Cli;
using CommandLine;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    internal static class SecretManagerCommandExtensions
    {
        public static async Task OneTimeShareCommand(this VaultContext context, OneTimeShareOptions arguments)
        {
            if (context.Vault.TryGetKeeperRecord(arguments.Record, out var record))
            {
            }
            else if (context.TryResolvePath(arguments.Record, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!context.Vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }
            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {arguments.Record}");
                return;
            }

            if (arguments.Command == "create")
            {
                if (string.IsNullOrEmpty(arguments.Expire))
                {
                    Console.WriteLine("--expire argument is required");
                    return;
                }
                var exp = TimeSpan.FromHours(1);
                var cnt = arguments.Expire;
                var p = 'h';
                if (char.IsLetter(arguments.Expire[arguments.Expire.Length - 1]))
                {
                    p = arguments.Expire[arguments.Expire.Length - 1];
                    cnt = cnt.Substring(0, cnt.Length - 1);
                }
                if (!int.TryParse(cnt, out int res))
                {
                    Console.WriteLine($"Invalid expiration {arguments.Expire}");
                    return;
                }
                switch (p)
                {
                    case 'm':
                        exp = TimeSpan.FromMinutes(res); break;
                    case 'h':
                        exp = TimeSpan.FromHours(res); break;
                    case 'd':
                        exp = TimeSpan.FromDays(res); break;
                }
                if (exp.TotalDays > 180)
                {
                    Console.WriteLine($"One time share URL expiration cannot exceed 180 days");
                    return;
                }
                var url = await context.Vault.CreateExternalRecordShare(record.Uid, exp, arguments.Client);
                Console.WriteLine($"URL: {url}");
            }
            else if (arguments.Command == "delete")
            {
                if (string.IsNullOrEmpty(arguments.Client))
                {
                    Console.WriteLine("--client argument is required");
                    return;
                }

                var shares = (await context.Vault.GetExernalRecordShares(record.Uid))
                    .Where(x => arguments.Client == "@all" || x.ClientId == arguments.Client || string.Equals(x.Name, arguments.Client, StringComparison.CurrentCultureIgnoreCase))
                    .ToArray();
                if (shares.Length > 0)
                {
                    await context.Vault.DeleteExernalRecordShares(record.Uid, shares.Select(x => x.ClientId));
                }
                else
                {
                    Console.WriteLine($"Client {arguments.Client} not found");
                }
            }
            else if (arguments.Command == "list")
            {
                var shares = await context.Vault.GetExernalRecordShares(record.Uid);
                var tab = new Tabulate(8)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] { "Record UID", "Record Title", "Share Name", "Generated", "Opened", "Expires" });
                foreach (var share in shares)
                {
                    tab.AddRow(new object[] { record.Uid, record.Title, share.Name,
                        share.CreatedOn.ToString("g"), share.FirstAccessed.HasValue ? share.FirstAccessed.Value.ToString("g") : "",
                        share.AccessExpiresOn.ToString("g")
                    });
                }

                tab.Sort(4);
                tab.Dump();
            }
            else
            {
                Console.WriteLine($"Action {arguments.Command} is not supported.");
            }
        }

        public static async Task SecretManagerCommand(this VaultContext context, SecretManagerOptions arguments)
        {
            var action = (string.IsNullOrEmpty(arguments.Command) ? "list" : arguments.Command).ToLowerInvariant();

            if (action == "list")
            {
                var tab = new Tabulate(2)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] { "Application UID", "Title" });
                foreach (var app in context.Vault.KeeperRecords.OfType<ApplicationRecord>())
                {
                    tab.AddRow(app.Uid, app.Title);
                }

                Console.WriteLine();
                tab.Dump();
                return;
            }
            if (string.IsNullOrEmpty(arguments.KsmId))
            {
                Console.Write("KSM application UID or Title is required.");
                return;
            }
            if (action == "create")
            {
                var record = await context.Vault.CreateSecretManagerApplication(arguments.KsmId);
                Console.WriteLine("{0, 20}: {1}", "Application UID", record.Uid);
                Console.WriteLine("{0, 20}: {1}", "Title", record.Title);
                return;
            }

            var application = context.Vault.KeeperRecords.OfType<ApplicationRecord>().FirstOrDefault(x => x.Uid == arguments.KsmId || string.Equals(x.Title, arguments.KsmId, StringComparison.InvariantCultureIgnoreCase));
            if (application == null)
            {
                Console.Write($"KSM application {arguments.KsmId} not found");
                return;
            }

            if (action == "view")
            {
                var app = await context.Vault.GetSecretManagerApplication(application.Uid);
                DumpSecretManagerApplicationInfo(context.Vault, app);
            }
            else if (action == "delete")
            {
                await context.Vault.DeleteSecretManagerApplication(application.Uid);
                Console.Write($"KSM Application {application.Title} has been deleted.");
            }
            else if (action == "share")
            {
                if (string.IsNullOrEmpty(arguments.Secret))
                {
                    Console.Write("Secret (Shared Folder/Record UID/Title) parameter is required.");
                    return;
                }
                string uid = "";

                if (context.Vault.TryGetKeeperRecord(arguments.Secret, out var record))
                {
                    uid = record.Uid;
                }
                else if (context.Vault.TryGetSharedFolder(arguments.Secret, out var sf))
                {
                    uid = sf.Uid;
                }
                else
                {
                    if (context.TryResolvePath(arguments.Secret, out var folder, out var title))
                    {
                        if (string.IsNullOrEmpty(title))
                        {
                            if (folder.FolderType == FolderType.SharedFolder)
                            {
                                uid = folder.FolderUid;
                            }
                            else
                            {
                                Console.Write($"Folder \"{arguments.Secret}\" is not Shared Folder.");
                                return;
                            }
                        }
                        else
                        {
                            record = folder.Records.Select(x => context.Vault.GetRecord(x)).FirstOrDefault(x =>
                                string.Compare(x.Title, title, StringComparison.CurrentCultureIgnoreCase) == 0);
                            if (record != null)
                            {
                                uid = record.Uid;
                            }
                        }
                    }
                }
                if (string.IsNullOrEmpty(uid))
                {
                    Console.Write($"Record or Shared Folder \"{arguments.Secret}\" does not exist.");
                    return;
                }
                var app = await context.Vault.ShareToSecretManagerApplication(application.Uid, uid, arguments.CanEdit);
                DumpSecretManagerApplicationInfo(context.Vault, app);
            }
            else if (action == "unshare")
            {
                if (string.IsNullOrEmpty(arguments.Secret))
                {
                    Console.Write("Secret (Shared Folder/Record UID/Title) parameter is required.");
                    return;
                }

                var uid = "";
                if (context.Vault.TryGetKeeperRecord(arguments.Secret, out var record))
                {
                    uid = record.Uid;
                }
                else if (context.Vault.TryGetSharedFolder(arguments.Secret, out var sf))
                {
                    uid = sf.Uid;
                }
                else
                {
                    if (context.TryResolvePath(arguments.Secret, out var folder, out var title))
                    {
                        if (string.IsNullOrEmpty(title))
                        {
                            if (folder.FolderType == FolderType.SharedFolder)
                            {
                                uid = folder.FolderUid;
                            }
                        }
                        else
                        {
                            record = folder.Records.Select(x => context.Vault.GetRecord(x)).FirstOrDefault(x =>
                                string.Compare(x.Title, title, StringComparison.CurrentCultureIgnoreCase) == 0);
                            if (record != null)
                            {
                                uid = record.Uid;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(uid))
                {
                    uid = arguments.Secret;
                }
                var app = await context.Vault.GetSecretManagerApplication(application.Uid);
                var share = app.Shares.FirstOrDefault(x => x.SecretUid == uid);

                if (share == null)
                {
                    Console.Write($"\"{arguments.Secret}\" is not shared to application {application.Title}");
                }
                app = await context.Vault.UnshareFromSecretManagerApplication(application.Uid, uid);
                DumpSecretManagerApplicationInfo(context.Vault, app);
            }
            else if (action == "add-client")
            {
                var unlockIp = arguments.UnlockIP;
                int? firstAccess = arguments.CreateExpire > 0 ? arguments.CreateExpire : (int?) null;
                int? accessExpire = arguments.AccessExpire > 0 ? arguments.AccessExpire : (int?) null;
                var t = await context.Vault.AddSecretManagerClient(application.Uid, unlockIp: arguments.B64 ? false : unlockIp,
                    firstAccessExpireInMinutes: firstAccess, accessExpiresInMinutes: accessExpire,
                    name: arguments.ClientName);

                var device = t.Item1;
                var clientKey = t.Item2;

                Console.WriteLine("Successfully generated Client Device\n");
                if (arguments.B64)
                {
                    var configuration = await context.Vault.GetConfiguration(clientKey);
                    var configData = JsonUtils.DumpJson(configuration);
                    var configText = Convert.ToBase64String(configData);
                    Console.WriteLine($"KSM Configuration:\n{configText}");
                }
                else
                {
                    Console.WriteLine($"One-Time Access Token: {clientKey}");
                    var ipLock = device.LockIp ? "Enabled" : "Disabled";
                    Console.WriteLine($"IP Lock: {ipLock}");
                    var firstAccessOn = device.FirstAccessExpireOn.HasValue ? device.FirstAccessExpireOn.Value.ToString("G") : "Taken";
                    Console.WriteLine($"Token Expires On: {firstAccessOn}");
                }

                var accessExpireOn = device.AccessExpireOn.HasValue ? device.AccessExpireOn.Value.ToString("G") : "Never";
                Console.WriteLine($"App Access Expires On: {accessExpireOn}");
            }
            else if (action == "delete-client")
            {
                if (string.IsNullOrEmpty(arguments.ClientName))
                {
                    Console.Write("\"client-name\" parameter is required");
                    return;
                }

                var app = await context.Vault.GetSecretManagerApplication(application.Uid);
                var device = app.Devices.FirstOrDefault(x => x.Name == arguments.ClientName || x.DeviceId.StartsWith(arguments.ClientName));
                if (device == null)
                {
                    Console.Write($"Device \"{arguments.ClientName}\" is not found in application {application.Title}");
                    return;
                }
                await context.Vault.DeleteSecretManagerClient(application.Uid, device.DeviceId);
                Console.Write($"Client \"{device.Name}\" has been deleted from application {application.Title}");
            }
            else if (action == "app-unshare")
            {
                if (string.IsNullOrEmpty(arguments.User))
                {
                    Console.Write("\"user\" parameter is required");
                    return;
                }
                var sharedFolderOptions = new SharedFolderOptions
                {
                    CanShare = arguments.CanShare,
                    ManageUsers = arguments.ManageUsers,
                    ManageRecords = arguments.ManageRecords,
                    CanEdit = arguments.CanEdit
                };
                try
                {
                    await ShareSecretsManagerApplicationWithUser(context.Vault,application.Uid, arguments.User, true, sharedFolderOptions);
                    Console.Write($"Application \"{application.Title}\" has been unshared from user {arguments.User}");
                }
                catch (Exception e)
                {
                    Console.Write($"Failed to unshare application \"{application.Title}\" from user {arguments.User}: {e.Message}");
                }
            }
            else if (action == "app-share")
            {
                if (string.IsNullOrEmpty(arguments.User))
                {
                    Console.Write("\"user\" parameter is required");
                    return;
                }

                var sharedFolderOptions = new SharedFolderOptions
                {
                    CanShare = arguments.CanShare,
                    ManageUsers = arguments.ManageUsers,
                    ManageRecords = arguments.ManageRecords,
                    CanEdit = arguments.CanEdit
                };
                var expiration = arguments.expiration;

                try
                {
                    await ShareSecretsManagerApplicationWithUser(context.Vault,application.Uid, arguments.User, false, sharedFolderOptions, expiration);
                    Console.Write($"Application \"{application.Title}\" has been shared with user {arguments.User}");
                }
                catch (Exception e)
                {
                    Console.Write($"Failed to share application \"{application.Title}\" with user {arguments.User}: {e.Message}");
                }
            }
            else
            {
                Console.Write($"Unsupported KSM command {arguments.Command}");
            }
        }

        private static void DumpSecretManagerApplicationInfo(VaultData vault, SecretsManagerApplication application)
        {
            var shareTab = new Tabulate(5)
            {
                DumpRowNo = true
            };
            shareTab.AddHeader("Share Type", "Share UID", "Share Title", "Editable", "Created");
            foreach (var share in application.Shares)
            {
                var shareType = share.SecretType == SecretManagerSecretType.Record ? "Record" : "SharedFolder";
                var shareTitle = "";
                if (share.SecretType == SecretManagerSecretType.Record)
                {
                    if (vault.TryGetKeeperRecord(share.SecretUid, out var r))
                    {
                        shareTitle = r.Title;
                    }
                }
                else
                {
                    if (vault.TryGetSharedFolder(share.SecretUid, out var sf))
                    {
                        shareTitle = sf.Name;
                    }
                }
                shareTab.AddRow(shareType, share.SecretUid, shareTitle, share.Editable, share.CreatedOn);
            }

            var clientTab = new Tabulate(4)
            {
                DumpRowNo = true
            };

            var nameLength = 6;
            var s = new HashSet<string>();
            while (true)
            {
                s.Clear();
                s.UnionWith(application.Devices.Select(x => x.DeviceId.Substring(0, nameLength)));
                if (s.Count == application.Devices.Length)
                {
                    break;
                }
                nameLength++;
            }

            clientTab.AddHeader("Name", "Device ID", "Created", "Last Accessed", "Expires");
            foreach (var client in application.Devices)
            {
                clientTab.AddRow(client.Name, client.DeviceId.Substring(0, nameLength), client.CreatedOn, client.LastAccess, client.AccessExpireOn);
            }

            Console.WriteLine("{0, 20}: {1}", "Application UID", application.Uid);
            Console.WriteLine("{0, 20}: {1}", "Title", application.Title);
            Console.WriteLine();
            Console.WriteLine("Shares");
            shareTab.Dump();

            Console.WriteLine("Devices");
            clientTab.Dump();
        }

        public static async Task ShareSecretsManagerApplicationWithUser(VaultOnline vault,string applicationId, string userUid, bool unshare, SharedFolderOptions sharedFolderOptions = null, DateTimeOffset expiration = default)
        {
            if (!vault.TryGetKeeperRecord(applicationId, out var record))
            {
                throw new KeeperSecurity.Authentication.KeeperInvalidParameter("ShareSecretsManagerApplicationWithUser", "applicationId", applicationId, "Application not found");
            }
            ApplicationRecord application = record as ApplicationRecord ?? throw new KeeperSecurity.Authentication.KeeperInvalidParameter("ShareSecretsManagerApplicationWithUser", "applicationId", applicationId, "Application not found");

            var appInfoResponse = await GetAppInfo(vault, application.Uid);
            var appInfo = appInfoResponse.FirstOrDefault(x => x.AppRecordUid.ToByteArray().SequenceEqual(application.Uid.Base64UrlDecode()));

            var isShareable = await GetUsersForShareRequest(vault, userUid);
            if (!isShareable)
            {
                await vault.SendShareInvitationRequest(userUid);
                Console.WriteLine($"Share invitation request has been sent to user {userUid}. Please wait for the user to accept the request before sharing the application.");
                return;
            }

            var (sharedRecordPermissions, sharedfolderUserOptions) = GetFolderAndRecordPermissions(vault,sharedFolderOptions, unshare, expiration);

            // process application first with the user
            await HandleRecordShareWithUser(vault,unshare, application.Uid, userUid, sharedRecordPermissions);

            // process each folder which application covers with the user
            await Task.WhenAll(
                appInfo.Shares
                    .Where(x => x.ShareType == Authentication.ApplicationShareType.ShareTypeFolder)
                    .Select(x => HandleFolderShareWithUser(vault,unshare, x.SecretUid, userUid, sharedfolderUserOptions))
            );

            // process each record which application covers with the user
            await Task.WhenAll(
                appInfo.Shares
                    .Where(x => x.ShareType == Authentication.ApplicationShareType.ShareTypeRecord)
                    .Select(x => HandleRecordShareWithUser(vault,unshare, x.SecretUid.ToByteArray().Base64UrlEncode(), userUid, sharedRecordPermissions))
            );

            // sync down the changes
            await vault.SyncDown();
        }

        private static async Task<bool> GetUsersForShareRequest(VaultOnline vault, string userUid)
        {
            ShareWithUsers users = await vault.GetUsersForShare();

            if (users == null || ((users.SharesFrom.Count() == 0)&& users.GroupUsers.Count() == 0 && users.SharesWith.Count() == 0))
            {
                Console.Error.WriteLine("No users found for sharing.");
                throw new KeeperSecurity.Authentication.KeeperInvalidParameter("ShareSecretsManagerApplicationWithUser", "userUid", userUid, "No users found for sharing");
            }

            if (users.GroupUsers.Contains(userUid) || users.SharesWith.Contains(userUid))
            {
                return true;
            }
            else
            {
                Console.WriteLine($"User {userUid} is not found in the list of users for sharing.");
                return false;
            }
            
        }

        private static (SharedFolderRecordOptions, SharedFolderUserOptions) GetFolderAndRecordPermissions(VaultOnline vault, SharedFolderOptions sharedFolderOptions, bool unshare, DateTimeOffset expiration = default)
        {
            var isAdmin = vault.Auth.AuthContext.IsEnterpriseAdmin;

            var sharedRecordPermissions = new SharedFolderRecordOptions
            {
                CanEdit = isAdmin && (sharedFolderOptions?.CanEdit ?? !unshare),
                CanShare = isAdmin && (sharedFolderOptions?.CanShare ?? !unshare)
            };

            var sharedfolderUserOptions = new SharedFolderUserOptions
            {
                ManageUsers = isAdmin && (sharedFolderOptions?.ManageUsers ?? !unshare),
                ManageRecords = isAdmin && (sharedFolderOptions?.ManageRecords ?? !unshare),
            };

            if (expiration != default)
            {
                sharedRecordPermissions.Expiration = expiration;
                sharedfolderUserOptions.Expiration = expiration;
            }

            return (sharedRecordPermissions, sharedfolderUserOptions);
        }

        private static async Task HandleFolderShareWithUser(VaultOnline vault,bool unshare, Google.Protobuf.ByteString sharedFolderUid, string userUid, SharedFolderUserOptions sharedfolderUserOptions)
        {
            string sharedFolderUidString = sharedFolderUid.ToByteArray().Base64UrlEncode();
            if (unshare)
            {
                await vault.RemoveUserFromSharedFolder(sharedFolderUidString, userUid, UserType.User);
            }
            else
            {
                await vault.PutUserToSharedFolder(sharedFolderUidString, userUid, UserType.User, sharedfolderUserOptions);
            }
        }

        private static async Task HandleRecordShareWithUser(VaultOnline vault,bool unshare, string recordUid, string userUid, SharedFolderRecordOptions sharedRecordPermissions)
        {
            if (unshare)
            {
                await vault.RevokeShareFromUser(recordUid, userUid);
            }
            else
            {
                await vault.ShareRecordWithUser(recordUid, userUid, sharedRecordPermissions);
            }
        }


        private static async Task<IEnumerable<Authentication.AppInfo>> GetAppInfo(VaultOnline vault,string applicationId)
        {
            var rq = new Authentication.GetAppInfoRequest
            {
                AppRecordUid = { Google.Protobuf.ByteString.CopyFrom(applicationId.Base64UrlDecode()) }
            };

            var appInforResponse = (Authentication.GetAppInfoResponse)await vault.Auth.ExecuteAuthRest("vault/get_app_info", rq, typeof(Authentication.GetAppInfoResponse));
            if (appInforResponse.AppInfo.Count == 0)
            {
                throw new KeeperSecurity.Authentication.KeeperInvalidParameter("GetAppInfo", "applicationId", applicationId, "Application not found");
            }
            return appInforResponse.AppInfo;
        }

    }

    class OneTimeShareOptions
    {
        [Option("client", Required = false, HelpText = "One-Time Share name. \"create\" or \"delete\"")]
        public string Client { get; set; }

        [Option("expire", Required = false, HelpText = "Expire share in <NUMBER>[(m)inutes|(h)ours|(d)ays. \"create\" only")]
        public string Expire { get; set; }

        [Value(0, Required = true, HelpText = "KSM command: \"create\", \"delete\", \"list\"")]
        public string Command { get; set; }

        [Value(1, Required = true, HelpText = "Record UID or path")]
        public string Record { get; set; }
    }

    class SecretManagerOptions
    {
        [Option("folder", Required = false, HelpText = "Shared Folder UID or name. \"share\", \"unshare\" only")]
        public string Secret { get; set; }
        [Option('e', "can-edit", Required = false, HelpText = "Can secret be edited?  \"share\", \"unshare\" only")]
        public bool CanEdit { get; set; }

        [Option("client-name", Required = false, HelpText = "Client name. \"add-client\", \"remove-client\" only")]
        public string ClientName { get; set; }
        [Option("unlock-ip", Required = false, HelpText = "Unlock IP Address? \"add-client\" only")]
        public bool UnlockIP { get; set; }
        [Option("create-expire", Required = false, HelpText = "Device creation expitation in minutes.  \"add-client\" only")]
        public int CreateExpire { get; set; }
        [Option("access-expire", Required = false, HelpText = "Device access expitation in minutes.  \"add-client\" only")]
        public int AccessExpire { get; set; }
        [Option("b64", Required = false, HelpText = "Return KSM configuration intead of one time token \"add-client\" only")]
        public bool B64 { get; set; }
        [Option("user", Required = false, HelpText = "User UID or email address.\"app-share\", \"app-unshare\" only")]
        public string User { get; set; }
        [Option('s',"can-share", Required = false, HelpText = "shared user can share re-share this record \"app-share\", \"app-unshare\" only")]
        public bool CanShare { get; set; }
        [Option("manage-users", Required = false, HelpText = "shared user can manage other user's access to this record if set to true \"app-share\", \"app-unshare\" only")]
        public bool ManageUsers { get; set; }
        [Option("manage-records", Required = false, HelpText = "shared user can manage records if set to true \"app-share\", \"app-unshare\" only")]
        public bool ManageRecords { get; set; }
        [Option("expiration", Required = false, HelpText = "share to user expires on. \"app-share\" only")]
        public DateTimeOffset expiration { get; set; }



        [Value(0, Required = false, HelpText = "KSM command: \"view\", \"create\", \"delete\", \"share\", \"unshare\", \"add-client\", \"delete-client\", \"list\", \"app-share\", \"app-unshare\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Secret Manager application UID or Title")]
        public string KsmId { get; set; }
    }

}
