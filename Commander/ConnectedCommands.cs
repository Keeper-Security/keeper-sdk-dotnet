using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using BreachWatch;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    public partial class ConnectedContext : StateContext
    {
        private readonly VaultOnline _vault;
        private readonly Auth _auth;

        private TeamInfo[] _teamCache;

        private AccountSummaryElements _accountSummary;

        public ConnectedContext(Auth auth)
        {
            _auth = auth;
            var storage = Program.CommanderStorage.GetKeeperStorage(auth.Username);
            _vault = new VaultOnline(_auth, storage)
            {
                VaultUi = new VaultUi(), 
                AutoSync = true
            };
            SubscribeToNotifications();
            CheckIfEnterpriseAdmin();
            lock (Commands)
            {
                Commands.Add("list",
                    new ParsableCommand<ListCommandOptions>
                    {
                        Order = 10,
                        Description = "List folder content",
                        Action = ListCommand
                    });

                Commands.Add("cd",
                    new SimpleCommand
                    {
                        Order = 11,
                        Description = "Change current folder",
                        Action = ChangeDirectoryCommand
                    });

                Commands.Add("tree",
                    new ParsableCommand<TreeCommandOptions>
                    {
                        Order = 12,
                        Description = "Display folder structure",
                        Action = TreeCommand
                    });

                Commands.Add("get",
                    new SimpleCommand
                    {
                        Order = 13,
                        Description = "Display specified Keeper record/folder/team",
                        Action = GetCommand
                    });

                Commands.Add("add-record",
                    new ParsableCommand<AddRecordOptions>
                    {
                        Order = 20,
                        Description = "Add record",
                        Action = AddRecordCommand
                    });

                Commands.Add("update-record",
                    new ParsableCommand<UpdateRecordOptions>
                    {
                        Order = 21,
                        Description = "Update record",
                        Action = UpdateRecordCommand
                    });

                Commands.Add("mkdir",
                    new ParsableCommand<MakeFolderOptions>
                    {
                        Order = 22,
                        Description = "Make folder",
                        Action = MakeFolderCommand
                    });

                Commands.Add("rmdir",
                    new ParsableCommand<FolderOptions>
                    {
                        Order = 22,
                        Description = "Remove folder",
                        Action = RemoveFolderCommand
                    });

                Commands.Add("mv",
                    new ParsableCommand<MoveOptions>
                    {
                        Order = 23,
                        Description = "Move record or folder",
                        Action = MoveCommand
                    });

                Commands.Add("rm",
                    new ParsableCommand<RemoveRecordOptions>
                    {
                        Order = 24,
                        Description = "Remove record(s)",
                        Action = RemoveRecordCommand
                    });

                Commands.Add("sf-list",
                    new SimpleCommand
                    {
                        Order = 30,
                        Description = "List shared folders",
                        Action = ListSharedFoldersCommand
                    });

                Commands.Add("sf-user",
                    new ParsableCommand<ShareFolderUserPermissionOptions>
                    {
                        Order = 31,
                        Description = "Change shared folder user permissions",
                        Action = ShareFolderUserPermissionCommand
                    });

                Commands.Add("sf-record",
                    new ParsableCommand<ShareFolderRecordPermissionOptions>
                    {
                        Order = 32,
                        Description = "Change shared folder record permissions",
                        Action = ShareFolderRecordPermissionCommand
                    });

                Commands.Add("devices",
                    new ParsableCommand<OtherDevicesOptions>
                    {
                        Order = 50,
                        Description = "Devices (other than current) commands",
                        Action = DeviceCommand,
                    });

                Commands.Add("this-device",
                    new ParsableCommand<ThisDeviceOptions>
                    {
                        Order = 51,
                        Description = "Current device command",
                        Action = ThisDeviceCommand,
                    });

                if (_auth.AuthContext.Settings?.ShareDatakeyWithEnterprise == true)
                {
                    Commands.Add("share-datakey",
                        new SimpleCommand
                        {
                            Order = 52,
                            Description = "Share data key with enterprise",
                            Action = ShareDatakeyCommand,
                        });
                }

                Commands.Add("sync-down",
                    new ParsableCommand<SyncDownOptions>
                    {
                        Order = 100,
                        Description = "Download & decrypt data",
                        Action = async (options) =>
                        {
                            if (options.Reset)
                            {
                                Console.WriteLine("Resetting offline storage.");
                                _vault.Storage.Clear();
                            }

                            var fullSync = _vault.Storage.Revision == 0;
                            Console.WriteLine("Syncing...");
                            await _vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(0));

                            if (fullSync)
                            {
                                Console.WriteLine($"Decrypted {_vault.RecordCount} record(s)");
                            }
                        }
                    });

                Commands.Add("logout",
                    new ParsableCommand<LogoutOptions>
                    {
                        Order = 200,
                        Description = "Logout",
                        Action = LogoutCommand,
                    });

                CommandAliases.Add("ls", "list");
                CommandAliases.Add("d", "sync-down");
                CommandAliases.Add("add", "add-record");
                CommandAliases.Add("upd", "update-record");
            }

            Program.EnqueueCommand("sync-down");
        }

        private string _currentFolder;

        private bool DeviceApprovalRequestCallback(NotificationEvent evt)
        {
            if (string.Compare(evt.Event, "device_approval_request", StringComparison.InvariantCultureIgnoreCase) != 0) return false;
            _accountSummary = null;
            var deviceToken = evt.EncryptedDeviceToken.Base64UrlDecode();
            Console.WriteLine(!string.IsNullOrEmpty(evt.EncryptedDeviceToken)
                ? $"New notification arrived for Device ID: {deviceToken.TokenToString()}"
                : "New notification arrived.");

            return false;
        }

        private void SubscribeToNotifications()
        {
            _auth.PushNotifications?.RegisterCallback(DeviceApprovalRequestCallback);
        }

        private void UnsubscribeFromNotifications()
        {
            _auth.PushNotifications?.RemoveCallback(DeviceApprovalRequestCallback);
            _auth.PushNotifications?.RemoveCallback(EnterpriseNotificationCallback);
        }

        private async Task<TeamInfo[]> GetAvailableTeams()
        {
            if (_teamCache == null)
            {
                _teamCache = (await _vault.GetAvailableTeams()).ToArray();
            }

            return _teamCache;
        }

        private async Task LogoutCommand(LogoutOptions options)
        {
            UnsubscribeFromNotifications();
            if (!options.Resume)
            {
                await _auth.Logout();
            }

            NextState = new NotConnectedCliContext(false);
        }

        private Task ListCommand(ListCommandOptions options)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(_currentFolder))
            {
                _vault.TryGetFolder(_currentFolder, out node);
            }

            if (node == null) {
                node = _vault.RootFolder;
            }

            if (options.Details)
            {
                if (node.Subfolders.Count > 0)
                {
                    var tab = new Tabulate(2)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader(new[] {"Folder UID", "Name"});
                    foreach (var uid in node.Subfolders)
                    {
                        if (_vault.TryGetFolder(uid, out var f))
                        {
                            tab.AddRow(new[] {f.FolderUid, f.Name});
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                }

                if (node.Records.Count > 0)
                {
                    var tab = new Tabulate(4)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader(new[] {"Record UID", "Title", "Login", "URL"});
                    foreach (var uid in node.Records)
                    {
                        if (_vault.TryGetRecord(uid, out var r))
                        {
                            tab.AddRow(new[] {r.Uid, r.Title, r.Login, r.Link});
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                }
            }
            else
            {
                var names = new List<string>();
                foreach (var uid in node.Subfolders)
                {
                    if (_vault.TryGetFolder(uid, out var subNode))
                    {
                        names.Add(subNode.Name + "/");
                    }
                }
                names.Sort(StringComparer.InvariantCultureIgnoreCase);

                var len = names.Count;
                foreach (var uid in node.Records)
                {
                    if (_vault.TryGetRecord(uid, out var record))
                    {
                        names.Add(string.IsNullOrEmpty(record.Title) ? record.Uid : record.Title);
                    }
                }
                if (names.Count <= 0) return Task.FromResult(true);
                names.Sort(len, names.Count - len, StringComparer.InvariantCultureIgnoreCase);

                len = names.Select(x => x.Length).Max();
                if (len < 16)
                {
                    len = 16;
                }

                len += 2;
                var columns = Console.BufferWidth / len;
                if (columns < 1)
                {
                    columns = 1;
                }

                var columnWidth = Console.BufferWidth / columns;
                var colNo = 0;
                foreach (var t in names)
                {
                    Console.Write(t.PadRight(columnWidth - 1));
                    colNo++;
                    if (colNo < columns) continue;
                    Console.WriteLine();
                    colNo = 0;
                }
            }

            return Task.FromResult(true);
        }

        public void PrintTree(FolderNode folder, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + folder.Name);
            indent += isRoot ? " " : (last ? "    " : "|   ");
            for (var i = 0; i < folder.Subfolders.Count; i++)
            {
                if (_vault.TryGetFolder(folder.Subfolders[i], out var node))
                {
                    PrintTree(node, indent, i == folder.Subfolders.Count - 1);
                }
            }
        }

        private Task GetCommand(string uid)
        {
            var tab = new Tabulate(3);
            if (_vault.TryGetRecord(uid, out var record))
            {
                tab.AddRow(new[] { "Record UID:", record.Uid });
                tab.AddRow(new[] { "Title:", record.Title });
                tab.AddRow(new[] { "Login:", record.Login });
                tab.AddRow(new[] { "Password:", record.Password });
                tab.AddRow(new[] { "Login URL:", record.Link });
                tab.AddRow(new[] { "Notes:", record.Notes });
                if (record.Custom != null && record.Custom.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "Custom Fields:", "" });
                    foreach (var c in record.Custom)
                    {
                        tab.AddRow(new[] { c.Name + ":", c.Value });
                    }
                }
                if (record.ExtraFields != null)
                {
                    var totps = record.ExtraFields
                        .Where(x => string.Equals(x.FieldType, "totp", StringComparison.InvariantCultureIgnoreCase) && x.Custom != null)
                        .Where(x => x.Custom.ContainsKey("data"))
                        .ToArray();
                    foreach (var t in totps)
                    {
                        try
                        {
                            var url = t.Custom["data"] as string;
                            var tup = CryptoUtils.GetTotpCode(url);
                            tab.AddRow($"{t.FieldTitle}:", $"{tup.Item1} expires in {tup.Item3 - tup.Item2} sec.");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }
            }
            else if (_vault.TryGetSharedFolder(uid, out var sf))
            {
                tab.AddRow(new[] { "Shared Folder UID:", sf.Uid });
                tab.AddRow(new[] { "Name:", sf.Name });
                tab.AddRow(new[] { "Default Manage Records:", sf.DefaultManageRecords.ToString() });
                tab.AddRow(new[] { "Default Manage Users:", sf.DefaultManageUsers.ToString() });
                tab.AddRow(new[] { "Default Can Edit:", sf.DefaultCanEdit.ToString() });
                tab.AddRow(new[] { "Default Can Share:", sf.DefaultCanShare.ToString() });
                if (sf.RecordPermissions.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "Record Permissions:" });
                    foreach (var r in sf.RecordPermissions)
                    {
                        tab.AddRow(new[]
                        {
                            r.RecordUid + ":", "Can Edit: " + r.CanEdit,
                            "Can Share: " + r.CanShare
                        });
                    }
                }

                var teamLookup = _vault.Teams.ToDictionary(t => t.TeamUid, t => t.Name);
                if (sf.UsersPermissions.Count > 0)
                {
                    tab.AddRow(new[] { "" });
                    tab.AddRow(new[] { "User/Team Permissions:" });
                    var sortedList = sf.UsersPermissions.ToList();
                    sortedList.Sort((x, y) =>
                    {
                        var res = x.UserType.CompareTo(y.UserType);
                        if (res == 0)
                        {
                            if (x.UserType == UserType.User)
                            {
                                res = string.Compare(x.UserId, y.UserId, StringComparison.OrdinalIgnoreCase);
                            }
                            else
                            {
                                var xName = teamLookup[x.UserId] ?? x.UserId;
                                var yName = teamLookup[y.UserId] ?? y.UserId;
                                res = string.Compare(xName, yName, StringComparison.OrdinalIgnoreCase);
                            }
                        }

                        return res;
                    });
                    foreach (var u in sortedList)
                    {
                        var subjectName = u.UserType == UserType.User ? u.UserId : (teamLookup[u.UserId] ?? u.UserId);
                        tab.AddRow(new[]
                        {
                            $"{u.UserType} {subjectName}:",
                            $"Can Manage Records: {u.ManageRecords}",
                            $"Can Manage Users: {u.ManageUsers}"
                        });
                    }
                }
            }
            else if (_vault.TryGetFolder(uid, out var f))
            {
                tab.AddRow(new[] { "Folder UID:", f.FolderUid });
                if (!string.IsNullOrEmpty(f.ParentUid))
                {
                    tab.AddRow(new[] { "Parent Folder UID:", f.ParentUid });
                }

                tab.AddRow(new[] { "Folder Type:", f.FolderType.ToString() });
                tab.AddRow(new[] { "Name:", f.Name });
            }
            else
            {
                Console.WriteLine($"UID {uid} is not a valid Keeper object");
                return Task.FromResult(false);
            }

            Console.WriteLine();
            tab.SetColumnRightAlign(0, true);
            tab.LeftPadding = 4;
            tab.Dump();
            return Task.FromResult(true);
        }

        private Task TreeCommand(TreeCommandOptions options)
        {
            PrintTree(_vault.RootFolder, "", true);
            return Task.FromResult(true);
        }

        private Task ChangeDirectoryCommand(string name)
        {
            if (TryResolvePath(name, out var node))
            {
                _currentFolder = node.FolderUid;
            }
            else
            {
                Console.WriteLine($"Invalid folder name: {name}");
            }

            return Task.FromResult(true);
        }

        private async Task AddRecordCommand(AddRecordOptions options)
        {
            if (!TryResolvePath(options.Folder, out FolderNode node))
            {
                Console.WriteLine($"Cannot resolve folder {options.Folder}");
                return;
            }

            var record = new PasswordRecord
            {
                Title = options.Title,
                Login = options.Login,
                Password = options.Password,
                Link = options.Url,
                Notes = options.Notes
            };
            if (string.IsNullOrEmpty(record.Password) && options.Generate)
            {
                record.Password = CryptoUtils.GenerateUid();
            }

            if (!options.Force)
            {
                if (string.IsNullOrEmpty(record.Login))
                {
                    Console.Write("..." + "Login: ".PadRight(16));
                    record.Login = await Program.GetInputManager().ReadLine();
                }

                if (string.IsNullOrEmpty(record.Password))
                {
                    Console.Write("..." + "Password: ".PadRight(16));
                    record.Login = await Program.GetInputManager().ReadLine(new ReadLineParameters
                    {
                        IsSecured = true
                    });
                }

                if (string.IsNullOrEmpty(record.Link))
                {
                    Console.Write("..." + "Login URL: ".PadRight(16));
                    record.Link = await Program.GetInputManager().ReadLine();
                }
            }

            await _vault.CreateRecord(record, node.FolderUid);
        }

        private async Task UpdateRecordCommand(UpdateRecordOptions options)
        {
            if (_vault.TryGetRecord(options.RecordId, out var record))
            {
            }
            else if (TryResolvePath(options.RecordId, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!_vault.TryGetRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {options.RecordId}");
                return;
            }

            if (!string.IsNullOrEmpty(options.Title))
            {
                record.Title = options.Title;
            }

            if (!string.IsNullOrEmpty(options.Login))
            {
                record.Login = options.Login;
            }

            if (string.IsNullOrEmpty(options.Password))
            {
                if (options.Generate)
                {
                    record.Password = CryptoUtils.GenerateUid();
                }
            }
            else
            {
                record.Password = options.Password;
            }

            if (!string.IsNullOrEmpty(options.Url))
            {
                record.Link = options.Url;
            }

            if (!string.IsNullOrEmpty(options.Notes))
            {
                record.Notes = options.Notes;
            }

            await _vault.UpdateRecord(record);
        }

        private async Task MakeFolderCommand(MakeFolderOptions options)
        {
            var sfOptions = options.Shared
                ? new SharedFolderOptions
                {
                    ManageRecords = options.ManageRecords,
                    ManageUsers = options.ManageUsers,
                    CanEdit = options.CanEdit,
                    CanShare = options.CanShare,
                }
                : null;
            _ = await _vault.CreateFolder(options.FolderName, _currentFolder, sfOptions);
        }

        private async Task RemoveRecordCommand(RemoveRecordOptions options)
        {
            if (string.IsNullOrEmpty(options.RecordName))
            {
                return;
            }

            if (_vault.TryGetRecord(options.RecordName, out var record))
            {
                var folders = Enumerable.Repeat(_vault.RootFolder, 1).Concat(_vault.Folders).Where(x => x.Records.Contains(record.Uid)).ToArray();
                if (folders.Length == 0)
                {
                    Console.WriteLine("not expected");
                    return;
                }

                var folder = folders.Length == 1
                    ? folders[0]
                    : folders.FirstOrDefault(x => x.FolderUid == _currentFolder)
                    ?? folders.FirstOrDefault(x => string.IsNullOrEmpty(x.FolderUid))
                    ?? folders.FirstOrDefault(x => x.FolderType == FolderType.UserFolder)
                    ?? folders[0];

                await _vault.DeleteRecords(new[] {new RecordPath {FolderUid = folder.FolderUid, RecordUid = record.Uid,}});
            }
            else
            {
                if (!TryResolvePath(options.RecordName, out var folder, out string recordTitle))
                {
                    Console.WriteLine($"Invalid record path: {options.RecordName}");
                    return;
                }

                var sb = new StringBuilder();
                sb.Append(recordTitle);
                sb = sb.Replace("*", ".*");
                sb = sb.Replace("?", @".");
                sb = sb.Replace("#", @"[0-9]");
                sb.Insert(0, "^");
                sb.Append("$");
                var pattern = sb.ToString();

                var records = new List<RecordPath>();
                foreach (var recordUid in folder.Records)
                {
                    if (!_vault.TryGetRecord(recordUid, out record)) continue;

                    var m = Regex.Match(record.Title, pattern, RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        records.Add(new RecordPath { FolderUid = folder.FolderUid, RecordUid = recordUid });
                    }
                }

                await _vault.DeleteRecords(records.ToArray());
            }
        }

        private async Task MoveCommand(MoveOptions options)
        {
            if (!_vault.TryGetFolder(options.DestinationName, out var dstFolder))
            {
                if (!TryResolvePath(options.DestinationName, out dstFolder))
                {
                    Console.WriteLine($"Invalid destination folder path: {options.DestinationName}");
                    return;
                }
            }

            if (_vault.TryGetFolder(options.SourceName, out var srcFolder))
            {
                await _vault.MoveFolder(srcFolder.FolderUid, dstFolder.FolderUid, options.Link);
            }
            else if (_vault.TryGetRecord(options.SourceName, out var record))
            {
                var folders = Enumerable.Repeat(_vault.RootFolder, 1).Concat(_vault.Folders).Where(x => x.Records.Contains(record.Uid)).ToArray();
                if (folders.Length == 0)
                {
                    Console.WriteLine("not expected");
                    return;
                }

                var folder = folders.Length == 1 ? folders[0] :
                    folders.FirstOrDefault(x => x.FolderUid == _currentFolder)
                    ?? folders.FirstOrDefault(x => string.IsNullOrEmpty(x.FolderUid))
                    ?? folders.FirstOrDefault(x => x.FolderType == FolderType.UserFolder)
                    ?? folders[0];

                await _vault.MoveRecords(new [] {new RecordPath {FolderUid = folder.FolderUid, RecordUid = record.Uid}}, dstFolder.FolderUid, options.Link);
            }
            else
            {
                if (!TryResolvePath(options.SourceName, out srcFolder, out string recordTitle))
                {
                    Console.WriteLine($"Invalid source path: {options.SourceName}");
                    return;
                }

                if (string.IsNullOrEmpty(recordTitle))
                {
                    await _vault.MoveFolder(srcFolder.FolderUid, dstFolder.FolderUid, options.Link);
                }
                else
                {
                    var sb = new StringBuilder();
                    sb.Append(recordTitle);
                    sb = sb.Replace("*", ".*");
                    sb = sb.Replace("?", @".");
                    sb = sb.Replace("#", @"[0-9]");
                    sb.Insert(0, "^");
                    sb.Append("$");
                    var pattern = sb.ToString();

                    var records = new List<RecordPath>();
                    foreach (var recordUid in srcFolder.Records)
                    {
                        if (!_vault.TryGetRecord(recordUid, out record)) continue;

                        var m = Regex.Match(record.Title, pattern, RegexOptions.IgnoreCase);
                        if (m.Success)
                        {
                            records.Add(new RecordPath { FolderUid = srcFolder.FolderUid, RecordUid = recordUid });
                        }
                    }

                    if (records.Count == 0)
                    {
                        throw new Exception($"Folder {srcFolder.Name} does not contain any record matching {recordTitle}");
                    }

                    await _vault.MoveRecords(records.ToArray(), dstFolder.FolderUid, options.Link);
                }
            }
        }

        private async Task RemoveFolderCommand(FolderOptions options)
        {
            if (TryResolvePath(options.FolderName, out var folder))
            {
                await _vault.DeleteFolder(folder.FolderUid);
            }
            else
            {
                Console.WriteLine($"Invalid folder path: {options.FolderName}");
            }
        }


        private async Task ThisDeviceCommand(ThisDeviceOptions arguments)
        {
            if (_accountSummary == null) {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            var device = _accountSummary?.Devices
                .FirstOrDefault(x => x.EncryptedDeviceToken.ToByteArray().SequenceEqual(_auth.DeviceToken));
            if (device == null)
            {
                Console.WriteLine("???????????????");
                return;
            }

            var availableVerbs = new[] {"rename", "register", "persistent_login", "ip_disable_auto_approve", "timeout", "bio"};

            var deviceToken = device.EncryptedDeviceToken.ToByteArray();
            var bioTarget = _auth.Username.BiometricCredentialTarget(deviceToken);
            var hasBio = CredentialManager.GetCredentials(bioTarget, out _, out _);
            switch (arguments.Command)
            {
                case null:
                {
                    Console.WriteLine();
                    Console.WriteLine("{0, 20}: {1}", "Device Name", device.DeviceName);
                    Console.WriteLine("{0, 20}: {1}", "Client Version", device.ClientVersion);
                    Console.WriteLine("{0, 20}: {1}", "Data Key Present", device.EncryptedDataKeyPresent);
                    Console.WriteLine("{0, 20}: {1}", "IP Auto Approve", !_accountSummary.Settings.IpDisableAutoApprove);
                    Console.WriteLine("{0, 20}: {1}", "Persistent Login", _accountSummary.Settings.PersistentLogin);
                    if (_accountSummary.Settings.LogoutTimer > 0)
                    {
                        if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromDays(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} day(s)", "Logout Timeout", TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalDays);
                        }
                        else if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromHours(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} hour(s)", "Logout Timeout", TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalHours);
                        }
                        else if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromSeconds(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} minute(s)", "Logout Timeout", TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalMinutes);
                        }
                        else
                        {
                            Console.WriteLine("{0, 20}: {1} second(s)", "Logout Timeout", TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalSeconds);
                        }
                    }
                    Console.WriteLine("{0, 20}: {1}", "Biometric Login", hasBio);

                    Console.WriteLine();
                    Console.WriteLine($"Available sub-commands: {string.Join(", ", availableVerbs)}");
                }
                break;

                case "rename":
                    if (string.IsNullOrEmpty(arguments.Parameter))
                    {
                        Console.WriteLine($"{arguments.Command} command requires new device name parameter.");
                    }
                    else
                    {
                        var request = new DeviceUpdateRequest
                        {
                            ClientVersion = _auth.Endpoint.ClientVersion,
                            DeviceStatus = DeviceStatus.DeviceOk,
                            DeviceName = arguments.Parameter,
                            EncryptedDeviceToken = device.EncryptedDeviceToken,
                        };
                        await _auth.ExecuteAuthRest("authentication/update_device", request);
                    }

                    break;

                case "register":
                {
                    if (!device.EncryptedDataKeyPresent)
                    {
                        await _auth.RegisterDataKeyForDevice(device);
                    }
                    else
                    {
                        Console.WriteLine("Device already registered.");
                    }

                }
                break;

                case "ip_disable_auto_approve":
                case "persistent_login":
                {
                    bool? enabled;
                    if (string.Compare(arguments.Parameter, "on", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        enabled = true;
                    }
                    else if (string.Compare(arguments.Parameter, "off", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        enabled = false;
                    }
                    else
                    {
                        Console.WriteLine($"\"{arguments.Command}\" accepts the following parameters: on, off");
                        return;
                    }
                    await _auth.SetSessionParameter(arguments.Command, enabled.Value ? "1" : "0");
                }
                break;

                case "timeout":
                {
                    if (string.IsNullOrEmpty(arguments.Parameter))
                    {
                        Console.WriteLine($"\"{arguments.Command}\" requires timeout in minutes parameter.");
                    }
                    else
                    {
                        if (int.TryParse(arguments.Parameter, out var timeout))
                        {
                            await _auth.SetSessionInactivityTimeout(timeout);
                            _accountSummary = null;
                        }
                        else
                        {
                            Console.WriteLine($"{arguments.Command}: invalid timeout in minutes parameter: {arguments.Parameter}");
                        }
                    }
                }
                    break;

                case "bio":
                {
                    bool enabled;
                    if (string.Compare(arguments.Parameter, "on", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        enabled = true;
                    }
                    else if (string.Compare(arguments.Parameter, "off", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        enabled = false;
                    }
                    else
                    {
                        Console.WriteLine($"\"{arguments.Command}\" accepts the following parameters: on, off");
                        return;
                    }

                    var deviceTokenName = deviceToken.TokenToString();
                    if (enabled)
                    {
                        var bioKey = CryptoUtils.GenerateEncryptionKey();
                        var authHash = CryptoUtils.CreateBioAuthHash(bioKey);
                        var encryptedDataKey = CryptoUtils.EncryptAesV2(_auth.AuthContext.DataKey, bioKey);
                        var request = new UserAuthRequest
                        {
                            LoginType = LoginType.Bio,
                            Name = deviceTokenName,
                            AuthHash = ByteString.CopyFrom(authHash),
                            EncryptedDataKey = ByteString.CopyFrom(encryptedDataKey)
                        };

                        await _auth.ExecuteAuthRest("authentication/set_v2_alternate_password", request);
                        CredentialManager.PutCredentials(bioTarget, _auth.Username, bioKey.Base64UrlEncode());
                    }
                    else
                    {
                        if (hasBio)
                        {
                            CredentialManager.DeleteCredentials(bioTarget);
                        }
                    }
                }
                    break;

                default:
                {
                    Console.WriteLine($"Available sub-commands: {string.Join(", ", availableVerbs)}");
                }
                break;
            }
        }

        private async Task ShareDatakeyCommand(string _)
        {
            /*
            if (_auth.AuthContext.Settings?.ShareDatakeyWithEnterprise != true) 
            {
                Console.WriteLine("Data key sharing is not requested.");
                return;
            }
            */
            Console.Write("Enterprise administrator requested data key to be shared. Proceed with sharing? (Yes/No) : ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }
            if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;

            var rs = (EnterprisePublicKeyResponse) await _auth.ExecuteAuthRest("enterprise/get_enterprise_public_key", null, typeof(EnterprisePublicKeyResponse));
            if (rs.EnterpriseECCPublicKey?.Length == 65)
            {
                var publicKey = CryptoUtils.LoadPublicEcKey(rs.EnterpriseECCPublicKey.ToByteArray());
                var encryptedDataKey = CryptoUtils.EncryptEc(_auth.AuthContext.DataKey, publicKey);
                var rq = new EnterpriseUserDataKey
                {
                    UserEncryptedDataKey = ByteString.CopyFrom(encryptedDataKey)
                };
                await _auth.ExecuteAuthRest("enterprise/set_enterprise_user_data_key", rq);
                Commands.Remove("share-datakey");
            }
            else
            {
                Console.Write("Your enterprise does not have EC key pair created.");
            }
        }

        private async Task DeviceCommand(OtherDevicesOptions arguments)
        {
            if (arguments.Force)
            {
                _accountSummary = null;
            }

            if (_accountSummary == null) {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            if (_accountSummary == null)
            {
                Console.WriteLine("No devices available");
                return;
            }

            var devices = _accountSummary.Devices
                .Where(x => !x.EncryptedDeviceToken.SequenceEqual(_auth.DeviceToken))
                .OrderBy(x => (int) x.DeviceStatus)
                .ToArray();

            if (devices.Length == 0)
            {
                Console.WriteLine("No devices available");
                return;
            }

            if (string.IsNullOrEmpty(arguments.Command) || arguments.Command == "list")
            {
                var tab = new Tabulate(5)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] {"Device Name", "Client", "ID", "Status", "Data Key"});
                foreach (var device in devices)
                {
                    var deviceToken = device.EncryptedDeviceToken.ToByteArray();
                    tab.AddRow(
                        device.DeviceName,
                        device.ClientVersion,
                        deviceToken.TokenToString(),
                        device.DeviceStatus.DeviceStatusToString(),
                        device.EncryptedDataKeyPresent ? "Yes" : "No"
                    );
                }

                Console.WriteLine();
                tab.Dump();
                return;
            }

            if (arguments.Command == "approve" || arguments.Command == "decline")
            {
                if (string.IsNullOrEmpty(arguments.DeviceId))
                {
                    Console.WriteLine("No device Id");
                    return;
                }

                var isDecline = arguments.Command == "decline";
                var toApprove = devices
                    .Where(x => ((x.DeviceStatus == DeviceStatus.DeviceNeedsApproval) || (arguments.Link && x.DeviceStatus == DeviceStatus.DeviceOk)))
                    .Where(x =>
                    {
                        if (arguments.DeviceId == "all")
                        {
                            return true;
                        }

                        var deviceToken = x.EncryptedDeviceToken.ToByteArray();
                        var token = deviceToken.TokenToString();
                        return token.StartsWith(arguments.DeviceId);
                    })
                    .ToArray();

                if (toApprove.Length == 0)
                {
                    Console.WriteLine($"No device approval for criteria \"{arguments.DeviceId}\"");
                    return;
                }

                foreach (var device in toApprove)
                {
                    var deviceApprove = new ApproveDeviceRequest
                    {
                        EncryptedDeviceToken = device.EncryptedDeviceToken,
                        DenyApproval = isDecline,

                    };
                    if ((_accountSummary.Settings.SsoUser || arguments.Link) && !isDecline)
                    {
                        var publicKeyBytes = device.DevicePublicKey.ToByteArray();
                        var publicKey = CryptoUtils.LoadPublicEcKey(publicKeyBytes);
                        var encryptedDataKey = CryptoUtils.EncryptEc(_auth.AuthContext.DataKey, publicKey);
                        deviceApprove.EncryptedDeviceDataKey = ByteString.CopyFrom(encryptedDataKey);
                        deviceApprove.LinkDevice = arguments.Link;
                    }

                    await _auth.ExecuteAuthRest("authentication/approve_device", deviceApprove);
                }

                _accountSummary = null;
                return;
            }

            Console.WriteLine($"Unsupported device command {arguments.Command}");
        }

        private Task ListSharedFoldersCommand(string arguments)
        {
            var tab = new Tabulate(4)
            {
                DumpRowNo = true
            };
            tab.AddHeader(new[] {"Shared Folder UID", "Name", "# Records", "# Users"});
            foreach (var sf in _vault.SharedFolders)
            {
                tab.AddRow(new object[] {sf.Uid, sf.Name, sf.RecordPermissions.Count, sf.UsersPermissions.Count});
            }

            tab.Sort(1);
            tab.Dump();

            return Task.FromResult(true);
        }

        private const string EmailPattern = @"(?i)^[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$";

        private async Task ShareFolderUserPermissionCommand(ShareFolderUserPermissionOptions options)
        {
            if (!_vault.TryGetSharedFolder(options.FolderName, out var sf))
            {
                var sfs = _vault.SharedFolders
                    .Where(x => string.Compare(x.Name, options.FolderName, StringComparison.CurrentCultureIgnoreCase) == 0)
                    .ToArray();
                if (sfs.Length == 1)
                {
                    sf = sfs[0];
                }
            }

            if (sf == null)
            {
                if (!_vault.TryGetFolder(options.FolderName, out var folder))
                {
                    if (!TryResolvePath(options.FolderName, out folder))
                    {
                        Console.WriteLine($"Folder \'{options.FolderName}\' not found");
                        return;
                    }
                }

                if (folder.FolderType == FolderType.UserFolder)
                {
                    Console.WriteLine($"Folder \'{folder.Name}\' is not Shared Folder");
                    return;
                }

                sf = _vault.GetSharedFolder(folder.FolderType == FolderType.SharedFolder ? folder.FolderUid : folder.SharedFolderUid);
            }

            if (string.IsNullOrEmpty(options.User))
            {
                var teams = await  GetAvailableTeams();
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.SetColumnRightAlign(2, true);
                tab.SetColumnRightAlign(3, true);
                tab.AddHeader(new[] {"User ID", "User Type", "Manage Records", "Manage Users"});
                foreach (var p in sf.UsersPermissions.OrderBy(x => $"{(int) x.UserType} {x.UserId.ToLowerInvariant()}"))
                {
                    if (p.UserType == UserType.User)
                    {
                        tab.AddRow(new[] {p.UserId, p.UserType.ToString(), p.ManageRecords ? "X" : "-", p.ManageUsers ? "X" : "="});
                    }
                    else
                    {
                        var team = teams.FirstOrDefault(x => x.TeamUid == p.UserId);
                        tab.AddRow(new[] { team?.Name ?? p.UserId, p.UserType.ToString(), p.ManageRecords ? "X" : "-", p.ManageUsers ? "X" : "-" });
                    }
                }
                tab.Dump();
            }
            else
            {
                var userType = UserType.User;
                string userId = null;
                var rx = new Regex(EmailPattern);
                if (rx.IsMatch(options.User))
                {
                    userId = options.User.ToLowerInvariant();
                }
                else
                {
                    userType = UserType.Team;
                    if (_vault.TryGetTeam(options.User, out var team))
                    {
                        userId = team.TeamUid;
                    }
                    else
                    {
                        team = _vault.Teams.FirstOrDefault(x => string.Compare(x.Name, options.User, StringComparison.CurrentCultureIgnoreCase) == 0);
                        if (team != null)
                        {
                            userId = team.TeamUid;
                        }
                        else
                        {
                            var teams = await GetAvailableTeams();
                            var teamInfo = teams.FirstOrDefault(x =>
                                string.Compare(x.Name, options.User, StringComparison.CurrentCultureIgnoreCase) == 0 ||
                                string.CompareOrdinal(x.TeamUid, options.User) == 0
                            );
                            if (teamInfo != null)
                            {
                                userId = teamInfo.TeamUid;
                            }
                        }
                    }

                    if (userId == null)
                    {
                        Console.WriteLine($"User {options.User} cannot be resolved as email or team");
                        return;
                    }
                }

                var userPermission = sf.UsersPermissions.FirstOrDefault(x => x.UserType == userType && x.UserId == userId);

                if (options.Delete)
                {
                    if (userPermission != null)
                    {
                        await _vault.RemoveUserFromSharedFolder(sf.Uid, userId, userType);
                    }
                    else
                    {
                        Console.WriteLine($"{(userType == UserType.User ? "User" : "Team")} \'{userId}\' is not a part of Shared Folder {sf.Name}");
                    }
                }
                else if (options.ManageUsers.HasValue || options.ManageRecords.HasValue)
                {
                    await _vault.PutUserToSharedFolder(sf.Uid, userId, userType, new SharedFolderUserOptions
                    {
                        ManageUsers = options.ManageUsers ?? sf.DefaultManageUsers,
                        ManageRecords = options.ManageRecords ?? sf.DefaultManageRecords,
                    });
                }
                else
                {
                    if (userPermission != null)
                    {
                        Console.WriteLine();
                        Console.WriteLine("{0, 20}: {1}", "User Type", userPermission.UserType.ToString());
                        Console.WriteLine("{0, 20}: {1}", "User ID", userPermission.UserId);
                        Console.WriteLine("{0, 20}: {1}", "Manage Records", userPermission.ManageRecords ? "Yes" : "No");
                        Console.WriteLine("{0, 20}: {1}", "Manage Users", userPermission.ManageUsers ? "Yes" : "No");
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine($"{(userType == UserType.User ? "User" : "Team")} \'{userId}\' is not a part of Shared Folder {sf.Name}");
                    }
                }
            }
        }

        private async Task ShareFolderRecordPermissionCommand(ShareFolderRecordPermissionOptions options)
        {
            if (!_vault.TryGetSharedFolder(options.FolderName, out var sf))
            {
                var sfs = _vault.SharedFolders
                    .Where(x => string.Compare(x.Name, options.FolderName, StringComparison.CurrentCultureIgnoreCase) == 0)
                    .ToArray();
                if (sfs.Length == 1)
                {
                    sf = sfs[0];
                }
            }

            if (sf == null)
            {
                if (!_vault.TryGetFolder(options.FolderName, out var folder))
                {
                    if (!TryResolvePath(options.FolderName, out folder))
                    {
                        Console.WriteLine($"Folder \'{options.FolderName}\'");
                        return;
                    }
                }

                if (folder.FolderType == FolderType.UserFolder)
                {
                    Console.WriteLine($"Folder \'{folder.Name}\' is not Shared Folder");
                    return;
                }

                sf = _vault.GetSharedFolder(folder.FolderType == FolderType.SharedFolder ? folder.FolderUid : folder.SharedFolderUid);
            }

            if (string.IsNullOrEmpty(options.Record))
            {
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] { "Record Title", "Record UID", "Can Edit", "Can Share" });
                foreach (var p in sf.RecordPermissions)
                {
                    if (_vault.TryGetRecord(p.RecordUid, out var record))
                    {
                        tab.AddRow(new[] { record.Title, p.RecordUid, p.CanEdit ? "X" : "-", p.CanShare ? "X" : "-" });
                    }
                }
                tab.Sort(0);
                tab.Dump();
            }
            else
            {
                string recordUid = null;
                if (_vault.TryGetRecord(options.Record, out var record))
                {
                    recordUid = record.Uid;
                }
                else
                {
                    if (TryResolvePath(options.Record, out var folder, out var title))
                    {
                        recordUid = folder.Records.Select(x => _vault.GetRecord(x)).FirstOrDefault(x => string.Compare(x.Title, title, StringComparison.CurrentCultureIgnoreCase) == 0)?.Uid;

                    }
                }
                if (string.IsNullOrEmpty(recordUid))
                {
                    Console.WriteLine($"\'{options.Record}\' cannot be resolved as record");
                    return;
                }

                var recordPermission = sf.RecordPermissions.FirstOrDefault(x => x.RecordUid == recordUid);
                if (recordPermission == null)
                {
                    Console.WriteLine($"Record \'{options.Record}\' is not a part of Shared Folder {sf.Name}");
                    return;
                }

                if (options.CanShare.HasValue || options.CanEdit.HasValue)
                {
                    await _vault.ChangeRecordInSharedFolder(sf.Uid, recordUid, new SharedFolderRecordOptions
                    {
                        CanEdit = options.CanEdit ?? recordPermission.CanEdit,
                        CanShare = options.CanShare ?? recordPermission.CanShare,
                    });
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("{0, 20}: {1}", "Record UID", record.Uid);
                    Console.WriteLine("{0, 20}: {1}", "Record Title", record.Title);
                    Console.WriteLine("{0, 20}: {1}", "Can Edit", recordPermission.CanEdit ? "Yes" : "No");
                    Console.WriteLine("{0, 20}: {1}", "Can Share", recordPermission.CanShare ? "Yes" : "No");
                    Console.WriteLine();
                }
            }
        }

        private bool TryResolvePath(string path, out FolderNode node)
        {
            var res = TryResolvePath(path, out node, out var text);
            if (res)
            {
                res = string.IsNullOrEmpty(text);
            }

            return res;
        }

        private bool TryResolvePath(string path, out FolderNode node, out string text)
        {
            node = null;
            text = null;
            if (string.IsNullOrEmpty(_currentFolder) || _currentFolder == _vault.RootFolder.FolderUid)
            {
                node = _vault.RootFolder;
            }
            else
            {
                _vault.TryGetFolder(_currentFolder, out node);
            }

            if (!string.IsNullOrEmpty(path))
            {
                path = path.Trim();
                if (string.IsNullOrEmpty(path))
                {
                    return node != null;
                }

                if (path[0] == '/')
                {
                    path = path.Substring(1);
                    node = _vault.RootFolder;
                }

                foreach (var folder in path.TokenizeArguments(CommandExtensions.IsPathDelimiter))
                {
                    if (folder == "..")
                    {
                        if (!string.IsNullOrEmpty(node.ParentUid))
                        {
                            if (!_vault.TryGetFolder(node.ParentUid, out node))
                            {
                                return false;
                            }
                        }
                        else if (!string.IsNullOrEmpty(node.FolderUid))
                        {
                            node = _vault.RootFolder;
                        }
                        else
                        {
                            return false;
                        }
                    }
                    else
                    {
                        var found = false;
                        foreach (var subFolder in node.Subfolders)
                        {
                            if (!_vault.TryGetFolder(subFolder, out var subNode)) return false;

                            if (string.Compare(folder, subNode.Name, StringComparison.CurrentCultureIgnoreCase) != 0) continue;

                            found = true;
                            node = subNode;
                            break;
                        }

                        if (found) continue;
                        if (string.IsNullOrEmpty(text))
                        {
                            text = folder;
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
            }

            return true;
        }

        public override async Task<bool> ProcessException(Exception e)
        {
            if (!(e is KeeperAuthFailed)) return await base.ProcessException(e);

            Console.WriteLine("Session is expired. Disconnecting...");
            await LogoutCommand(new LogoutOptions {Resume = true});
            return true;
        }

        public override string GetPrompt()
        {
            if (!_auth.IsAuthenticated())
            {
                _ = LogoutCommand(new LogoutOptions { Resume = true });
                return "";
            }

            if (!string.IsNullOrEmpty(_currentFolder))
            {
                var folder = _currentFolder;
                var sb = new StringBuilder();
                while (_vault.TryGetFolder(folder, out var node))
                {
                    if (sb.Length > 0)
                    {
                        sb.Insert(0, '/');
                    }

                    sb.Insert(0, node.Name);
                    folder = node.ParentUid;
                    if (!string.IsNullOrEmpty(folder)) continue;

                    sb.Insert(0, _vault.RootFolder.Name + "/");
                    if (sb.Length <= 40) return sb.ToString();

                    sb.Remove(0, sb.Length - 37);
                    sb.Insert(0, "...");
                    return sb.ToString();
                }
            }

            return _vault.RootFolder.Name;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _vault.Dispose();
            _auth.Dispose();
        }
    }

    class LogoutOptions
    {
        [Option("resume", Required = false, HelpText = "resume last login")]
        public bool Resume { get; set; }
    }

    class ListCommandOptions
    {
        [Option('l', "list", Required = false, Default = false, HelpText = "detailed output")]
        public bool Details { get; set; }

        [Value(0, Required = false, MetaName = "pattern", HelpText = "search pattern")]
        public string Pattern { get; set; }
    }

    internal class TreeCommandOptions
    {
        [Value(0, Required = false, MetaName = "folder", HelpText = "folder path or UID")]
        public string Folder { get; set; }
    }

    internal class EditRecord
    {
        [Option("login", Required = false, HelpText = "login name")]
        public string Login { get; set; }

        [Option("pass", Required = false, HelpText = "password")]
        public string Password { get; set; }

        [Option("url", Required = false, HelpText = "url")]
        public string Url { get; set; }

        [Option("notes", Required = false, HelpText = "notes")]
        public string Notes { get; set; }

        [Option('g', "generate", Required = false, Default = false, HelpText = "generate random password")]
        public bool Generate { get; set; }
    }

    class AddRecordOptions : EditRecord
    {
        [Option("folder", Required = false, HelpText = "folder")]
        public string Folder { get; set; }

        [Option('f', "force", Required = false, Default = false, HelpText = "do not prompt for omitted fields")]
        public bool Force { get; set; }

        [Value(0, Required = true, MetaName = "title", HelpText = "title")]
        public string Title { get; set; }
    }

    class UpdateRecordOptions : EditRecord
    {
        [Option("title", Required = false, HelpText = "title")]
        public string Title { get; set; }

        [Value(0, Required = true, MetaName = "title", HelpText = "record path or UID")]
        public string RecordId { get; set; }
    }

    class ShareFolderRecordPermissionOptions : FolderOptions
    {
        [Option('r', "record", Required = false, Default = null, HelpText = "record name or record uid")]
        public string Record { get; set; }

        [Option('s', "can-share", Required = false, Default = null, HelpText = "record permission: can be shared.")]
        public bool? CanShare { get; set; }

        [Option('e', "can-edit", Required = false, Default = null, HelpText = "record permission: can be edited.")]
        public bool? CanEdit { get; set; }
    }

    class ShareFolderUserPermissionOptions : FolderOptions
    {

        [Option('u', "user", Required = false, Default = null, HelpText = "account email, team name, or team uid")]
        public string User { get; set; }

        [Option('d', "delete", Required = false, Default = false, SetName = "delete", HelpText = "delete user from shared folder")]
        public bool Delete { get; set; }

        [Option('r', "manage-records", Required = false, Default = null, SetName = "set", HelpText = "account permission: can manage records.")]
        public bool? ManageRecords { get; set; }

        [Option('u', "manage-users", Required = false, Default = null, SetName = "set", HelpText = "account permission: can manage users.")]
        public bool? ManageUsers { get; set; }
    }

    class RemoveRecordOptions
    {
        [Value(0, Required = true, MetaName = "record title, uid, or pattern", HelpText = "remove records")]
        public string RecordName { get; set; }
    }

    class MoveOptions
    {
        [Option("link", Required = false, HelpText = "do not delete source")]
        public bool Link { get; set; }

        [Value(0, Required = true, MetaName = "source record or folder", HelpText = "source record or folder")]
        public string SourceName { get; set; }

        [Value(1, Required = true, MetaName = "destination folder", HelpText = "destination folder")]
        public string DestinationName { get; set; }
    }

    class FolderOptions
    {
        [Value(0, Required = true, MetaName = "folder name", HelpText = "folder name")]
        public string FolderName { get; set; }
    }

    class MakeFolderOptions : FolderOptions
    {
        [Option('s', "shared", Required = false, Default = false, HelpText = "shared folder")]
        public bool Shared { get; set; }

        [Option("manage-users", Required = false, Default = null, HelpText = "default manage users")]
        public bool? ManageUsers { get; set; }

        [Option("manage-records", Required = false, Default = null, HelpText = "default manage records")]
        public bool? ManageRecords { get; set; }

        [Option("can-share", Required = false, Default = null, HelpText = "default can share")]
        public bool? CanShare { get; set; }

        [Option("can-edit", Required = false, Default = null, HelpText = "default can edit")]
        public bool? CanEdit { get; set; }
    }

    class OtherDevicesOptions
    {
        [Option('f', "force", Required = false, Default = false, HelpText = "reload device list")]
        public bool Force { get; set; }

        [Value(0, Required = false, HelpText = "device command: \"approve\", \"decline\", \"list\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "device id or \"all\" or \"clear\"")]
        public string DeviceId { get; set; }

        [Option('l', "link", Required = false, Default = false, HelpText = "link device")]
        public bool Link { get; set; }
    }

    class ThisDeviceOptions
    {
        [Value(0, Required = false, HelpText = "this-device command: \"register\", \"rename\", \"timeout\", \"bio\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "sub-command parameter")]
        public string Parameter { get; set; }
    }

    class SyncDownOptions
    {
        [Option("reset", Required = false, Default = false, HelpText = "resets on-disk storage")]
        public bool Reset { get; set; }
    }
}