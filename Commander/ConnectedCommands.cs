using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using BreachWatch;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Sdk;

namespace Commander
{
    public partial class ConnectedContext : StateContext
    {
        private readonly Vault _vault;
        private readonly Auth _auth;

        private AccountSummaryElements _accountSummary;
        public ConnectedContext(Auth auth)
        {
            _auth = auth;
            _vault = new Vault(_auth);
            SubscribeToNotifications();
            CheckIfEnterpriseAdmin();
            Task.Run(async () =>
            {
                try
                {
                    await _vault.SyncDown();
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            });

            lock (Commands)
            {
                Commands.Add("list", new ParsableCommand<ListCommandOptions>
                {
                    Order = 10,
                    Description = "List folder content",
                    Action = ListCommand
                });

                Commands.Add("cd", new SimpleCommand
                {
                    Order = 11,
                    Description = "Change current folder",
                    Action = ChangeDirectoryCommand
                });

                Commands.Add("tree", new ParsableCommand<TreeCommandOptions>
                {
                    Order = 12,
                    Description = "Display folder structure",
                    Action = TreeCommand
                });

                Commands.Add("get", new SimpleCommand
                {
                    Order = 13,
                    Description = "Display specified Keeper record/folder/team",
                    Action = GetCommand
                });

                Commands.Add("add-record", new ParsableCommand<AddRecordOptions>
                {
                    Order = 20,
                    Description = "Add record",
                    Action = AddRecordCommand
                });

                Commands.Add("update-record", new ParsableCommand<UpdateRecordOptions>
                {
                    Order = 21,
                    Description = "Update record",
                    Action = UpdateRecordCommand
                });

                Commands.Add("list-sf", new SimpleCommand
                {
                    Order = 22,
                    Description = "List shared folders",
                    Action = ListSharedFoldersCommand
                });

                if (_auth.AuthContext is AuthContextV3)
                {
                    Commands.Add("devices", new ParsableCommand<OtherDevicesOptions>
                    {
                        Order = 50,
                        Description = "Devices (other than current) commands",
                        Action = DeviceCommand,
                    });

                    Commands.Add("this-device", new ParsableCommand<ThisDeviceOptions>
                    {
                        Order = 51,
                        Description = "Current device command",
                        Action = ThisDeviceCommand,
                    });

                    if (_auth.AuthContext.Settings?.shareDatakeyWithEccPublicKey == true)
                    {
                        Commands.Add("share-datakey", new SimpleCommand
                        {
                            Order = 52,
                            Description = "Share data key with enterprise",
                            Action = ShareDatakeyCommand,
                        });
                    }
                }

                Commands.Add("sync-down", new SimpleCommand
                {
                    Order = 100,
                    Description = "Download & decrypt data",
                    Action = async _ =>
                    {
                        Console.WriteLine("Syncing...");
                        await _vault.SyncDown();
                    }
                });

                Commands.Add("logout", new SimpleCommand
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
        }

        private string _currentFolder;
        private bool NotificationCallback(NotificationEvent evt)
        {
            _vault.OnNotificationReceived(evt);
            if (string.Compare(evt.Event, "device_approval_request", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                _accountSummary = null;
                if (!string.IsNullOrEmpty(evt.EncryptedDeviceToken))
                {
                    Console.WriteLine($"New notification arrived for Device ID: {TokenToString(evt.EncryptedDeviceToken.Base64UrlDecode())}");
                }
                else
                {
                    Console.WriteLine("New notification arrived.");
                }
            }

            return false;
        }

        private void SubscribeToNotifications()
        {
            _auth.AuthContext.PushNotifications.RegisterCallback(NotificationCallback);
        }

        private void UnsubscribeFromNotifications()
        {
            _auth.AuthContext?.PushNotifications.RemoveCallback(NotificationCallback);
            _auth.AuthContext?.PushNotifications.RemoveCallback(EnterpriseNotificationCallback);
        }

        private async Task LogoutCommand(string _)
        {
            UnsubscribeFromNotifications();
            await _auth.Logout();
            NextStateContext = new NotConnectedCliContext(_auth);
        }

        private Task ListCommand(ListCommandOptions options)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(_currentFolder))
            {
                _vault.TryGetFolder(_currentFolder, out node);
            }

            if (node == null)
            {
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
                tab.AddRow(new[] {"Record UID:", record.Uid});
                tab.AddRow(new[] {"Title:", record.Title});
                tab.AddRow(new[] {"Login:", record.Login});
                tab.AddRow(new[] {"Password:", record.Password});
                tab.AddRow(new[] {"Login URL:", record.Link});
                tab.AddRow(new[] {"Notes:", record.Notes});
                if (record.Custom != null && record.Custom.Count > 0)
                {
                    tab.AddRow(new[] {""});
                    tab.AddRow(new[] {"Custom Fields:", ""});
                    foreach (var c in record.Custom)
                    {
                        tab.AddRow(new[] {c.Name + ":", c.Value});
                    }
                }
            }
            else if (_vault.TryGetSharedFolder(uid, out var sf))
            {
                tab.AddRow(new[] {"Shared Folder UID:", sf.Uid});
                tab.AddRow(new[] {"Name:", sf.Name});
                tab.AddRow(new[] {"Default Manage Records:", sf.DefaultManageRecords.ToString()});
                tab.AddRow(new[] {"Default Manage Users:", sf.DefaultManageUsers.ToString()});
                tab.AddRow(new[] {"Default Can Edit:", sf.DefaultCanEdit.ToString()});
                tab.AddRow(new[] {"Default Can Share:", sf.DefaultCanShare.ToString()});
                if (sf.RecordPermissions.Count > 0)
                {
                    tab.AddRow(new[] {""});
                    tab.AddRow(new[] {"Record Permissions:"});
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
                    tab.AddRow(new[] {""});
                    tab.AddRow(new[] {"User/Team Permissions:"});
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
                tab.AddRow(new[] {"Folder UID:", f.FolderUid});
                if (!string.IsNullOrEmpty(f.ParentUid))
                {
                    tab.AddRow(new[] {"Parent Folder UID:", f.ParentUid});
                }

                tab.AddRow(new[] {"Folder Type:", f.FolderType.ToString()});
                tab.AddRow(new[] {"Name:", f.Name});
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
                    record.Login = await Program.InputManager.ReadLine();
                }

                if (string.IsNullOrEmpty(record.Password))
                {
                    Console.Write("..." + "Password: ".PadRight(16));
                    record.Login = await Program.InputManager.ReadLine(new ReadLineParameters
                    {
                        IsSecured = true
                    });
                }

                if (string.IsNullOrEmpty(record.Link))
                {
                    Console.Write("..." + "Login URL: ".PadRight(16));
                    record.Link = await Program.InputManager.ReadLine();
                }
            }

            await _vault.AddRecord(record, node.FolderUid);
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

            await _vault.PutRecord(record);
        }

        private string TokenToString(byte[] token)
        {
            var sb = new StringBuilder();
            foreach (var b in token)
            {
                sb.AppendFormat("{0:x2}", b);
                if (sb.Length >= 20)
                {
                    break;
                }
            }

            return sb.ToString();
        }

        private string DeviceStatusToString(DeviceStatus status)
        {
            switch (status)
            {
                case DeviceStatus.DeviceOk:
                    return "OK";
                case DeviceStatus.DeviceNeedsApproval:
                    return "Need Approval";
                case DeviceStatus.DeviceDisabledByUser:
                    return "Disabled";
                case DeviceStatus.DeviceLockedByAdmin:
                    return "Locked";
                default:
                    return "";
            }
        }

        private async Task ThisDeviceCommand(ThisDeviceOptions arguments)
        {
            if (!(_auth.AuthContext is AuthContextV3)) return;

            if (_accountSummary == null)
            {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            var device = _accountSummary?.Devices
                .FirstOrDefault(x => x.EncryptedDeviceToken.ToByteArray().SequenceEqual(_auth.AuthContext.DeviceToken));
            if (device == null)
            {
                Console.WriteLine("???????????????");
                return;
            }

            var availableVerbs = new[] {"rename", "register", "persistent_login", "ip_disable_auto_approve", "timeout"};

            switch (arguments.Command)
            {
                case null:
                {
                    Console.WriteLine();
                    Console.WriteLine("{0, 20}: {1}", "Device Name", device.DeviceName);
                    Console.WriteLine("{0, 20}: {1}", "Client Version", device.ClientVersion);
                    Console.WriteLine("{0, 20}: {1}", "Has Data Key", device.EncryptedDataKey.Length > 0);
                    Console.WriteLine("{0, 20}: {1}", "IP Auto Approve", !_accountSummary.Settings.IpDisableAutoApprove);
                    Console.WriteLine("{0, 20}: {1}", "Persistent Login", _accountSummary.Settings.PersistentLogin);

                    var uc = _auth.Storage.Users.Get(_auth.AuthContext.Username);
                    if (uc?.LastDevice?.LogoutTimer != null)
                    {
                        Console.WriteLine("{0, 20}: {1}", "Logout Timeout", uc.LastDevice.LogoutTimer);
                    }

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
                    if (device.EncryptedDataKey.Length == 0)
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
                            var uc = _auth.Storage.Users.Get(_auth.AuthContext.Username);
                            if (uc?.LastDevice != null && uc.LastDevice.LogoutTimer != timeout)
                            {
                                var userConf = new UserConfiguration(uc)
                                {
                                    LastDevice = new UserDeviceConfiguration(uc.LastDevice)
                                    {
                                        LogoutTimer = timeout
                                    }
                                };
                                _auth.Storage.Users.Put(userConf);
                            }
                        }
                        else
                        {
                            Console.WriteLine($"{arguments.Command}: invalid timeout in minutes parameter: {arguments.Parameter}");
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
            if (!(_auth.AuthContext is AuthContextV3 contextV3)) return;
            if (_auth.AuthContext.Settings?.shareDatakeyWithEccPublicKey != true) 
            {
                Console.WriteLine("Data key sharing is not requested.");
                return;
            }
            Console.Write("Enterprise administrator requested data key to be shared. Proceed with sharing? (Yes/No) : ");
            var answer = await Program.InputManager.ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }
            if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;

            var rs = (EnterprisePublicKeyResponse) await _auth.ExecuteAuthRest("breachwatch/get_enterprise_public_key", null, typeof(EnterprisePublicKeyResponse));
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
            if (!(_auth.AuthContext is AuthContextV3 contextV3)) return;

            if (arguments.Force)
            {
                _accountSummary = null;
            }

            if (_accountSummary == null)
            {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            if (_accountSummary == null)
            {
                Console.WriteLine("No devices available");
                return;
            }

            var devices = _accountSummary.Devices
                .Where(x => !x.EncryptedDeviceToken.SequenceEqual(contextV3.DeviceToken))
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
                    tab.AddRow(new[]
                    {
                        device.DeviceName,
                        device.ClientVersion,
                        TokenToString(device.EncryptedDeviceToken.ToByteArray()),
                        DeviceStatusToString(device.DeviceStatus),
                        device.EncryptedDataKey.Length > 0 ? "Yes" : "No"
                    });
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

                        var token = TokenToString(x.EncryptedDeviceToken.ToByteArray());
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

                            if (string.CompareOrdinal(folder, subNode.Name) != 0) continue;

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
            await LogoutCommand("");
            return true;
        }

        public override string GetPrompt()
        {
            if (!_auth.IsAuthenticated())
            {
                _ = LogoutCommand("");
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
    }

    class ListCommandOptions
    {
        [Option('l', "list", Required = false, Default = false, HelpText = "detailed output")]
        public bool Details { get; set; }

        [Value(0, Required = false, MetaName = "pattern", HelpText = "search pattern")]
        public string Pattern { get; set; }
    }

    class TreeCommandOptions
    {
        [Value(0, Required = false, MetaName = "folder", HelpText = "folder path or UID")]
        public string Folder { get; set; }
    }

    class EditRecord
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
        [Value(0, Required = false, HelpText = "this-device command: \"register\", \"rename\", \"timeout\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "sub-command parameter")]
        public string Parameter { get; set; }
    }
}