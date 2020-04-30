using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Sdk;

namespace Commander
{
    public class ConnectedContext : StateContext
    {
        private readonly Vault _vault;

        public ConnectedContext(Vault vault)
        {
            _vault = vault;
            Task.Run(() =>
            {
                try
                {
                    _ = SubscribeToNotifications();
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            });
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

            Commands.Add("sync-down", new SimpleCommand
            {
                Order = 100,
                Description = "Download & decrypt data",
                Action = async (_) =>
                {
                    Console.WriteLine("Syncing...");
                    await _vault.SyncDown();
                }
            });

            Commands.Add("logout", new SimpleCommand
            {
                Order = 200,
                Description = "Logout",
                Action = (_) =>
                {
                    UnsubscribeFromNotifications();
                    _vault.Auth.Logout();
                    NextStateContext = new NotConnectedCliContext(_vault.Auth);
                    return Task.FromResult(false);
                }
            });

            CommandAliases.Add("ls", "list");
            CommandAliases.Add("d", "sync-down");
            CommandAliases.Add("add", "add-record");
            CommandAliases.Add("upd", "update-record");
        }

        private string _currentFolder;

        private CancellationTokenSource _notificationCancelToken;

        private async Task SubscribeToNotifications()
        {
            var pushUrl = await _vault.Auth.GetNotificationUrl();
            var ws = new ClientWebSocket();
            var ts = new CancellationTokenSource();
            await ws.ConnectAsync(new Uri(pushUrl), ts.Token);
            _notificationCancelToken = ts;
            _ = Task.Run(async () =>
            {
                var webSocket = ws;
                var tokenSource = ts;
                var buffer = new byte[1024];
                var segment = new ArraySegment<byte>(buffer);
                try
                {
                    while (webSocket.State == WebSocketState.Open && !tokenSource.IsCancellationRequested)
                    {
                        var rs = await ws.ReceiveAsync(segment, tokenSource.Token);
                        if (rs == null) break;
                        if (rs.Count <= 0) continue;

                        var notification = new byte[rs.Count];
                        Array.Copy(buffer, notification, rs.Count);
                        _vault.OnNotificationReceived(notification);
                    }

                    if (webSocket.State == WebSocketState.Open)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
                    }

                    if (!tokenSource.IsCancellationRequested)
                    {
                        tokenSource.Cancel();
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
                finally
                {
                    if (_notificationCancelToken == tokenSource)
                    {
                        _notificationCancelToken = null;
                    }

                    tokenSource.Dispose();
                    webSocket.Dispose();
                }
            }, ts.Token);
        }

        private void UnsubscribeFromNotifications()
        {
            if (_notificationCancelToken == null) return;

            if (!_notificationCancelToken.IsCancellationRequested)
            {
                _notificationCancelToken.Cancel();
            }

            _notificationCancelToken.Dispose();
            _notificationCancelToken = null;
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
                            r.RecordUid + ":", "Can Edit: " + r.CanEdit.ToString(),
                            "Can Share: " + r.CanShare.ToString()
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
                    record.Login = Console.ReadLine();
                }

                if (string.IsNullOrEmpty(record.Password))
                {
                    Console.Write("..." + "Password: ".PadRight(16));
                    record.Login = HelperUtils.ReadLineMasked();
                }

                if (string.IsNullOrEmpty(record.Link))
                {
                    Console.Write("..." + "Login URL: ".PadRight(16));
                    record.Link = Console.ReadLine();
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

        public override string GetPrompt()
        {
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
}