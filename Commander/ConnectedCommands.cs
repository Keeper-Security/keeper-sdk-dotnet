using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
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
                Commands.Add("search",
                    new ParsableCommand<SearchCommandOptions>
                    {
                        Order = 10,
                        Description = "Search the vault. Can use a regular expression",
                        Action = SearchCommand
                    });

                Commands.Add("list",
                    new ParsableCommand<ListCommandOptions>
                    {
                        Order = 11,
                        Description = "List folder content",
                        Action = ListCommand
                    });

                Commands.Add("cd",
                    new SimpleCommand
                    {
                        Order = 12,
                        Description = "Change current folder",
                        Action = ChangeDirectoryCommand
                    });

                Commands.Add("tree",
                    new ParsableCommand<TreeCommandOptions>
                    {
                        Order = 13,
                        Description = "Display folder structure",
                        Action = TreeCommand
                    });

                Commands.Add("get",
                    new SimpleCommand
                    {
                        Order = 14,
                        Description = "Display specified Keeper record/folder/team",
                        Action = GetCommand
                    });

                if (auth.AuthContext.Settings.RecordTypesEnabled)
                {
                    Commands.Add("record-type-info",
                        new ParsableCommand<RecordTypeInfoOptions>
                        {
                            Order = 20,
                            Description = "Get record type info",
                            Action = RecordTypeInfoCommand
                        }
                    );
                    CommandAliases.Add("rti", "record-type-info");

                }

                Commands.Add("add-record",
                    new ParsableCommand<AddRecordOptions>
                    {
                        Order = 21,
                        Description = "Add record",
                        Action = AddRecordCommand
                    });

                Commands.Add("update-record",
                    new ParsableCommand<UpdateRecordOptions>
                    {
                        Order = 22,
                        Description = "Update record",
                        Action = UpdateRecordCommand
                    });

                Commands.Add("mkdir",
                    new ParsableCommand<MakeFolderOptions>
                    {
                        Order = 23,
                        Description = "Make folder",
                        Action = MakeFolderCommand
                    });

                Commands.Add("rmdir",
                    new ParsableCommand<FolderOptions>
                    {
                        Order = 24,
                        Description = "Remove folder",
                        Action = RemoveFolderCommand
                    });

                Commands.Add("update-dir",
                    new ParsableCommand<UpdateFolderOptions>
                    {
                        Order = 25,
                        Description = "Update folder",
                        Action = UpdateFolderCommand
                    });

                Commands.Add("mv",
                    new ParsableCommand<MoveOptions>
                    {
                        Order = 26,
                        Description = "Move record or folder",
                        Action = MoveCommand
                    });

                Commands.Add("rm",
                    new ParsableCommand<RemoveRecordOptions>
                    {
                        Order = 27,
                        Description = "Remove record(s)",
                        Action = RemoveRecordCommand
                    });

                Commands.Add("download-attachment",
                    new ParsableCommand<DownloadAttachmentOptions>
                    {
                        Order = 28,
                        Description = "Download Attachment(s)",
                        Action = DownloadAttachmentCommand
                    });

                Commands.Add("upload-attachment",
                    new ParsableCommand<UploadAttachmentOptions>
                    {
                        Order = 29,
                        Description = "Upload file attachment",
                        Action = UploadAttachmentCommand
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

                Commands.Add("share-record",
                    new ParsableCommand<ShareRecordOptions>
                    {
                        Order = 32,
                        Description = "Change the sharing permissions of an individual record",
                        Action = ShareRecordCommand
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
                CommandAliases.Add("edit", "update-record");
            }

            Program.EnqueueCommand("sync-down");
        }

        private string _currentFolder;

        private bool DeviceApprovalRequestCallback(NotificationEvent evt)
        {
            if (string.Compare(evt.Event, "device_approval_request", StringComparison.InvariantCultureIgnoreCase) !=
                0) return false;
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

        private Task SearchCommand(SearchCommandOptions options)
        {
            if (options.Limit <= 0)
            {
                options.Limit = 100;
            }
            else if (options.Limit > 1000)
            {
                options.Limit = 1000;
            }

            Regex pattern = string.IsNullOrEmpty(options.Pattern)
                ? null
                : new Regex(options.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);

            var matchedRecords = _vault.KeeperRecords
                .Where(record =>
                {
                    if (pattern == null)
                    {
                        return true;
                    }

                    if (record.Uid == options.Pattern)
                    {
                        return true;
                    }

                    if (pattern.IsMatch(record.Title))
                    {
                        return true;
                    }

                    if (record is PasswordRecord legacy)
                    {
                        return new[] {legacy.Notes, legacy.Login, legacy.Password, legacy.Notes}
                            .Where(x => !string.IsNullOrEmpty(x))
                            .Any(x => pattern.IsMatch(x));
                    }

                    if (record is TypedRecord typed)
                    {

                        var matched = new[] { typed.Notes, typed.TypeName }
                            .Where(x => !string.IsNullOrEmpty(x))
                            .Any(x => pattern.IsMatch(x));

                        if (matched)
                        {
                            return true;
                        }

                        matched = typed.Fields
                            .Any(x => x.GetTypedFieldValues().Any(y => pattern.IsMatch(y)));
                        if (matched)
                        {
                            return true;
                        }

                        return typed.Custom
                            .Any(x => x.GetTypedFieldValues().Any(y => pattern.IsMatch(y)));
                    }

                    return false;
                })
                .Take(options.Limit)
                .ToArray();

            if (matchedRecords.Length > 0)
            {
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.AddHeader("Record UID", "Title", "Type", "Info");
                foreach (var r in matchedRecords)
                {
                    tab.AddRow(r.Uid, r.Title, r.KeeperRecordType(), r.KeeperRecordPublicInformation());
                }

                tab.Sort(1);
                tab.Dump();

                if (matchedRecords.Length == options.Limit)
                {
                    Console.WriteLine($"First {options.Limit} found records are shown.");
                }
            }
            else
            {
                Console.WriteLine("No records found");
            }

            return Task.FromResult(true);
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
                    tab.AddHeader("Folder UID", "Name");
                    foreach (var uid in node.Subfolders)
                    {
                        if (_vault.TryGetFolder(uid, out var f))
                        {
                            tab.AddRow(f.FolderUid, f.Name);
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
                    tab.AddHeader("Record UID", "Title", "Type", "Info");
                    foreach (var uid in node.Records)
                    {
                        if (_vault.TryGetKeeperRecord(uid, out var r))
                        {
                            tab.AddRow(r.Uid, r.Title, r.KeeperRecordType(), r.KeeperRecordPublicInformation());
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
                    if (_vault.TryGetKeeperRecord(uid, out var r))
                    {
                        if (r.Version == 2 || r.Version == 3)
                        {
                            names.Add(string.IsNullOrEmpty(r.Title) ? r.Uid : r.Title);
                        }
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
            if (_vault.TryGetKeeperRecord(uid, out var record))
            {
                List<string> totps = null;

                tab.AddRow("Record UID:", record.Uid);
                tab.AddRow("Type:", record.KeeperRecordType());
                tab.AddRow("Title:", record.Title);
                if (record is PasswordRecord legacy)
                {
                    tab.AddRow("Notes:", legacy.Notes);
                    tab.AddRow("(login):", legacy.Login);
                    tab.AddRow("(password):", legacy.Password);
                    tab.AddRow("(url):", legacy.Link);
                    if (legacy.Custom != null && legacy.Custom.Count > 0)
                    {
                        foreach (var c in legacy.Custom)
                        {
                            tab.AddRow(c.Name + ":", c.Value);
                        }
                    }

                    if (legacy.ExtraFields != null)
                    {
                        totps = legacy.ExtraFields
                            .Where(x =>
                                string.Equals(x.FieldType, "totp", StringComparison.InvariantCultureIgnoreCase) &&
                                x.Custom != null)
                            .Where(x => x.Custom.ContainsKey("data"))
                            .Select(x => x.Custom["data"] as string)
                            .Where(x => !string.IsNullOrEmpty(x))
                            .ToList();
                    }
                }
                else if (record is TypedRecord typed)
                {
                    tab.AddRow("Notes:", typed.Notes);
                    foreach (var f in typed.Fields.Concat(typed.Custom))
                    {
                        if (f.FieldName == "totp")
                        {
                            if (totps == null)
                            {
                                totps = new List<string>();
                            }

                            if (f is TypedField<string> sf && sf.Count > 0)
                            {
                                totps.AddRange(sf.Values.Where(x => !string.IsNullOrEmpty(x)));
                            }
                        }
                        else
                        {
                            var label = f.GetTypedFieldName();
                            var values = f.GetTypedFieldValues().ToArray();
                            for (var i = 0; i < Math.Max(values.Length, 1); i++)
                            {
                                var v = i < values.Length ? values[i] : "";
                                if (v.Length > 80)
                                {
                                    v = v.Substring(0, 77) + "...";
                                }

                                tab.AddRow(i == 0 ? $"{label}:" : "", v);
                            }
                        }
                    }
                }
                else if (record is FileRecord file)
                {
                    tab.AddRow("Name:", file.Name);
                    tab.AddRow("MIME Type:", file.MimeType ?? "");
                    tab.AddRow("Size:", file.FileSize.ToString("N"));
                    if (file.ThumbnailSize > 0)
                    {
                        tab.AddRow("Thumbnail Size:", file.ThumbnailSize.ToString("N"));
                    }
                }

                if (totps != null)
                {
                    foreach (var url in totps)
                    {
                        try
                        {
                            var tup = CryptoUtils.GetTotpCode(url);
                            tab.AddRow($"{tup.Item1}:", $"expires in {tup.Item3 - tup.Item2} sec.");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }

                tab.AddRow("Last Modified:", record.ClientModified.LocalDateTime.ToString("F"));

            }
            else if (_vault.TryGetSharedFolder(uid, out var sf))
            {
                tab.AddRow("Shared Folder UID:", sf.Uid);
                tab.AddRow("Name:", sf.Name);
                tab.AddRow("Default Manage Records:", sf.DefaultManageRecords.ToString());
                tab.AddRow("Default Manage Users:", sf.DefaultManageUsers.ToString());
                tab.AddRow("Default Can Edit:", sf.DefaultCanEdit.ToString());
                tab.AddRow("Default Can Share:", sf.DefaultCanShare.ToString());
                if (sf.RecordPermissions.Count > 0)
                {
                    tab.AddRow("");
                    tab.AddRow("Record Permissions:");
                    foreach (var r in sf.RecordPermissions)
                    {
                        tab.AddRow(r.RecordUid + ":",
                            $"Can Edit: {(r.CanEdit ? "Y" : "N")} Can Share: {(r.CanShare ? "Y" : "N")}");
                    }
                }

                var teamLookup = _vault.Teams.ToDictionary(t => t.TeamUid, t => t.Name);
                if (sf.UsersPermissions.Count > 0)
                {
                    tab.AddRow("");
                    tab.AddRow("User/Team Permissions:");
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
                        tab.AddRow($"{u.UserType} {subjectName}:", $"Can Manage Records: {u.ManageRecords}",
                            $"Can Manage Users: {u.ManageUsers}");
                    }
                }
            }
            else if (_vault.TryGetFolder(uid, out var f))
            {
                tab.AddRow("Folder UID:", f.FolderUid);
                if (!string.IsNullOrEmpty(f.ParentUid))
                {
                    tab.AddRow("Parent Folder UID:", f.ParentUid);
                }

                tab.AddRow("Folder Type:", f.FolderType.ToString());
                tab.AddRow("Name:", f.Name);
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

        private static readonly Tuple<string, bool>[] Prefixes = {Tuple.Create("field.",true), Tuple.Create("f.", true), Tuple.Create("custom.", false), Tuple.Create("c.", false)};
        private const string FieldPattern = "^(\\w+)(\\.[^\\[]+)?(\\[*.\\])?\\s*=\\s*(.*)$";

        private static IEnumerable<CmdLineRecordField> ParseRecordFields(IEnumerable<string> inputs)
        {
            var rx = new Regex(FieldPattern);
            foreach (var f in inputs)
            {
                var field = f;
                var crf = new CmdLineRecordField();
                foreach (var pair in Prefixes)
                {
                    var prefix = pair.Item1;
                    var isField = pair.Item2;
                    if (field.StartsWith(prefix, StringComparison.InvariantCultureIgnoreCase))
                    {
                        crf.IsRecordField = isField;
                        field = field.Substring(prefix.Length);
                        break;
                    }
                }
                var match = rx.Match(field);
                if (!match.Success || match.Groups.Count < 5)
                {
                    throw new Exception($"Invalid field parameter: {f}");
                }

                crf.FieldName = match.Groups[1].Value.Trim();
                crf.FieldLabel = match.Groups[2].Value.Trim('.').Trim();
                crf.FieldIndex = match.Groups[3].Value.Trim('[', ']').Trim();
                crf.Value = match.Groups[4].Value.Trim();
                if (crf.Value.Length >= 2 && crf.Value.StartsWith("\"") && crf.Value.EndsWith("\""))
                {
                    crf.Value = crf.Value.Trim('"').Replace("\\\"", "\"");
                }

                yield return crf;
            }
        }


        private void AssignRecordFields(KeeperRecord record, CmdLineRecordField[] fields)
        {
            if (record is PasswordRecord password)
            {
                foreach (var field in fields)
                {
                    switch (field.FieldName.ToLowerInvariant())
                    {
                        case "login":
                            password.Login = field.Value;
                            break;
                        case "password":
                            password.Password = field.Value;
                            break;
                        case "notes":
                            password.Notes = field.Value;
                            break;
                        default:
                            password.SetCustomField(field.FieldName, field.Value);
                            break;
                    }
                }
            }
            else if (record is TypedRecord typed)
            {
                var indexes = new Dictionary<string, int>(StringComparer.InvariantCultureIgnoreCase);
                foreach (var f in typed.Fields.Concat(typed.Custom))
                {
                    if (f.Count <= 1) continue;
                    var fullName = f.GetTypedFieldName();
                    for (var i = 1; i < f.Count; i++)
                    {
                        indexes.Add($"{fullName}[{i}]", i);
                    }
                }

                if (_vault.TryGetRecordTypeByName(typed.TypeName, out var recordType))
                {
                    VerifyTypedFields(fields, recordType);
                }

                var fieldSet = fields.Where(x => !string.IsNullOrEmpty(x.Value)).ToArray();
                var fieldDelete = fields.Where(x => string.IsNullOrEmpty(x.Value)).ToArray();
                foreach (var field in fieldSet.Concat(fieldDelete))
                {
                    if (string.Equals(field.FieldName, "notes", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (string.IsNullOrEmpty(typed.Notes))
                        {
                            typed.Notes = "";
                        }
                        else
                        {
                            typed.Notes += "\n";
                        }
                        typed.Notes += field.Value;
                    }
                    else
                    {
                        var fieldSource = field.IsRecordField == true ? typed.Fields : typed.Custom;
                        if (!fieldSource.FindTypedField(field, out var typedField))
                        {
                            if (string.IsNullOrEmpty(field.Value)) continue;

                            typedField = field.CreateTypedField();
                            fieldSource.Add(typedField);
                        }

                        if (string.IsNullOrEmpty(field.Value))
                        {
                            if (string.IsNullOrEmpty(field.FieldIndex))
                            {
                                fieldSource.Remove(typedField);
                            }
                            else
                            {
                                var fullName = field.GetTypedFieldName();
                                var valuePath = $"{fullName}[{field.FieldIndex}]";
                                if (!indexes.TryGetValue(valuePath, out var idx))
                                {
                                    if (idx >= 0 && idx < typedField.Count)
                                    {
                                        typedField.DeleteValueAt(idx);
                                    }
                                    indexes.Remove(valuePath);
                                }
                            }
                        }
                        else
                        {
                            var idx = 0;
                            if (!string.IsNullOrEmpty(field.FieldIndex))
                            {
                                var fullName = field.GetTypedFieldName();
                                var valuePath = $"{fullName}[{field.FieldIndex}]";
                                if (!indexes.TryGetValue(valuePath, out idx))
                                {
                                    typedField.AppendValue();
                                    idx = typedField.Count - 1;
                                    indexes.Add(valuePath, idx);
                                }
                            }

                            if (typedField.Count == 0)
                            {
                                typedField.AppendValue();
                            }

                            if (typedField is TypedField<string> tfs)
                            {
                                tfs.Values[idx] = field.Value;
                            }
                            else if (typedField is TypedField<long> tfl)
                            {
                                if (!long.TryParse(field.Value, out var lv))
                                {
                                    if (DateTimeOffset.TryParse(field.Value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeUniversal, out var dto))
                                    {
                                        lv = dto.ToUnixTimeMilliseconds();
                                    }
                                    else
                                    {
                                        throw new Exception($"Field \"{field.FieldName}\": invalid value \"{field.Value}\"");
                                    }
                                }
                                tfl.Values[idx] = lv;
                            }
                            else
                            {
                                if (typedField.GetValueAt(idx) is IFieldTypeSerialize typedValue)
                                {
                                    foreach (var pair in field.Value.Split(','))
                                    {
                                        var pos = pair.IndexOf('=');
                                        var element = pos > 0 ? pair.Substring(0, pos) : pair;
                                        var value = pos > 0 ? pair.Substring(pos + 1) : "";
                                        if (!typedValue.SetElementValue(element, value))
                                        {
                                            throw new Exception($"Field type {field.FieldName}: Invalid element name: {element}.");
                                        }
                                    }
                                }
                                else
                                {
                                    throw new Exception($"Field type {field.FieldName}: Value serialization is not supported.");
                                }
                            }
                        }
                    }
                }
            }
        }

        private void VerifyTypedFields(CmdLineRecordField[] fields, RecordType recordType)
        {
            var recordFields = new Dictionary<string, RecordTypeField>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var f in recordType.Fields)
            {
                recordFields[f.FieldName] = f;
            }
            foreach (var field in fields)
            {
                if (string.Equals(field.FieldName, "notes", StringComparison.InvariantCultureIgnoreCase))
                {
                    continue;
                }

                if (!field.IsRecordField.HasValue)
                {
                    if (recordFields.TryGetValue(field.FieldName, out var rtf))
                    {
                        field.FieldLabel = rtf.FieldLabel;
                        field.IsRecordField = true;
                        if (rtf.RecordField.Multiple == RecordFieldMultiple.Default)
                        {
                            recordFields.Remove(field.FieldName);
                        }
                    }
                    else
                    {
                        field.IsRecordField = false;
                    }
                }

                if (string.IsNullOrEmpty(field.Value)) continue;

                if (!RecordTypesConstants.TryGetRecordField(field.FieldName, out var recordField))
                {
                    throw new Exception($"Record field \"{field.FieldName}\" is not supported.");
                }

                if (string.IsNullOrEmpty(field.FieldIndex)) continue;

                if (recordField.Multiple != RecordFieldMultiple.Default)
                {
                    throw new Exception($"Record field \"{field.FieldName}\" does not support multiple values");
                }
            }
        }

        private async Task AddRecordCommand(AddRecordOptions options)
        {
            if (!TryResolvePath(options.Folder, out var node))
            {
                Console.WriteLine($"Cannot resolve folder {options.Folder}");
                return;
            }
            if (string.IsNullOrEmpty(options.Title)) 
            {
                Console.WriteLine($"\"Title\" parameter is missing.");
                return;
            }
            var fields = ParseRecordFields(options.Fields).ToArray();
            if (options.Generate)
            {
                foreach (var field in fields)
                {
                    if (string.Equals(field.FieldName, "password", StringComparison.InvariantCultureIgnoreCase) && string.IsNullOrEmpty(field.Value))
                    {
                        field.Value = CryptoUtils.GenerateUid();
                    }
                }
            }

            KeeperRecord record = null;
            if (string.Equals(options.RecordType, "general", StringComparison.InvariantCultureIgnoreCase) || 
                string.Equals(options.RecordType, "legacy", StringComparison.InvariantCultureIgnoreCase))
            {
                record = new PasswordRecord
                {
                    Title = options.Title
                };
            }
            else
            {
                record = new TypedRecord(options.RecordType)
                {
                    Title = options.Title
                };
            }

            AssignRecordFields(record, fields);
            await _vault.CreateRecord(record, node.FolderUid);
        }

        private async Task UpdateRecordCommand(UpdateRecordOptions options)
        {
            if (_vault.TryGetKeeperRecord(options.RecordId, out var record))
            {
            }
            else if (TryResolvePath(options.RecordId, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!_vault.TryGetKeeperRecord(uid, out var r)) continue;
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

            var fields = ParseRecordFields(options.Fields).ToArray();
            if (options.Generate)
            {
                foreach (var field in fields)
                {
                    if (string.Equals(field.FieldName, "password", StringComparison.InvariantCultureIgnoreCase) && string.IsNullOrEmpty(field.Value))
                    {
                        field.Value = CryptoUtils.GenerateUid();
                    }
                }
            }

            AssignRecordFields(record, fields);
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

            if (_vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
                var folders = Enumerable.Repeat(_vault.RootFolder, 1).Concat(_vault.Folders)
                    .Where(x => x.Records.Contains(record.Uid)).ToArray();
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

                await _vault.DeleteRecords(new[]
                    {new RecordPath {FolderUid = folder.FolderUid, RecordUid = record.Uid,}});
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
                    if (!_vault.TryGetKeeperRecord(recordUid, out record)) continue;

                    var m = Regex.Match(record.Title, pattern, RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        records.Add(new RecordPath {FolderUid = folder.FolderUid, RecordUid = recordUid});
                    }
                }

                await _vault.DeleteRecords(records.ToArray());
            }
        }


        private async Task DownloadAttachmentCommand(DownloadAttachmentOptions options)
        {
            if (_vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
            }
            else if (TryResolvePath(options.RecordName, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!_vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {options.RecordName}");
                return;
            }

            if (string.IsNullOrEmpty(options.OutputDirectory))
            {
                options.OutputDirectory = Directory.GetCurrentDirectory();
            }
            else
            {
                var dirEntry = System.IO.Directory.CreateDirectory(options.OutputDirectory);
                options.OutputDirectory = dirEntry.FullName;
            }

            var attas = _vault.RecordAttachments(record)
                .Where(x =>
                {
                    if (string.IsNullOrEmpty(options.FileName))
                    {
                        return true;
                    }

                    if (string.Equals(options.FileName, x.Id))
                    {
                        return true;
                    }

                    if (string.Equals(options.FileName, x.Title, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return true;
                    }

                    if (string.Equals(options.FileName, x.Name, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return true;
                    }

                    return false;
                }).ToArray();

            if (attas.Length > 0)
            {
                foreach (var atta in attas)
                {
                    Console.Write($"Downloading {atta.Name} ...");
                    try
                    {
                        using (var stream = File.OpenWrite(Path.Combine(options.OutputDirectory, atta.Name)))
                        {
                            switch (atta)
                            {
                                case AttachmentFile af:
                                    await _vault.DownloadAttachmentFile(record.Uid, af, stream);
                                    break;
                                case FileRecord fr:
                                    await _vault.DownloadFile(fr, stream);
                                    break;
                            }
                        }

                        Console.WriteLine(" Done.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Failed: {e.Message}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"Attachment not found: {(options.FileName ?? "")}");
            }
        }

        private async Task UploadAttachmentCommand(UploadAttachmentOptions options)
        {
            if (_vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
            }
            else if (TryResolvePath(options.RecordName, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!_vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {options.RecordName}");
                return;
            }

            if (!File.Exists(options.FileName))
            {
                Console.WriteLine($"File {options.FileName} not found.");
                return;
            }

            var uploadTask = new FileAttachmentUploadTask(options.FileName);
            if (record is PasswordRecord password)
            {
                await _vault.UploadAttachment(password, uploadTask);
            }
            else if (record is TypedRecord typed)
            {
                await _vault.UploadAttachment(typed, uploadTask);
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
            else if (_vault.TryGetKeeperRecord(options.SourceName, out var record))
            {
                var folders = Enumerable.Repeat(_vault.RootFolder, 1).Concat(_vault.Folders)
                    .Where(x => x.Records.Contains(record.Uid)).ToArray();
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

                await _vault.MoveRecords(new[] {new RecordPath {FolderUid = folder.FolderUid, RecordUid = record.Uid}},
                    dstFolder.FolderUid, options.Link);
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
                        if (!_vault.TryGetKeeperRecord(recordUid, out record)) continue;

                        var m = Regex.Match(record.Title, pattern, RegexOptions.IgnoreCase);
                        if (m.Success)
                        {
                            records.Add(new RecordPath {FolderUid = srcFolder.FolderUid, RecordUid = recordUid});
                        }
                    }

                    if (records.Count == 0)
                    {
                        throw new Exception(
                            $"Folder {srcFolder.Name} does not contain any record matching {recordTitle}");
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

        private async Task UpdateFolderCommand(UpdateFolderOptions options)
        {
            if (TryResolvePath(options.FolderName, out var folder))
            {
                SharedFolderOptions sharedFolderOptions = null;
                if (folder.FolderType == FolderType.SharedFolder)
                {
                    sharedFolderOptions = new SharedFolderOptions
                    {
                        ManageRecords = options.ManageRecords,
                        ManageUsers = options.ManageUsers,
                        CanEdit = options.CanEdit,
                        CanShare = options.CanShare,
                    };
                }

                await _vault.UpdateFolder(folder.FolderUid, options.NewName, sharedFolderOptions);
            }
            else
            {
                Console.WriteLine($"Invalid folder path: {options.FolderName}");
            }
        }

        private async Task ThisDeviceCommand(ThisDeviceOptions arguments)
        {
            if (_accountSummary == null)
            {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            var device = _accountSummary?.Devices
                .FirstOrDefault(x => x.EncryptedDeviceToken.ToByteArray().SequenceEqual(_auth.DeviceToken));
            if (device == null)
            {
                Console.WriteLine("???????????????");
                return;
            }

            var availableVerbs = new[]
                {"rename", "register", "persistent_login", "ip_disable_auto_approve", "timeout", "bio"};

            var deviceToken = device.EncryptedDeviceToken.ToByteArray();
            var bioTarget = _auth.Username.BiometricCredentialTarget(deviceToken);
            var hasBio = CredentialManager.GetCredentials(bioTarget, out _, out _);
            var persistentLoginDisabled = false;
            if (_auth.AuthContext.Enforcements.ContainsKey("restrict_persistent_login"))
            {
                var pl = _auth.AuthContext.Enforcements["restrict_persistent_login"];
                if (pl is bool b)
                {
                    persistentLoginDisabled = b;
                }
                else if (pl is IConvertible conv)
                {
                    persistentLoginDisabled = conv.ToBoolean(CultureInfo.InvariantCulture);
                }
                else
                {
                    persistentLoginDisabled = true;
                }
            }

            switch (arguments.Command)
            {
                case null:
                {
                    Console.WriteLine();
                    Console.WriteLine("{0, 20}: {1}", "Device Name", device.DeviceName);
                    Console.WriteLine("{0, 20}: {1}", "Client Version", device.ClientVersion);
                    Console.WriteLine("{0, 20}: {1}", "Data Key Present", device.EncryptedDataKeyPresent);
                    Console.WriteLine("{0, 20}: {1}", "IP Auto Approve",
                        !_accountSummary.Settings.IpDisableAutoApprove);
                    Console.WriteLine("{0, 20}: {1}", "Persistent Login",
                        !persistentLoginDisabled && _accountSummary.Settings.PersistentLogin);
                    if (_accountSummary.Settings.LogoutTimer > 0)
                    {
                        if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromDays(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} day(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalDays);
                        }
                        else if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromHours(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} hour(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalHours);
                        }
                        else if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromSeconds(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} minute(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalMinutes);
                        }
                        else
                        {
                            Console.WriteLine("{0, 20}: {1} second(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalSeconds);
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
                    else if (string.Compare(arguments.Parameter, "off", StringComparison.InvariantCultureIgnoreCase) ==
                             0)
                    {
                        enabled = false;
                    }
                    else
                    {
                        Console.WriteLine($"\"{arguments.Command}\" accepts the following parameters: on, off");
                        return;
                    }

                    if (arguments.Command == "persistent_login" && persistentLoginDisabled)
                    {
                        Console.WriteLine("\"Stay Logged In\" feature is restricted by Keeper Administrator");
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
                            Console.WriteLine(
                                $"{arguments.Command}: invalid timeout in minutes parameter: {arguments.Parameter}");
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
                    else if (string.Compare(arguments.Parameter, "off", StringComparison.InvariantCultureIgnoreCase) ==
                             0)
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
            Console.Write(
                "Enterprise administrator requested data key to be shared. Proceed with sharing? (Yes/No) : ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }

            if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;

            var rs = (EnterprisePublicKeyResponse) await _auth.ExecuteAuthRest("enterprise/get_enterprise_public_key",
                null, typeof(EnterprisePublicKeyResponse));
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
                    .Where(x => ((x.DeviceStatus == DeviceStatus.DeviceNeedsApproval) ||
                                 (arguments.Link && x.DeviceStatus == DeviceStatus.DeviceOk)))
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
                    .Where(x => string.Compare(x.Name, options.FolderName, StringComparison.CurrentCultureIgnoreCase) ==
                                0)
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

                sf = _vault.GetSharedFolder(folder.FolderType == FolderType.SharedFolder
                    ? folder.FolderUid
                    : folder.SharedFolderUid);
            }

            if (string.IsNullOrEmpty(options.User))
            {
                var teams = await GetAvailableTeams();
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
                        tab.AddRow(new[]
                            {p.UserId, p.UserType.ToString(), p.ManageRecords ? "X" : "-", p.ManageUsers ? "X" : "="});
                    }
                    else
                    {
                        var team = teams.FirstOrDefault(x => x.TeamUid == p.UserId);
                        tab.AddRow(new[]
                        {
                            team?.Name ?? p.UserId, p.UserType.ToString(), p.ManageRecords ? "X" : "-",
                            p.ManageUsers ? "X" : "-"
                        });
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
                        team = _vault.Teams.FirstOrDefault(x =>
                            string.Compare(x.Name, options.User, StringComparison.CurrentCultureIgnoreCase) == 0);
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

                var userPermission =
                    sf.UsersPermissions.FirstOrDefault(x => x.UserType == userType && x.UserId == userId);

                if (options.Delete)
                {
                    if (userPermission != null)
                    {
                        await _vault.RemoveUserFromSharedFolder(sf.Uid, userId, userType);
                    }
                    else
                    {
                        Console.WriteLine(
                            $"{(userType == UserType.User ? "User" : "Team")} \'{userId}\' is not a part of Shared Folder {sf.Name}");
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
                        Console.WriteLine("{0, 20}: {1}", "Manage Records",
                            userPermission.ManageRecords ? "Yes" : "No");
                        Console.WriteLine("{0, 20}: {1}", "Manage Users", userPermission.ManageUsers ? "Yes" : "No");
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine(
                            $"{(userType == UserType.User ? "User" : "Team")} \'{userId}\' is not a part of Shared Folder {sf.Name}");
                    }
                }
            }
        }

        private async Task ShareFolderRecordPermissionCommand(ShareFolderRecordPermissionOptions options)
        {
            if (!_vault.TryGetSharedFolder(options.FolderName, out var sf))
            {
                var sfs = _vault.SharedFolders
                    .Where(x => string.Compare(x.Name, options.FolderName, StringComparison.CurrentCultureIgnoreCase) ==
                                0)
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

                sf = _vault.GetSharedFolder(folder.FolderType == FolderType.SharedFolder
                    ? folder.FolderUid
                    : folder.SharedFolderUid);
            }

            if (string.IsNullOrEmpty(options.Record))
            {
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] {"Record Title", "Record UID", "Can Edit", "Can Share"});
                foreach (var p in sf.RecordPermissions)
                {
                    if (_vault.TryGetKeeperRecord(p.RecordUid, out var record))
                    {
                        tab.AddRow(record.Title, p.RecordUid, p.CanEdit ? "X" : "-", p.CanShare ? "X" : "-");
                    }
                }

                tab.Sort(0);
                tab.Dump();
            }
            else
            {
                string recordUid = null;
                if (_vault.TryGetKeeperRecord(options.Record, out var record))
                {
                    recordUid = record.Uid;
                }
                else
                {
                    if (TryResolvePath(options.Record, out var folder, out var title))
                    {
                        recordUid = folder.Records.Select(x => _vault.GetRecord(x)).FirstOrDefault(x =>
                            string.Compare(x.Title, title, StringComparison.CurrentCultureIgnoreCase) == 0)?.Uid;

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

        private async Task ShareRecordCommand(ShareRecordOptions options)
        {

            if (string.Equals("cancel", options.Action, StringComparison.InvariantCultureIgnoreCase))
            {
                Console.Write(
                    $"Do you want to cancel all shares with user \"{options.Email}\"? (Yes/No) : ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    answer = "yes";
                }

                if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;
                await _vault.CancelSharesWithUser(options.Email);
                return;
            }

            if (string.IsNullOrEmpty(options.RecordName))
            {
                Console.WriteLine("Record parameter cannot be empty");
                return;
            }

            if (_vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
            }
            else if (TryResolvePath(options.RecordName, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!_vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record \"{options.RecordName}\"");
                return;
            }

            if (string.Equals("share", options.Action, StringComparison.InvariantCultureIgnoreCase))
            {
                await _vault.ShareRecordWithUser(record.Uid, options.Email, options.CanShare, options.CanEdit);
            }
            else if (string.Equals("revoke", options.Action, StringComparison.InvariantCultureIgnoreCase))
            {
                await _vault.RevokeShareFromUser(record.Uid, options.Email);
            }
            else if (string.Equals("transfer", options.Action, StringComparison.InvariantCultureIgnoreCase))
            {
                await _vault.TransferRecordToUser(record.Uid, options.Email);
            }
            else
            {
                throw new Exception($"Invalid record share action: {options.Action}");
            }
        }

        private Task RecordTypeInfoCommand(RecordTypeInfoOptions options)
        {
            Tabulate table = null;
            if (string.IsNullOrEmpty(options.Name))
            {
                if (options.ShowFields)
                {
                    table = new Tabulate(4);
                    table.AddHeader("Field Type ID", "Type", "Multiple", "Description");
                    foreach (var f in RecordTypesConstants.RecordFields)
                    {
                        table.AddRow(f.Name, f.Type?.Name,
                            f.Multiple == RecordFieldMultiple.Optional
                                ? "optional"
                                : (f.Multiple == RecordFieldMultiple.Default ? "default" : ""),
                            f.Type?.Description ?? "");
                    }
                }
                else
                {
                    table = new Tabulate(3)
                    {
                        LeftPadding = 4
                    };
                    table.SetColumnRightAlign(0, true);
                    table.AddHeader("Record Type ID", "Type Name", "Scope", "Description");
                    foreach (var rt in _vault.RecordTypes)
                    {
                        table.AddRow(rt.Id, rt.Name, rt.Scope.ToText(), rt.Description);
                    }

                    table.Sort(0);
                }
            }
            else
            {
                if (options.ShowFields)
                {
                    if (!RecordTypesConstants.TryGetRecordField(options.Name, out var fieldInfo))
                    {
                        Console.WriteLine($"Error - Unknown field type: {options.Name}");
                        return Task.FromResult(false);
                    }

                    table = new Tabulate(2)
                    {
                        LeftPadding = 4
                    };
                    table.SetColumnRightAlign(0, true);
                    table.AddRow("Field Type ID:", fieldInfo.Name);
                    table.AddRow("Type:", fieldInfo.Type.Name);
                    var valueType = "";
                    if (fieldInfo.Type != null)
                    {
                        if (fieldInfo.Type?.Type == typeof(string))
                        {
                            valueType = "string";
                        }
                        else if (fieldInfo.Type?.Type == typeof(long))
                        {
                            valueType = "integer";
                        }
                        else
                        {
                            valueType = "object";
                        }
                    }

                    table.AddRow("Value Type:", valueType);
                    if (fieldInfo.Type != null)
                    {
                        if (typeof(IFieldTypeSerialize).IsAssignableFrom(fieldInfo.Type.Type))
                        {
                            IFieldTypeSerialize fts = (IFieldTypeSerialize) Activator.CreateInstance(fieldInfo.Type.Type);
                            table.AddRow("Value Elements:", string.Join(", ", fts.Elements.Select(x => $"\"{x}\"")));
                        }
                    }
                }
                else
                {
                    if (!_vault.TryGetRecordTypeByName(options.Name, out var recordInfo))
                    {
                        Console.WriteLine($"Error - Unknown record type: {options.Name}");
                        return Task.FromResult(false);
                    }

                    table = new Tabulate(2)
                    {
                        LeftPadding = 4
                    };
                    table.SetColumnRightAlign(0, true);
                    table.AddRow("Record Type ID:", recordInfo.Id);
                    table.AddRow("Type Name:", recordInfo.Name);
                    table.AddRow("Scope:", recordInfo.Scope.ToText());
                    table.AddRow("Description:", recordInfo.Description);
                    var fields = recordInfo.Fields
                        .Select(x =>
                            $"{x.FieldLabel ?? ""} ({(string.IsNullOrEmpty(x.FieldName) ? "text" : x.FieldName)})"
                                .Trim())
                        .ToArray();
                    for (var i = 0; i < Math.Max(fields.Length, 1); i++)
                    {
                        table.AddRow(i == 0 ? "Fields:" : "", i < fields.Length ? fields[i] : "");
                    }
                }
            }

            table?.Dump();
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

    class SearchCommandOptions
    {
        [Option("limit", Required = false, Default = 0, HelpText = "limit output")]
        public int Limit { get; set; }

        [Value(0, Required = false, MetaName = "pattern", HelpText = "search pattern")]
        public string Pattern { get; set; }
    }

    class ListCommandOptions
    {
        [Option('l', "list", Required = false, Default = false, HelpText = "detailed output")]
        public bool Details { get; set; }
    }

    internal class TreeCommandOptions
    {
        [Value(0, Required = false, MetaName = "folder", HelpText = "folder path or UID")]
        public string Folder { get; set; }
    }

    class AddRecordOptions
    {
        [Option("folder", Required = false, HelpText = "folder")]
        public string Folder { get; set; }

        [Option('t', "type", Required = true, HelpText = "record type. legacy if omitted.")]
        public string RecordType { get; set; }

        [Option( "title", Required = true, HelpText = "record title.")]
        public string Title { get; set; }

        [Option('g', "generate", Required = false, Default = false, HelpText = "generate random password")]
        public bool Generate { get; set; }

        [Value(0, Required = false, MetaName = "Record fields", HelpText = "Record fields")]
        public IEnumerable<string> Fields { get; set; }
    }

    class UpdateRecordOptions
    {
        [Option("title", Required = false, HelpText = "title")]
        public string Title { get; set; }

        [Option('g', "generate", Required = false, Default = false, HelpText = "generate random password")]
        public bool Generate { get; set; }

        [Value(0, Required = true, MetaName = "record", HelpText = "record path or UID")]
        public string RecordId { get; set; }

        [Value(1, Required = false, MetaName = "Record fields", HelpText = "Record fields")]
        public IEnumerable<string> Fields { get; set; }
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

    class ShareRecordOptions {
        [Option('a', "action", Required = false, Default = "share", HelpText = "user share action: \'share\' (default), \'revoke\', \'transfer\', \'cancel\'")]
        public string Action { get; set; }

        [Option('s', "share", Required = false, Default = null, HelpText = "can re-share record")]
        public bool? CanShare { get; set; }

        [Option('w', "write", Required = false, Default = null, HelpText = "can modify record")]
        public bool? CanEdit { get; set; }

        [Option('e', "email", Required = true, HelpText = "peer account email")]
        public string Email { get; set; }
        [Value(0, Required = false, MetaName = "record", HelpText = "record path or UID")]
        public string RecordName { get; set; }
    }

    class RemoveRecordOptions
    {
        [Value(0, Required = true, MetaName = "record title, uid, or pattern", HelpText = "remove records")]
        public string RecordName { get; set; }
    }

    class DownloadAttachmentOptions
    {
        [Option('o', "output-dir", Required = false, Default = null, HelpText = "Output directory")]
        public string OutputDirectory { get; set; }

        [Option('f', "file", Required = false, Default = null, HelpText = "Attachment UID, name, or title")]
        public string FileName { get; set; }


        [Value(0, Required = true, MetaName = "record path or uid", HelpText = "Keeper Record")]
        public string RecordName { get; set; }
    }

    class UploadAttachmentOptions
    {
        [Option('f', "file", Required = true, Default = null, HelpText = "File path")]
        public string FileName { get; set; }


        [Value(0, Required = true, MetaName = "record path or uid", HelpText = "Keeper Record")]
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

    class UpdateFolderOptions : FolderOptions
    {
        [Option("manage-users", Required = false, Default = null, HelpText = "default manage users")]
        public bool? ManageUsers { get; set; }

        [Option("manage-records", Required = false, Default = null, HelpText = "default manage records")]
        public bool? ManageRecords { get; set; }

        [Option("can-share", Required = false, Default = null, HelpText = "default can share")]
        public bool? CanShare { get; set; }

        [Option("can-edit", Required = false, Default = null, HelpText = "default can edit")]
        public bool? CanEdit { get; set; }

        [Option("name", Required = false, Default = null, HelpText = "new folder folder")]
        public string NewName { get; set; }
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

    class RecordTypeInfoOptions
    {
        [Option('f', "field", Required = false, HelpText = "Show field. ")]
        public bool ShowFields { get; set; }

        [Value(0, Required = false, HelpText = "record or field type name")]
        public string Name { get; set; }
    }

    class CmdLineRecordField: IRecordTypeField
    {
        public bool? IsRecordField { get; set; }
        public string FieldName { get; set; }
        public string FieldLabel { get; set; }
        public string FieldIndex { get; set; }
        public string Value { get; set; }
    }
}