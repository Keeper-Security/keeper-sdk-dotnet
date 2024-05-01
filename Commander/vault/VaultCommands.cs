using Cli;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using CommandLine;

namespace Commander
{
    internal partial class VaultContext {
        internal readonly VaultOnline Vault;
        internal string CurrentFolder;
        public VaultContext(VaultOnline vault) 
        { 
            Vault = vault;
        }

        public void PrintTree(FolderNode folder, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + folder.Name);
            indent += isRoot ? " " : (last ? "    " : "|   ");
            for (var i = 0; i < folder.Subfolders.Count; i++)
            {
                if (Vault.TryGetFolder(folder.Subfolders[i], out var node))
                {
                    PrintTree(node, indent, i == folder.Subfolders.Count - 1);
                }
            }
        }

        public bool TryResolvePath(string path, out FolderNode node)
        {
            var res = TryResolvePath(path, out node, out var text);
            if (res)
            {
                res = string.IsNullOrEmpty(text);
            }

            return res;
        }

        public bool TryResolvePath(string path, out FolderNode node, out string text)
        {
            node = null;
            text = null;
            if (string.IsNullOrEmpty(CurrentFolder) || CurrentFolder == Vault.RootFolder.FolderUid)
            {
                node = Vault.RootFolder;
            }
            else
            {
                Vault.TryGetFolder(CurrentFolder, out node);
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
                    node = Vault.RootFolder;
                }

                foreach (var folder in path.TokenizeArguments(CommandExtensions.IsPathDelimiter))
                {
                    if (folder == "..")
                    {
                        if (!string.IsNullOrEmpty(node.ParentUid))
                        {
                            if (!Vault.TryGetFolder(node.ParentUid, out node))
                            {
                                return false;
                            }
                        }
                        else if (!string.IsNullOrEmpty(node.FolderUid))
                        {
                            node = Vault.RootFolder;
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
                            if (!Vault.TryGetFolder(subFolder, out var subNode)) return false;

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
    }

    internal static class VaultCommandExtensions
    {
        internal static void AppendVaultCommands(this VaultContext context, CliCommands cli)
        {
            cli.Commands.Add("search",
                new Cli.ParseableCommand<SearchCommandOptions>
                {
                    Order = 10,
                    Description = "Search the vault. Can use a regular expression",
                    Action = context.SearchCommand
                });

            cli.Commands.Add("ls",
                new ParseableCommand<ListCommandOptions>
                {
                    Order = 11,
                    Description = "List folder content",
                    Action = context.ListCommand
                });

            cli.Commands.Add("cd",
                new SimpleCommand
                {
                    Order = 12,
                    Description = "Change current folder",
                    Action = context.ChangeDirectoryCommand
                });

            cli.Commands.Add("tree",
                new ParseableCommand<TreeCommandOptions>
                {
                    Order = 13,
                    Description = "Display folder structure",
                    Action = context.TreeCommand
                });

            cli.Commands.Add("get",
                new SimpleCommand
                {
                    Order = 14,
                    Description = "Display specified Keeper record/folder/team",
                    Action = context.GetCommand
                });
            if (context.Vault.Auth.AuthContext.Settings.RecordTypesEnabled)
            {
                cli.Commands.Add("record-type-info",
                    new ParseableCommand<RecordTypeInfoOptions>
                    {
                        Order = 20,
                        Description = "Get record type info",
                        Action = context.RecordTypeInfoCommand
                    }
                );
                cli.CommandAliases.Add("rti", "record-type-info");

            }

            cli.Commands.Add("add-record",
                new ParseableCommand<AddRecordOptions>
                {
                    Order = 21,
                    Description = "Add record",
                    Action = context.AddRecordCommand
                });

            cli.Commands.Add("update-record",
                new ParseableCommand<UpdateRecordOptions>
                {
                    Order = 22,
                    Description = "Update record",
                    Action = context.UpdateRecordCommand
                });

            cli.Commands.Add("download-attachment",
                new ParseableCommand<DownloadAttachmentOptions>
                {
                    Order = 23,
                    Description = "Download Attachment(s)",
                    Action = context.DownloadAttachmentCommand
                });

            cli.Commands.Add("upload-attachment",
                new ParseableCommand<UploadAttachmentOptions>
                {
                    Order = 24,
                    Description = "Upload file attachment",
                    Action = context.UploadAttachmentCommand
                });

            cli.Commands.Add("mkdir",
                new ParseableCommand<MakeFolderOptions>
                {
                    Order = 25,
                    Description = "Make folder",
                    Action = context.MakeFolderCommand
                });

            cli.Commands.Add("rmdir",
                new ParseableCommand<FolderOptions>
                {
                    Order = 26,
                    Description = "Remove folder",
                    Action = context.RemoveFolderCommand
                });

            cli.Commands.Add("update-dir",
                new ParseableCommand<UpdateFolderOptions>
                {
                    Order = 27,
                    Description = "Update folder",
                    Action = context.UpdateFolderCommand
                });

            cli.Commands.Add("mv",
                new ParseableCommand<MoveOptions>
                {
                    Order = 28,
                    Description = "Move record or folder",
                    Action = context.MoveCommand
                });

            cli.Commands.Add("rm",
                new ParseableCommand<RemoveRecordOptions>
                {
                    Order = 29,
                    Description = "Remove record(s)",
                    Action = context.RemoveRecordCommand
                });

            cli.Commands.Add("sf-list",
                new SimpleCommand
                {
                    Order = 30,
                    Description = "List shared folders",
                    Action = context.ListSharedFoldersCommand
                });

            cli.Commands.Add("sf-user",
                new ParseableCommand<ShareFolderUserPermissionOptions>
                {
                    Order = 31,
                    Description = "Change shared folder user permissions",
                    Action = context.ShareFolderUserPermissionCommand
                });

            cli.Commands.Add("sf-record",
                new ParseableCommand<ShareFolderRecordPermissionOptions>
                {
                    Order = 32,
                    Description = "Change shared folder record permissions",
                    Action = context.ShareFolderRecordPermissionCommand
                });

            cli.Commands.Add("share-record",
                new ParseableCommand<ShareRecordOptions>
                {
                    Order = 33,
                    Description = "Change the sharing permissions of an individual record",
                    Action = context.ShareRecordCommand
                });

            cli.Commands.Add("import",
                new ParseableCommand<ImportCommandOptions>
                {
                    Order = 33,
                    Description = "Imports records from JSON file",
                    Action = context.ImportCommand
                });

            if (context.Vault.Auth.AuthContext.Enforcements.TryGetValue("allow_secrets_manager", out var value))
            {
                if (value is bool b && b)
                {
                    cli.Commands.Add("ksm",
                        new ParseableCommand<SecretManagerOptions>
                        {
                            Order = 40,
                            Description = "Keeper Secret Manager commands",
                            Action = context.SecretManagerCommand
                        });
                }
            }
            cli.Commands.Add("one-time-share",
                new ParseableCommand<OneTimeShareOptions>
                {
                    Order = 41,
                    Description = "Manage One Time Shares",
                    Action = context.OneTimeShareCommand
                });

            cli.Commands.Add("sync-down",
                new ParseableCommand<SyncDownOptions>
                {
                    Order = 100,
                    Description = "Download & decrypt data",
                    Action = async (options) =>
                    {
                        if (options.Reset)
                        {
                            Console.WriteLine("Resetting offline storage.");
                            context.Vault.Storage.Clear();
                            context.Vault.RecordTypesLoaded = false;
                        }

                        var fullSync = context.Vault.Storage.Revision == 0;
                        Console.WriteLine("Syncing...");
                        await context.Vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(0));
                        if (fullSync)
                        {
                            Console.WriteLine($"Decrypted {context.Vault.RecordCount} record(s)");
                        }
                    }
                });


            cli.CommandAliases.Add("list", "search");
            cli.CommandAliases.Add("d", "sync-down");
            cli.CommandAliases.Add("add", "add-record");
            cli.CommandAliases.Add("edit", "update-record");

        }
        private static Task SearchCommand(this VaultContext context, SearchCommandOptions options)
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

            var matchedRecords = context.Vault.KeeperRecords
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
                        return new[] { legacy.Notes, legacy.Login, legacy.Password, legacy.Notes }
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

        private static Task ListCommand(this VaultContext context, ListCommandOptions options)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(context.CurrentFolder))
            {
                context.Vault.TryGetFolder(context.CurrentFolder, out node);
            }

            if (node == null)
            {
                node = context.Vault.RootFolder;
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
                        if (context.Vault.TryGetFolder(uid, out var f))
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
                        if (context.Vault.TryGetKeeperRecord(uid, out var r))
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
                    if (context.Vault.TryGetFolder(uid, out var subNode))
                    {
                        names.Add(subNode.Name + "/");
                    }
                }

                names.Sort(StringComparer.InvariantCultureIgnoreCase);

                var len = names.Count;
                foreach (var uid in node.Records)
                {
                    if (context.Vault.TryGetKeeperRecord(uid, out var r))
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

        private static Task ChangeDirectoryCommand(this VaultContext context, string name)
        {
            if (context.TryResolvePath(name, out var node))
            {
                context.CurrentFolder = node.FolderUid;
            }
            else
            {
                Console.WriteLine($"Invalid folder name: {name}");
            }

            return Task.FromResult(true);
        }

        private static Task TreeCommand(this VaultContext context, TreeCommandOptions options)
        {
            context.PrintTree(context.Vault.RootFolder, "", true);
            return Task.FromResult(true);
        }

        private static async Task GetCommand(this VaultContext context, string uid)
        {
            var tab = new Tabulate(3);
            if (context.Vault.TryGetKeeperRecord(uid, out var record))
            {
                List<string> totps = null;

                tab.AddRow("Record UID:", record.Uid);
                tab.AddRow("Type:", record.KeeperRecordType());
                tab.AddRow("Title:", record.Title);
                if (record is PasswordRecord legacy)
                {
                    tab.AddRow("Notes:", legacy.Notes);
                    tab.AddRow("$login:", legacy.Login);
                    tab.AddRow("$password:", legacy.Password);
                    tab.AddRow("$url:", legacy.Link);
                    if (!string.IsNullOrEmpty(legacy.Totp))
                    {
                        if (totps == null)
                        {
                            totps = new List<string>();
                        }
                        totps.Add(legacy.Totp);
                        tab.AddRow("$oneTimeCode:", legacy.Totp);
                    }
                    if (legacy.Custom != null && legacy.Custom.Count > 0)
                    {
                        foreach (var c in legacy.Custom)
                        {
                            tab.AddRow(c.Name + ":", c.Value);
                        }
                    }
                }
                else if (record is TypedRecord typed)
                {
                    tab.AddRow("Notes:", typed.Notes);
                    foreach (var f in typed.Fields.Concat(typed.Custom))
                    {
                        if (f.FieldName == "oneTimeCode")
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
                        tab.AddRow("$oneTimeCode:", url);
                        try
                        {
                            var tup = CryptoUtils.GetTotpCode(url);
                            if (tup != null)
                            {
                                tab.AddRow($"{tup.Item1}:", $"expires in {tup.Item3 - tup.Item2} sec.");
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }

                tab.AddRow("Last Modified:", record.ClientModified.LocalDateTime.ToString("F"));
                var shareInfo = (await context.Vault.GetSharesForRecords(new[] { record.Uid }))
                    .FirstOrDefault(x => x.RecordUid == record.Uid);
                if (shareInfo != null)
                {
                    if (shareInfo?.UserPermissions.Length > 0)
                    {
                        tab.AddRow("", "");
                        tab.AddRow("User Shares:", "");
                        foreach (var rs in shareInfo.UserPermissions)
                        {
                            var status = "";

                            if (rs.Owner)
                            {
                                status = "Owner";
                            }
                            else
                            {
                                if (rs.AwaitingApproval)
                                {
                                    status = "Awaiting Approval";
                                }
                                else
                                {
                                    if (!rs.CanEdit && !rs.CanShare)
                                    {
                                        status = "Read Only";
                                    }
                                    else if (rs.CanEdit && rs.CanShare)
                                    {
                                        status = "Can Edit & Share";
                                    }
                                    else if (rs.CanEdit)
                                    {
                                        status = "Can Edit";
                                    }
                                    else
                                    {
                                        status = "Can Share";
                                    }
                                }
                            }
                            tab.AddRow(rs.Username, status);
                        }
                    }
                    if (shareInfo?.SharedFolderPermissions != null)
                    {
                        tab.AddRow("", "");
                        tab.AddRow("Shared Folders:", "");
                        foreach (var sfs in shareInfo.SharedFolderPermissions)
                        {
                            var status = "";
                            if (!sfs.CanEdit && !sfs.CanShare)
                            {
                                status = "Read Only";
                            }
                            else if (sfs.CanEdit && sfs.CanShare)
                            {
                                status = "Can Edit & Share";
                            }
                            else if (sfs.CanEdit)
                            {
                                status = "Can Edit";
                            }
                            else
                            {
                                status = "Can Share";
                            }
                            var name = sfs.SharedFolderUid;
                            if (context.Vault.TryGetSharedFolder(sfs.SharedFolderUid, out var sf))
                            {
                                name = sf.Name;
                            }
                            tab.AddRow(name, status);
                        }
                    }

                    context.Vault.AuditLogRecordOpen(record.Uid);
                }
            }
            else if (context.Vault.TryGetSharedFolder(uid, out var sf))
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

                var teamLookup = context.Vault.Teams.ToDictionary(t => t.TeamUid, t => t.Name);
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
            else if (context.Vault.TryGetFolder(uid, out var f))
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
            }

            Console.WriteLine();
            tab.SetColumnRightAlign(0, true);
            tab.LeftPadding = 4;
            tab.Dump();
        }
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

    class SyncDownOptions
    {
        [Option("reset", Required = false, Default = false, HelpText = "resets on-disk storage")]
        public bool Reset { get; set; }
    }


}