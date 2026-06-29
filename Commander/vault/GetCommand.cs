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
    internal static class GetCommandExtensions
    {
        public static async Task GetCommand(this VaultContext context, GetObjectOptions options)
        {
            var identifier = options.ObjectIdentifier;
            var tab = new Tabulate(3) { MaxColumnWidth = 1000 };

            var typeCount = new[] { options.IsRecord, options.IsFolder, options.IsSharedFolder, options.IsTeam }.Count(x => x);
            if (typeCount > 1)
            {
                Console.WriteLine("Error: Only one object type can be specified at a time.");
                Console.WriteLine("Use one of: --record, --folder, --shared-folder, --team");
                return;
            }

            var checkRecords = options.IsRecord || typeCount == 0;
            var checkFolders = options.IsFolder || typeCount == 0;
            var checkSharedFolders = options.IsSharedFolder || typeCount == 0;
            var checkTeams = options.IsTeam || typeCount == 0;

            if (checkRecords)
            {
                var record = TryResolveRecord(context, identifier, out var multipleFound);
                if (multipleFound)
                {
                    Console.WriteLine($"Multiple records found with title '{identifier}'. Please use UID.");
                    return;
                }

                if (record != null)
                {
                    await DisplayRecordInfo(context, record, tab);
                    Console.WriteLine();
                    tab.SetColumnRightAlign(0, true);
                    tab.LeftPadding = 4;
                    tab.Dump();
                    return;
                }

                if (options.IsRecord)
                {
                    Console.WriteLine($"Record with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }

            if (checkSharedFolders)
            {
                var sharedFolder = TryResolveSharedFolder(context, identifier);
                if (sharedFolder != null)
                {
                    DisplaySharedFolderInfo(context, sharedFolder, tab);
                    Console.WriteLine();
                    tab.SetColumnRightAlign(0, true);
                    tab.LeftPadding = 4;
                    tab.Dump();
                    return;
                }

                if (options.IsSharedFolder)
                {
                    Console.WriteLine($"Shared folder with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }

            if (checkFolders)
            {
                var folder = TryResolveFolder(context, identifier, out var multipleFound);
                if (multipleFound)
                {
                    Console.WriteLine($"Multiple folders found with name '{identifier}'. Please use UID.");
                    return;
                }

                if (folder != null)
                {
                    DisplayFolderInfo(folder, tab);
                    Console.WriteLine();
                    tab.SetColumnRightAlign(0, true);
                    tab.LeftPadding = 4;
                    tab.Dump();
                    return;
                }

                if (options.IsFolder)
                {
                    Console.WriteLine($"Folder with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }

            if (checkTeams)
            {
                if (await context.TryGetTeamCommand(identifier, options.IsTeam))
                {
                    return;
                }

                if (options.IsTeam)
                {
                    return;
                }
            }

            Console.WriteLine($"Object with name or UID '{identifier}' not found or not accessible.");
        }

        private static KeeperRecord TryResolveRecord(VaultContext context, string identifier, out bool multipleFound)
        {
            multipleFound = false;
            if (context.Vault.TryGetKeeperRecord(identifier, out var record))
            {
                return record;
            }

            var matches = context.Vault.KeeperRecords
                .Where(r => string.Equals(r.Title, identifier, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (matches.Count > 1)
            {
                multipleFound = true;
                return null;
            }

            return matches.FirstOrDefault();
        }

        private static FolderNode TryResolveFolder(VaultContext context, string identifier, out bool multipleFound)
        {
            multipleFound = false;
            if (context.Vault.TryGetFolder(identifier, out var folder))
            {
                return folder;
            }

            if (context.TryResolvePath(identifier, out var folderByPath))
            {
                return folderByPath;
            }

            var matches = context.Vault.Folders
                .Where(f => string.Equals(f.Name, identifier, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (matches.Count > 1)
            {
                multipleFound = true;
                return null;
            }

            return matches.FirstOrDefault();
        }

        private static SharedFolder TryResolveSharedFolder(VaultContext context, string identifier)
        {
            if (context.Vault.TryGetSharedFolder(identifier, out var sharedFolder))
            {
                return sharedFolder;
            }

            return context.Vault.SharedFolders
                .FirstOrDefault(sf => string.Equals(sf.Name, identifier, StringComparison.OrdinalIgnoreCase));
        }

        private static async Task DisplayRecordInfo(VaultContext context, KeeperRecord record, Tabulate tab)
        {
            var totps = new List<string>();

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
                            tab.AddRow(i == 0 ? $"{label}:" : "", v);
                        }
                    }
                }
            }
            else if (record is FileRecord file)
            {
                tab.AddRow("Name:", file.Name);
                tab.AddRow("MIME Type:", file.MimeType ?? "");
                tab.AddRow("Size:", file.FileSize.ToString("N0"));
                if (file.ThumbnailSize > 0)
                {
                    tab.AddRow("Thumbnail Size:", file.ThumbnailSize.ToString("N0"));
                }
            }

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
                    Console.WriteLine($"Error: {e.Message}");
                }
            }

            tab.AddRow("Last Modified:", record.ClientModified.LocalDateTime.ToString("F"));
            var shareInfo = (await context.Vault.GetSharesForRecords(new[] { record.Uid }))
                .FirstOrDefault(x => x.RecordUid == record.Uid);

            if (shareInfo?.UserPermissions?.Length > 0)
            {
                tab.AddRow("", "");
                tab.AddRow("User Shares:", "");
                foreach (var rs in shareInfo.UserPermissions)
                {
                    tab.AddRow(rs.Username, FormatUserRecordShareStatus(rs));
                }
            }

            if (shareInfo?.SharedFolderPermissions != null)
            {
                tab.AddRow("", "");
                tab.AddRow("Shared Folders:", "");
                foreach (var sfs in shareInfo.SharedFolderPermissions)
                {
                    var name = sfs.SharedFolderUid;
                    if (context.Vault.TryGetSharedFolder(sfs.SharedFolderUid, out var sf))
                    {
                        name = sf.Name;
                    }

                    tab.AddRow(name, FormatCanEditShareStatus(sfs.CanEdit, sfs.CanShare));
                }
            }

            context.Vault.AuditLogRecordOpen(record.Uid);
        }

        private static string FormatUserRecordShareStatus(UserRecordPermissions permission)
        {
            string status;
            if (permission.Owner)
            {
                status = "Owner";
            }
            else if (permission.AwaitingApproval)
            {
                status = "Awaiting Approval";
            }
            else
            {
                status = FormatCanEditShareStatus(permission.CanEdit, permission.CanShare);
            }

            if (permission.Expiration.HasValue)
            {
                status += $" (Expires: {permission.Expiration.Value.LocalDateTime:g})";
            }

            return status;
        }

        private static string FormatCanEditShareStatus(bool canEdit, bool canShare)
        {
            if (!canEdit && !canShare)
            {
                return "Read Only";
            }

            if (canEdit && canShare)
            {
                return "Can Edit & Share";
            }

            return canEdit ? "Can Edit" : "Can Share";
        }

        private static string FormatSharedFolderRecordPermission(bool canEdit, bool canShare)
        {
            if (canEdit && canShare)
            {
                return "Can Edit & Share";
            }

            if (canEdit)
            {
                return "Can Edit";
            }

            if (canShare)
            {
                return "Can Share";
            }

            return "View Only";
        }

        private static void DisplaySharedFolderInfo(VaultContext context, SharedFolder sf, Tabulate tab)
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
                    tab.AddRow(r.RecordUid + ":", FormatSharedFolderRecordPermission(r.CanEdit, r.CanShare));
                }
            }

            string GetUsername(string userId, UserType userType)
            {
                switch (userType)
                {
                    case UserType.User:
                        if (context.Vault.TryGetUsername(userId, out var email))
                        {
                            return email;
                        }
                        break;
                    case UserType.Team:
                        if (context.Vault.TryGetTeam(userId, out var team))
                        {
                            return team.Name;
                        }
                        break;
                }

                return userId;
            }

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
                        var xName = GetUsername(x.Uid, x.UserType);
                        var yName = GetUsername(y.Uid, y.UserType);
                        res = string.Compare(xName, yName, StringComparison.OrdinalIgnoreCase);
                    }

                    return res;
                });

                foreach (var u in sortedList)
                {
                    string permissions;
                    if (u.ManageRecords || u.ManageUsers)
                    {
                        permissions = "Can Manage " +
                                      string.Join(" & ",
                                          new[] { u.ManageUsers ? "Users" : "", u.ManageRecords ? "Records" : "" }
                                              .Where(x => !string.IsNullOrEmpty(x)));
                    }
                    else
                    {
                        permissions = "No User Permissions";
                    }

                    var subjectName = GetUsername(u.Uid, u.UserType);
                    tab.AddRow($"{u.UserType} {subjectName}:", permissions);
                }
            }
        }

        private static void DisplayFolderInfo(FolderNode f, Tabulate tab)
        {
            tab.AddRow("Folder UID:", f.FolderUid);
            if (!string.IsNullOrEmpty(f.ParentUid))
            {
                tab.AddRow("Parent Folder UID:", f.ParentUid);
            }

            tab.AddRow("Folder Type:", f.FolderType.ToString());
            tab.AddRow("Name:", f.Name);
            if (!string.IsNullOrEmpty(f.SharedFolderUid))
            {
                tab.AddRow("Shared Folder UID:", f.SharedFolderUid);
            }
        }
    }

    class GetObjectOptions
    {
        [Value(0, Required = true, HelpText = "UID or name of the object (record, folder, shared-folder, team) to retrieve information about")]
        public string ObjectIdentifier { get; set; }

        [Option('r', "record", Required = false, HelpText = "Record title / uid")]
        public bool IsRecord { get; set; }

        [Option('f', "folder", Required = false, HelpText = "Specify that the UID is a folder")]
        public bool IsFolder { get; set; }

        [Option('s', "shared-folder", Required = false, HelpText = "Specify that the UID is a shared folder")]
        public bool IsSharedFolder { get; set; }

        [Option('t', "team", Required = false, HelpText = "Specify that the UID is a team")]
        public bool IsTeam { get; set; }
    }
}
