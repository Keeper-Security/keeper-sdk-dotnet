using Cli;
using CommandLine;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ZeroDep;

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
                    if (string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase) &&
                        record is not PasswordRecord && record is not TypedRecord)
                    {
                        Console.WriteLine($"JSON output is not supported for record type {record.GetType().Name}.");
                        return;
                    }

                    if ((record is PasswordRecord || record is TypedRecord) &&
                        string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
                    {
                        await DisplayClassicRecordJsonInfo(context, record, options.Unmask);
                        context.Vault.AuditLogRecordOpen(record.Uid);
                        if (options.Unmask && RecordSecurity.HasPassword(record))
                            context.Vault.AuditLogRecordRevealPassword(record.Uid);
                        return;
                    }

                    await DisplayRecordInfo(context, record, tab, options.Unmask);
                    Console.WriteLine();
                    tab.SetColumnRightAlign(0, true);
                    tab.LeftPadding = 4;
                    tab.Dump();
                    context.Vault.AuditLogRecordOpen(record.Uid);
                    if (options.Unmask && RecordSecurity.HasPassword(record))
                    {
                        context.Vault.AuditLogRecordRevealPassword(record.Uid);
                    }
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
                SharedFolder sharedFolder;
                try
                {
                    sharedFolder = ResolveSharedFolder(context, identifier);
                }
                catch (AmbiguousSharedFolderException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    return;
                }

                if (sharedFolder != null)
                {
                    if (string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
                    {
                        DisplaySharedFolderJsonInfo(context, sharedFolder, options.IncludeDag);
                        return;
                    }

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
                    if (string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
                    {
                        DisplayFolderJsonInfo(context, folder);
                        return;
                    }

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

            if (context.ResolvePath(identifier, out var folderByPath))
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

        private static SharedFolder ResolveSharedFolder(VaultContext context, string identifier)
        {
            if (context.Vault.TryGetSharedFolder(identifier, out var sharedFolder))
            {
                return sharedFolder;
            }

            var matches = context.Vault.SharedFolders
                .Where(sf => string.Equals(sf.Name, identifier, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matches.Count > 1)
            {
                throw new AmbiguousSharedFolderException(identifier, matches);
            }

            return matches.Count == 1 ? matches[0] : null;
        }

        private static async Task DisplayRecordInfo(VaultContext context, KeeperRecord record, Tabulate tab, bool unmask)
        {
            var totps = new List<string>();

            tab.AddRow("Record UID:", record.Uid);
            tab.AddRow("Type:", record.KeeperRecordType());
            tab.AddRow("Title:", record.Title);

            if (record is PasswordRecord legacy)
            {
                tab.AddRow("Notes:", legacy.Notes);
                tab.AddRow("$login:", legacy.Login);
                tab.AddRow("$password:", RecordSecurity.Mask(legacy.Password, unmask));
                tab.AddRow("$url:", legacy.Link);
                if (!string.IsNullOrEmpty(legacy.Totp))
                {
                    totps.Add(legacy.Totp);
                }

                if (legacy.Custom != null && legacy.Custom.Count > 0)
                {
                    foreach (var c in legacy.Custom)
                    {
                        tab.AddRow(c.Name + ":", RecordSecurity.IsSensitive(c.Name)
                            ? RecordSecurity.Mask(c.Value, unmask) : c.Value);
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
                            tab.AddRow(i == 0 ? $"{label}:" : "", RecordSecurity.IsSensitive(f)
                                ? RecordSecurity.Mask(v, unmask) : v);
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
                tab.AddRow("$oneTimeCode:", RecordSecurity.Mask(url, unmask));
                if (!unmask) continue;
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

        }

        private static async Task DisplayClassicRecordJsonInfo(VaultContext context, KeeperRecord record, bool unmask)
        {
            var json = new Dictionary<string, object>
            {
                ["record_uid"] = record.Uid,
                ["source"] = "classic"
            };
            if (record is PasswordRecord legacy)
            {
                json["title"] = legacy.Title;
                json["record_type"] = "general";
                if (!string.IsNullOrEmpty(legacy.Login)) json["login"] = legacy.Login;
                if (!string.IsNullOrEmpty(legacy.Password)) json["password"] = RecordSecurity.Mask(legacy.Password, unmask);
                if (!string.IsNullOrEmpty(legacy.Link)) json["login_url"] = legacy.Link;
                if (legacy.Custom.Count > 0)
                {
                    json["custom_fields"] = legacy.Custom.Select(x => new Dictionary<string, object>
                    {
                        ["name"] = x.Name,
                        ["value"] = RecordSecurity.IsSensitive(x.Name) || IsGetFieldSensitive(x.Name) || IsGetFieldSensitive(x.Type)
                            ? RecordSecurity.Mask(x.Value, unmask) : x.Value,
                        ["type"] = x.Type
                    }).ToArray();
                }
                if (!string.IsNullOrEmpty(legacy.Totp)) json["totp"] = RecordSecurity.Mask(legacy.Totp, unmask);
                if (legacy.Attachments.Count > 0)
                {
                    json["attachments"] = legacy.Attachments.Select(x => new Dictionary<string, object>
                    {
                        ["id"] = x.Id, ["name"] = x.Name, ["size"] = x.Size
                    }).ToArray();
                }
                if (!string.IsNullOrEmpty(legacy.Notes)) json["notes"] = legacy.Notes;
            }
            else if (record is TypedRecord typed)
            {
                json["type"] = typed.TypeName;
                json["title"] = typed.Title;
                json["fields"] = typed.Fields.Select(x => BuildTypedFieldJson(x, unmask)).ToArray();
                json["custom"] = typed.Custom.Select(x => BuildTypedFieldJson(x, unmask)).ToArray();
                if (!string.IsNullOrEmpty(typed.Notes)) json["notes"] = typed.Notes;
            }
            json["version"] = record.Version;
            json["shared"] = record.Shared;
            json["client_modified_time"] = record.ClientModified.LocalDateTime.ToString("yyyy-MM-ddTHH:mm:ss");

            var shares = (await context.Vault.GetSharesForRecords(new[] { record.Uid }))
                .FirstOrDefault(x => x.RecordUid == record.Uid);
            if (shares?.UserPermissions != null)
            {
                json["user_permissions"] = shares.UserPermissions.Select(x => new Dictionary<string, object>
                {
                    ["username"] = x.Username,
                    ["owner"] = x.Owner,
                    ["sharable"] = x.CanShare,
                    ["editable"] = x.CanEdit
                }).ToArray();
            }
            if (shares?.SharedFolderPermissions != null)
            {
                json["shared_folder_permissions"] = shares.SharedFolderPermissions.Select(x => new Dictionary<string, object>
                {
                    ["shared_folder_uid"] = x.SharedFolderUid,
                    ["can_edit"] = x.CanEdit,
                    ["can_share"] = x.CanShare
                }).ToArray();
            }
            json["revision"] = record.Revision;
            var folder = context.Vault.Folders.FirstOrDefault(x => x.Records.Contains(record.Uid));
            json["folder"] = new Dictionary<string, object>
            {
                ["uid"] = folder?.FolderUid,
                ["path"] = folder == null ? "/" : GetFolderPath(context, folder.FolderUid)
            };

            Json.WriteFormatted(Console.Out, json);
            Console.WriteLine();
        }

        private static Dictionary<string, object> BuildTypedFieldJson(ITypedField field, bool unmask)
        {
            var values = Enumerable.Range(0, field.Count)
                .Select(i => field.GetValueAt(i))
                .Select(value => (RecordSecurity.IsSensitive(field) || IsGetFieldSensitive(field.FieldName) || IsGetFieldSensitive(field.FieldLabel)) && !unmask
                    ? (object)RecordSecurity.Mask(value?.ToString(), false) : value)
                .ToArray();
            var json = new Dictionary<string, object>
            {
                ["type"] = field.FieldName,
                ["value"] = values
            };
            if (!string.IsNullOrEmpty(field.FieldLabel)) json["label"] = field.FieldLabel;
            return json;
        }

        private static bool IsGetFieldSensitive(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            var fieldType = name.Split(':')[0];
            var normalized = new string(fieldType.Where(char.IsLetterOrDigit).ToArray());
            if (RecordSecurity.IsSensitive(normalized)) return true;
            return new[]
            {
                "note", "json", "paymentcard", "bankaccount", "securityquestion",
                "accountnumber", "cardnumber", "cardsecuritycode", "routingnumber",
                "securityanswer", "recoverycode", "recoverycodes", "backupcode", "backupcodes",
                "socialsecuritynumber", "ssn", "cvv", "cvc", "secretkey", "accesskey"
            }.Contains(normalized, StringComparer.OrdinalIgnoreCase);
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

        private static void DisplaySharedFolderJsonInfo(VaultContext context, SharedFolder sf, bool includeDag)
        {
            var users = sf.UsersPermissions
                .Where(x => x.UserType == UserType.User)
                .Select(x => new Dictionary<string, object>
                {
                    ["username"] = x.Name,
                    ["user_id"] = x.Uid,
                    ["owner"] = x.Owner,
                    ["manage_records"] = x.ManageRecords,
                    ["manage_users"] = x.ManageUsers,
                    ["expiration"] = x.Expiration.HasValue
                        ? x.Expiration.Value.UtcDateTime.ToString("o")
                        : "never"
                })
                .ToList();

            var json = new Dictionary<string, object>
            {
                ["folder_uid"] = sf.Uid,
                ["type"] = "classic_folder",
                ["name"] = sf.Name,
                ["path"] = GetFolderPath(context, sf.Uid),
                ["parent_uid"] = context.Vault.TryGetFolder(sf.Uid, out var node) && !string.IsNullOrEmpty(node.ParentUid)
                    ? node.ParentUid : null,
                ["folder"] = GetFolderLocation(context, sf.Uid),
                ["manage_users"] = sf.DefaultManageUsers,
                ["manage_records"] = sf.DefaultManageRecords,
                ["can_edit"] = sf.DefaultCanEdit,
                ["can_share"] = sf.DefaultCanShare,
                ["users"] = users,
                ["share_admins"] = sf.UsersPermissions
                    .Where(x => x.UserType == UserType.User && x.ManageUsers)
                    .Select(x => x.Name)
                    .ToList()
            };

            if (includeDag)
            {
                json["records"] = sf.RecordPermissions
                    .Select(x => new Dictionary<string, object>
                    {
                        ["record_uid"] = x.RecordUid,
                        ["record_name"] = GetRecordName(context, x.RecordUid)
                    })
                    .ToList();
            }

            Json.WriteFormatted(Console.Out, json);
            Console.WriteLine();
        }

        private static void DisplayFolderJsonInfo(VaultContext context, FolderNode folder)
        {
            var records = folder.Records
                .Where(recordUid => !string.IsNullOrEmpty(recordUid))
                .Select(recordUid =>
                {
                    var entry = new Dictionary<string, object> { ["record_uid"] = recordUid };
                    if (context.Vault.TryGetKeeperRecord(recordUid, out var record))
                        entry["record_name"] = record.Title;
                    return entry;
                })
                .ToList();

            var json = new Dictionary<string, object>
            {
                ["folder_uid"] = folder.FolderUid,
                ["type"] = folder.FolderType == FolderType.UserFolder ? "user_folder" : "classic_folder",
                ["name"] = folder.Name,
                ["path"] = GetFolderPath(context, folder.FolderUid),
                ["parent_uid"] = string.IsNullOrEmpty(folder.ParentUid) ? null : folder.ParentUid,
                ["folder"] = GetFolderLocation(context, folder.FolderUid)
            };
            if (folder.FolderType == FolderType.SharedFolderFolder)
                json["shared_folder_uid"] = folder.SharedFolderUid;
            if (folder.FolderType == FolderType.UserFolder)
                json["records"] = records;

            Json.WriteFormatted(Console.Out, json);
            Console.WriteLine();
        }

        private static Dictionary<string, object> GetFolderLocation(VaultContext context, string folderUid)
        {
            if (context?.Vault != null && !string.IsNullOrEmpty(folderUid) &&
                context.Vault.TryGetFolder(folderUid, out var folder))
            {
                return new Dictionary<string, object>
                {
                    ["uid"] = string.IsNullOrEmpty(folder.ParentUid) ? null : folder.ParentUid,
                    ["path"] = string.IsNullOrEmpty(folder.ParentUid) ? "/" : GetFolderPath(context, folder.ParentUid)
                };
            }

            return new Dictionary<string, object>
            {
                ["uid"] = null,
                ["path"] = "/"
            };
        }

        private static string GetFolderPath(VaultContext context, string folderUid)
        {
            var components = new List<string>();
            var currentUid = folderUid;
            var visited = new HashSet<string>();
            while (context?.Vault != null && !string.IsNullOrEmpty(currentUid) && visited.Add(currentUid) &&
                   context.Vault.TryGetFolder(currentUid, out var folder))
            {
                if (!string.IsNullOrEmpty(folder.Name))
                {
                    components.Add(folder.Name.Replace("/", "//"));
                }
                currentUid = folder.ParentUid;
            }

            components.Reverse();
            return string.Join("/", components);
        }

        private static string GetRecordName(VaultContext context, string recordUid)
        {
            if (context?.Vault != null && !string.IsNullOrEmpty(recordUid) &&
                context.Vault.TryGetKeeperRecord(recordUid, out var record) &&
                !string.IsNullOrEmpty(record.Title))
            {
                return record.Title;
            }

            return recordUid ?? string.Empty;
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

        [Option("format", Required = false, Default = "table", HelpText = "table or json")]
        public string Format { get; set; }

        [Option("include-dag", Required = false, HelpText = "Include classic shared-folder record graph data")]
        public bool IncludeDag { get; set; }

        [Option("unmask", Required = false, HelpText = "display hidden field content")]
        public bool Unmask { get; set; }
    }
}
