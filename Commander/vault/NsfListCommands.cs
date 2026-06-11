using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Enterprise;
using Folder.V3;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Record.V3.Details;
using ZeroDep;

namespace Commander
{
    internal static class NsfListCommandExtensions
    {
        public static Task NsfFoldersCommand(this VaultContext context, NsfFoldersOptions options)
        {
            var vault = context.Vault;
            if (!vault.KeeperNSFFolderNodes.Any())
            {
                Console.WriteLine("No Keeper NSF folders found.");
                return Task.CompletedTask;
            }

            var tab = new Tabulate(5);
            tab.AddHeader(new[] { "FolderUid", "Name", "ParentUid", "Subfolders", "Records" });
            foreach (var folder in vault.KeeperNSFFolderNodes)
            {
                tab.AddRow(new[]
                {
                    folder.FolderUid,
                    folder.Name ?? "",
                    string.IsNullOrEmpty(folder.ParentUid) ? "(root)" : folder.ParentUid,
                    folder.Subfolders.Count.ToString(),
                    folder.Records.Count.ToString()
                });
            }

            tab.Dump();
            return Task.CompletedTask;
        }

        public static Task NsfRecordsCommand(this VaultContext context, NsfRecordsOptions options)
        {
            var vault = context.Vault;
            if (!vault.KeeperNSFRecordEntries.Any())
            {
                Console.WriteLine("No Keeper NSF records found.");
                return Task.CompletedTask;
            }

            var tab = new Tabulate(8);
            tab.AddHeader(new[] { "RecordUid", "Name", "Type", "Revision", "Version", "Shared", "FileSize", "ThumbnailSize" });
            foreach (var record in vault.KeeperNSFRecordEntries)
            {
                var meta = NsfHelpers.GetRecordTypeAndTitle(record);
                tab.AddRow(new[]
                {
                    record.RecordUid,
                    record.Title ?? meta.Title,
                    meta.Type,
                    record.Revision.ToString(),
                    record.Version.ToString(),
                    record.Shared.ToString(),
                    record.FileSize.ToString("N0"),
                    record.ThumbnailSize.ToString("N0")
                });
            }

            tab.Dump();
            return Task.CompletedTask;
        }

        public static Task NsfListCommand(this VaultContext context, NsfListOptions options)
        {
            var vault = context.Vault;
            var showFolders = !options.Records || options.Folders;
            var showRecords = !options.Folders || options.Records;

            var combined = new List<Dictionary<string, string>>();
            List<object> folderItems = null;
            List<object> recordItems = null;

            if (showFolders)
            {
                folderItems = new List<object>();
                foreach (var folder in vault.KeeperNSFFolderNodes)
                {
                    folderItems.Add(folder);
                    combined.Add(new Dictionary<string, string>
                    {
                        ["ItemType"] = "Folder",
                        ["UID"] = folder.FolderUid,
                        ["Title"] = folder.Name ?? "",
                        ["Type"] = "folder",
                        ["Description"] = $"Subfolders: {folder.Subfolders.Count}, Records: {folder.Records.Count}",
                        ["Parent"] = string.IsNullOrEmpty(folder.ParentUid) ? "(root)" : folder.ParentUid
                    });
                }
            }

            if (showRecords)
            {
                recordItems = new List<object>();
                foreach (var record in vault.KeeperNSFRecordEntries)
                {
                    var meta = NsfHelpers.GetRecordTypeAndTitle(record);
                    recordItems.Add(record);
                    combined.Add(new Dictionary<string, string>
                    {
                        ["ItemType"] = "Record",
                        ["UID"] = record.RecordUid,
                        ["Title"] = record.Title ?? meta.Title,
                        ["Type"] = meta.Type,
                        ["Description"] = $"Rev: {record.Revision}, Shared: {record.Shared}",
                        ["Parent"] = ""
                    });
                }
            }

            if (combined.Count == 0)
            {
                Console.WriteLine("No Keeper NSF data found. Run sync-down to refresh.");
                return Task.CompletedTask;
            }

            var format = options.Format ?? "table";
            if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            {
                var jsonData = combined.Select(item => new Dictionary<string, object>
                {
                    ["item_type"] = item["ItemType"],
                    ["uid"] = item["UID"],
                    ["title"] = item["Title"],
                    ["type"] = item["Type"],
                    ["description"] = item["Description"],
                    ["parent"] = item["Parent"]
                }).ToList();
                var jsonText = Json.Serialize(jsonData);
                if (!string.IsNullOrEmpty(options.Output))
                {
                    System.IO.File.WriteAllText(options.Output, jsonText, Encoding.UTF8);
                    Console.WriteLine($"JSON output written to '{options.Output}' ({combined.Count} items).");
                }
                else
                {
                    Console.WriteLine(jsonText);
                }

                return Task.CompletedTask;
            }

            if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
            {
                var rows = new List<string[]>
                {
                    new[] { "ItemType", "UID", "Title", "Type", "Description", "Parent" }
                };
                rows.AddRange(combined.Select(c => new[]
                {
                    c["ItemType"], c["UID"], c["Title"], c["Type"], c["Description"], c["Parent"]
                }));

                if (!string.IsNullOrEmpty(options.Output))
                {
                    NsfHelpers.WriteCsv(options.Output, rows);
                    Console.WriteLine($"CSV output written to '{options.Output}' ({combined.Count} items).");
                }
                else
                {
                    foreach (var row in rows)
                    {
                        Console.WriteLine(string.Join(",", row));
                    }
                }

                return Task.CompletedTask;
            }

            var folderCount = combined.Count(c => c["ItemType"] == "Folder");
            var recordCount = combined.Count(c => c["ItemType"] == "Record");
            Console.WriteLine();
            Console.WriteLine("=== Keeper NSF Summary ===");
            Console.WriteLine($"  Folders: {folderCount}");
            Console.WriteLine($"  Records: {recordCount}");
            Console.WriteLine();

            if (showFolders && folderCount > 0)
            {
                Console.WriteLine("--- Folders ---");
                var tab = new Tabulate(5);
                tab.AddHeader(new[] { "FolderUid", "Name", "ParentUid", "Subfolders", "Records" });
                foreach (FolderNode folder in folderItems)
                {
                    tab.AddRow(new[]
                    {
                        folder.FolderUid,
                        folder.Name ?? "",
                        string.IsNullOrEmpty(folder.ParentUid) ? "(root)" : folder.ParentUid,
                        folder.Subfolders.Count.ToString(),
                        folder.Records.Count.ToString()
                    });
                }

                tab.Dump();
            }

            if (showRecords && recordCount > 0)
            {
                Console.WriteLine("--- Records ---");
                var tab = new Tabulate(8);
                tab.AddHeader(new[] { "RecordUid", "Name", "Type", "Revision", "Version", "Shared", "FileSize", "ThumbnailSize" });
                foreach (KeeperNSFRecord record in recordItems)
                {
                    var meta = NsfHelpers.GetRecordTypeAndTitle(record);
                    tab.AddRow(new[]
                    {
                        record.RecordUid,
                        record.Title ?? meta.Title,
                        meta.Type,
                        record.Revision.ToString(),
                        record.Version.ToString(),
                        record.Shared.ToString(),
                        record.FileSize.ToString("N0"),
                        record.ThumbnailSize.ToString("N0")
                    });
                }

                tab.Dump();
            }

            return Task.CompletedTask;
        }

        public static async Task NsfGetCommand(this VaultContext context, NsfGetOptions options)
        {
            if (string.IsNullOrEmpty(options.Uid) && string.IsNullOrEmpty(options.Name))
            {
                Console.WriteLine("Please provide either --uid or --name parameter.");
                return;
            }

            var vault = context.Vault;
            var currentAccountUid = vault.Auth.AuthContext.AccountUid.Base64UrlEncode();
            var (record, folder) = NsfHelpers.ResolveNsfObject(vault, options.Uid, options.Name);

            if (record == null && folder == null)
            {
                var id = !string.IsNullOrEmpty(options.Uid) ? options.Uid : options.Name;
                Console.WriteLine($"Keeper NSF object with identifier '{id}' not found.");
                return;
            }

            var format = options.Format ?? "detail";
            if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            {
                object jsonObj;
                if (record != null)
                {
                    jsonObj = await NsfDetailHelper.BuildRecordJsonAsync(vault, record, currentAccountUid);
                }
                else
                {
                    jsonObj = await NsfDetailHelper.BuildFolderJsonAsync(vault, folder, currentAccountUid);
                }

                Console.WriteLine(Json.Serialize(jsonObj));
                return;
            }

            if (record != null)
            {
                await NsfDetailHelper.ShowRecordDetailAsync(vault, record, currentAccountUid);
            }
            else
            {
                await NsfDetailHelper.ShowFolderDetailAsync(vault, folder, currentAccountUid);
            }
        }

        public static async Task NsfRecordDetailsCommand(this VaultContext context, NsfRecordDetailsOptions options)
        {
            var vault = context.Vault;
            var identifiers = options.RecordUids?.ToList() ?? new List<string>();
            if (identifiers.Count == 0)
            {
                Console.WriteLine("At least one record UID or title is required.");
                return;
            }

            var recordUids = identifiers
                .Select(uid =>
                {
                    var trimmed = uid?.Trim();
                    var resolved = NsfHelpers.ResolveNsfRecord(vault, trimmed);
                    return resolved?.RecordUid ?? trimmed;
                })
                .Where(uid => !string.IsNullOrEmpty(uid))
                .ToList();

            KeeperNSFRecordDetailsResult details;
            try
            {
                details = await vault.GetKeeperNSFRecordDetails(recordUids);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            var format = options.Format ?? "table";
            if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            {
                var data = details.Data.Select(entry => new Dictionary<string, object>
                {
                    ["record_uid"] = entry.RecordUid,
                    ["title"] = entry.Title,
                    ["type"] = entry.Type,
                    ["version"] = entry.Version,
                    ["revision"] = entry.Revision
                }).ToList();

                var output = new Dictionary<string, object>
                {
                    ["data"] = data,
                    ["forbidden_records"] = details.ForbiddenRecords
                };

                Console.WriteLine(Json.Serialize(output));
                return;
            }

            foreach (var entry in details.Data)
            {
                Console.WriteLine($"{NsfDetailHelper.PadLabel("Record UID", NsfHelpers.LabelWidth)}: {entry.RecordUid}");
                Console.WriteLine($"{NsfDetailHelper.PadLabel("Title", NsfHelpers.LabelWidth)}: {entry.Title}");
                Console.WriteLine($"{NsfDetailHelper.PadLabel("Type", NsfHelpers.LabelWidth)}: {entry.Type}");
                Console.WriteLine($"{NsfDetailHelper.PadLabel("Version", NsfHelpers.LabelWidth)}: {entry.Version}");
                Console.WriteLine($"{NsfDetailHelper.PadLabel("Revision", NsfHelpers.LabelWidth)}: {entry.Revision}");
                Console.WriteLine();
            }

            if (details.ForbiddenRecords.Count > 0)
            {
                Console.WriteLine($"Forbidden records: {details.ForbiddenRecords.Count}");
                foreach (var uid in details.ForbiddenRecords)
                {
                    Console.WriteLine($"  {uid}");
                }
            }

            Console.WriteLine($"Total records retrieved: {details.Data.Count}");
        }
    }

    internal static class NsfDetailHelper
    {
        internal static string PadLabel(string label, int width) =>
            label.PadLeft(width);

        internal static async Task ShowRecordDetailAsync(VaultOnline vault, KeeperNSFRecord record, string currentAccountUid)
        {
            var meta = NsfHelpers.GetRecordTypeAndTitle(record);
            Console.WriteLine();
            Console.WriteLine($"{PadLabel("UID", NsfHelpers.LabelWidth)}: {record.RecordUid}");
            Console.WriteLine($"{PadLabel("Type", NsfHelpers.LabelWidth)}: {meta.Type}");
            Console.WriteLine($"{PadLabel("Title", NsfHelpers.LabelWidth)}: {meta.Title}");

            if (!string.IsNullOrEmpty(record.Notes))
            {
                Console.WriteLine($"{PadLabel("Notes", NsfHelpers.LabelWidth)}: {record.Notes}");
            }

            var fields = GetRecordFields(vault, record);
            foreach (var field in fields)
            {
                if (string.IsNullOrWhiteSpace(field.Type) || field.Value == null || field.Value.Count == 0)
                {
                    continue;
                }

                if (field.Type == "name")
                {
                    var nameValue = FormatFieldDisplayValue(field.Type, field.Value[0]);
                    if (nameValue == meta.Title)
                    {
                        continue;
                    }
                }

                var displayValues = field.Value
                    .Select(v => FormatFieldDisplayValue(field.Type, v))
                    .Where(v => !string.IsNullOrEmpty(v))
                    .ToList();
                if (displayValues.Count == 0)
                {
                    continue;
                }

                var label = NsfHelpers.GetFieldLabel(field.Type);
                Console.WriteLine($"{PadLabel(label, NsfHelpers.LabelWidth)}: {displayValues[0]}");
                for (var i = 1; i < displayValues.Count; i++)
                {
                    Console.WriteLine($"{PadLabel("", NsfHelpers.LabelWidth)}  {displayValues[i]}");
                }
            }

            var folderMap = NsfHelpers.GetFolderNodeMap(vault);
            var pathLabel = !string.IsNullOrEmpty(record.FolderUid)
                ? NsfHelpers.GetFolderPath(vault, record.FolderUid, folderMap)
                : "/";
            Console.WriteLine($"{PadLabel("Folder UID", NsfHelpers.LabelWidth)}: {(string.IsNullOrEmpty(record.FolderUid) ? "(root)" : record.FolderUid)}");
            Console.WriteLine($"{PadLabel("Folder Name", NsfHelpers.LabelWidth)}: {record.FolderName ?? "(unknown)"}");
            Console.WriteLine($"{PadLabel("Folder Path", NsfHelpers.LabelWidth)}: {pathLabel}");

            foreach (var folderUid in vault.GetKeeperNSFFoldersForRecord(record.RecordUid))
            {
                if (folderUid == record.FolderUid)
                {
                    continue;
                }

                folderMap.TryGetValue(folderUid, out var node);
                var name = node?.Name ?? "(unknown)";
                Console.WriteLine($"{PadLabel("Also in folder", NsfHelpers.LabelWidth)}: {name} ({folderUid})");
            }

            if (record.FileSize > 0)
            {
                Console.WriteLine($"{PadLabel("File Size", NsfHelpers.LabelWidth)}: {record.FileSize:N0}");
            }

            if (record.ThumbnailSize > 0)
            {
                Console.WriteLine($"{PadLabel("Thumbnail Size", NsfHelpers.LabelWidth)}: {record.ThumbnailSize:N0}");
            }

            Console.WriteLine();
            var accesses = await GetRecordAccessesAsync(vault, record);
            var shareAdmins = await GetShareAdminEmailsAsync(vault, record.RecordUid);
            await ShowPermissionsAsync(vault, accesses, shareAdmins, currentAccountUid, "record");
            Console.WriteLine();
        }

        internal static async Task ShowFolderDetailAsync(VaultOnline vault, FolderNode folder, string currentAccountUid)
        {
            Console.WriteLine();
            Console.WriteLine($"{PadLabel("Nested Share Folder UID", NsfHelpers.FolderLabelWidth)}: {folder.FolderUid}");
            Console.WriteLine($"{PadLabel("Name", NsfHelpers.FolderLabelWidth)}: {folder.Name}");
            Console.WriteLine();

            var accesses = await GetFolderAccessesAsync(vault, folder);
            var storedFolder = vault.Storage.KdFolders.GetEntity(folder.FolderUid);
            var ownerAccountUid = storedFolder?.OwnerAccountUid;
            var ownerUsername = storedFolder?.OwnerUsername;
            await ShowFolderPermissionsAsync(vault, accesses, currentAccountUid, ownerAccountUid, ownerUsername);
        }

        internal static async Task<object> BuildRecordJsonAsync(VaultOnline vault, KeeperNSFRecord record, string currentAccountUid)
        {
            var meta = NsfHelpers.GetRecordTypeAndTitle(record);
            var accesses = await GetRecordAccessesAsync(vault, record);
            var shareAdmins = await GetShareAdminEmailsAsync(vault, record.RecordUid);
            var userPerms = await BuildUserPermissionsAsync(vault, accesses, currentAccountUid, "record");
            var folderMap = NsfHelpers.GetFolderNodeMap(vault);
            var folderPath = !string.IsNullOrEmpty(record.FolderUid)
                ? NsfHelpers.GetFolderPath(vault, record.FolderUid, folderMap)
                : "/";

            return new Dictionary<string, object>
            {
                ["uid"] = record.RecordUid,
                ["type"] = meta.Type,
                ["title"] = meta.Title,
                ["notes"] = record.Notes,
                ["folder"] = new Dictionary<string, object>
                {
                    ["uid"] = record.FolderUid,
                    ["name"] = record.FolderName,
                    ["path"] = folderPath
                },
                ["fields"] = BuildFieldsJson(GetRecordFields(vault, record)),
                ["file_size"] = record.FileSize,
                ["thumbnail_size"] = record.ThumbnailSize,
                ["version"] = record.Version,
                ["revision"] = record.Revision,
                ["shared"] = record.Shared,
                ["permissions"] = userPerms,
                ["share_admins"] = shareAdmins
            };
        }

        internal static async Task<object> BuildFolderJsonAsync(VaultOnline vault, FolderNode folder, string currentAccountUid)
        {
            var accesses = await GetFolderAccessesAsync(vault, folder);
            var storedFolder = vault.Storage.KdFolders.GetEntity(folder.FolderUid);
            var ownerAccountUid = storedFolder?.OwnerAccountUid;
            var ownerUsername = storedFolder?.OwnerUsername;
            var permJson = await BuildFolderPermissionsJsonAsync(vault, accesses, currentAccountUid, ownerAccountUid, ownerUsername);
            var folderMap = NsfHelpers.GetFolderNodeMap(vault);
            var parentUid = NsfHelpers.ResolveFolderParentUid(folder.ParentUid, folderMap);
            var parentPath = parentUid == null
                ? "/"
                : NsfHelpers.FormatNsfFolderPath(NsfHelpers.GetFolderPath(vault, parentUid, folderMap));

            var records = new List<object>();
            foreach (var recordUid in folder.Records)
            {
                var recordName = recordUid;
                if (vault.TryGetKeeperNSFRecord(recordUid, out var kdRecord))
                {
                    var meta = NsfHelpers.GetRecordTypeAndTitle(kdRecord);
                    recordName = kdRecord.Title ?? meta.Title;
                }

                records.Add(new Dictionary<string, object>
                {
                    ["record_uid"] = recordUid,
                    ["record_name"] = recordName
                });
            }

            var json = new Dictionary<string, object>
            {
                ["folder_uid"] = folder.FolderUid,
                ["type"] = "nested_share_folder",
                ["name"] = folder.Name,
                ["parent_uid"] = parentUid,
                ["folder"] = new Dictionary<string, object>
                {
                    ["uid"] = parentUid,
                    ["path"] = parentPath
                },
                ["records"] = records
            };

            if (!string.IsNullOrEmpty(ownerUsername))
            {
                json["owner"] = ownerUsername;
            }

            if (permJson.UserPermissions.Count > 0)
            {
                json["user_permissions"] = permJson.UserPermissions;
            }

            if (permJson.TeamPermissions.Count > 0)
            {
                json["team_permissions"] = permJson.TeamPermissions;
            }

            if (permJson.ShareAdmins.Count > 0)
            {
                json["share_admins"] = permJson.ShareAdmins;
            }

            return json;
        }

        private class FolderPermissionsJson
        {
            public List<object> UserPermissions { get; set; } = new List<object>();
            public List<object> TeamPermissions { get; set; } = new List<object>();
            public List<string> ShareAdmins { get; set; } = new List<string>();
        }

        private static async Task<FolderPermissionsJson> BuildFolderPermissionsJsonAsync(
            VaultOnline vault,
            List<NsfAccessView> accesses,
            string currentAccountUid,
            string ownerAccountUid,
            string ownerUsername)
        {
            var result = new FolderPermissionsJson();
            var shareAdminSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var access in accesses)
            {
                var username = !string.IsNullOrEmpty(access.AccessorEmail)
                    ? access.AccessorEmail
                    : await NsfHelpers.ResolveUsernameAsync(vault, access.AccessTypeUid);

                var accessTypeLabel = NsfHelpers.GetAccessTypeLabel(access.AccessType);
                var accessor = !string.IsNullOrEmpty(username) ? username : access.AccessTypeUid;

                var isOwner = NsfHelpers.IsFolderOwner(access.AccessTypeUid, username, ownerAccountUid, ownerUsername);

                var roleLabel = isOwner ? "owner" : NsfHelpers.GetAccessRoleLabel(access.AccessRoleType);

                var entry = new Dictionary<string, object>
                {
                    ["accessor"] = accessor,
                    ["access_type"] = accessTypeLabel,
                    ["role"] = roleLabel,
                    ["inherited"] = access.Inherited
                };

                if (accessTypeLabel == "AT_TEAM")
                {
                    result.TeamPermissions.Add(entry);
                }
                else
                {
                    result.UserPermissions.Add(entry);
                }

                if (access.AccessRoleType == 6 && shareAdminSet.Add(accessor))
                {
                    result.ShareAdmins.Add(accessor);
                }
            }

            return result;
        }

        private class ParsedField
        {
            public string Type { get; set; }
            public List<string> Value { get; set; }
        }

        private static List<ParsedField> GetRecordFields(VaultOnline vault, KeeperNSFRecord record)
        {
            if (record.RecordKey != null && record.RecordKey.Length > 0)
            {
                var storageRecord = vault.Storage.KdRecords.GetEntity(record.RecordUid);
                if (storageRecord != null && !string.IsNullOrEmpty(storageRecord.Data))
                {
                    try
                    {
                        var encrypted = storageRecord.Data.Base64UrlDecode();
                        var decrypted = CryptoUtils.DecryptAesV2(encrypted, record.RecordKey);
                        var jsonText = Encoding.UTF8.GetString(decrypted);
                        var data = Json.Deserialize(jsonText) as IDictionary<string, object>;
                        if (data != null && data.TryGetValue("fields", out var fieldsObj) && fieldsObj is IList<object> fieldList)
                        {
                            var fields = new List<ParsedField>();
                            foreach (var f in fieldList)
                            {
                                if (f is IDictionary<string, object> fd &&
                                    fd.TryGetValue("type", out var typeObj) &&
                                    typeObj is string fieldType &&
                                    !string.IsNullOrWhiteSpace(fieldType))
                                {
                                    var values = new List<string>();
                                    if (fd.TryGetValue("value", out var valObj))
                                    {
                                        if (valObj is IList<object> valList)
                                        {
                                            foreach (var v in valList)
                                            {
                                                if (v != null)
                                                {
                                                    values.Add(v.ToString());
                                                }
                                            }
                                        }
                                        else if (valObj != null)
                                        {
                                            values.Add(valObj.ToString());
                                        }
                                    }

                                    fields.Add(new ParsedField { Type = fieldType, Value = values });
                                }
                            }

                            if (fields.Count > 0)
                            {
                                return fields;
                            }
                        }
                    }
                    catch
                    {
                        // fall through to cached fields
                    }
                }
            }

            return record.Fields?.Select(f => new ParsedField
            {
                Type = f.Type,
                Value = f.Value?.ToList() ?? new List<string>()
            }).ToList() ?? new List<ParsedField>();
        }

        private static List<object> BuildFieldsJson(IEnumerable<ParsedField> fields)
        {
            var result = new List<object>();
            if (fields == null)
            {
                return result;
            }

            foreach (var f in fields)
            {
                var values = new List<object>();
                if (f.Value != null)
                {
                    foreach (var v in f.Value)
                    {
                        if (v == null)
                        {
                            values.Add(null);
                            continue;
                        }

                        if (NsfHelpers.IsSecretField(f.Type) && !NsfHelpers.PasswordVisible)
                        {
                            values.Add("********");
                            continue;
                        }

                        if (v is string s)
                        {
                            var parsed = TryParseJsonValue(s.Trim());
                            values.Add(parsed ?? v);
                        }
                        else
                        {
                            values.Add(v);
                        }
                    }
                }

                result.Add(new Dictionary<string, object>
                {
                    ["type"] = f.Type,
                    ["value"] = values
                });
            }

            return result;
        }

        private static string FormatFieldDisplayValue(string fieldType, object rawValue)
        {
            if (rawValue == null)
            {
                return null;
            }

            if (rawValue is string s && string.IsNullOrWhiteSpace(s))
            {
                return null;
            }

            if (NsfHelpers.IsSecretField(fieldType) && !NsfHelpers.PasswordVisible)
            {
                return "********";
            }

            if (fieldType == "host")
            {
                return FormatHostDisplayValue(rawValue);
            }

            if (rawValue is IDictionary<string, object> dict)
            {
                return FormatComplexFieldValue(fieldType, dict);
            }

            if (rawValue is string str)
            {
                var parsed = TryParseJsonValue(str);
                if (parsed is IDictionary<string, object> parsedDict)
                {
                    return FormatComplexFieldValue(fieldType, parsedDict);
                }

                if (fieldType == "date")
                {
                    return FormatDateFieldValue(str);
                }

                return str;
            }

            return rawValue.ToString();
        }

        private static string FormatHostDisplayValue(object value)
        {
            if (value is string s)
            {
                var parsed = TryParseJsonValue(s);
                if (parsed != null && parsed != (object)s)
                {
                    return FormatHostDisplayValue(parsed);
                }

                return string.IsNullOrWhiteSpace(s) ? null : s.Trim();
            }

            if (value is IDictionary<string, object> dict)
            {
                dict.TryGetValue("hostName", out var hostName);
                if (hostName == null)
                {
                    dict.TryGetValue("host", out hostName);
                }

                dict.TryGetValue("port", out var port);
                if (hostName != null || port != null)
                {
                    var parts = new List<string>();
                    if (hostName != null)
                    {
                        parts.Add($"hostName: {hostName}");
                    }

                    if (port != null)
                    {
                        parts.Add($"port: {port}");
                    }

                    return string.Join(", ", parts);
                }
            }

            return null;
        }

        private static string FormatComplexFieldValue(string fieldType, IDictionary<string, object> value)
        {
            switch (fieldType)
            {
                case "name":
                {
                    var parts = new[] { "first", "middle", "last" }
                        .Select(k => value.TryGetValue(k, out var v) ? v?.ToString() : null)
                        .Where(p => !string.IsNullOrWhiteSpace(p))
                        .ToList();
                    return parts.Count > 0 ? string.Join(" ", parts) : null;
                }
                case "address":
                {
                    var parts = new[] { "street1", "street2", "city", "state", "zip", "country" }
                        .Select(k => value.TryGetValue(k, out var v) ? v?.ToString() : null)
                        .Where(p => !string.IsNullOrWhiteSpace(p))
                        .ToList();
                    return parts.Count > 0 ? string.Join(", ", parts) : null;
                }
                case "phone":
                {
                    value.TryGetValue("number", out var number);
                    if (number == null)
                    {
                        return null;
                    }

                    var result = number.ToString();
                    if (value.TryGetValue("ext", out var ext) && ext != null)
                    {
                        result += $" ext. {ext}";
                    }

                    if (value.TryGetValue("type", out var type) && type != null)
                    {
                        result += $" ({type})";
                    }

                    return result;
                }
                default:
                {
                    var parts = value
                        .Where(kv => kv.Value != null && !string.IsNullOrEmpty(kv.Value.ToString()))
                        .Select(kv => $"{kv.Key}: {kv.Value}")
                        .ToList();
                    return parts.Count > 0 ? string.Join(", ", parts) : Json.Serialize(value);
                }
            }
        }

        private static string FormatDateFieldValue(string value)
        {
            if (long.TryParse(value, out var timestamp) && timestamp > 0)
            {
                try
                {
                    if (timestamp > 9999999999)
                    {
                        return DateTimeOffset.FromUnixTimeMilliseconds(timestamp).ToString("yyyy-MM-dd");
                    }

                    return DateTimeOffset.FromUnixTimeSeconds(timestamp).ToString("yyyy-MM-dd");
                }
                catch
                {
                    // ignored
                }
            }

            return value;
        }

        private static object TryParseJsonValue(string rawValue)
        {
            if (string.IsNullOrWhiteSpace(rawValue))
            {
                return null;
            }

            var trimmed = rawValue.Trim();
            if (!trimmed.StartsWith("{") && !trimmed.StartsWith("["))
            {
                return rawValue;
            }

            try
            {
                return Json.Deserialize(trimmed);
            }
            catch
            {
                return rawValue;
            }
        }

        private class NsfAccessView
        {
            public string AccessTypeUid { get; set; }
            public int AccessType { get; set; }
            public int AccessRoleType { get; set; }
            public bool Inherited { get; set; }
            public bool Owner { get; set; }
            public bool CanEdit { get; set; }
            public bool CanView { get; set; }
            public bool CanDelete { get; set; }
            public string AccessorEmail { get; set; }
        }

        private static async Task<List<NsfAccessView>> GetRecordAccessesAsync(VaultOnline vault, KeeperNSFRecord record)
        {
            try
            {
                var rq = new RecordAccessRequest();
                rq.RecordUids.Add(ByteString.CopyFrom(record.RecordUid.Base64UrlDecode()));
                var rs = await vault.Auth.ExecuteAuthRest<RecordAccessRequest, RecordAccessResponse>(
                    "vault/records/v3/details/access", rq);
                var converted = new List<NsfAccessView>();
                foreach (var ra in rs.RecordAccesses)
                {
                    var d = ra.Data;
                    if (d == null)
                    {
                        continue;
                    }

                    var emailHint = ra.AccessorInfo?.Name;
                    converted.Add(new NsfAccessView
                    {
                        AccessTypeUid = d.AccessTypeUid.ToByteArray().Base64UrlEncode(),
                        AccessRoleType = (int)d.AccessRoleType,
                        Owner = d.Owner,
                        CanEdit = d.CanEdit,
                        CanView = d.CanView,
                        CanDelete = d.CanDelete,
                        AccessorEmail = emailHint
                    });
                }

                return converted;
            }
            catch
            {
                return vault.Storage.KdRecordAccesses.GetLinksForSubject(record.RecordUid)
                    .Select(a => new NsfAccessView
                    {
                        AccessTypeUid = a.AccessTypeUid,
                        AccessRoleType = a.AccessRoleType,
                        Owner = a.Owner,
                        CanEdit = a.CanEdit,
                        CanView = a.CanView,
                        CanDelete = a.CanDelete
                    }).ToList();
            }
        }

        private static async Task<List<string>> GetShareAdminEmailsAsync(VaultOnline vault, string recordUid)
        {
            try
            {
                var rq = new GetSharingAdminsRequest
                {
                    RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode())
                };
                var response = await vault.Auth.ExecuteAuthRest<GetSharingAdminsRequest, GetSharingAdminsResponse>(
                    "enterprise/get_sharing_admins", rq);
                return response.UserProfileExts
                    .Where(p => !string.IsNullOrEmpty(p.Email))
                    .Select(p => p.Email)
                    .ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        private static async Task<List<NsfAccessView>> GetFolderAccessesAsync(VaultOnline vault, FolderNode folder)
        {
            try
            {
                var rq = new GetFolderAccessRequest();
                rq.FolderUid.Add(ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()));
                var rs = await vault.Auth.ExecuteAuthRest<GetFolderAccessRequest, GetFolderAccessResponse>(
                    "vault/folders/v3/access", rq);
                foreach (var result in rs.FolderAccessResults)
                {
                    if (result.Error != null)
                    {
                        continue;
                    }

                    return result.Accessors.Select(a => new NsfAccessView
                    {
                        AccessTypeUid = a.AccessTypeUid.ToByteArray().Base64UrlEncode(),
                        AccessType = (int)a.AccessType,
                        AccessRoleType = (int)a.AccessRoleType,
                        Inherited = a.Inherited
                    }).ToList();
                }
            }
            catch
            {
                // fall through
            }

            return vault.Storage.KdFolderAccesses.GetLinksForSubject(folder.FolderUid)
                .Select(a => new NsfAccessView
                {
                    AccessTypeUid = a.AccessTypeUid,
                    AccessType = a.AccessType,
                    AccessRoleType = a.AccessRoleType,
                    Inherited = a.Inherited
                }).ToList();
        }

        private class UserPermView
        {
            public string Username { get; set; }
            public bool Owner { get; set; }
            public string Role { get; set; }
            public bool CanEdit { get; set; }
            public bool CanView { get; set; }
            public bool CanDelete { get; set; }
        }

        private static async Task<List<object>> BuildUserPermissionsAsync(
            VaultOnline vault,
            List<NsfAccessView> accesses,
            string currentAccountUid,
            string objectType,
            string ownerAccountUid = null,
            string ownerUsername = null)
        {
            var userPerms = await GetUserPermissionsAsync(vault, accesses, currentAccountUid, objectType, ownerAccountUid, ownerUsername);
            var result = new List<object>();
            foreach (var perm in userPerms)
            {
                var entry = new Dictionary<string, object>
                {
                    ["user"] = perm.Username,
                    ["shareable"] = perm.CanEdit || perm.Owner ? "Yes" : "No",
                    ["read_only"] = !perm.CanEdit && !perm.Owner ? "Yes" : "No"
                };
                if (perm.Owner)
                {
                    entry["owner"] = "Yes";
                }
                else
                {
                    entry["role"] = perm.Role;
                }

                result.Add(entry);
            }

            return result;
        }

        private static async Task<List<UserPermView>> GetUserPermissionsAsync(
            VaultOnline vault,
            List<NsfAccessView> accesses,
            string currentAccountUid,
            string objectType,
            string ownerAccountUid,
            string ownerUsername)
        {
            var userPerms = new List<UserPermView>();
            foreach (var access in accesses)
            {
                var username = !string.IsNullOrEmpty(access.AccessorEmail)
                    ? access.AccessorEmail
                    : await NsfHelpers.ResolveUsernameAsync(vault, access.AccessTypeUid);

                var isOwner = objectType == "record"
                    ? access.Owner
                    : NsfHelpers.IsFolderOwner(access.AccessTypeUid, username, ownerAccountUid, ownerUsername);

                userPerms.Add(new UserPermView
                {
                    Username = username,
                    Owner = isOwner,
                    Role = NsfHelpers.GetAccessRoleLabel(access.AccessRoleType),
                    CanEdit = access.CanEdit,
                    CanView = access.CanView,
                    CanDelete = access.CanDelete
                });
            }

            return userPerms;
        }

        private static async Task ShowFolderPermissionsAsync(
            VaultOnline vault,
            List<NsfAccessView> accesses,
            string currentAccountUid,
            string ownerAccountUid,
            string ownerUsername)
        {
            if (accesses == null || accesses.Count == 0)
            {
                Console.WriteLine("No permissions found for this folder.");
                Console.WriteLine();
                return;
            }

            var users = new List<(string Accessor, string RoleLabel, bool IsOwner)>();
            var teams = new List<(string Accessor, string RoleLabel)>();
            var shareAdmins = new List<(string Accessor, bool IsOwner)>();

            foreach (var access in accesses)
            {
                var username = !string.IsNullOrEmpty(access.AccessorEmail)
                    ? access.AccessorEmail
                    : await NsfHelpers.ResolveUsernameAsync(vault, access.AccessTypeUid);

                var accessTypeLabel = NsfHelpers.GetAccessTypeLabel(access.AccessType);
                var accessor = !string.IsNullOrEmpty(username) ? username : access.AccessTypeUid;
                var isOwner = NsfHelpers.IsFolderOwner(access.AccessTypeUid, username, ownerAccountUid, ownerUsername);
                var roleLabel = isOwner ? "owner" : NsfHelpers.GetAccessRoleLabel(access.AccessRoleType);

                if (accessTypeLabel == "AT_TEAM")
                {
                    teams.Add((accessor, roleLabel));
                }
                else
                {
                    users.Add((accessor, roleLabel, isOwner));
                }

                if (access.AccessRoleType == 6)
                {
                    shareAdmins.Add((accessor, isOwner));
                }
            }

            if (users.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"{PadLabel("User Permissions", NsfHelpers.FolderLabelWidth)}:");
                foreach (var (accessor, roleLabel, _) in users)
                {
                    Console.WriteLine($"{PadLabel(accessor, NsfHelpers.FolderLabelWidth)}: {roleLabel}");
                }
            }

            if (teams.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"{PadLabel("Team Permissions", NsfHelpers.FolderLabelWidth)}:");
                foreach (var (accessor, roleLabel) in teams)
                {
                    Console.WriteLine($"{PadLabel(accessor, NsfHelpers.FolderLabelWidth)}: {roleLabel}");
                }
            }

            if (shareAdmins.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"{PadLabel("Share Administrators", NsfHelpers.FolderLabelWidth)}:");
                foreach (var (accessor, isOwner) in shareAdmins)
                {
                    var adminRole = isOwner ? "owner" : "full-manager";
                    Console.WriteLine($"{PadLabel(accessor, NsfHelpers.FolderLabelWidth)}: {adminRole}");
                }
            }

            Console.WriteLine();
        }

        private static async Task ShowPermissionsAsync(
            VaultOnline vault,
            List<NsfAccessView> accesses,
            IList<string> shareAdminEmails,
            string currentAccountUid,
            string objectType,
            string ownerAccountUid = null,
            string ownerUsername = null)
        {
            var userPerms = await GetUserPermissionsAsync(vault, accesses, currentAccountUid, objectType, ownerAccountUid, ownerUsername);

            if (userPerms.Count > 0)
            {
                if (objectType != "folder")
                {
                    Console.WriteLine($"{PadLabel("User Permissions", NsfHelpers.LabelWidth)}:");
                    Console.WriteLine();
                    foreach (var perm in userPerms)
                    {
                        Console.WriteLine($"{PadLabel("User", NsfHelpers.LabelWidth)}: {perm.Username}");
                        if (perm.Owner)
                        {
                            Console.WriteLine($"{PadLabel("Owner", NsfHelpers.LabelWidth)}: Yes");
                        }
                        else
                        {
                            Console.WriteLine($"{PadLabel("Role", NsfHelpers.LabelWidth)}: {perm.Role}");
                        }

                        Console.WriteLine($"{PadLabel("Shareable", NsfHelpers.LabelWidth)}: {(perm.CanEdit || perm.Owner ? "Yes" : "No")}");
                        Console.WriteLine($"{PadLabel("Read-Only", NsfHelpers.LabelWidth)}: {(!perm.CanEdit && !perm.Owner ? "Yes" : "No")}");
                        Console.WriteLine();
                    }
                }
            }

            if (objectType != "folder" && shareAdminEmails != null && shareAdminEmails.Count > 0)
            {
                const int maxShow = 10;
                var total = shareAdminEmails.Count;
                Console.WriteLine();
                Console.WriteLine(total > maxShow
                    ? $"{PadLabel($"Share Admins ({total}, showing first {maxShow})", NsfHelpers.LabelWidth)}:"
                    : $"{PadLabel($"Share Admins ({total})", NsfHelpers.LabelWidth)}:");
                for (var i = 0; i < Math.Min(maxShow, total); i++)
                {
                    Console.WriteLine($"  {shareAdminEmails[i]}");
                }

                if (total > maxShow)
                {
                    Console.WriteLine($"  ... and {total - maxShow} more");
                }
            }
            else if (userPerms.Count == 0)
            {
                Console.WriteLine($"No permissions found for this {objectType}.");
            }
        }
    }

    class NsfFoldersOptions { }

    class NsfRecordsOptions { }

    class NsfListOptions
    {
        [Option("folders", Required = false, HelpText = "Show only folders")]
        public bool Folders { get; set; }

        [Option("records", Required = false, HelpText = "Show only records")]
        public bool Records { get; set; }

        [Option('f', "format", Required = false, Default = "table", HelpText = "Output format: table, csv, json")]
        public string Format { get; set; }

        [Option('o', "output", Required = false, HelpText = "Output file path (csv/json)")]
        public string Output { get; set; }
    }

    class NsfGetOptions
    {
        [Option("uid", Required = false, HelpText = "Record or folder UID")]
        public string Uid { get; set; }

        [Option("name", Required = false, HelpText = "Record or folder name")]
        public string Name { get; set; }

        [Option('f', "format", Required = false, Default = "detail", HelpText = "Output format: detail, json")]
        public string Format { get; set; }
    }

    class NsfRecordDetailsOptions
    {
        [Value(0, Min = 1, Required = true, HelpText = "Record UID(s) or title(s)")]
        public IEnumerable<string> RecordUids { get; set; }

        [Option('f', "format", Required = false, Default = "table", HelpText = "Output format: table, json")]
        public string Format { get; set; }
    }
}
