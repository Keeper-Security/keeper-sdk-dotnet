using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Commander
{
    internal static class FindDuplicatesCommandExtensions
    {
        public static async Task FindDuplicatesCommand(this VaultContext context, FindDuplicatesCommandOptions options)
        {
            if (options.Scope == "enterprise")
            {
                throw new NotImplementedException("Enterprise scope is not yet implemented. Use --scope vault");
            }

            var compareFields = new List<string>();
            if (options.Full)
            {
                compareFields.Add("All Fields");
            }
            else
            {
                if (options.Title || (!options.Login && !options.Password && !options.Url))
                    compareFields.Add("Title");
                if (options.Login || (!options.Title && !options.Password && !options.Url))
                    compareFields.Add("Login");
                if (options.Password || (!options.Title && !options.Login && !options.Url))
                    compareFields.Add("Password");
                if (options.Url)
                    compareFields.Add("URL");
            }
            Console.WriteLine($"Find duplicated records by: {string.Join(", ", compareFields)}");
            Console.WriteLine();

            Dictionary<string, RecordSharePermissions> shareInfoMap = null;
            var recordUids = context.Vault.KeeperRecords.Select(r => r.Uid).ToList();
            try
            {
                var sharesList = await context.Vault.GetSharesForRecords(recordUids);
                shareInfoMap = sharesList.ToDictionary(s => s.RecordUid, s => s);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not load share information: {ex.Message}");
                shareInfoMap = new Dictionary<string, RecordSharePermissions>();
            }

            Dictionary<string, RecordSharePermissions> shareInfoForHash = null;
            if (options.Full || options.Shares)
            {
                shareInfoForHash = shareInfoMap;
            }

            // Build the duplicate hash map
            var duplicateGroups = BuildDuplicateHashMap(context, options, shareInfoForHash);

            if (duplicateGroups.Count == 0)
            {
                Console.WriteLine("No duplicate records found.");
                return;
            }

            Console.WriteLine("Duplicates Found:");
            Console.WriteLine();
            
            if (options.Merge)
            {
                if (options.DryRun)
                {
                    Console.WriteLine("DRY RUN MODE: No records will be removed");
                    Console.WriteLine();
                }

                await HandleMergeOperation(context, duplicateGroups, options, shareInfoMap);
            }
            else
            {
                DisplayDuplicateReport(context, duplicateGroups, options, shareInfoMap);
            }
        }

        private static Dictionary<string, List<string>> BuildDuplicateHashMap(
            VaultContext context, 
            FindDuplicatesCommandOptions options,
            Dictionary<string, RecordSharePermissions> shareInfoMap)
        {
            var hashMap = new Dictionary<string, List<string>>();

            foreach (var record in context.Vault.KeeperRecords)
            {
                var hash = CreateRecordHash(record, options, shareInfoMap);
                if (string.IsNullOrEmpty(hash))
                    continue;

                if (!hashMap.ContainsKey(hash))
                {
                    hashMap[hash] = new List<string>();
                }
                hashMap[hash].Add(record.Uid);
            }

            // Filter to only groups with duplicates
            return hashMap.Where(kvp => kvp.Value.Count > 1).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        private static string CreateRecordHash(
            KeeperRecord record, 
            FindDuplicatesCommandOptions options,
            Dictionary<string, RecordSharePermissions> shareInfoMap)
        {
            var hashParts = new List<string>();

            if (options.Full)
            {
                hashParts.Add(record.Title ?? "");
                hashParts.Add(ExtractLogin(record));
                hashParts.Add(ExtractPassword(record));
                hashParts.Add(ExtractUrl(record));
                hashParts.Add(ExtractNotes(record));
                hashParts.Add(ExtractCustomFields(record));
                hashParts.Add(ExtractAllTypedFields(record));
                hashParts.Add(GetShareInfo(record, shareInfoMap));
            }
            else
            {
                // Match by selected fields
                if (options.Title)
                    hashParts.Add(record.Title ?? "");
                if (options.Login)
                    hashParts.Add(ExtractLogin(record));
                if (options.Password)
                    hashParts.Add(ExtractPassword(record));
                if (options.Url)
                    hashParts.Add(ExtractUrl(record));
            }

            if (hashParts.Count == 0)
            {
                hashParts.Add(record.Title ?? "");
                hashParts.Add(ExtractLogin(record));
                hashParts.Add(ExtractPassword(record));
            }

            if (options.Shares)
            {
                hashParts.Add(GetShareInfo(record, shareInfoMap));
            }

            var combined = string.Join("|", hashParts);
            if (string.IsNullOrWhiteSpace(combined))
                return null;

            return ComputeSHA256Hash(combined);
        }

        private static string ComputeSHA256Hash(string input)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha256.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        private static string ExtractLogin(KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord pr => pr.Login ?? "",
                TypedRecord tr => ExtractTypedField(tr, "login"),
                _ => ""
            };
        }

        private static string ExtractPassword(KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord pr => pr.Password ?? "",
                TypedRecord tr => ExtractTypedField(tr, "password"),
                _ => ""
            };
        }

        private static string ExtractUrl(KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord pr => pr.Link ?? "",
                TypedRecord tr => ExtractTypedField(tr, "url"),
                _ => ""
            };
        }

        private static string ExtractNotes(KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord pr => pr.Notes ?? "",
                TypedRecord tr => tr.Notes ?? "",
                _ => ""
            };
        }

        private static string ExtractCustomFields(KeeperRecord record)
        {
            var fields = new List<string>();

            switch (record)
            {
                case PasswordRecord pr:
                    if (pr.Custom != null)
                    {
                        foreach (var cf in pr.Custom.OrderBy(c => c.Name))
                        {
                            fields.Add($"{cf.Name}:{cf.Value}");
                        }
                    }
                    break;

                case TypedRecord tr:
                    if (tr.Custom != null)
                    {
                        foreach (var cf in tr.Custom.OrderBy(c => c.FieldName))
                        {
                            fields.Add($"{cf.FieldName}:{GetFieldValueAsString(cf)}");
                        }
                    }
                    break;
            }

            return string.Join(";", fields);
        }

        private static string ExtractTypedField(TypedRecord record, string fieldName)
        {
            var field = record.Fields?.FirstOrDefault(f =>
                string.Equals(f.FieldName, fieldName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.FieldLabel, fieldName, StringComparison.OrdinalIgnoreCase));

            if (field != null)
            {
                return GetFieldValueAsString(field);
            }

            var customField = record.Custom?.FirstOrDefault(f =>
                string.Equals(f.FieldName, fieldName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.FieldLabel, fieldName, StringComparison.OrdinalIgnoreCase));

            return customField != null ? GetFieldValueAsString(customField) : "";
        }

        private static string ExtractAllTypedFields(KeeperRecord record)
        {
            if (record is not TypedRecord tr || tr.Fields == null)
                return "";

            var fields = new List<string>();
            
            var standardFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "login", "password", "url"
            };

            foreach (var field in tr.Fields.OrderBy(f => f.FieldName))
            {
                if (standardFields.Contains(field.FieldName))
                    continue;

                var value = GetFieldValueAsString(field);
                if (!string.IsNullOrEmpty(value))
                {
                    fields.Add($"{field.FieldName}:{value}");
                }
            }

            return string.Join(";", fields);
        }

        private static string GetFieldValueAsString(ITypedField field)
        {
            if (field == null) return "";

            var value = field.ObjectValue;
            if (value == null) return "";

            if (value is string str)
            {
                return str;
            }
            else if (value is System.Collections.IEnumerable enumerable && !(value is string))
            {
                var items = new List<string>();
                foreach (var item in enumerable)
                {
                    if (item != null)
                    {
                        items.Add(item.ToString());
                    }
                }
                return string.Join(",", items);
            }

            return value.ToString();
        }

        private static string GetShareInfo(KeeperRecord record, Dictionary<string, RecordSharePermissions> shareInfoMap)
        {
            if (shareInfoMap == null || !shareInfoMap.TryGetValue(record.Uid, out var shareInfo))
            {
                return "";
            }

            var shareParts = new List<string>();

            if (shareInfo.UserPermissions != null)
            {
                var users = shareInfo.UserPermissions
                    .OrderBy(u => u.Username)
                    .Select(u => $"user:{u.Username}:owner={u.Owner}:edit={u.CanEdit}:share={u.CanShare}")
                    .ToList();
                shareParts.AddRange(users);
            }

            if (shareInfo.SharedFolderPermissions != null)
            {
                var folders = shareInfo.SharedFolderPermissions
                    .OrderBy(sf => sf.SharedFolderUid)
                    .Select(sf => $"sf:{sf.SharedFolderUid}:edit={sf.CanEdit}:share={sf.CanShare}")
                    .ToList();
                shareParts.AddRange(folders);
            }

            return string.Join(";", shareParts);
        }

        private static void DisplayDuplicateReport(
            VaultContext context, 
            Dictionary<string, List<string>> duplicateGroups, 
            FindDuplicatesCommandOptions options,
            Dictionary<string, RecordSharePermissions> shareInfoMap)
        {
            var table = new Tabulate(options.Url ? 7 : 6)
            {
                DumpRowNo = false
            };

            var headers = new[] { "Group", "Title", "Login" }
                .Concat(options.Url ? new[] { "URL" } : Array.Empty<string>())
                .Concat(new[] { "UID", "Record Owner", "Shared To" })
                .ToArray();

            table.AddHeader(headers);

            var groupIndex = 1;
            foreach (var group in duplicateGroups.OrderBy(g => g.Key))
            {
                var isFirstInGroup = true;
                foreach (var recordUid in group.Value)
                {
                    if (context.Vault.TryGetKeeperRecord(recordUid, out var record))
                    {
                        var login = ExtractLogin(record);
                        var url = options.Url ? TruncateUrl(ExtractUrl(record)) : "";
                        
                        var owner = GetRecordOwner(recordUid, shareInfoMap);
                        
                        var sharedUsers = GetSharedUsersArray(context, recordUid, shareInfoMap, owner);

                        var groupCell = isFirstInGroup ? groupIndex.ToString() : "";
                        
                        var firstSharedUser = sharedUsers.Length > 0 ? sharedUsers[0] : "";
                        var row = new object[] { groupCell, record.Title, login }
                            .Concat(options.Url ? new object[] { url } : Array.Empty<object>())
                            .Concat(new object[] { recordUid, owner, firstSharedUser })
                            .ToArray();

                        table.AddRow(row);
                        
                        for (var i = 1; i < sharedUsers.Length; i++)
                        {
                            var continuationRow = new object[] { "", "", "" }
                                .Concat(options.Url ? new object[] { "" } : Array.Empty<object>())
                                .Concat(new object[] { "", "", sharedUsers[i] })
                                .ToArray();
                            table.AddRow(continuationRow);
                        }
                        
                        isFirstInGroup = false;
                    }
                }
                groupIndex++;
            }

            table.Dump();
        }

        private static string GetRecordOwner(string recordUid, Dictionary<string, RecordSharePermissions> shareInfoMap)
        {
            if (shareInfoMap != null && shareInfoMap.TryGetValue(recordUid, out var shareInfo))
            {
                var owner = shareInfo.UserPermissions?.FirstOrDefault(u => u.Owner);
                if (owner != null)
                {
                    return owner.Username;
                }
            }
            return "";
        }

        private static string[] GetSharedUsersArray(VaultContext context, string recordUid, Dictionary<string, RecordSharePermissions> shareInfoMap, string owner)
        {
            var allSharedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            if (shareInfoMap != null && shareInfoMap.TryGetValue(recordUid, out var shareInfo))
            {
                if (shareInfo.UserPermissions != null)
                {
                    foreach (var user in shareInfo.UserPermissions.Where(u => !u.Owner))
                    {
                        allSharedUsers.Add(user.Username);
                    }
                }

                if (shareInfo.SharedFolderPermissions != null)
                {
                    foreach (var sfPerm in shareInfo.SharedFolderPermissions)
                    {
                        if (context.Vault.TryGetSharedFolder(sfPerm.SharedFolderUid, out var sharedFolder))
                        {
                            if (sharedFolder.UsersPermissions != null)
                            {
                                foreach (var userPerm in sharedFolder.UsersPermissions)
                                {
                                    if (userPerm.UserType == UserType.User && 
                                        !string.Equals(userPerm.Name, owner, StringComparison.OrdinalIgnoreCase))
                                    {
                                        allSharedUsers.Add(userPerm.Name);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return allSharedUsers.OrderBy(u => u).ToArray();
        }

        private static string TruncateUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return "";
            }

            try
            {
                var uri = new Uri(url);
                var host = uri.Host;
                return host.Length > 30 ? host.Substring(0, 30) : host;
            }
            catch
            {
                return url.Length > 30 ? url.Substring(0, 30) : url;
            }
        }

        private static async Task HandleMergeOperation(
            VaultContext context, 
            Dictionary<string, List<string>> duplicateGroups, 
            FindDuplicatesCommandOptions options,
            Dictionary<string, RecordSharePermissions> shareInfoMap)
        {
            var recordsToRemove = new List<string>();

            foreach (var group in duplicateGroups.Values)
            {
                // Keep first, remove rest
                recordsToRemove.AddRange(group.Skip(1));
            }

            if (recordsToRemove.Count == 0)
            {
                Console.WriteLine("No duplicate records to remove.");
                return;
            }

            Console.WriteLine($"The following {recordsToRemove.Count} duplicate record(s) will be removed:");
            Console.WriteLine();

            var removalTable = new Tabulate(3)
            {
                DumpRowNo = true
            };
            removalTable.AddHeader("Title", "UID", "Login");

            foreach (var recordUid in recordsToRemove)
            {
                if (context.Vault.TryGetKeeperRecord(recordUid, out var record))
                {
                    removalTable.AddRow(record.Title, recordUid, ExtractLogin(record));
                }
            }

            removalTable.Dump();
            Console.WriteLine();

            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: No records were removed.");
                return;
            }

            if (!options.Force)
            {
                Console.Write("Do you want to proceed with removing these duplicates? (y/n): ");
                var response = Console.ReadLine()?.Trim().ToLower();
                if (response != "y" && response != "yes")
                {
                    Console.WriteLine("Operation cancelled.");
                    return;
                }
            }

            Console.WriteLine("Removing duplicate records...");

            try
            {
                var recordPaths = recordsToRemove
                    .Select(uid => new RecordPath { RecordUid = uid, FolderUid = "" })
                    .ToArray();

                await context.Vault.DeleteRecords(recordPaths);

                Console.WriteLine($"Successfully removed {recordsToRemove.Count} duplicate record(s).");
                Console.WriteLine("Syncing vault...");

                await context.Vault.SyncDown(true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing duplicates: {ex.Message}");
            }
        }
    }

    class FindDuplicatesCommandOptions
    {
        [Option("title", Required = false, Default = false,
            HelpText = "Match duplicates by title")]
        public bool Title { get; set; }

        [Option("login", Required = false, Default = false,
            HelpText = "Match duplicates by login")]
        public bool Login { get; set; }

        [Option("password", Required = false, Default = false,
            HelpText = "Match duplicates by password")]
        public bool Password { get; set; }

        [Option("url", Required = false, Default = false,
            HelpText = "Match duplicates by URL")]
        public bool Url { get; set; }

        [Option("shares", Required = false, Default = false,
            HelpText = "Match duplicates by share permissions")]
        public bool Shares { get; set; }

        [Option("full", Required = false, Default = false,
            HelpText = "Match duplicates by all fields")]
        public bool Full { get; set; }

        [Option('m', "merge", Required = false, Default = false,
            HelpText = "Consolidate duplicate records (removes duplicates)")]
        public bool Merge { get; set; }

        [Option("ignore-shares-on-merge", Required = false, Default = false,
            HelpText = "Ignore share permissions when grouping duplicates to merge")]
        public bool IgnoreSharesOnMerge { get; set; }

        [Option('f', "force", Required = false, Default = false,
            HelpText = "Delete duplicates without confirmation (valid only with --merge)")]
        public bool Force { get; set; }

        [Option('n', "dry-run", Required = false, Default = false,
            HelpText = "Simulate removing duplicates without actually removing them (valid only with --merge)")]
        public bool DryRun { get; set; }

        [Option('q', "quiet", Required = false, Default = false,
            HelpText = "Suppress screen output (valid only with --force)")]
        public bool Quiet { get; set; }

        [Option('s', "scope", Required = false, Default = "vault",
            HelpText = "Search scope: vault or enterprise (default: vault)")]
        public string Scope { get; set; }

        [Option('r', "refresh-data", Required = false, Default = false,
            HelpText = "Populate local cache with latest data (valid only with --scope=enterprise)")]
        public bool RefreshData { get; set; }
    }
}
