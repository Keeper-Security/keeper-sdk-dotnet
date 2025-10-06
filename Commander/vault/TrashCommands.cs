using CommandLine;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using KeeperSecurity.Utils;
using KeeperSecurity.Commands;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Cli;

namespace Commander
{
    internal static class TrashCommandExtensions
    {
        public static async Task TrashListCommand(this VaultContext context, TrashListOptions options)
        {
            await TrashManagement.EnsureDeletedRecordsLoaded(context.Vault);

            var deletedRecords = TrashManagement.GetDeletedRecords();
            var orphanedRecords = TrashManagement.GetOrphanedRecords();
            var sharedFolders = TrashManagement.GetSharedFolders();

            if (TrashManagement.IsTrashEmpty())
            {
                Console.WriteLine("Trash is empty");
                return;
            }

            var pattern = NormalizeSearchPattern(options.Pattern);
            var titlePattern = string.IsNullOrEmpty(pattern) ? null : CreateTitlePattern(pattern);

            var tab = new Tabulate(6)
            {
                DumpRowNo = true
            };
            tab.AddHeader(new[] { "Folder UID", "Record UID", "Name", "Record Type", "Deleted At", "Status" });

            var recordTable = BuildRecordTable(deletedRecords, orphanedRecords, pattern, titlePattern);
            var folderTable = BuildFolderTable(sharedFolders, options.Verbose);

            var allRecords = recordTable.Concat(folderTable).ToList();
            allRecords.Sort((x, y) => string.Compare(x[2]?.ToString(), y[2]?.ToString(), StringComparison.OrdinalIgnoreCase));

            foreach (var row in allRecords)
            {
                tab.AddRow(row);
            }

            tab.Dump();
        }

        private static string NormalizeSearchPattern(string pattern)
        {
            if (pattern == "*")
            {
                return null;
            }
            return pattern?.ToLower();
        }

        private static Regex CreateTitlePattern(string pattern)
        {
            const int STRING_LENGTH_LIMIT = 100;
            
            if (string.IsNullOrEmpty(pattern))
                return null;
                
            if (pattern.Length > STRING_LENGTH_LIMIT)
            {
                Console.WriteLine("Warning: Pattern too long, truncated");
                pattern = pattern.Substring(0, STRING_LENGTH_LIMIT);
            }

            try
            {
                var regexPattern = "^" + Regex.Escape(pattern)
                    .Replace(@"\*", ".*")
                    .Replace(@"\?", ".") + "$";
                    
                return new Regex(regexPattern, RegexOptions.IgnoreCase);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"Warning: Invalid pattern: {ex.Message}");
                return null;
            }
        }

        private static List<object[]> BuildRecordTable(Dictionary<string, DeletedRecord> deletedRecords, 
            Dictionary<string, DeletedRecord> orphanedRecords, string pattern, Regex titlePattern)
        {
            var recordTable = new List<object[]>();
            AddRecordsToTable(deletedRecords, false, pattern, titlePattern, recordTable);            
            AddRecordsToTable(orphanedRecords, true, pattern, titlePattern, recordTable);
            return recordTable;
        }

        private static void AddRecordsToTable(Dictionary<string, DeletedRecord> records, bool isShared, 
            string pattern, Regex titlePattern, List<object[]> recordTable)
        {
            foreach (var record in records.Values)
            {
                if (ShouldIncludeRecord(record, pattern, titlePattern))
                {
                    var row = CreateRecordRow(record, isShared);
                    recordTable.Add(row);
                }
            }
        }

        private static bool ShouldIncludeRecord(DeletedRecord record, string pattern, Regex titlePattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return true;
                
            if (pattern == record.RecordUid)
                return true;
                
            if (titlePattern != null && record.DataUnencrypted != null)
            {
                try
                {
                    var recordTypeData = JsonUtils.ParseJson<KeeperRecord>(record.DataUnencrypted);
                    var recordTitle = recordTypeData.Title ?? "";
                    return titlePattern.IsMatch(recordTitle);
                }
                catch (Exception)
                {
                    
                    return false;
                }
            }
            return false;
        }

        private static object[] CreateRecordRow(DeletedRecord record, bool isShared)
        {
            var recordTitle = "";
            var recordType = "";
            
            if (record.DataUnencrypted != null)
            {
                try
                {
                    var recordTypeData = JsonUtils.ParseJson<KeeperRecord>(record.DataUnencrypted);
                    recordTitle = recordTypeData?.Title ?? "";
                    recordType = recordTypeData.KeeperRecordType();
                }
                catch (Exception)
                {
                    try
                    {
                        var recordData = JsonUtils.ParseJson<RecordData>(record.DataUnencrypted);
                        recordTitle = recordData?.Title ?? "";
                    }
                    catch (Exception)
                    {
                        recordTitle = "Parse Error";
                        recordType = "Unknown";
                    }
                }
            }

            var status = isShared ? "Share" : "Record";
            var dateDeleted = isShared ? null : GetDeletedDate(record.DateDeleted);

            return new object[] { "", record.RecordUid, recordTitle, recordType, dateDeleted, status };
        }

        private static List<object[]> BuildFolderTable(TrashManagement.DeletedSharedFolderCacheData sharedFolders, bool verbose)
        {
            if (sharedFolders?.Folders == null || sharedFolders?.Records == null)
                return new List<object[]>();
                
            return verbose 
                ? BuildVerboseFolderTable(sharedFolders.Folders, sharedFolders.Records)
                : BuildSummaryFolderTable(sharedFolders.Folders, sharedFolders.Records);
        }

        private static List<object[]> BuildVerboseFolderTable(Dictionary<string, DeletedSharedFolder> folders, 
            Dictionary<string, DeletedRecord> records)
        {
            var folderTable = new List<object[]>();
            
            foreach (var record in records.Values)
            {
                var recordTitle = "";
                var recordType = "";
                
                if (record.DataUnencrypted != null)
                {
                    try
                    {
                        var recordTypeData = JsonUtils.ParseJson<KeeperRecord>(record.DataUnencrypted);
                        if (recordTypeData != null)
                        {
                            recordTitle = recordTypeData.Title ?? "";
                            recordType = recordTypeData.KeeperRecordType();
                        }
                        else
                        {
                            continue;
                        }
                    }
                    catch (Exception)
                    {
                        try
                        {
                            var recordData = JsonUtils.ParseJson<RecordData>(record.DataUnencrypted);
                            if (recordData != null)
                            {
                                recordTitle = recordData.Title ?? "";
                            }
                            else
                            {
                                continue;
                            }
                        }
                        catch (Exception)
                        {
                            continue;
                        }
                    }
                }
                
                var dateDeleted = GetDeletedDate(record.DateDeleted);
                
                folderTable.Add(new object[] 
                { 
                    record.FolderUid, record.RecordUid, recordTitle, 
                    recordType, dateDeleted, "Folder" 
                });
            }
            
            return folderTable;
        }

        private static List<object[]> BuildSummaryFolderTable(Dictionary<string, DeletedSharedFolder> folders, 
            Dictionary<string, DeletedRecord> records)
        {
            var folderTable = new List<object[]>();
            var recordCounts = CountRecordsPerFolder(records);
            
            foreach (var folder in folders.Values)
            {
                var dateDeleted = GetDeletedDate(folder.DateDeleted);
                if (recordCounts.TryGetValue(folder.FolderUidString, out var recordCount))
                {
                    recordCount = 0;
                }
                
                var recordCountText = recordCount > 0 ? $"{recordCount} record(s)" : null;
                var folderName = GetFolderName(folder, folder.FolderUidString);
                
                folderTable.Add(new object[] 
                { 
                    folder.FolderUidString, recordCountText, folderName, 
                    "", dateDeleted, "Folder" 
                });
            }
            
            return folderTable;
        }

        private static Dictionary<string, int> CountRecordsPerFolder(Dictionary<string, DeletedRecord> records)
        {
            var recordCounts = new Dictionary<string, int>();
            foreach (var record in records.Values)
            {
                var folderUid = record.FolderUid;
                if (recordCounts.TryGetValue(folderUid, out var count))
                {
                    recordCounts[folderUid] = count + 1;
                }
                else
                {
                    recordCounts[folderUid] = 1;
                }
            }
            return recordCounts;
        }

        private static DateTime? GetDeletedDate(long dateDeletedTimestamp)
        {
            if (dateDeletedTimestamp <= 0)
                return null;
            try
            {
                var timestampSeconds = dateDeletedTimestamp / 1000;
                if (timestampSeconds < 0 || timestampSeconds > 4102444800)
                    return null;
                return DateTimeOffset.FromUnixTimeSeconds(timestampSeconds).DateTime;
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        private static string GetFolderName(DeletedSharedFolder folder, string folderUid)
        {
            try
            {
                if (folder.DataUnEncrypted != null)
                {
                    var folderData = JsonUtils.ParseJson<FolderData>(folder.DataUnEncrypted);
                    return folderData?.name ?? folderUid;
                }
                return folderUid;
            }
            catch (Exception)
            {
                return folderUid;
            }
        }

        
    }

    [Verb("list", HelpText = "List deleted records in trash")]
    public class TrashListOptions
    {
        [Option('v', "verbose", Required = false, HelpText = "Show detailed information")]
        public bool Verbose { get; set; }

        [Option("pattern", Required = false, HelpText = "Filter by pattern")]
        public string Pattern { get; set; }
    }
}