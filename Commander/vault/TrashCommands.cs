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
        private const int STRING_LENGTH_LIMIT = 100;
        private const int MAX_RECORDS_LIMIT = 10000;
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

            recordTable.Sort((x, y) =>
            {
                var dateComparison = CompareDeletedDates(x[4], y[4]);
                if (dateComparison != 0) return dateComparison;
                return string.Compare(x[2]?.ToString(), y[2]?.ToString(), StringComparison.OrdinalIgnoreCase);
            });

            folderTable.Sort((x, y) =>
            {
                var dateComparison = CompareDeletedDates(x[4], y[4]);
                if (dateComparison != 0) return dateComparison;
                return string.Compare(x[2]?.ToString(), y[2]?.ToString(), StringComparison.OrdinalIgnoreCase);
            });

            var allRecords = recordTable.Concat(folderTable).ToList();

            foreach (var row in allRecords)
            {
                tab.AddRow(row);
            }

            tab.Dump();
        }

        public static async Task TrashRestoreCommand(this VaultContext context, TrashRestoreOptions options)
        {
            var records = ValidateRecordsParameter(options.Records?.ToList());

            if (records == null || records.Count == 0)
            {
                Console.WriteLine("Records parameter is empty or invalid.");
                return;
            }

            await TrashManagement.RestoreTrashRecords(context.Vault, records);
        }

        private static List<string> ValidateRecordsParameter(List<string> records)
        {
            if (records == null || records.Count == 0)
            {
                return null;
            }

            if (records.Count > MAX_RECORDS_LIMIT)
            {
                Console.WriteLine($"Too many records specified (max: {MAX_RECORDS_LIMIT})");
                return null;
            }

            var validatedRecords = new List<string>();
            for (int i = 0; i < records.Count; i++)
            {
                if (IsValidRecord(records[i], i + 1))
                {
                    validatedRecords.Add(records[i]);
                }
            }

            return validatedRecords.Count > 0 ? validatedRecords : null;
        }

        private static bool IsValidRecord(string record, int index)
        {
            if (string.IsNullOrEmpty(record))
            {
                Console.WriteLine($"Record {index} must not be empty");
                return false;
            }

            if (record.Length > STRING_LENGTH_LIMIT)
            {
                Console.WriteLine($"Record {index} has invalid length (max: {STRING_LENGTH_LIMIT})");
                return false;
            }

            return true;
        }

        private static string NormalizeSearchPattern(string pattern)
        {
            const int PATTERN_LENGTH_LIMIT = 100;

            if (string.IsNullOrEmpty(pattern) || pattern == "*")
            {
                return null;
            }

            if (pattern.Length > PATTERN_LENGTH_LIMIT)
            {
                Console.WriteLine("Warning: Pattern too long, truncated");
                pattern = pattern.Substring(0, PATTERN_LENGTH_LIMIT);
            }

            return pattern?.ToLower();
        }

        private static Regex CreateTitlePattern(string pattern)
        {
            const int PATTERN_LENGTH_LIMIT = 100;
            
            if (string.IsNullOrEmpty(pattern))
                return null;
            
            if (pattern.Length > PATTERN_LENGTH_LIMIT)
            {
                Console.WriteLine("Warning: Pattern too long, truncated");
                pattern = pattern.Substring(0, PATTERN_LENGTH_LIMIT);
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

        private static List<object[]> BuildRecordTable(IReadOnlyDictionary<string, DeletedRecord> deletedRecords, 
            IReadOnlyDictionary<string, DeletedRecord> orphanedRecords, string pattern, Regex titlePattern)
        {
            var recordTable = new List<object[]>();
            AddRecordsToTable(deletedRecords, false, pattern, titlePattern, recordTable);            
            AddRecordsToTable(orphanedRecords, true, pattern, titlePattern, recordTable);
            return recordTable;
        }

        private static void AddRecordsToTable(IReadOnlyDictionary<string, DeletedRecord> records, bool isShared, 
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
                
            if (titlePattern != null)
            {
                var (recordTitle, _) = ParseRecordData(record.DataUnencrypted);
                return titlePattern.IsMatch(recordTitle);
            }
            return false;
        }

        private static object[] CreateRecordRow(DeletedRecord record, bool isShared)
        {
            var (recordTitle, recordType) = ParseRecordData(record.DataUnencrypted);

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
            IReadOnlyDictionary<string, DeletedRecord> records)
        {
            var folderTable = new List<object[]>();
            
            foreach (var record in records.Values)
            {
                var (recordTitle, recordType) = ParseRecordData(record.DataUnencrypted);
                
                if (recordTitle == "Parse Error" && recordType == "Unknown")
                    continue;
                
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
            IReadOnlyDictionary<string, DeletedRecord> records)
        {
            var folderTable = new List<object[]>();
            var recordCounts = CountRecordsPerFolder(records);
            
            foreach (var folder in folders.Values)
            {
                var dateDeleted = GetDeletedDate(folder.DateDeleted);
                if (!recordCounts.TryGetValue(folder.FolderUidString, out var recordCount))
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

        private static Dictionary<string, int> CountRecordsPerFolder(IReadOnlyDictionary<string, DeletedRecord> records)
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
            const long MAX_TIMESTAMP = 4102444800; 
            const long MIN_TIMESTAMP = 0;
            
            if (dateDeletedTimestamp <= MIN_TIMESTAMP)
                return null;
            try
            {
                var timestampSeconds = dateDeletedTimestamp / 1000;
                if (timestampSeconds < MIN_TIMESTAMP || timestampSeconds > MAX_TIMESTAMP)
                    return null;
                return DateTimeOffset.FromUnixTimeSeconds(timestampSeconds).DateTime;
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        private static (string title, string type) ParseRecordData(byte[] dataUnencrypted)
        {
            if (dataUnencrypted == null)
                return ("", "");

            try
            {
                var recordTypeData = JsonUtils.ParseJson<KeeperRecord>(dataUnencrypted);
                if (recordTypeData != null)
                {
                    return (recordTypeData.Title ?? "", recordTypeData.KeeperRecordType());
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error parsing KeeperRecord: {ex.Message}");
                try
                {
                    var recordData = JsonUtils.ParseJson<RecordData>(dataUnencrypted);
                    if (recordData != null)
                    {
                        return (recordData.Title ?? "", "Unknown");
                    }
                }
                catch (Exception ex2)
                {
                    System.Diagnostics.Debug.WriteLine($"Error parsing RecordData: {ex2.Message}");
                }
            }
            
            return ("Parse Error", "Unknown");
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
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error parsing folder data: {ex.Message}");
                return folderUid;
            }
        }

        private static int CompareDeletedDates(object date1, object date2)
        {
            if (date1 == null && date2 == null) return 0;
            if (date1 == null) return 1;
            if (date2 == null) return -1; 

            DateTime? dt1 = date1 as DateTime?;
            DateTime? dt2 = date2 as DateTime?;

            if (dt1 == null && dt2 == null) return 0;
            if (dt1 == null) return 1;
            if (dt2 == null) return -1;

            return dt2.Value.CompareTo(dt1.Value);
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

    [Verb("restore", HelpText = "Restore deleted records from trash")]
    public class TrashRestoreOptions
    {
        [Option('f', "force", Required = false, HelpText = "Do not prompt for confirmation")]
        public bool Force { get; set; }

        [Value(0, MetaName = "records", Required = true, HelpText = "Record UID or search pattern")]
        public IEnumerable<string> Records { get; set; }
    }
}