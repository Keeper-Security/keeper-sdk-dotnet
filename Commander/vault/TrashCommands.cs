using CommandLine;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using KeeperSecurity.Utils;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Cli;
using Google.Protobuf;
using Records;

namespace Commander
{
    internal static class TrashCommandExtensions
    {
        private const int STRING_LENGTH_LIMIT = 100;
        private const int MAX_RECORDS_LIMIT = 990;
        private const long MAX_TIMESTAMP = 4102444800;
        private const long MIN_TIMESTAMP = 0;
        private const int FIELD_LABEL_WIDTH = 21;
        private const string STATUS_SUCCESS = "success";
        private const string WARNING_PATTERN_TOO_LONG = "Warning: Pattern too long, truncated";
        private const int CHUNK_SIZE = 100;
        private const int MIN_UID_LENGTH = 16;
        private const int MAX_UID_LENGTH = 64;
        private const string VAULT_RECORDS_SHARE_UPDATE_ENDPOINT = "vault/records_share_update";
        private const string UID_VALIDATION_PATTERN = "^[A-Za-z0-9_-]+$";
        private const string STATUS_LABEL_SHARE = "Share";
        private const string STATUS_LABEL_RECORD = "Record";
        private const string STATUS_LABEL_FOLDER = "Folder";
        private const string PARSE_ERROR_SENTINEL = "Parse Error";
        private const string TYPE_UNKNOWN = "Unknown";
        private const string TYPE_PASSWORD = "password";
        private const int COLUMN_INDEX_DELETED_AT = 4;
        private const int COLUMN_INDEX_NAME = 2;
        private const int PERMISSION_SORT_OWNER = 1;
        private const int PERMISSION_SORT_CAN_EDIT = 2;
        private const int PERMISSION_SORT_CAN_SHARE = 3;
        private const int PERMISSION_SORT_READ_ONLY = 4;        
        private const int RECORD_VERSION_LEGACY_MIN = 0;
        private const int RECORD_VERSION_LEGACY_MAX = 2;
        private const int RECORD_VERSION_V3 = 3;
        private const int RECORD_VERSION_V4 = 4;
        private const int RECORD_VERSION_V5 = 5;
        private const int RECORD_VERSION_V6 = 6;
        
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
            var titlePattern = string.IsNullOrEmpty(pattern) ? null : CreateWildcardPattern(pattern);

            var tab = new Tabulate(6)
            {
                DumpRowNo = true
            };
            tab.AddHeader(new[] { "Folder UID", "Record UID", "Name", "Record Type", "Deleted At", "Status" });

            var recordTable = BuildRecordTable(deletedRecords, orphanedRecords, pattern, titlePattern);
            var folderTable = BuildFolderTable(sharedFolders, options.Verbose);

            SortTableByDateAndName(recordTable);
            SortTableByDateAndName(folderTable);

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

            try
            {
                await TrashManagement.RestoreTrashRecords(context.Vault, records);
                Console.WriteLine($"Successfully initiated restoration of {records.Count} record(s)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to restore records: {ex.Message}");
            }
        }

        private static List<string> ValidateRecordsParameter(List<string> records)
        {
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
            if (string.IsNullOrWhiteSpace(record))
            {
                Console.WriteLine($"Record at index {index} must not be empty or whitespace");
                return false;
            }

            if (record.Length > STRING_LENGTH_LIMIT)
            {
                Console.WriteLine($"Record '{record}' at index {index} exceeds maximum length ({STRING_LENGTH_LIMIT} characters)");
                return false;
            }

            return true;
        }

        private static string TruncatePattern(string pattern, int maxLength)
        {
            if (pattern.Length > maxLength)
            {
                Console.WriteLine(WARNING_PATTERN_TOO_LONG);
                return pattern.Substring(0, maxLength);
            }
            return pattern;
        }

        private static string NormalizeSearchPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern) || pattern == "*")
            {
                return null;
            }

            pattern = TruncatePattern(pattern, STRING_LENGTH_LIMIT);
            return pattern.ToLower();
        }

        private static Regex CreateWildcardPattern(string pattern, int maxLength = STRING_LENGTH_LIMIT)
        {
            if (string.IsNullOrEmpty(pattern))
                return null;
            
            pattern = TruncatePattern(pattern, maxLength);

            try
            {
                var regexPattern = "^" + Regex.Escape(pattern)
                    .Replace(@"\*", ".*")
                    .Replace(@"\?", ".") + "$";
                return new Regex(regexPattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
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
                
            if (string.Equals(pattern, record.RecordUid, StringComparison.Ordinal))
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

            var status = isShared ? STATUS_LABEL_SHARE : STATUS_LABEL_RECORD;
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
                
                if (recordTitle == PARSE_ERROR_SENTINEL && recordType == TYPE_UNKNOWN)
                    continue;
                
                var dateDeleted = GetDeletedDate(record.DateDeleted);
                
                folderTable.Add(new object[] 
                { 
                    record.FolderUid, record.RecordUid, recordTitle, 
                    recordType, dateDeleted, STATUS_LABEL_FOLDER 
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
                    "", dateDeleted, STATUS_LABEL_FOLDER 
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
                recordCounts.TryGetValue(folderUid, out var count);
                recordCounts[folderUid] = count + 1;
            }
            return recordCounts;
        }

        private static DateTime? GetDeletedDate(long dateDeletedTimestamp)
        {
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
        
        private static (string title, string type) ExtractRecordMetadata(Dictionary<string, object> data)
        {
            if (data == null)
                return (PARSE_ERROR_SENTINEL, TYPE_UNKNOWN);

            var title = data.TryGetValue("title", out var titleObj) ? titleObj?.ToString() ?? "" : "";
            var type = data.TryGetValue("type", out var typeObj) ? typeObj?.ToString() ?? "" : "";

            if (string.IsNullOrEmpty(type))
            {
                if (data.ContainsKey("secret1") || data.ContainsKey("secret2"))
                {
                    type = TYPE_PASSWORD;
                }
                else
                {
                    type = TYPE_UNKNOWN;
                }
            }

            return (title, type);
        }

        private static (string title, string type) ParseRecordData(byte[] dataUnencrypted)
        {
            if (dataUnencrypted == null || dataUnencrypted.Length == 0)
                return ("", "");

            try
            {
                var data = JsonUtils.ParseJson<Dictionary<string, object>>(dataUnencrypted);
                return ExtractRecordMetadata(data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not parse record metadata: {ex.Message}");
                return (PARSE_ERROR_SENTINEL, TYPE_UNKNOWN);
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

        private static void SortTableByDateAndName(List<object[]> table)
        {
            table.Sort((x, y) =>
            {
                var dateComparison = CompareDeletedDates(x[COLUMN_INDEX_DELETED_AT], y[COLUMN_INDEX_DELETED_AT]);
                if (dateComparison != 0) return dateComparison;
                return string.Compare(x[COLUMN_INDEX_NAME]?.ToString(), y[COLUMN_INDEX_NAME]?.ToString(), StringComparison.OrdinalIgnoreCase);
            });
        }

        private static int CompareDeletedDates(object date1, object date2)
        {
            if (date1 == null && date2 == null) return 0;
            if (date1 == null) return 1;
            if (date2 == null) return -1; 

            var dt1 = date1 as DateTime?;
            var dt2 = date2 as DateTime?;

            if (!dt1.HasValue && !dt2.HasValue) return 0;
            if (!dt1.HasValue) return 1;
            if (!dt2.HasValue) return -1;

            return dt2.Value.CompareTo(dt1.Value);
        }

        public static async Task TrashUnshareCommand(this VaultContext context, TrashUnshareOptions options)
        {
            var records = ValidateRecordsParameter(options.Records?.ToList());

            if (records == null || records.Count == 0)
            {
                Console.WriteLine("Records parameter is empty or invalid.");
                return;
            }

            await TrashManagement.EnsureDeletedRecordsLoaded(context.Vault);
            var orphanedRecords = TrashManagement.GetOrphanedRecords();

            if (orphanedRecords == null || orphanedRecords.Count == 0)
            {
                Console.WriteLine("Trash is empty");
                return;
            }

            var recordsToUnshare = FindRecordsToUnshare(records, orphanedRecords);
            if (recordsToUnshare.Count == 0)
            {
                Console.WriteLine("There are no records to unshare");
                return;
            }

            if (!ConfirmUnshare(options.Force, recordsToUnshare.Count))
            {
                return;
            }

            await RemoveSharesFromRecords(context.Vault, recordsToUnshare);
        }

        private static List<string> FindRecordsToUnshare(List<string> recordPatterns, IReadOnlyDictionary<string, DeletedRecord> orphanedRecords)
        {
            var recordsToUnshare = new HashSet<string>();

            foreach (var pattern in recordPatterns)
            {
                if (orphanedRecords.ContainsKey(pattern))
                {
                    recordsToUnshare.Add(pattern);
                }
                else
                {
                    AddMatchingRecords(pattern, orphanedRecords, recordsToUnshare);
                }
            }

            return recordsToUnshare.ToList();
        }

        private static void AddMatchingRecords(string pattern, IReadOnlyDictionary<string, DeletedRecord> orphanedRecords, HashSet<string> recordsToUnshare)
        {
            var titlePattern = CreateWildcardPattern(pattern);
            if (titlePattern == null)
                return;

            foreach (var kvp in orphanedRecords)
            {
                var recordUid = kvp.Key;
                var record = kvp.Value;

                if (recordsToUnshare.Contains(recordUid))
                    continue;

                var (recordTitle, _) = ParseRecordData(record.DataUnencrypted);
                if (!string.IsNullOrEmpty(recordTitle) && titlePattern.IsMatch(recordTitle))
                {
                    recordsToUnshare.Add(recordUid);
                }
            }
        }

        private static void ClearConsoleInputBuffer()
        {
            Console.Out.Flush();
            while (Console.KeyAvailable)
            {
                Console.ReadKey(true);
            }
        }

        private static bool ConfirmOperation(string promptMessage, bool force)
        {
            if (force)
            {
                return true;
            }

            Console.Write($"{promptMessage} (yes/No): ");
            ClearConsoleInputBuffer();
            
            var answer = Console.ReadLine()?.Trim().ToLower();
            return answer == "y" || answer == "yes";
        }

        private static bool ConfirmUnshare(bool force, int recordCount)
        {
            return ConfirmOperation($"Do you want to remove shares from {recordCount} record(s)?", force);
        }

        private static async Task RemoveSharesFromRecords(VaultOnline vault, List<string> recordsToUnshare)
        {
            var recordShares = await GetRecordSharesForUnshare(vault, recordsToUnshare);
            if (recordShares == null || recordShares.Count == 0)
            {
                return;
            }

            var removeShareRequests = BuildRemoveShareRequests(recordShares);
            if (removeShareRequests.Count == 0)
            {
                return;
            }

            await ExecuteShareRemovalRequests(vault, removeShareRequests);
        }

        private static async Task<List<RecordSharePermissions>> GetRecordSharesForUnshare(VaultOnline vault, List<string> recordUids)
        {
            try
            {
                var shares = await vault.GetSharesForRecords(recordUids);
                return shares?.ToList() ?? new List<RecordSharePermissions>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting record shares: {ex.Message}");
                return new List<RecordSharePermissions>();
            }
        }

        private static List<SharedRecord> BuildRemoveShareRequests(List<RecordSharePermissions> recordShares)
        {
            var removeRequests = new List<SharedRecord>();

            foreach (var recordShare in recordShares)
            {
                if (recordShare.UserPermissions == null)
                    continue;

                foreach (var userPermission in recordShare.UserPermissions)
                {
                    if (!userPermission.Owner)
                    {
                        var shareRequest = new SharedRecord
                        {
                            ToUsername = userPermission.Username,
                            RecordUid = ByteString.CopyFrom(recordShare.RecordUid.Base64UrlDecode())
                        };
                        removeRequests.Add(shareRequest);
                    }
                }
            }

            return removeRequests;
        }

        private static async Task ExecuteShareRemovalRequests(VaultOnline vault, List<SharedRecord> removeRequests)
        {
            for (int i = 0; i < removeRequests.Count; i += CHUNK_SIZE)
            {
                var chunk = removeRequests.Skip(i).Take(CHUNK_SIZE).ToList();
                await ProcessShareRemovalChunk(vault, chunk);
            }
        }

        private static async Task ProcessShareRemovalChunk(VaultOnline vault, List<SharedRecord> chunk)
        {
            try
            {
                var updateRequest = new RecordShareUpdateRequest();
                updateRequest.RemoveSharedRecord.AddRange(chunk);

                var response = await vault.Auth.ExecuteAuthRest(VAULT_RECORDS_SHARE_UPDATE_ENDPOINT, updateRequest, typeof(RecordShareUpdateResponse)) as RecordShareUpdateResponse;

                LogShareRemovalErrors(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing shares: {ex.Message}");
            }
        }

        private static void LogShareRemovalErrors(RecordShareUpdateResponse response)
        {
            if (response?.RemoveSharedRecordStatus == null)
                return;

            foreach (var status in response.RemoveSharedRecordStatus)
            {
                if (!string.Equals(status.Status, STATUS_SUCCESS, StringComparison.InvariantCultureIgnoreCase))
                {
                    var recordUid = status.RecordUid.ToArray().Base64UrlEncode();
                    Console.WriteLine($"Remove share \"{status.Username}\" from record UID \"{recordUid}\" error: {status.Message}");
                }
            }
        }

        public static async Task TrashPurgeCommand(this VaultContext context, TrashPurgeOptions options)
        {
            if (!ConfirmOperation("Are you sure you want to permanently delete all records in trash? This action cannot be undone.", options.Force))
            {
                Console.WriteLine("Purge operation cancelled");
                return;
            }

            try
            {
                await PurgeTrashRecords(context.Vault);
                Console.WriteLine("Successfully purged all records from trash");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to purge trash: {ex.Message}");
            }
        }

        private static async Task PurgeTrashRecords(VaultOnline vault)
        {
            var request = new PurgeDeletedRecordsCommand();
            await vault.Auth.ExecuteAuthCommand<PurgeDeletedRecordsCommand>(request);
        }

        public static async Task TrashGetCommand(this VaultContext context, TrashGetOptions options)
        {
            var recordUid = options.Record;
            
            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID parameter is required");
                return;
            }

            if (recordUid.Length < MIN_UID_LENGTH || recordUid.Length > MAX_UID_LENGTH)
            {
                Console.WriteLine("Invalid record UID length");
                return;
            }

            if (!Regex.IsMatch(recordUid, UID_VALIDATION_PATTERN, RegexOptions.None, TimeSpan.FromMilliseconds(100)))
            {
                Console.WriteLine("Invalid record UID format");
                return;
            }

            await TrashManagement.EnsureDeletedRecordsLoaded(context.Vault);

            var (record, isShared) = GetTrashRecord(recordUid);
            if (record == null)
            {
                Console.WriteLine($"{recordUid} is not a valid deleted record UID");
                return;
            }

            var recordData = ParseRecordDataForDisplay(record);
            if (recordData == null)
            {
                Console.WriteLine($"Cannot parse record {recordUid}");
                return;
            }

            DisplayRecordInfo(recordData);

            if (isShared)
            {
                await DisplayShareInfo(context, recordUid);
            }
        }

        private static (DeletedRecord record, bool isShared) GetTrashRecord(string recordUid)
        {
            var deletedRecords = TrashManagement.GetDeletedRecords();
            if (deletedRecords.TryGetValue(recordUid, out var deletedRecord))
            {
                return (deletedRecord, false);
            }

            var orphanedRecords = TrashManagement.GetOrphanedRecords();
            if (orphanedRecords.TryGetValue(recordUid, out var orphanedRecord))
            {
                return (orphanedRecord, true);
            }

            return (null, false);
        }
        private static object ParseRecordDataForDisplay(DeletedRecord record)
        {
            if (record == null || record.RecordKeyUnencrypted == null)
                return null;

            try
            {
                var storageRecord = new DeletedStorageRecord(record);
                
                return record.Version switch
                {
                    >= RECORD_VERSION_LEGACY_MIN and <= RECORD_VERSION_LEGACY_MAX => 
                        storageRecord.LoadV2(record.RecordKeyUnencrypted),
                    
                    RECORD_VERSION_V3 or RECORD_VERSION_V6 => 
                        storageRecord.LoadV3(record.RecordKeyUnencrypted),
                    
                    RECORD_VERSION_V4 => 
                        storageRecord.LoadV4(record.RecordKeyUnencrypted),
                    
                    RECORD_VERSION_V5 => 
                        storageRecord.LoadV5(record.RecordKeyUnencrypted),
                    
                    _ => throw new NotSupportedException($"Unsupported record version: {record.Version}")
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not parse record for display: {ex.Message}");
                return null;
            }
        }

        private class DeletedStorageRecord : IStorageRecord
        {
            private readonly DeletedRecord _record;

            public DeletedStorageRecord(DeletedRecord record)
            {
                _record = record;
            }

            public string Uid => _record.RecordUid;
            public string RecordUid => _record.RecordUid;
            public long Revision => _record.Revision;
            public int Version => _record.Version;
            public string Data => _record.Data;
            public string Udata => null;
            public bool Shared { get; set; }
            public long ClientModifiedTime => _record.ClientModifiedTime;
            public string Extra => null;
        }

        private static (string title, string type) GetRecordTitleAndType(object recordData)
        {
            return recordData switch
            {
                TypedRecord tr => (tr.Title, tr.TypeName),
                PasswordRecord pr => (pr.Title, pr.KeeperRecordType()),
                _ => ("", TYPE_UNKNOWN)
            };
        }

        private static void DisplayRecordInfo(object recordData)
        {
            if (recordData == null)
                return;

            var (title, type) = GetRecordTitleAndType(recordData);
            Console.WriteLine($"{"Title",FIELD_LABEL_WIDTH}: {title}");
            Console.WriteLine($"{"Type",FIELD_LABEL_WIDTH}: {type}");

            if (recordData is TypedRecord typedRecord)
            {
                if (typedRecord.Fields != null && typedRecord.Fields.Count > 0)
                {
                    DisplayRecordFields(typedRecord.Fields);
                }

                if (typedRecord.Custom != null && typedRecord.Custom.Count > 0)
                {
                    DisplayRecordFields(typedRecord.Custom);
                }
            }
            else if (recordData is PasswordRecord passwordRecord)
            {
                DisplayPasswordRecordFields(passwordRecord);
            }
        }

        private static void WriteFormattedField(string label, string value, bool indent = false)
        {
            if (string.IsNullOrEmpty(value))
                return;

            if (indent)
            {
                Console.WriteLine($"{"",FIELD_LABEL_WIDTH}  {value}");
            }
            else
            {
                Console.WriteLine($"{label,FIELD_LABEL_WIDTH}: {value}");
            }
        }

        private static void DisplayRecordFields(List<ITypedField> fields)
        {
            foreach (var field in fields)
            {
                var fieldName = GetFieldName(field);
                var values = field.GetTypedFieldValues().ToArray();

                for (var i = 0; i < Math.Max(values.Length, 1); i++)
                {
                    var value = i < values.Length ? values[i] : "";
                    WriteFormattedField(fieldName, value, indent: i > 0);
                }
            }
        }

        private static void DisplayPasswordRecordFields(PasswordRecord record)
        {
            WriteFormattedField("Login", record.Login);
            WriteFormattedField("Password", record.Password);
            WriteFormattedField("URL", record.Link);
            WriteFormattedField("Notes", record.Notes);
            
            if (record.Custom != null && record.Custom.Count > 0)
            {
                foreach (var custom in record.Custom)
                {
                    var name = string.IsNullOrEmpty(custom.Name) ? "Custom" : custom.Name;
                    WriteFormattedField(name, custom.Value);
                }
            }
        }

        private static string GetFieldName(ITypedField field)
        {
            return !string.IsNullOrEmpty(field.FieldLabel) ? field.FieldLabel : (field.FieldName ?? "");
        }

        private static async Task DisplayShareInfo(VaultContext context, string recordUid)
        {
            try
            {
                var shares = await context.Vault.GetSharesForRecords(new[] { recordUid });
                var recordShares = shares?.FirstOrDefault();

                if (recordShares?.UserPermissions != null && recordShares.UserPermissions.Length > 0)
                {
                    var currentUsername = context.Vault.Auth?.Username ?? "";
                    DisplayUserPermissions(recordShares.UserPermissions, currentUsername);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading share information: {ex.Message}");
            }
        }

        private static void DisplayUserPermissions(UserRecordPermissions[] userPermissions, string currentUsername)
        {
            var sortedPermissions = SortUserPermissions(userPermissions);
            bool isFirst = true;

            foreach (var permission in sortedPermissions)
            {
                if (permission.Owner)
                    continue;

                var flags = GetPermissionFlags(permission);
                var selfFlag = permission.Username == currentUsername ? "self" : "";
                var header = isFirst ? "Direct User Shares" : "";

                Console.WriteLine($"{header,FIELD_LABEL_WIDTH}: {permission.Username,-26} ({flags}) {selfFlag}");
                isFirst = false;
            }
        }

        private static UserRecordPermissions[] SortUserPermissions(UserRecordPermissions[] permissions)
        {
            return permissions.OrderBy(p =>
            {
                if (p.Owner) return PERMISSION_SORT_OWNER;
                if (p.CanEdit) return PERMISSION_SORT_CAN_EDIT;
                if (p.CanShare) return PERMISSION_SORT_CAN_SHARE;
                return PERMISSION_SORT_READ_ONLY;
            }).ThenBy(p => p.Username).ToArray();
        }

        private static string GetPermissionFlags(UserRecordPermissions permission)
        {
            var flags = new List<string>();

            if (permission.CanEdit)
            {
                flags.Add("Can Edit");
            }

            if (permission.CanShare)
            {
                flags.Add(flags.Count > 0 ? "& Can Share" : "Can Share");
            }

            return flags.Count > 0 ? string.Join(" ", flags) : "Read Only";
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

    [Verb("unshare", HelpText = "Remove shares from deleted records")]
    public class TrashUnshareOptions
    {
        [Option('f', "force", Required = false, HelpText = "Do not prompt for confirmation")]
        public bool Force { get; set; }

        [Value(0, MetaName = "records", Required = true, HelpText = "Record UID or search pattern. \"*\" for all records")]
        public IEnumerable<string> Records { get; set; }
    }

    [Verb("get", HelpText = "Get details of a deleted record")]
    public class TrashGetOptions
    {
        [Value(0, MetaName = "record", Required = true, HelpText = "Deleted record UID")]
        public string Record { get; set; }
    }

    [Verb("purge", HelpText = "Permanently delete all records in trash")]
    public class TrashPurgeOptions
    {
        [Option('f', "force", Required = false, HelpText = "Do not prompt for confirmation")]
        public bool Force { get; set; }
    }
}