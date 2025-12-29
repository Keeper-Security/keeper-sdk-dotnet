using Cli;
using CommandLine;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;

namespace Commander
{
    internal static class RecordHistoryCommandExtensions
    {
        public static async Task RecordHistoryCommand(this VaultContext context, RecordHistoryCommandOptions options)
        {
            if (context?.Vault == null)
            {
                throw new ArgumentNullException(nameof(context), "Context and vault cannot be null");
            }

            if (string.IsNullOrEmpty(options.Record))
            {
                Console.WriteLine("Error: Record name or UID is required");
                return;
            }

            var recordUid = FindRecordUid(context, options.Record);
            if (string.IsNullOrEmpty(recordUid))
            {
                Console.WriteLine($"Error: Record not found: {options.Record}");
                return;
            }

            var action = string.IsNullOrEmpty(options.Action) ? "list" : options.Action.ToLower();

            try
            {
                switch (action)
                {
                    case "list":
                        await ListHistory(context, recordUid);
                        break;

                    case "view":
                        await ViewRevision(context, recordUid, options.Revision ?? 0);
                        break;

                    case "diff":
                        await ShowDiff(context, recordUid, options.Revision ?? 0);
                        break;

                    case "restore":
                        await RestoreRevision(context, recordUid, options.Revision);
                        break;

                default:
                    Console.WriteLine($"Error: Unknown action: {action}. Valid actions: list, view, diff, restore");
                    break;
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Error: Access denied. {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        private static string FindRecordUid(VaultContext context, string recordName)
        {
            if (context.Vault.TryGetKeeperRecord(recordName, out _))
            {
                return recordName;
            }

            // Search once, prioritizing exact matches
            var allMatches = context.Vault.KeeperRecords
                .Where(r => r.Title?.IndexOf(recordName, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            var exactMatches = allMatches
                .Where(r => string.Equals(r.Title, recordName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (exactMatches.Count == 1)
                return exactMatches[0].Uid;

            if (exactMatches.Count > 1)
            {
                Console.WriteLine($"Error: Multiple records found with title '{recordName}'. Please use UID.");
                return null;
            }

            if (allMatches.Count == 1)
                return allMatches[0].Uid;

            return null;
        }

        private static bool ValidateHistory(RecordHistory[] history, out string errorMessage)
        {
            if (history == null || history.Length == 0)
            {
                errorMessage = "Record does not have history of edits.";
                return false;
            }
            errorMessage = null;
            return true;
        }

        private static async Task<RecordHistory[]> GetAndValidateHistory(VaultContext context, string recordUid)
        {
            var history = await context.Vault.GetRecordHistory(recordUid);
            
            if (!ValidateHistory(history, out var error))
            {
                Console.WriteLine(error);
                return null;
            }

            return history;
        }

        private static async Task ListHistory(VaultContext context, string recordUid)
        {
            var history = await GetAndValidateHistory(context, recordUid);
            if (history == null) return;

            var table = new Tabulate(4)
            {
                DumpRowNo = true,
                LeftPadding = 4
            };

            table.AddHeader("Version", "Modified By", "Time Modified", "Changes");

            for (int i = 0; i < history.Length; i++)
            {
                var rev = history[i];
                var versionLabel = i == 0 ? "Current" : $"V.{history.Length - i}";
                var modified = rev.KeeperRecord.ClientModified != DateTimeOffset.MinValue
                    ? rev.KeeperRecord.ClientModified.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    : "";
                
                var changes = rev.RecordChange != 0 ? FormatChanges(rev.RecordChange) : "";

                table.AddRow(versionLabel, rev.Username ?? "", modified, changes);
            }

            table.Dump();
        }

        private static string FormatChanges(RecordChange changes)
        {
            var parts = new System.Collections.Generic.List<string>();
            
            if ((changes & RecordChange.RecordType) != 0) parts.Add("Type");
            if ((changes & RecordChange.Title) != 0) parts.Add("Title");
            if ((changes & RecordChange.Login) != 0) parts.Add("Login");
            if ((changes & RecordChange.Password) != 0) parts.Add("Password");
            if ((changes & RecordChange.Url) != 0) parts.Add("URL");
            if ((changes & RecordChange.Notes) != 0) parts.Add("Notes");
            if ((changes & RecordChange.Totp) != 0) parts.Add("TOTP");
            if ((changes & RecordChange.Hostname) != 0) parts.Add("Host");
            if ((changes & RecordChange.Address) != 0) parts.Add("Address");
            if ((changes & RecordChange.PaymentCard) != 0) parts.Add("Card");
            if ((changes & RecordChange.CustomField) != 0) parts.Add("Custom");
            if ((changes & RecordChange.File) != 0) parts.Add("Files");

            return string.Join(", ", parts);
        }

        private static async Task ViewRevision(VaultContext context, string recordUid, int revision)
        {
            var history = await GetAndValidateHistory(context, recordUid);
            if (history == null) return;

            // Convert version number to array index
            // revision 0 = Current (index 0)
            // revision 1 = V.1 oldest (index history.Length - 1)
            // revision 2 = V.2 (index history.Length - 2), etc.
            int arrayIndex = revision == 0 ? 0 : history.Length - revision;

            if (revision < 0 || revision > history.Length - 1)
            {
                Console.WriteLine($"Error: Invalid revision {revision}: valid revisions 0..{history.Length - 1}");
                return;
            }

            var rev = history[arrayIndex];
            var versionLabel = revision == 0 ? "V.0" : $"V.{revision}";

            Console.WriteLine();
            Console.WriteLine($"Record Revision {versionLabel}");
            Console.WriteLine();

            var record = rev.KeeperRecord;

            switch (record)
            {
                case PasswordRecord pr:
                    WriteField("title", record.Title);
                    if (!string.IsNullOrEmpty(pr.Login))
                        WriteField("login", pr.Login);
                    if (!string.IsNullOrEmpty(pr.Password))
                        WriteField("password", pr.Password);
                    if (!string.IsNullOrEmpty(pr.Link))
                        WriteField("url", pr.Link);
                    if (!string.IsNullOrEmpty(pr.Notes))
                        WriteField("notes", pr.Notes);
                    break;

                case TypedRecord tr:
                    WriteField("title", record.Title);
                    WriteField("type", tr.TypeName);
                    
                    if (tr.Fields != null)
                    {
                        foreach (var field in tr.Fields)
                        {
                            var label = !string.IsNullOrEmpty(field.FieldLabel) ? field.FieldLabel : field.FieldName;
                            var value = field.ObjectValue?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                WriteField(label.ToLower(), value);
                            }
                        }
                    }
                    
                    if (!string.IsNullOrEmpty(tr.Notes))
                        WriteField("notes", tr.Notes);
                    break;
            }

            if (rev.KeeperRecord.ClientModified != DateTimeOffset.MinValue)
            {
                var modifiedTime = rev.KeeperRecord.ClientModified.ToLocalTime();
                WriteField("Modified", modifiedTime.ToString("yyyy-MM-dd HH:mm:ss"));
            }
            
            Console.WriteLine();
        }

        private static void WriteField(string label, string value)
        {
            const int labelWidth = 10;
            var formattedLabel = $"({label})".PadLeft(labelWidth);
            Console.WriteLine($"{formattedLabel}  {value}");
        }

        private static async Task ShowDiff(VaultContext context, string recordUid, int revision)
        {
            var history = await GetAndValidateHistory(context, recordUid);
            if (history == null) return;

            // Convert version number to array index
            int startIndex = revision == 0 ? 0 : history.Length - revision;

            if (revision < 0 || revision > history.Length - 1)
            {
                Console.WriteLine($"Error: Invalid revision {revision}: valid revisions 0..{history.Length - 1}");
                return;
            }

            Console.WriteLine($"Version    Field       New Value                                              Old Value");
            Console.WriteLine();
            Console.WriteLine($"---------  ----------  -----------------------------------------------------  ---------------------------------------------------");

            for (int i = startIndex; i < history.Length; i++)
            {
                var current = history[i];
                var previous = i < history.Length - 1 ? history[i + 1] : null;
                var versionLabel = i == 0 ? "Current" : $"V.{history.Length - i}";

                var diffs = GetRecordDifferences(current.KeeperRecord, previous?.KeeperRecord);
                
                if (diffs.Count > 0)
                {
                    bool firstField = true;
                    foreach (var diff in diffs)
                    {
                        var version = firstField ? versionLabel : "";
                        var newValue = TruncateValue(diff.NewValue, 53);
                        var oldValue = TruncateValue(diff.OldValue, 51);
                        
                        Console.WriteLine($"{version,-9}  {diff.Field,-10}  {newValue,-53}  {oldValue}");
                        firstField = false;
                    }
                }
            }

            Console.WriteLine();
        }

        private static System.Collections.Generic.List<FieldDiff> GetRecordDifferences(KeeperRecord current, KeeperRecord previous)
        {
            var diffs = new System.Collections.Generic.List<FieldDiff>();

            if (current is PasswordRecord currentPr)
            {
                var previousPr = previous as PasswordRecord;

                if (previousPr == null)
                {
                    // First version - show all fields
                    if (!string.IsNullOrEmpty(current.Title))
                        diffs.Add(new FieldDiff { Field = "(title)", NewValue = current.Title, OldValue = "" });
                    if (!string.IsNullOrEmpty(currentPr.Login))
                        diffs.Add(new FieldDiff { Field = "(login)", NewValue = currentPr.Login, OldValue = "" });
                    if (!string.IsNullOrEmpty(currentPr.Password))
                        diffs.Add(new FieldDiff { Field = "(password)", NewValue = currentPr.Password, OldValue = "" });
                    if (!string.IsNullOrEmpty(currentPr.Link))
                        diffs.Add(new FieldDiff { Field = "(url)", NewValue = currentPr.Link, OldValue = "" });
                    if (!string.IsNullOrEmpty(currentPr.Notes))
                        diffs.Add(new FieldDiff { Field = "(notes)", NewValue = currentPr.Notes, OldValue = "" });
                }
                else
                {
                    // Compare with previous version
                    if (current.Title != previousPr.Title)
                        diffs.Add(new FieldDiff { Field = "(title)", NewValue = current.Title ?? "", OldValue = previousPr.Title ?? "" });
                    if (currentPr.Login != previousPr.Login)
                        diffs.Add(new FieldDiff { Field = "(login)", NewValue = currentPr.Login ?? "", OldValue = previousPr.Login ?? "" });
                    if (currentPr.Password != previousPr.Password)
                        diffs.Add(new FieldDiff { Field = "(password)", NewValue = currentPr.Password ?? "", OldValue = previousPr.Password ?? "" });
                    if (currentPr.Link != previousPr.Link)
                        diffs.Add(new FieldDiff { Field = "(url)", NewValue = currentPr.Link ?? "", OldValue = previousPr.Link ?? "" });
                    if (currentPr.Notes != previousPr.Notes)
                        diffs.Add(new FieldDiff { Field = "(notes)", NewValue = currentPr.Notes ?? "", OldValue = previousPr.Notes ?? "" });
                }
            }
            else if (current is TypedRecord currentTr)
            {
                var previousTr = previous as TypedRecord;

                if (previousTr == null)
                {
                    // First version - show all fields
                    if (!string.IsNullOrEmpty(current.Title))
                        diffs.Add(new FieldDiff { Field = "(title)", NewValue = current.Title, OldValue = "" });
                    if (currentTr.Fields != null)
                    {
                        foreach (var field in currentTr.Fields)
                        {
                            var value = field.ObjectValue?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                var label = !string.IsNullOrEmpty(field.FieldLabel) ? field.FieldLabel : field.FieldName;
                                diffs.Add(new FieldDiff { Field = $"({label.ToLower()})", NewValue = value, OldValue = "" });
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(currentTr.Notes))
                        diffs.Add(new FieldDiff { Field = "(notes)", NewValue = currentTr.Notes, OldValue = "" });
                }
                else
                {
                    // Compare with previous version
                    if (current.Title != previousTr.Title)
                        diffs.Add(new FieldDiff { Field = "(title)", NewValue = current.Title ?? "", OldValue = previousTr.Title ?? "" });

                    // Compare typed record fields
                    if (currentTr.Fields != null)
                    {
                        foreach (var field in currentTr.Fields)
                        {
                            var label = !string.IsNullOrEmpty(field.FieldLabel) ? field.FieldLabel : field.FieldName;
                            var currentValue = field.ObjectValue?.ToString() ?? "";
                            
                            var previousField = previousTr.Fields?.FirstOrDefault(f => f.FieldName == field.FieldName);
                            var previousValue = previousField?.ObjectValue?.ToString() ?? "";

                            if (currentValue != previousValue)
                            {
                                diffs.Add(new FieldDiff { Field = $"({label.ToLower()})", NewValue = currentValue, OldValue = previousValue });
                            }
                        }
                    }

                    if (currentTr.Notes != previousTr.Notes)
                        diffs.Add(new FieldDiff { Field = "(notes)", NewValue = currentTr.Notes ?? "", OldValue = previousTr.Notes ?? "" });
                }
            }

            return diffs;
        }

        private static string TruncateValue(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            
            if (value.Length <= maxLength)
                return value;
            
            return value.Substring(0, maxLength - 3) + "...";
        }

        private class FieldDiff
        {
            public string Field { get; set; }
            public string NewValue { get; set; }
            public string OldValue { get; set; }
        }

        private static async Task RestoreRevision(VaultContext context, string recordUid, int? revision)
        {
            if (!revision.HasValue)
            {
                Console.WriteLine("Error: Revision number is required for restore action");
                return;
            }

            var history = await GetAndValidateHistory(context, recordUid);
            if (history == null) return;

            if (revision.Value < 1 || revision.Value > history.Length - 1)
            {
                Console.WriteLine($"Error: Invalid revision to restore: Revisions: 1-{history.Length - 1}");
                return;
            }

            // Convert version number to array index
            int arrayIndex = history.Length - revision.Value;

            if (arrayIndex < 0 || arrayIndex >= history.Length)
            {
                Console.WriteLine($"Error: Invalid revision {revision.Value}: valid revisions 1-{history.Length - 1}");
                return;
            }

            var revToRestore = history[arrayIndex];
            var recordBytes = recordUid.Base64UrlDecode();

            var request = new Records.RecordsRevertRequest();
            request.Records.Add(new Records.RecordRevert
            {
                RecordUid = ByteString.CopyFrom(recordBytes),
                RevertToRevision = revToRestore.Revision
            });

            var responseObj = await context.Vault.Auth.ExecuteAuthRest(
                "vault/records_revert",
                request,
                typeof(Records.RecordsModifyResponse)
            );

            if (responseObj is not Records.RecordsModifyResponse response)
            {
                Console.WriteLine("Error: Invalid response from server");
                return;
            }

            if (response.Records != null && response.Records.Count > 0)
            {
                var result = response.Records[0];
                if (result.Status == Records.RecordModifyResult.RsSuccess)
                {
                    var record = revToRestore.KeeperRecord;
                    await context.Vault.SyncDown();
                    Console.WriteLine($"Record \"{record.Title}\" revision V.{revision.Value} has been restored");
                }
                else
                {
                    var message = !string.IsNullOrEmpty(result.Message) ? result.Message : result.Status.ToString();
                    Console.WriteLine($"Error: Failed to restore record \"{recordUid}\": {message}");
                }
            }
            else
            {
                Console.WriteLine("Error: Failed to restore record: No response from server");
            }
        }
    }

    class RecordHistoryCommandOptions
    {
        [Value(0, Required = true, MetaName = "record", HelpText = "Record UID or name")]
        public string Record { get; set; }

        [Value(1, Required = false, MetaName = "action", HelpText = "Action: list (default), view, diff, restore")]
        public string Action { get; set; }

        [Option('r', "revision", Required = false, HelpText = "Revision number for view/diff/restore actions")]
        public int? Revision { get; set; }
    }
}

