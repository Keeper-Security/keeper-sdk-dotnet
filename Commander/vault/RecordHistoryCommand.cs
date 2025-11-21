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
            if (string.IsNullOrEmpty(options.Record))
            {
                Console.WriteLine("Error: Record name or UID is required");
                return;
            }

            var recordUid = FindRecordUid(context, options.Record);
            if (string.IsNullOrEmpty(recordUid))
            {
                Console.WriteLine($"Record not found: {options.Record}");
                return;
            }

            var action = string.IsNullOrEmpty(options.Action) ? "list" : options.Action.ToLower();

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
                    Console.WriteLine($"Unknown action: {action}. Valid actions: list, view, diff, restore");
                    break;
            }
        }

        private static string FindRecordUid(VaultContext context, string recordName)
        {
            if (context.Vault.TryGetKeeperRecord(recordName, out _))
            {
                return recordName;
            }

            var matches = context.Vault.KeeperRecords
                .Where(r => string.Equals(r.Title, recordName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matches.Count == 1)
            {
                return matches[0].Uid;
            }

            if (matches.Count > 1)
            {
                Console.WriteLine($"Multiple records found with title '{recordName}'. Please use UID.");
                return null;
            }

            matches = context.Vault.KeeperRecords
                .Where(r => r.Title.IndexOf(recordName, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (matches.Count == 1)
            {
                return matches[0].Uid;
            }

            return null;
        }

        private static async Task ListHistory(VaultContext context, string recordUid)
        {
            var history = await context.Vault.GetRecordHistory(recordUid);
            
            if (history == null || history.Length == 0)
            {
                Console.WriteLine("Record does not have history of edits.");
                return;
            }

            var table = new Tabulate(4)
            {
                DumpRowNo = true,
                LeftPadding = 4
            };

            table.AddHeader("Version", "Modified By", "Time Modified", "Changes");

            for (int i = 0; i < history.Length; i++)
            {
                var rev = history[i];
                var versionLabel = i == 0 ? "Current" : $"V.{i}";
                var modified = rev.KeeperRecord.ClientModified != DateTimeOffset.MinValue
                    ? rev.KeeperRecord.ClientModified.ToString("yyyy-MM-dd HH:mm:ss")
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
            var history = await context.Vault.GetRecordHistory(recordUid);
            
            if (history == null || history.Length == 0)
            {
                Console.WriteLine("Record does not have history of edits.");
                return;
            }

            if (revision < 0 || revision >= history.Length)
            {
                Console.WriteLine($"Invalid revision {revision}: valid revisions 0..{history.Length - 1}");
                return;
            }

            var rev = history[revision];
            var versionLabel = revision == 0 ? "Current" : $"V.{revision}";

            Console.WriteLine();
            Console.WriteLine($"Record Revision {versionLabel}");
            Console.WriteLine(new string('=', 60));
            Console.WriteLine($"Modified By: {rev.Username}");
            
            if (rev.KeeperRecord.ClientModified != DateTimeOffset.MinValue)
            {
                Console.WriteLine($"Modified: {rev.KeeperRecord.ClientModified:yyyy-MM-dd HH:mm:ss}");
            }
            
            if (rev.RecordChange != 0)
            {
                Console.WriteLine($"Changes: {FormatChanges(rev.RecordChange)}");
            }
            
            Console.WriteLine();
            Console.WriteLine("Record Data:");
            Console.WriteLine(new string('-', 60));
            
            var record = rev.KeeperRecord;
            Console.WriteLine($"Title: {record.Title}");

            switch (record)
            {
                case PasswordRecord pr:
                    Console.WriteLine($"Type: Legacy");
                    if (!string.IsNullOrEmpty(pr.Login))
                        Console.WriteLine($"Login: {pr.Login}");
                    if (!string.IsNullOrEmpty(pr.Password))
                        Console.WriteLine($"Password: {pr.Password}");
                    if (!string.IsNullOrEmpty(pr.Link))
                        Console.WriteLine($"URL: {pr.Link}");
                    if (!string.IsNullOrEmpty(pr.Notes))
                        Console.WriteLine($"Notes: {pr.Notes}");
                    break;

                case TypedRecord tr:
                    Console.WriteLine($"Type: {tr.TypeName}");
                    if (!string.IsNullOrEmpty(tr.Notes))
                        Console.WriteLine($"Notes: {tr.Notes}");
                    
                    if (tr.Fields != null)
                    {
                        foreach (var field in tr.Fields)
                        {
                            var label = !string.IsNullOrEmpty(field.FieldLabel) ? field.FieldLabel : field.FieldName;
                            var value = field.ObjectValue?.ToString();
                            if (!string.IsNullOrEmpty(value))
                            {
                                Console.WriteLine($"{label}: {value}");
                            }
                        }
                    }
                    break;
            }
            
            Console.WriteLine();
        }

        private static async Task ShowDiff(VaultContext context, string recordUid, int revision)
        {
            var history = await context.Vault.GetRecordHistory(recordUid);
            
            if (history == null || history.Length == 0)
            {
                Console.WriteLine("Record does not have history of edits.");
                return;
            }

            if (revision < 0 || revision >= history.Length)
            {
                Console.WriteLine($"Invalid revision {revision}: valid revisions 0..{history.Length - 1}");
                return;
            }

            Console.WriteLine($"Showing changes from V.{revision} onwards:");
            Console.WriteLine();

            var table = new Tabulate(2)
            {
                LeftPadding = 4
            };

            table.AddHeader("Version", "Changes");

            for (int i = revision; i < Math.Min(revision + 10, history.Length); i++)
            {
                var rev = history[i];
                var versionLabel = i == 0 ? "Current" : $"V.{i}";
                var changes = rev.RecordChange != 0 ? FormatChanges(rev.RecordChange) : "No changes";

                table.AddRow(versionLabel, changes);
            }

            table.Dump();
        }

        private static async Task RestoreRevision(VaultContext context, string recordUid, int? revision)
        {
            if (!revision.HasValue)
            {
                Console.WriteLine("Error: Revision number is required for restore action");
                return;
            }

            var history = await context.Vault.GetRecordHistory(recordUid);
            
            if (history == null || history.Length == 0)
            {
                Console.WriteLine("Record does not have history of edits.");
                return;
            }

            if (revision.Value < 0 || revision.Value >= history.Length)
            {
                Console.WriteLine($"Invalid revision {revision.Value}: valid revisions 0..{history.Length - 1}");
                return;
            }

            if (revision.Value == 0)
            {
                Console.WriteLine("Cannot restore to current version");
                return;
            }

            Console.Write($"Are you sure you want to restore record to V.{revision.Value}? (yes/no): ");
            var confirm = Console.ReadLine()?.Trim().ToLower();
            
            if (confirm != "yes" && confirm != "y")
            {
                Console.WriteLine("Restore cancelled");
                return;
            }

            var revToRestore = history[revision.Value];
            var recordBytes = recordUid.Base64UrlDecode();

            var request = new Records.RecordsRevertRequest();
            request.Records.Add(new Records.RecordRevert
            {
                RecordUid = ByteString.CopyFrom(recordBytes),
                RevertToRevision = revToRestore.KeeperRecord.Revision
            });

            var response = (Records.RecordsModifyResponse) await context.Vault.Auth.ExecuteAuthRest(
                "vault/records_revert", 
                request, 
                typeof(Records.RecordsModifyResponse)
            );

            if (response.Records != null && response.Records.Count > 0)
            {
                var result = response.Records[0];
                if (result.Status == Records.RecordModifyResult.RsSuccess)
                {
                    Console.WriteLine("Record restored successfully");
                    await context.Vault.SyncDown();
                }
                else
                {
                    Console.WriteLine($"Failed to restore record: {result.Status}");
                }
            }
            else
            {
                Console.WriteLine("Failed to restore record: No response from server");
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

