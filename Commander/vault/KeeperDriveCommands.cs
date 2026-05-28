using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Folder.V3.Remove;
using Google.Protobuf;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    internal static class KeeperDriveCommandExtensions
    {
        internal static void AppendKeeperDriveCommands(this VaultContext context, CliCommands cli)
        {
            cli.Commands.Add("kd-list", new SimpleCommand
            {
                Order = 43,
                Description = "List Keeper Drive folders and records (summary)",
                Action = _ => context.KdListCommand(),
            });

            cli.Commands.Add("kd-folders", new SimpleCommand
            {
                Order = 43,
                Description = "List Keeper Drive folders",
                Action = _ => context.KdFoldersCommand(),
            });

            cli.Commands.Add("kd-records", new SimpleCommand
            {
                Order = 43,
                Description = "List Keeper Drive records",
                Action = _ => context.KdRecordsCommand(),
            });

            cli.Commands.Add("kd-diag", new SimpleCommand
            {
                Order = 43,
                Description = "Diagnostic: inspect raw Keeper Drive storage tables",
                Action = _ => context.KdDiagCommand(),
            });

            cli.Commands.Add("kd-rm", new ParseableCommand<KdRemoveOptions>
            {
                Order = 44,
                Description = "Remove Keeper Drive record(s) (owner-trash, folder-trash, or unlink)",
                Action = context.KdRemoveCommand,
            });
            cli.Aliases.Add("nsf-rm", "kd-rm");

            cli.Commands.Add("kd-rndir", new ParseableCommand<KdRndirOptions>
            {
                Order = 44,
                Description = "Rename or recolor a Keeper Drive folder",
                Action = context.KdRndirCommand,
            });
            cli.Aliases.Add("nsf-rndir", "kd-rndir");

            cli.Commands.Add("kd-rmdir", new ParseableCommand<KdRmdirOptions>
            {
                Order = 44,
                Description = "Remove Keeper Drive folder(s)",
                Action = context.KdRmdirCommand,
            });
            cli.Aliases.Add("nsf-rmdir", "kd-rmdir");

            cli.Commands.Add("kd-ln", new ParseableCommand<KdLnOptions>
            {
                Order = 44,
                Description = "Link a Keeper Drive record into a folder",
                Action = context.KdLnCommand,
            });
            cli.Aliases.Add("nsf-ln", "kd-ln");

            cli.Commands.Add("kd-transfer-record", new ParseableCommand<KdTransferRecordOptions>
            {
                Order = 44,
                Description = "Transfer Keeper Drive record ownership to another user",
                Action = context.KdTransferRecordCommand,
            });
            cli.Aliases.Add("nsf-transfer-record", "kd-transfer-record");
        }

        private static Task KdListCommand(this VaultContext context)
        {
            var vault = context.Vault;
            var folderCount = vault.KeeperNSFFolderCount;
            var recordCount = vault.KeeperNSFRecordCount;

            Console.WriteLine();
            Console.WriteLine("=== Keeper Drive Summary ===");
            Console.WriteLine($"  Folders: {folderCount}");
            Console.WriteLine($"  Records: {recordCount}");
            Console.WriteLine();

            if (folderCount > 0)
            {
                Console.WriteLine("--- Folders ---");
                DumpKeeperDriveFolders(vault);
            }

            if (recordCount > 0)
            {
                Console.WriteLine("--- Records ---");
                DumpKeeperNSFRecords(vault);
            }

            if (folderCount == 0 && recordCount == 0)
            {
                Console.WriteLine("No Keeper Drive data found. Run sync-down first.");
            }

            return Task.CompletedTask;
        }

        private static Task KdFoldersCommand(this VaultContext context)
        {
            var folders = context.Vault.KeeperNSFFolderNodes?.ToList();
            if (folders == null || folders.Count == 0)
            {
                Console.WriteLine("No Keeper Drive folders found.");
                return Task.CompletedTask;
            }

            DumpKeeperDriveFolders(context.Vault);
            return Task.CompletedTask;
        }

        private static Task KdRecordsCommand(this VaultContext context)
        {
            var records = context.Vault.KeeperNSFRecordEntries?.ToList();
            if (records == null || records.Count == 0)
            {
                Console.WriteLine("No Keeper Drive records found.");
                return Task.CompletedTask;
            }

            DumpKeeperNSFRecords(context.Vault);
            return Task.CompletedTask;
        }

        private static Task KdDiagCommand(this VaultContext context)
        {
            var vault = context.Vault;
            var storage = vault.Storage;

            var kdFolders = storage.KdFolders.GetAll().ToList();
            var kdFolderKeys = storage.KdFolderKeys.GetAllLinks().ToList();
            var kdRecords = storage.KdRecords.GetAll().ToList();
            var kdRecordKeys = storage.KdRecordKeys.GetAllLinks().ToList();
            var kdFolderRecords = storage.KdFolderRecords.GetAllLinks().ToList();

            Console.WriteLine();
            Console.WriteLine("=== KD Storage Diagnostic ===");
            Console.WriteLine($"  KdFolders (SQLite):       {kdFolders.Count}");
            Console.WriteLine($"  KdFolderKeys (SQLite):    {kdFolderKeys.Count}");
            Console.WriteLine($"  KdRecords (SQLite):       {kdRecords.Count}");
            Console.WriteLine($"  KdRecordKeys (SQLite):    {kdRecordKeys.Count}");
            Console.WriteLine($"  KdFolderRecords (SQLite): {kdFolderRecords.Count}");
            Console.WriteLine();
            Console.WriteLine($"  In-memory KD Folders:     {vault.KeeperNSFFolderCount}");
            Console.WriteLine($"  In-memory KD Records:     {vault.KeeperNSFRecordCount}");
            Console.WriteLine();

            if (kdFolders.Count > 0)
            {
                Console.WriteLine("--- Raw KD Folders ---");
                foreach (var folder in kdFolders)
                {
                    Console.WriteLine(
                        $"  UID={folder.FolderUid}  Parent={folder.ParentUid}  KeyType={folder.KeyType}  FolderType={folder.FolderType}");
                }
            }

            if (kdRecords.Count > 0)
            {
                Console.WriteLine("--- Raw KD Records ---");
                foreach (var record in kdRecords)
                {
                    Console.WriteLine(
                        $"  UID={record.RecordUid}  Rev={record.Revision}  Ver={record.Version}  FileSize={record.FileSize}");
                }
            }

            return Task.CompletedTask;
        }

        private static void DumpKeeperDriveFolders(VaultOnline vault)
        {
            var tab = new Tabulate(5)
            {
                DumpRowNo = true,
            };
            tab.AddHeader("Folder UID", "Name", "Parent UID", "Subfolders", "Records");

            foreach (var folder in vault.KeeperNSFFolderNodes ?? Enumerable.Empty<FolderNode>())
            {
                var parentUid = string.IsNullOrEmpty(folder.ParentUid) ? "(root)" : folder.ParentUid;
                tab.AddRow(folder.FolderUid, folder.Name, parentUid, folder.Subfolders.Count, folder.Records.Count);
            }

            tab.Dump();
        }

        private static void DumpKeeperNSFRecords(VaultOnline vault)
        {
            var tab = new Tabulate(7)
            {
                DumpRowNo = true,
            };
            tab.AddHeader("Record UID", "Revision", "Version", "Shared", "File Size", "Thumbnail Size", "Data");

            foreach (var record in vault.KeeperNSFRecordEntries ?? Enumerable.Empty<KeeperNSFRecord>())
            {
                var dataPreview = TruncateDataPreview(record.DecryptedData, 80);
                tab.AddRow(
                    record.RecordUid,
                    record.Revision,
                    record.Version,
                    record.Shared,
                    record.FileSize,
                    record.ThumbnailSize,
                    dataPreview);
            }

            tab.Dump();
        }

        private static string TruncateDataPreview(string data, int maxLength)
        {
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }

            return data.Length <= maxLength ? data : data.Substring(0, maxLength);
        }

        public static async Task KdRemoveCommand(this VaultContext context, KdRemoveOptions options)
        {
            var records = options.Records?.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
            if (records == null || records.Count == 0)
            {
                Console.WriteLine("At least one record UID or title is required.");
                return;
            }

            if (records.Count > 500)
            {
                Console.WriteLine("Maximum 500 records per invocation.");
                return;
            }

            if (!TryParseRecordRemoveOperation(options.Operation, out var operation))
            {
                Console.WriteLine("Invalid operation. Use owner-trash, folder-trash, or unlink.");
                return;
            }

            var folderContext = options.Folder ?? context.CurrentFolder;
            if (operation == KeeperNSFRecordRemoveOperation.Unlink && string.IsNullOrWhiteSpace(folderContext))
            {
                Console.WriteLine("Folder context is required for unlink. Use --folder or cd into a Keeper Drive folder.");
                return;
            }

            var vault = context.Vault;
            var removals = new List<KeeperNSFRecordRemoval>();

            foreach (var identifier in records)
            {
                if (!vault.TryResolveKeeperNSFRecord(identifier, out var kdRecord))
                {
                    Console.WriteLine($"Keeper Drive record \"{identifier}\" was not found. Run sync-down or kd-list first.");
                    return;
                }

                if (!vault.TryResolveKeeperNSFRecordRemovalFolder(
                        kdRecord.RecordUid, folderContext, operation, out var folderUid))
                {
                    Console.WriteLine(
                        $"No folder context for record \"{identifier}\". Use --folder or --operation owner-trash.");
                    return;
                }

                removals.Add(new KeeperNSFRecordRemoval
                {
                    RecordUid = kdRecord.RecordUid,
                    FolderUid = folderUid,
                    Operation = operation,
                });
            }

            await PreviewAndConfirmRecordRemoval(vault, removals, options.Operation, options.Force, options.DryRun);
        }

        public static async Task KdRndirCommand(this VaultContext context, KdRndirOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.Folder))
            {
                Console.WriteLine("Enter the path or UID of an existing folder.");
                return;
            }

            if (options.Name != null && string.IsNullOrWhiteSpace(options.Name))
            {
                Console.WriteLine("Folder name cannot be empty.");
                return;
            }

            if (options.Name == null && options.Color == null)
            {
                Console.WriteLine("Specify --name and/or --color to update the folder.");
                return;
            }

            var vault = context.Vault;
            if (!vault.TryResolveKeeperNSFFolder(options.Folder, out var folderNode))
            {
                Console.WriteLine($"Keeper Drive folder \"{options.Folder}\" was not found. Run sync-down or kd-list first.");
                return;
            }

            try
            {
                var result = await vault.UpdateKeeperNSFFolder(folderNode.FolderUid, options.Name, options.Color);
                VaultOnline.ValidateFolderModifyResult(result);
                await vault.SyncDown(false);
                Console.WriteLine("Keeper Drive folder updated.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to update folder: {ex.Message}");
            }
        }

        public static async Task KdRmdirCommand(this VaultContext context, KdRmdirOptions options)
        {
            var folders = options.Folders?.Where(f => !string.IsNullOrWhiteSpace(f)).ToList();
            if (folders == null || folders.Count == 0)
            {
                Console.WriteLine("Enter the name or UID of at least one folder.");
                return;
            }

            if (folders.Count > 100)
            {
                Console.WriteLine("Maximum 100 folders per invocation.");
                return;
            }

            if (!TryParseFolderRemoveOperation(options.Operation, out var operation))
            {
                Console.WriteLine("Invalid operation. Use folder-trash or delete-permanent.");
                return;
            }

            var vault = context.Vault;
            var removals = new List<KeeperNSFFolderRemoval>();

            foreach (var identifier in folders)
            {
                if (!vault.TryResolveKeeperNSFFolder(identifier, out var folderNode))
                {
                    Console.WriteLine($"Keeper Drive folder \"{identifier}\" was not found. Run sync-down or kd-list first.");
                    return;
                }

                removals.Add(new KeeperNSFFolderRemoval
                {
                    FolderUid = folderNode.FolderUid,
                    Operation = operation,
                });
            }

            if (operation == KeeperNSFFolderRemoveOperation.DeletePermanent && !options.Force && !options.DryRun)
            {
                Console.WriteLine();
                Console.WriteLine("*** WARNING ***");
                Console.WriteLine("  delete-permanent is IRREVERSIBLE.");
                Console.WriteLine("  All sub-folders and records inside will be permanently destroyed.");
            }

            await PreviewAndConfirmFolderRemoval(vault, removals, options.Operation, options.Force, options.DryRun);
        }

        public static async Task KdLnCommand(this VaultContext context, KdLnOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.Record) || string.IsNullOrWhiteSpace(options.Folder))
            {
                Console.WriteLine("Usage: kd-ln RECORD FOLDER");
                return;
            }

            var vault = context.Vault;
            if (!vault.TryResolveKeeperNSFRecord(options.Record, out _))
            {
                Console.WriteLine($"Keeper Drive record \"{options.Record}\" was not found. Run sync-down or kd-list first.");
                return;
            }

            if (!vault.TryResolveKeeperNSFFolder(options.Folder, out _))
            {
                Console.WriteLine($"Keeper Drive folder \"{options.Folder}\" was not found. Run sync-down or kd-list first.");
                return;
            }

            try
            {
                var result = await vault.LinkKeeperNSFRecordToFolder(options.Record, options.Folder);
                VaultOnline.ValidateFolderRecordUpdateResult(result);
                await vault.SyncDown(false);
                Console.WriteLine("Keeper Drive record linked into folder.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to link record: {ex.Message}");
            }
        }

        public static async Task KdTransferRecordCommand(this VaultContext context, KdTransferRecordOptions options)
        {
            var args = options.Args;
            if (args == null || args.Length < 2)
            {
                Console.WriteLine("Usage: kd-transfer-record RECORD [RECORD...] NEW_OWNER_EMAIL");
                return;
            }

            var newOwnerEmail = args[args.Length - 1]?.Trim();
            var recordArgs = args.Take(args.Length - 1).ToList();

            if (recordArgs.Count == 0 || string.IsNullOrWhiteSpace(newOwnerEmail))
            {
                Console.WriteLine("Record UID(s) and new owner email are required.");
                return;
            }

            if (newOwnerEmail.IndexOf('@') < 0)
            {
                Console.WriteLine($"New owner must be an email address: \"{newOwnerEmail}\"");
                return;
            }

            var vault = context.Vault;
            var resolvedRecords = new List<string>();

            foreach (var identifier in recordArgs)
            {
                if (!vault.TryResolveKeeperNSFRecord(identifier, out var kdRecord))
                {
                    Console.WriteLine($"Keeper Drive record \"{identifier}\" was not found. Run sync-down or kd-list first.");
                    return;
                }

                resolvedRecords.Add(kdRecord.RecordUid);
            }

            if (!options.Force)
            {
                Console.WriteLine();
                Console.WriteLine("*** WARNING ***");
                Console.WriteLine("After ownership is transferred you will no longer have access to the record(s).");
                Console.WriteLine("Make sure the new owner is correct before continuing.");
                Console.WriteLine();
            }

            if (!ConfirmOperation(
                    $"Transfer {resolvedRecords.Count} record(s) to {newOwnerEmail}",
                    options.Force))
            {
                Console.WriteLine("Transfer cancelled.");
                return;
            }

            try
            {
                var results = await vault.TransferKeeperNSFRecordOwnership(resolvedRecords, newOwnerEmail);
                VaultOnline.ValidateKeeperNSFTransferResults(results);

                foreach (var result in results)
                {
                    Console.WriteLine($"Record '{result.RecordUid}' ownership transferred to {result.Username}.");
                    Console.WriteLine("You will no longer have access to this record.");
                }

                await vault.SyncDown(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to transfer record ownership: {ex.Message}");
            }
        }

        private static async Task PreviewAndConfirmRecordRemoval(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordRemoval> removals,
            string operationLabel,
            bool force,
            bool dryRun)
        {
            Console.WriteLine();
            Console.WriteLine("=== Keeper Drive Remove Preview ===");
            var previewResult = await vault.RemoveKeeperNSFRecords(removals, dryRun: true);
            WriteRemoveImpact(previewResult.PreviewResponse);

            try
            {
                VaultOnline.ValidateRemoveResponse(previewResult.PreviewResponse, isConfirm: false);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }

            if (dryRun)
            {
                Console.WriteLine();
                Console.WriteLine("Dry run: no records were removed.");
                return;
            }

            var targets = string.Join(", ", removals.Select(r => r.RecordUid));
            if (!ConfirmOperation($"Remove Keeper Drive record(s) ({operationLabel}): {targets}", force))
            {
                Console.WriteLine("Removal cancelled.");
                return;
            }

            if (previewResult.PreviewResponse?.ConfirmationToken == null
                || previewResult.PreviewResponse.ConfirmationToken.IsEmpty)
            {
                Console.WriteLine("Preview did not return a confirmation token.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("Removing records...");
            var confirmResult = await vault.RemoveKeeperNSFRecords(removals, dryRun: false);
            if (!confirmResult.Confirmed)
            {
                Console.WriteLine("Record removal was not confirmed by the server.");
                return;
            }

            await vault.SyncDown(false);
            Console.WriteLine();
            Console.WriteLine("Keeper Drive record removal completed.");
        }

        private static async Task PreviewAndConfirmFolderRemoval(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderRemoval> removals,
            string operationLabel,
            bool force,
            bool dryRun)
        {
            Console.WriteLine();
            Console.WriteLine("=== Keeper Drive Folder Remove Preview ===");
            var previewResult = await vault.RemoveKeeperNSFFolders(removals, dryRun: true);
            WriteRemoveImpact(previewResult.PreviewResponse, "Folder");

            try
            {
                VaultOnline.ValidateRemoveResponse(previewResult.PreviewResponse, isConfirm: false);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }

            if (dryRun)
            {
                Console.WriteLine();
                Console.WriteLine("Dry run: no folders were removed.");
                return;
            }

            var targets = string.Join(", ", removals.Select(r => r.FolderUid));
            if (!ConfirmOperation($"Remove Keeper Drive folder(s) ({operationLabel}): {targets}", force))
            {
                Console.WriteLine("Removal cancelled.");
                return;
            }

            if (previewResult.PreviewResponse?.ConfirmationToken == null
                || previewResult.PreviewResponse.ConfirmationToken.IsEmpty)
            {
                Console.WriteLine("Preview did not return a confirmation token.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("Removing folders...");
            var confirmResult = await vault.RemoveKeeperNSFFolders(removals, dryRun: false);
            if (!confirmResult.Confirmed)
            {
                Console.WriteLine("Folder removal was not confirmed by the server.");
                return;
            }

            await vault.SyncDown(false);
            Console.WriteLine();
            Console.WriteLine("Keeper Drive folder removal completed.");
        }

        private static void WriteRemoveImpact(RemoveResponse response, string itemLabel = "Record")
        {
            if (response == null)
            {
                return;
            }

            if (!string.IsNullOrEmpty(response.ErrorMessage))
            {
                Console.WriteLine($"Error: {response.ErrorMessage}");
            }

            foreach (var result in response.Results)
            {
                var itemUid = result.ItemUid.Length > 0
                    ? result.ItemUid.ToByteArray().Base64UrlEncode()
                    : "(unknown)";

                var folderUid = result.FolderUid.Length > 0
                    ? result.FolderUid.ToByteArray().Base64UrlEncode()
                    : string.Empty;

                Console.WriteLine();
                Console.WriteLine($"{itemLabel}: {itemUid}");
                if (!string.IsNullOrEmpty(folderUid))
                {
                    Console.WriteLine($"  Folder context: {folderUid}");
                }

                Console.WriteLine($"  Status: {result.Status}");

                if (result.Error != null && !string.IsNullOrEmpty(result.Error.Message))
                {
                    Console.WriteLine($"  Error: {result.Error.Message}");
                }

                if (result.Impact != null)
                {
                    var impact = result.Impact;
                    Console.WriteLine("  Impact:");
                    Console.WriteLine($"    Folders:          {impact.FoldersCount}");
                    Console.WriteLine($"    Records:          {impact.RecordsCount}");
                    Console.WriteLine($"    Affected users:   {impact.AffectedUsersCount}");
                    Console.WriteLine($"    Affected teams:   {impact.AffectedTeamsCount}");
                    if (impact.RecordInfo != null && impact.RecordInfo.Count > 0)
                    {
                        Console.WriteLine($"    Other locations:  {impact.RecordInfo[0].LocationsCount}");
                    }

                    foreach (var warning in impact.Warnings)
                    {
                        Console.WriteLine($"    Warning: {warning}");
                    }
                }
            }
        }

        private static bool TryParseRecordRemoveOperation(string operation, out KeeperNSFRecordRemoveOperation parsed)
        {
            parsed = KeeperNSFRecordRemoveOperation.OwnerTrash;
            if (string.IsNullOrWhiteSpace(operation))
            {
                return true;
            }

            switch (operation.Trim().ToLowerInvariant())
            {
                case "owner-trash":
                    parsed = KeeperNSFRecordRemoveOperation.OwnerTrash;
                    return true;
                case "folder-trash":
                    parsed = KeeperNSFRecordRemoveOperation.FolderTrash;
                    return true;
                case "unlink":
                    parsed = KeeperNSFRecordRemoveOperation.Unlink;
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryParseFolderRemoveOperation(string operation, out KeeperNSFFolderRemoveOperation parsed)
        {
            parsed = KeeperNSFFolderRemoveOperation.FolderTrash;
            if (string.IsNullOrWhiteSpace(operation))
            {
                return true;
            }

            switch (operation.Trim().ToLowerInvariant())
            {
                case "folder-trash":
                    parsed = KeeperNSFFolderRemoveOperation.FolderTrash;
                    return true;
                case "delete-permanent":
                    parsed = KeeperNSFFolderRemoveOperation.DeletePermanent;
                    return true;
                default:
                    return false;
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

            var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
            return answer == "y" || answer == "yes";
        }
    }

    class KdRemoveOptions
    {
        [Value(0, MetaName = "records", Required = true, HelpText = "Record UID(s) or title(s) to remove")]
        public IEnumerable<string> Records { get; set; }

        [Option("folder", Required = false, HelpText = "Folder UID or name that provides context")]
        public string Folder { get; set; }

        [Option('o', "operation", Required = false, Default = "owner-trash", HelpText = "owner-trash, folder-trash, or unlink")]
        public string Operation { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation after preview")]
        public bool Force { get; set; }

        [Option("dry-run", Required = false, HelpText = "Preview only; do not remove records")]
        public bool DryRun { get; set; }
    }

    class KdRndirOptions
    {
        [Value(0, MetaName = "folder", Required = true, HelpText = "Folder UID or name")]
        public string Folder { get; set; }

        [Option('n', "name", Required = false, HelpText = "New folder name")]
        public string Name { get; set; }

        [Option("color", Required = false, HelpText = "Folder color (none, red, orange, yellow, green, blue, gray, grey)")]
        public string Color { get; set; }
    }

    class KdRmdirOptions
    {
        [Value(0, MetaName = "folders", Required = true, HelpText = "Folder UID(s) or name(s) to remove")]
        public IEnumerable<string> Folders { get; set; }

        [Option('o', "operation", Required = false, Default = "folder-trash", HelpText = "folder-trash or delete-permanent")]
        public string Operation { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation after preview")]
        public bool Force { get; set; }

        [Option("dry-run", Required = false, HelpText = "Preview only; do not remove folders")]
        public bool DryRun { get; set; }
    }

    class KdLnOptions
    {
        [Value(0, MetaName = "record", Required = true, HelpText = "Record UID or title")]
        public string Record { get; set; }

        [Value(1, MetaName = "folder", Required = true, HelpText = "Folder UID, name, or / for root")]
        public string Folder { get; set; }
    }

    class KdTransferRecordOptions
    {
        [Value(0, MetaName = "args", Required = true, HelpText = "Record UID(s) and new owner email")]
        public string[] Args { get; set; }

        [Option('f', "force", Required = false, HelpText = "Do not prompt for confirmation")]
        public bool Force { get; set; }
    }
}
