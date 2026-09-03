using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Commander
{
    internal static class NsfRecordCommandExtensions
    {
        public static async Task NsfRecordAddCommand(this VaultContext context, NsfRecordAddOptions options)
        {
            Dictionary<string, object> fieldDict = null;
            if ((options.Fields != null && options.Fields.Any()) || options.GeneratePassword)
            {
                fieldDict = NsfHelpers.ParseFieldSpecs(options.Fields, options.GeneratePassword, out _);
            }

            try
            {
                string folderUid = options.FolderUid;
                if (!string.IsNullOrWhiteSpace(folderUid)
                    && !context.Vault.TryGetKeeperNSFFolder(folderUid, out _)
                    && context.Vault.TryResolveKeeperNSFFolder(folderUid, out var folderNode)
                    && folderNode != null)
                {
                    folderUid = folderNode.FolderUid;
                }

                var recordUid = await context.Vault.CreateKeeperNSFRecord(
                    options.Title,
                    options.RecordType ?? "login",
                    folderUid,
                    options.Notes,
                    fieldDict);
                Console.WriteLine($"Record '{options.Title}' created successfully (UID: {recordUid}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating record: {ex.Message}");
            }
        }

        public static async Task NsfRecordUpdateCommand(this VaultContext context, NsfRecordUpdateOptions options)
        {
            var hasTitle = options.Title != null;
            var hasType = options.RecordType != null;
            var hasNotes = options.Notes != null;
            var hasFields = options.Fields != null && options.Fields.Any();

            if (!hasTitle && !hasType && !hasNotes && !hasFields && !options.GeneratePassword)
            {
                Console.WriteLine("Error: At least one of --title, --type, --notes, --generate, or field values must be specified.");
                return;
            }

            Dictionary<string, object> fieldDict = null;
            if (hasFields || options.GeneratePassword)
            {
                fieldDict = NsfHelpers.ParseFieldSpecs(options.Fields, options.GeneratePassword, out var parsedCount);
                if (parsedCount == 0 && !options.GeneratePassword)
                {
                    Console.WriteLine("Error: No valid field values were parsed. Use key=value (e.g. login=a12).");
                    return;
                }
            }

            try
            {
                await context.Vault.UpdateKeeperNSFRecord(
                    options.RecordUid,
                    hasTitle ? options.Title : null,
                    hasType ? options.RecordType : null,
                    hasNotes ? options.Notes : null,
                    fieldDict);
                Console.WriteLine($"Record '{options.RecordUid}' updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating record: {ex.Message}");
            }
        }

        public static async Task NsfShareRecordCommand(this VaultContext context, NsfShareRecordOptions options)
        {
            var vault = context.Vault;
            if (!vault.TryGetKeeperNSFRecord(options.RecordUid, out _))
            {
                Console.WriteLine($"Error: NSF record '{options.RecordUid}' not found.");
                return;
            }

            var action = options.Action ?? "grant";
            foreach (var user in options.Email ?? Array.Empty<string>())
            {
                try
                {
                    if (string.Equals(action, "grant", StringComparison.OrdinalIgnoreCase))
                    {
                        await vault.ShareKeeperNSFRecord(options.RecordUid, user, options.Role ?? "viewer");
                        Console.WriteLine($"Granted '{options.Role ?? "viewer"}' access to '{user}' on record '{options.RecordUid}'.");
                    }
                    else
                    {
                        await vault.UnshareKeeperNSFRecord(options.RecordUid, user);
                        Console.WriteLine($"Revoked access for '{user}' from record '{options.RecordUid}'.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error {action}ing access for '{user}': {ex.Message}");
                }
            }
        }

        public static async Task NsfRecordPermissionCommand(this VaultContext context, NsfRecordPermissionOptions options)
        {
            var vault = context.Vault;
            var action = options.Action;
            if (string.Equals(action, "grant", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(options.Role))
            {
                Console.WriteLine("Error: --role is required for grant action.");
                return;
            }

            var folderUid = options.FolderUid;
            if (!string.IsNullOrEmpty(folderUid) && !vault.TryGetKeeperNSFFolder(folderUid, out _))
            {
                var match = vault.KeeperNSFFolderNodes
                    .FirstOrDefault(f => f.Name != null && string.Equals(f.Name, folderUid, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    folderUid = match.FolderUid;
                }
            }

            var folderDisplay = string.IsNullOrEmpty(folderUid) ? "root" : folderUid;
            var roleLabel = !string.IsNullOrEmpty(options.Role) ? $"'{options.Role}'" : "all";
            var scopeLabel = options.Recursive ? "recursively" : "only";
            Console.WriteLine();
            Console.WriteLine($"Request to {action.ToUpper()} {roleLabel} permission(s) in '{folderDisplay}' folder {scopeLabel}");

            KeeperNSFPermissionResult permResult;
            try
            {
                permResult = await vault.UpdateKeeperNSFRecordPermissions(
                    folderUid, action, options.Role, options.Recursive, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            var hasChanges = permResult.Grants.Count > 0 || permResult.Revokes.Count > 0 || permResult.Denies.Count > 0;
            NsfHelpers.DisplayPermissionChanges(permResult, true);

            if (!hasChanges && permResult.Skipped.Count == 0)
            {
                Console.WriteLine("No permission changes are needed.");
                return;
            }

            if (options.DryRun)
            {
                Console.WriteLine();
                Console.WriteLine("[Dry-run mode - no changes were made]");
                Console.WriteLine($"Summary: {permResult.Grants.Count + permResult.Revokes.Count + permResult.Denies.Count} planned, {permResult.Skipped.Count} skipped");
                return;
            }

            if (!hasChanges)
            {
                Console.WriteLine();
                Console.WriteLine($"Summary: 0 changes, {permResult.Skipped.Count} skipped");
                return;
            }

            if (!options.Force)
            {
                if (!await NsfHelpers.ConfirmAsync("Are you sure you want to apply the above changes? (yes/No) "))
                {
                    Console.WriteLine("Update operation cancelled");
                    return;
                }
            }

            try
            {
                permResult = await vault.UpdateKeeperNSFRecordPermissions(
                    folderUid, action, options.Role, options.Recursive, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error executing changes: {ex.Message}");
                return;
            }

            NsfHelpers.DisplayPermissionChanges(permResult, false);
            var successCount = permResult.Grants.Count(g => g.Success) + permResult.Revokes.Count(r => r.Success) + permResult.Denies.Count(d => d.Success);
            var failCount = permResult.Grants.Count(g => !g.Success) + permResult.Revokes.Count(r => !r.Success) + permResult.Denies.Count(d => !d.Success);
            Console.WriteLine();
            Console.WriteLine($"Summary: {successCount} succeeded, {failCount} failed, {permResult.Skipped.Count} skipped");
        }

        public static Task NsfShortcutListCommand(this VaultContext context, NsfShortcutListOptions options)
        {
            var vault = context.Vault;
            string recordUid = null;
            string folderUid = null;

            if (!string.IsNullOrEmpty(options.Target))
            {
                if (vault.TryGetKeeperNSFRecord(options.Target, out _))
                {
                    recordUid = options.Target;
                }
                else if (vault.TryGetKeeperNSFFolder(options.Target, out _))
                {
                    folderUid = options.Target;
                }
                else
                {
                    var recordMatch = vault.KeeperNSFRecordEntries
                        .FirstOrDefault(r => r.Title != null && string.Equals(r.Title, options.Target, StringComparison.OrdinalIgnoreCase));
                    if (recordMatch != null)
                    {
                        recordUid = recordMatch.RecordUid;
                    }
                    else
                    {
                        var folderMatch = vault.KeeperNSFFolderNodes
                            .FirstOrDefault(f => f.Name != null && string.Equals(f.Name, options.Target, StringComparison.OrdinalIgnoreCase));
                        if (folderMatch != null)
                        {
                            folderUid = folderMatch.FolderUid;
                        }
                        else
                        {
                            Console.WriteLine($"Error: Target '{options.Target}' not found as record UID, title, folder UID, or folder name.");
                            return Task.CompletedTask;
                        }
                    }
                }
            }

            IList<KeeperNSFShortcutEntry> entries;
            try
            {
                entries = vault.GetKeeperNSFShortcuts(recordUid, folderUid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return Task.CompletedTask;
            }

            if (entries.Count == 0)
            {
                Console.WriteLine("No shortcut records found.");
                return Task.CompletedTask;
            }

            var format = options.Format ?? "table";
            if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            {
                var jsonItems = entries.Select(e => new Dictionary<string, object>
                {
                    ["record_uid"] = e.RecordUid,
                    ["record_title"] = e.Title,
                    ["folders"] = e.Folders.Select(f => new Dictionary<string, object>
                    {
                        ["folder_uid"] = f.FolderUid,
                        ["name"] = f.Name
                    }).ToList()
                }).ToList();

                var jsonText = Json.Serialize(jsonItems);
                if (!string.IsNullOrEmpty(options.Output))
                {
                    File.WriteAllText(options.Output, jsonText, Encoding.UTF8);
                    Console.WriteLine($"JSON output written to '{options.Output}' ({entries.Count} shortcuts).");
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
                    new[] { "RecordUid", "Title", "FolderCount", "FolderUids", "FolderNames" }
                };
                foreach (var e in entries)
                {
                    rows.Add(new[]
                    {
                        e.RecordUid,
                        e.Title ?? "",
                        e.Folders.Count.ToString(),
                        string.Join("; ", e.Folders.Select(f => f.FolderUid)),
                        string.Join("; ", e.Folders.Select(f => f.Name))
                    });
                }

                if (!string.IsNullOrEmpty(options.Output))
                {
                    NsfHelpers.WriteCsv(options.Output, rows);
                    Console.WriteLine($"CSV output written to '{options.Output}' ({entries.Count} shortcuts).");
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

            Console.WriteLine();
            Console.WriteLine($"  Shortcut Records ({entries.Count}):");
            Console.WriteLine();
            foreach (var e in entries)
            {
                Console.WriteLine($"  {e.RecordUid}  {e.Title}  [{e.Folders.Count} folders]");
                foreach (var f in e.Folders)
                {
                    Console.WriteLine($"    - {f.Name} ({f.FolderUid})");
                }
            }

            Console.WriteLine();
            return Task.CompletedTask;
        }

        public static async Task NsfShortcutKeepCommand(this VaultContext context, NsfShortcutKeepOptions options)
        {
            var vault = context.Vault;
            var recordUid = options.RecordUid;
            var folderUid = options.FolderUid;

            if (!vault.TryGetKeeperNSFRecord(recordUid, out _))
            {
                var match = vault.KeeperNSFRecordEntries
                    .FirstOrDefault(r => r.Title != null && string.Equals(r.Title, recordUid, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    recordUid = match.RecordUid;
                }
                else
                {
                    Console.WriteLine($"Error: Record '{options.RecordUid}' not found.");
                    return;
                }
            }

            if (!vault.TryGetKeeperNSFFolder(folderUid, out _))
            {
                var match = vault.KeeperNSFFolderNodes
                    .FirstOrDefault(f => f.Name != null && string.Equals(f.Name, folderUid, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    folderUid = match.FolderUid;
                }
                else
                {
                    Console.WriteLine($"Error: Folder '{options.FolderUid}' not found.");
                    return;
                }
            }

            var shortcuts = vault.GetKeeperNSFShortcuts(recordUid, null);
            if (shortcuts.Count == 0)
            {
                Console.WriteLine($"Record '{recordUid}' does not appear in multiple folders.");
                return;
            }

            var entry = shortcuts[0];
            var keepFolder = entry.Folders.FirstOrDefault(f => f.FolderUid == folderUid);
            if (keepFolder == null)
            {
                Console.WriteLine($"Error: Record '{recordUid}' is not in folder '{folderUid}'.");
                return;
            }

            var removeFolders = entry.Folders.Where(f => f.FolderUid != folderUid).ToList();
            if (!options.Force)
            {
                Console.WriteLine();
                Console.WriteLine($"  Will remove record '{entry.Title}' ({recordUid}) from:");
                foreach (var rf in removeFolders)
                {
                    Console.WriteLine($"    - {rf.Name} ({rf.FolderUid})");
                }

                Console.WriteLine($"  Keeping in: {keepFolder.Name} ({keepFolder.FolderUid})");
                Console.WriteLine();
                if (!await NsfHelpers.ConfirmAsync(
                        $"Are you sure you want to keep the record only in '{keepFolder.Name}' and remove it from the other folder(s) above? (yes/No) "))
                {
                    Console.WriteLine("Shortcut-keep operation cancelled");
                    return;
                }
            }

            KeeperNSFShortcutKeepResult result;
            try
            {
                result = await vault.KeepKeeperNSFRecordInFolder(recordUid, folderUid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            foreach (var removal in result.Removals)
            {
                if (removal.Success)
                {
                    Console.WriteLine($"  [OK] Removed from '{removal.FolderName}' ({removal.FolderUid})");
                }
                else
                {
                    Console.WriteLine($"  [FAIL] '{removal.FolderName}' ({removal.FolderUid}): {removal.Message}");
                }
            }

            var successCount = result.Removals.Count(r => r.Success);
            var failCount = result.Removals.Count(r => !r.Success);
            Console.WriteLine();
            Console.WriteLine($"Record kept in '{result.KeptFolderName}'. {successCount} removed, {failCount} failed.");
        }

        public static async Task NsfRmCommand(this VaultContext context, NsfRmOptions options)
        {
            var vault = context.Vault;
            var records = options.Record?.ToList() ?? new List<string>();
            if (records.Count == 0)
            {
                Console.WriteLine("At least one record UID or title is required.");
                return;
            }

            string resolvedFolderUid = null;
            if (!string.IsNullOrEmpty(options.Folder))
            {
                if (!vault.TryResolveKeeperNSFFolder(options.Folder, out var folderNode))
                {
                    Console.WriteLine($"Keeper NSF folder \"{options.Folder}\" was not found. Run sync-down or nsf-list first.");
                    return;
                }

                resolvedFolderUid = folderNode.FolderUid;
            }
            else if (!string.IsNullOrEmpty(context.CurrentFolder))
            {
                if (vault.TryResolveKeeperNSFFolder(context.CurrentFolder, out var currentFolder))
                {
                    resolvedFolderUid = currentFolder.FolderUid;
                }
            }

            var op = ParseRecordRemoveOperation(options.Operation ?? "owner-trash");
            if (op == KeeperNSFRecordRemoveOperation.Unlink && string.IsNullOrEmpty(resolvedFolderUid))
            {
                Console.WriteLine("Folder context is required for unlink. Use --folder or cd into a Keeper NSF folder.");
                return;
            }

            var removals = new List<KeeperNSFRecordRemoval>();
            foreach (var name in records)
            {
                if (!vault.TryResolveKeeperNSFRecord(name, out var kdRecord))
                {
                    Console.WriteLine($"Keeper NSF record \"{name}\" was not found. Run sync-down or nsf-list first.");
                    continue;
                }

                var folderUid = resolvedFolderUid;
                if (string.IsNullOrEmpty(folderUid) && op != KeeperNSFRecordRemoveOperation.OwnerTrash)
                {
                    var folderUids = vault.GetKeeperNSFFoldersForRecord(kdRecord.RecordUid).ToList();
                    if (folderUids.Count == 0)
                    {
                        Console.WriteLine($"No folder context for record \"{name}\". Use --folder or --operation owner-trash.");
                        continue;
                    }

                    folderUid = folderUids[0];
                }

                removals.Add(new KeeperNSFRecordRemoval
                {
                    RecordUid = kdRecord.RecordUid,
                    FolderUid = folderUid,
                    Operation = op
                });
            }

            if (removals.Count == 0)
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine("=== Keeper NSF Remove Preview ===");
            KeeperNSFRemoveResult previewResult;
            try
            {
                previewResult = await vault.RemoveKeeperNSFRecords(removals, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            NsfHelpers.WriteRemoveImpact(previewResult.PreviewResponse);

            try
            {
                VaultOnline.ValidateRemoveResponse(previewResult.PreviewResponse, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            if (options.DryRun)
            {
                Console.WriteLine();
                Console.WriteLine("Dry run: no records were removed.");
                return;
            }

            if (!options.Force)
            {
                var prompt = (options.Operation ?? "owner-trash") switch
                {
                    "folder-trash" => "Are you sure you want to move the record(s) above to folder trash? (yes/No)",
                    "unlink" => "Are you sure you want to unlink the record(s) above from the folder? (yes/No)",
                    _ => "Are you sure you want to move the record(s) above to your trash? (yes/No)"
                };
                if (!await NsfHelpers.ConfirmAsync(prompt + " "))
                {
                    Console.WriteLine("Remove operation cancelled");
                    return;
                }
            }

            if (previewResult.PreviewResponse.ConfirmationToken.IsEmpty)
            {
                Console.WriteLine("Preview did not return a confirmation token.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("Removing records...");
            KeeperNSFRemoveResult confirmResult;
            try
            {
                confirmResult = await vault.RemoveKeeperNSFRecords(removals, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            if (!confirmResult.Confirmed)
            {
                Console.WriteLine("Record removal was not confirmed by the server.");
                return;
            }

            await vault.SyncDown(false);
            Console.WriteLine();
            Console.WriteLine("Keeper NSF record removal completed.");
        }

        public static async Task NsfMoveRecordCommand(this VaultContext context, NsfMoveRecordOptions options)
        {
            var vault = context.Vault;
            if (string.IsNullOrWhiteSpace(options.Record))
            {
                Console.WriteLine("Record UID or title is required.");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.SourceFolder))
            {
                Console.WriteLine("Source folder UID or name is required.");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.TargetFolder))
            {
                Console.WriteLine("Target folder UID or name is required.");
                return;
            }

            try
            {
                if (!vault.TryResolveKeeperNSFRecord(options.Record, out var kdRecord))
                {
                    Console.WriteLine($"Keeper NSF record \"{options.Record}\" was not found. Run sync-down or nsf-list first.");
                    return;
                }

                if (!vault.TryResolveKeeperNSFFolder(options.SourceFolder, out var sourceFolder))
                {
                    Console.WriteLine($"Source folder \"{options.SourceFolder}\" was not found. Run sync-down or nsf-list first.");
                    return;
                }

                if (!vault.TryResolveKeeperNSFFolder(options.TargetFolder, out var targetFolder))
                {
                    Console.WriteLine($"Target folder \"{options.TargetFolder}\" was not found. Run sync-down or nsf-list first.");
                    return;
                }

                var result = await vault.MoveKeeperNSFRecord(kdRecord.RecordUid, sourceFolder.FolderUid, targetFolder.FolderUid);

                if (result.Success)
                {
                    Console.WriteLine($"Record '{kdRecord.RecordUid}' moved from '{sourceFolder.FolderUid}' to '{targetFolder.FolderUid}' successfully.");
                    await vault.SyncDown(false).ConfigureAwait(false);
                }
                else
                {
                    Console.WriteLine($"Failed to move record: {result.Status} - {result.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error moving record: {ex.Message}");
            }
        }

        public static async Task NsfLnCommand(this VaultContext context, NsfLnOptions options)
        {
            var vault = context.Vault;
            if (!vault.TryResolveKeeperNSFRecord(options.Record, out var kdRecord))
            {
                Console.WriteLine($"Keeper NSF record \"{options.Record}\" was not found. Run sync-down or nsf-list first.");
                return;
            }

            if (!vault.TryResolveKeeperNSFFolder(options.Folder, out var folderNode))
            {
                Console.WriteLine($"Keeper NSF folder \"{options.Folder}\" was not found. Run sync-down or nsf-list first.");
                return;
            }

            try
            {
                var result = await vault.LinkKeeperNSFRecordToFolder(options.Record, options.Folder);
                VaultOnline.ValidateFolderRecordUpdateResult(result);
                await vault.SyncDown(false);
                Console.WriteLine("Keeper NSF record linked into folder.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task NsfTransferRecordCommand(this VaultContext context, NsfTransferRecordOptions options)
        {
            var args = options.Arguments?.ToList() ?? new List<string>();
            if (args.Count < 2)
            {
                Console.WriteLine("Usage: nsf-transfer-record RECORD [RECORD...] NEW_OWNER_EMAIL");
                return;
            }

            var newOwnerEmail = args[args.Count - 1];
            var recordArgs = args.Take(args.Count - 1).ToList();

            if (recordArgs.Count == 0 || string.IsNullOrWhiteSpace(newOwnerEmail))
            {
                Console.WriteLine("Record UID(s) and new owner email are required.");
                return;
            }

            if (!newOwnerEmail.Contains('@'))
            {
                Console.WriteLine($"New owner must be an email address: \"{newOwnerEmail}\"");
                return;
            }

            var vault = context.Vault;
            var resolvedRecords = new List<string>();
            foreach (var name in recordArgs)
            {
                if (!vault.TryResolveKeeperNSFRecord(name, out var kdRecord))
                {
                    Console.WriteLine($"Keeper NSF record \"{name}\" was not found. Run sync-down or nsf-list first.");
                    return;
                }

                resolvedRecords.Add(kdRecord.RecordUid);
            }

            if (!options.Force)
            {
                Console.WriteLine();
                Console.WriteLine("*** WARNING ***");
                Console.WriteLine("After ownership is transferred you will lose owner rights on the record(s).");
                Console.WriteLine("You may still see the record(s) if you retain access via a shared folder or admin role; otherwise they will disappear after sync.");
                Console.WriteLine("Make sure the new owner is correct before continuing.");
                Console.WriteLine();
                if (!await NsfHelpers.ConfirmAsync(
                        $"Are you sure you want to transfer ownership to '{newOwnerEmail}'? This action cannot be undone. (yes/No) "))
                {
                    Console.WriteLine("Transfer operation cancelled");
                    return;
                }
            }

            try
            {
                var results = await vault.TransferKeeperNSFRecordOwnership(resolvedRecords, newOwnerEmail);
                VaultOnline.ValidateKeeperNSFTransferResults(results);
                foreach (var result in results)
                {
                    Console.WriteLine($"Record '{result.RecordUid}' ownership transferred to {result.Username}.");
                    Console.WriteLine("You no longer own this record. Run sync-down to refresh; it will remain visible only if you retain access via a shared folder or admin role.");
                }

                await vault.SyncDown(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static KeeperNSFRecordRemoveOperation ParseRecordRemoveOperation(string operation)
        {
            if (string.Equals(operation, "folder-trash", StringComparison.OrdinalIgnoreCase))
            {
                return KeeperNSFRecordRemoveOperation.FolderTrash;
            }

            if (string.Equals(operation, "unlink", StringComparison.OrdinalIgnoreCase))
            {
                return KeeperNSFRecordRemoveOperation.Unlink;
            }

            return KeeperNSFRecordRemoveOperation.OwnerTrash;
        }
    }

    class NsfRecordAddOptions
    {
        [Value(0, Required = true, HelpText = "Record title")]
        public string Title { get; set; }

        [Option('t', "type", Required = false, Default = "login", HelpText = "Record type")]
        public string RecordType { get; set; }

        [Option("folder", Required = false, HelpText = "Folder UID or name")]
        public string FolderUid { get; set; }

        [Option("notes", Required = false, HelpText = "Record notes")]
        public string Notes { get; set; }

        [Option('g', "generate", Required = false, HelpText = "Generate random password")]
        public bool GeneratePassword { get; set; }

        [Value(1, Required = false, HelpText = "Field values as key=value")]
        public IEnumerable<string> Fields { get; set; }
    }

    class NsfRecordUpdateOptions
    {
        [Value(0, Required = true, HelpText = "Record UID")]
        public string RecordUid { get; set; }

        [Option("title", Required = false, HelpText = "New title")]
        public string Title { get; set; }

        [Option('t', "type", Required = false, HelpText = "New record type")]
        public string RecordType { get; set; }

        [Option("notes", Required = false, HelpText = "New notes")]
        public string Notes { get; set; }

        [Option('g', "generate", Required = false, HelpText = "Generate random password")]
        public bool GeneratePassword { get; set; }

        [Value(1, Required = false, HelpText = "Field values as key=value")]
        public IEnumerable<string> Fields { get; set; }
    }

    class NsfShareRecordOptions
    {
        [Value(0, Required = true, HelpText = "Record UID")]
        public string RecordUid { get; set; }

        [Option("action", Required = false, Default = "grant", HelpText = "grant or revoke")]
        public string Action { get; set; }

        [Option("email", Required = true, HelpText = "User email(s)")]
        public IEnumerable<string> Email { get; set; }

        [Option("role", Required = false, Default = "viewer", HelpText = "viewer, share-manager, content-manager, content-share-manager, full-manager")]
        public string Role { get; set; }
    }

    class NsfRecordPermissionOptions
    {
        [Value(0, Required = false, HelpText = "Folder UID or name (root if omitted)")]
        public string FolderUid { get; set; }

        [Option("action", Required = true, HelpText = "grant or revoke")]
        public string Action { get; set; }

        [Option("role", Required = false, HelpText = "Access role for grant/revoke filter")]
        public string Role { get; set; }

        [Option('r', "recursive", Required = false, HelpText = "Include subfolders")]
        public bool Recursive { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation")]
        public bool Force { get; set; }

        [Option("dry-run", Required = false, HelpText = "Preview only")]
        public bool DryRun { get; set; }
    }

    class NsfShortcutListOptions
    {
        [Value(0, Required = false, HelpText = "Record/folder UID or name filter")]
        public string Target { get; set; }

        [Option('f', "format", Required = false, Default = "table", HelpText = "table, csv, json")]
        public string Format { get; set; }

        [Option('o', "output", Required = false, HelpText = "Output file (csv/json)")]
        public string Output { get; set; }
    }

    class NsfShortcutKeepOptions
    {
        [Value(0, Required = true, HelpText = "Record UID or title")]
        public string RecordUid { get; set; }

        [Value(1, Required = true, HelpText = "Folder UID or name to keep")]
        public string FolderUid { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation")]
        public bool Force { get; set; }
    }

    class NsfRmOptions
    {
        [Value(0, Min = 1, Required = true, HelpText = "Record UID(s) or title(s)")]
        public IEnumerable<string> Record { get; set; }

        [Option("folder", Required = false, HelpText = "Folder context UID or name")]
        public string Folder { get; set; }

        [Option('o', "operation", Required = false, Default = "owner-trash", HelpText = "owner-trash, folder-trash, unlink")]
        public string Operation { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation")]
        public bool Force { get; set; }

        [Option("dry-run", Required = false, HelpText = "Preview only")]
        public bool DryRun { get; set; }
    }

    class NsfLnOptions
    {
        [Value(0, Required = true, HelpText = "Record UID or title")]
        public string Record { get; set; }

        [Value(1, Required = true, HelpText = "Folder UID, name, or /")]
        public string Folder { get; set; }
    }

    class NsfTransferRecordOptions
    {
        [Value(0, Min = 2, Required = true, HelpText = "Record UID(s) and new owner email")]
        public IEnumerable<string> Arguments { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation")]
        public bool Force { get; set; }
    }

    class NsfMoveRecordOptions
    {
        [Value(0, Required = true, HelpText = "Record UID or title")]
        public string Record { get; set; }

        [Option('s', "source", Required = true, HelpText = "Source folder UID or name")]
        public string SourceFolder { get; set; }

        [Option('t', "target", Required = true, HelpText = "Target folder UID or name")]
        public string TargetFolder { get; set; }
    }
}
