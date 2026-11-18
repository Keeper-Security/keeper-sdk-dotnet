using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using KeeperSecurity.Utils;
using ZeroDep;

namespace Commander
{
    internal static class NsfRecordCommandExtensions
    {
        public static async Task NsfConvertCommand(this VaultContext context, NsfConvertOptions options)
        {
            if (!TrySelectClassicRecords(context, options.Record, out var records, out var alreadyNsf, out var error))
            {
                Console.WriteLine(error);
                return;
            }

            var vault = context.Vault;
            string folderUid = null;
            if (!string.IsNullOrWhiteSpace(options.Folder))
            {
                if (!vault.TryResolveKeeperNSFFolderReference(options.Folder, out var folder))
                {
                    Console.WriteLine($"Keeper NSF folder '{options.Folder}' was not found or is ambiguous. Specify its UID or full path.");
                    return;
                }
                folderUid = folder.FolderUid;
            }

            if (records.Count == 0)
            {
                Console.WriteLine($"No classic records remain to convert ({alreadyNsf.Count} already NSF).");
                return;
            }

            foreach (var uid in alreadyNsf)
            {
                Console.WriteLine($"Record '{uid}' is already an NSF record; skipped.");
            }

            if (!options.Force)
            {
                Console.WriteLine("WARNING: Conversion is permanent. Classic shared-folder membership and additional classic folder placements are not retained.");
                Console.WriteLine($"Destination: {(folderUid ?? "Vault (root)")}");
                foreach (var record in records) Console.WriteLine($"  {record.Uid}: {record.Title}");
                if (!await NsfHelpers.ConfirmAsync("Continue? (yes/No) ").ConfigureAwait(false))
                {
                    Console.WriteLine("Conversion cancelled.");
                    return;
                }
            }

            try
            {
                var results = await vault.ConvertClassicRecordsToKeeperNSF(records.Select(x => x.Uid).ToList(), folderUid)
                    .ConfigureAwait(false);
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        Console.WriteLine($"Classic record '{result.RecordUid}' converted to a Keeper NSF record.");
                    }
                    else if (result.OutcomeUncertain)
                    {
                        Console.WriteLine($"Classic record '{result.RecordUid}' conversion outcome is uncertain: {result.Message} (status: {result.Status}).");
                    }
                    else if (result.Skipped)
                    {
                        Console.WriteLine($"WARNING: Classic record '{result.RecordUid}' skipped: {result.Message}");
                    }
                    else
                    {
                        Console.WriteLine($"Classic record '{result.RecordUid}' was not converted: {result.Message} (status: {result.Status}).");
                    }
                }
                if (results.Any(x => !string.IsNullOrEmpty(x.RefreshWarning)))
                {
                    Console.WriteLine($"WARNING: {results.First(x => !string.IsNullOrEmpty(x.RefreshWarning)).RefreshWarning}");
                }
                Console.WriteLine($"Conversion complete: {results.Count(x => x.Success)} confirmed converted, "
                    + $"{results.Count(x => x.OutcomeUncertain)} uncertain, "
                    + $"{results.Count(x => !x.Success && !x.OutcomeUncertain && !x.Skipped)} failed; "
                    + $"{results.Count(x => x.Skipped) + alreadyNsf.Count} skipped.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error converting records: {ex.Message}");
            }
        }

        private static bool TrySelectClassicRecords(VaultContext context, IEnumerable<string> recordRefs,
            out List<KeeperRecord> records, out List<string> alreadyNsf, out string error)
        {
            records = new List<KeeperRecord>();
            alreadyNsf = new List<string>();
            error = null;
            var references = recordRefs?.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
            if (references == null || references.Count == 0)
            {
                error = "At least one classic record UID, title, or path is required.";
                return false;
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var recordRef in references)
            {
                if (context.Vault.TryGetKeeperNSFRecord(recordRef, out var nsfRecord))
                {
                    if (!seen.Add(nsfRecord.RecordUid))
                    {
                        Console.WriteLine($"WARNING: Record '{nsfRecord.RecordUid}' was selected more than once; duplicate skipped.");
                        continue;
                    }
                    alreadyNsf.Add(nsfRecord.RecordUid);
                    continue;
                }

                if (!TryResolveClassicRecord(context, recordRef, out var record, out error))
                {
                    return false;
                }

                if (!seen.Add(record.Uid))
                {
                    Console.WriteLine($"WARNING: Record '{record.Uid}' was selected more than once; duplicate skipped.");
                    continue;
                }

                records.Add(record);
            }

            return true;
        }

        private static bool TryResolveClassicRecord(VaultContext context, string recordRef,
            out KeeperRecord record, out string error)
        {
            error = null;
            if (context.Vault.TryGetKeeperRecord(recordRef, out record))
            {
                return true;
            }

            if (!context.ResolvePath(recordRef, out var folder, out var title))
            {
                error = $"Classic record '{recordRef}' was not found. Specify its UID or path.";
                return false;
            }

            var matches = folder.Records
                .Select(uid => context.Vault.TryGetKeeperRecord(uid, out var candidate) ? candidate : null)
                .Where(candidate => candidate != null && string.Equals(candidate.Title, title, StringComparison.OrdinalIgnoreCase))
                .Take(2).ToList();
            if (matches.Count != 1)
            {
                error = $"Classic record '{recordRef}' was not found or is ambiguous. Specify its UID.";
                return false;
            }

            record = matches[0];
            return true;
        }

        public static async Task NsfRecordAddCommand(this VaultContext context, NsfRecordAddOptions options)
        {
            if (options.RecordType != "general" && options.RecordType != "legacy"
                && !context.Vault.TryGetRecordTypeByName(options.RecordType, out _))
            {
                Console.WriteLine($"Record type '{options.RecordType}' cannot be found.");
                return;
            }
            string folderUid = null;
            if (!string.IsNullOrWhiteSpace(options.FolderUid))
            {
                try
                {
                    if (!context.Vault.TryResolveKeeperNSFFolderReference(options.FolderUid, out var folder))
                    {
                        if (options.FolderUid.IndexOfAny(new[] { '/', '\\' }) < 0)
                            context.Vault.ResolveKeeperNSFFolderStrict(options.FolderUid);
                        Console.WriteLine($"Cannot resolve folder {options.FolderUid}");
                        return;
                    }
                    folderUid = folder.FolderUid;
                }
                catch (AmbiguousFolderException)
                {
                    Console.WriteLine($"Folder '{options.FolderUid}' is ambiguous. Pass the folder UID.");
                    return;
                }
            }
            Dictionary<string, object> fieldDict = null;
            if ((options.Fields != null && options.Fields.Any()) || options.GeneratePassword)
            {
                try
                {
                    fieldDict = NsfHelpers.ParseFieldSpecs(options.Fields, options.GeneratePassword, out _);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    return;
                }
            }

            try
            {
                var recordUid = await context.Vault.CreateKeeperNSFRecord(
                    options.Title,
                    options.RecordType,
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

            if (hasType && !context.Vault.TryGetRecordTypeByName(options.RecordType, out _))
            {
                Console.WriteLine($"Error: Record type '{options.RecordType}' not found.");
                return;
            }

            Dictionary<string, object> fieldDict = null;
            if (hasFields || options.GeneratePassword)
            {
                int parsedCount;
                try
                {
                    fieldDict = NsfHelpers.ParseFieldSpecs(options.Fields, options.GeneratePassword, out parsedCount);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    return;
                }
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
            var recordUids = new List<string>();
            try
            {
                if (options.Recursive)
                {
                    if (string.IsNullOrWhiteSpace(options.RecordUid)
                        || !vault.TryResolveKeeperNSFFolderReference(options.RecordUid, out var folder))
                    {
                        if (!string.IsNullOrWhiteSpace(options.RecordUid)
                            && options.RecordUid.IndexOfAny(new[] { '/', '\\' }) < 0)
                            vault.ResolveKeeperNSFFolderStrict(options.RecordUid);
                        Console.WriteLine("Error: -R requires a Keeper NSF folder path or UID.");
                        return;
                    }
                    var folders = new HashSet<string>(StringComparer.Ordinal) { folder.FolderUid };
                    bool changed;
                    do
                    {
                        changed = false;
                        foreach (var child in vault.KeeperNSFFolderNodes)
                            if (folders.Contains(child.ParentUid)) changed |= folders.Add(child.FolderUid);
                    } while (changed);
                    recordUids.AddRange(vault.Storage.KdFolderRecords.GetAllLinks()
                        .Where(link => folders.Contains(link.FolderUid)).Select(link => link.RecordUid).Distinct());
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(options.RecordUid))
                    {
                        Console.WriteLine("Error: Record path or UID is required.");
                        return;
                    }
                    KeeperNSFRecord record = null;
                    var separator = options.RecordUid.LastIndexOfAny(new[] { '/', '\\' });
                    if (separator > 0 && vault.TryResolveKeeperNSFFolderReference(
                        options.RecordUid.Substring(0, separator), out var recordFolder))
                    {
                        var title = options.RecordUid.Substring(separator + 1);
                        var matches = vault.Storage.KdFolderRecords.GetAllLinks()
                            .Where(link => link.FolderUid == recordFolder.FolderUid)
                            .Select(link => vault.TryGetKeeperNSFRecord(link.RecordUid, out var candidate) ? candidate : null)
                            .Where(candidate => candidate != null && string.Equals(candidate.Title, title, StringComparison.Ordinal))
                            .Take(2).ToList();
                        if (matches.Count > 1)
                        {
                            Console.WriteLine("Error: Record path is ambiguous. Pass the record UID.");
                            return;
                        }
                        record = matches.FirstOrDefault();
                    }
                    if (record == null) record = NsfHelpers.ResolveNsfRecordByUidOrTitle(vault, options.RecordUid);
                    if (record == null)
                    {
                        Console.WriteLine($"Error: NSF record '{options.RecordUid}' not found.");
                        return;
                    }
                    recordUids.Add(record.RecordUid);
                }
            }
            catch (Exception ex) when (ex is AmbiguousFolderException || ex is AmbiguousNsfRecordException)
            {
                Console.WriteLine($"Error: {ex.Message} Pass the UID.");
                return;
            }

            var action = options.Action ?? "grant";
            var isGrant = string.Equals(action, "grant", StringComparison.OrdinalIgnoreCase)
                || string.Equals(action, "update", StringComparison.OrdinalIgnoreCase);
            var isRevoke = string.Equals(action, "revoke", StringComparison.OrdinalIgnoreCase);
            if (!isGrant && !isRevoke)
            {
                Console.WriteLine("--action must be grant or revoke.");
                return;
            }
            if (!string.IsNullOrWhiteSpace(options.ExpireAt) && !string.IsNullOrWhiteSpace(options.ExpireIn))
            {
                Console.WriteLine("Error: --expire-at and --expire-in cannot be used together.");
                return;
            }

            var users = (options.Email ?? Array.Empty<string>()).ToArray();
            if (users.Length == 0)
            {
                Console.WriteLine("Error: Recipient email is required (use -e or --email).");
                return;
            }
            if (options.ContactsOnly)
            {
                try
                {
                    var targets = (global::Records.GetShareObjectsResponse)await vault.Auth.ExecuteAuthRest(
                        "vault/get_share_objects", new global::Records.GetShareObjectsRequest(),
                        typeof(global::Records.GetShareObjectsResponse));
                    var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var list in new[] { targets.ShareRelationships, targets.ShareFamilyUsers,
                        targets.ShareEnterpriseUsers, targets.ShareMCEnterpriseUsers })
                        foreach (var target in list) known.Add(target.Username);
                    var unknown = users.Where(user => !known.Contains(user)).ToArray();
                    if (unknown.Length > 0)
                    {
                        Console.WriteLine($"Error: Unknown share contact(s): {string.Join(", ", unknown)}");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error checking known share contacts: {ex.Message}");
                    return;
                }
            }

            var role = NormalizeNsfShareRole(options.Role);
            if (!string.IsNullOrWhiteSpace(options.Role) && string.IsNullOrEmpty(role))
            {
                Console.WriteLine($"Error: Unknown role '{options.Role}'. Valid roles: viewer, share-manager, content-manager, content-share-manager, full-manager.");
                return;
            }
            if (isGrant && string.IsNullOrEmpty(role))
            {
                Console.WriteLine("Error: --role is required for grant or update actions.");
                return;
            }

            SharedFolderRecordOptions shareOptions = null;
            if (isGrant)
            {
                if (!TryCreateNsfShareOptions(options, out shareOptions, out var expirationError))
                {
                    Console.WriteLine($"Error: {expirationError}");
                    return;
                }
            }

            if (options.RotateOnExpiration && (!isGrant || shareOptions?.Expiration == null || shareOptions.Expiration <= DateTimeOffset.UtcNow))
            {
                Console.WriteLine("Error: --rotate-on-expiration requires grant and a future --expire-at or --expire-in.");
                return;
            }
            if (options.RotateOnExpiration && recordUids.Any(uid =>
                !vault.TryGetKeeperNSFRecord(uid, out var candidate)
                || !string.Equals(candidate.Type, "pamUser", StringComparison.Ordinal)
                || !vault.RecordHasRotationConfigured(uid)))
            {
                Console.WriteLine("Error: --rotate-on-expiration requires a pamUser record with rotation configured.");
                return;
            }
            if (shareOptions != null) shareOptions.RotateOnExpiration = options.RotateOnExpiration;

            if (options.DryRun)
            {
                Console.WriteLine($"[dry-run] Action: {action}");
                foreach (var uid in recordUids)
                    foreach (var user in users) Console.WriteLine($"[dry-run] Record: {uid}, Recipient: {user}");
                if (isGrant)
                {
                    Console.WriteLine($"[dry-run] Role: {options.Role}");
                    if (shareOptions?.Expiration != null)
                    {
                        Console.WriteLine($"[dry-run] Expires: {shareOptions.Expiration.Value.ToUniversalTime():O}");
                    }
                }
                return;
            }

            if (isRevoke
                && !options.Force
                && !await NsfHelpers.ConfirmAsync(
                    $"Are you sure you want to revoke access to {recordUids.Count} record(s) from {users.Length} user(s)? (yes/No) "))
            {
                return;
            }

            foreach (var recordUid in recordUids)
            foreach (var user in users)
            {
                try
                {
                    if (isGrant)
                    {
                        // ShareKeeperNSFRecord promotes an already-existing direct share to an update,
                        // so both grant and update retain the same idempotent CLI behavior.
                        await vault.ShareKeeperNSFRecord(recordUid, user, role, shareOptions);
                        Console.WriteLine($"{(string.Equals(action, "update", StringComparison.OrdinalIgnoreCase) ? "Updated" : "Granted")} '{options.Role}' access to '{user}' on record '{recordUid}'.");
                    }
                    else
                    {
                        await vault.UnshareKeeperNSFRecord(recordUid, user);
                        Console.WriteLine($"Revoked access for '{user}' from record '{recordUid}'.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error {action}ing access for '{user}': {ex.Message}");
                }
            }
        }

        private static string NormalizeNsfShareRole(string role)
        {
            switch (role?.Trim().ToLowerInvariant())
            {
                case "viewer": return "viewer";
                case "content-manager": return "content-manager";
                case "shared-manager":
                case "share-manager": return "share-manager";
                case "content-share-manager": return "content-share-manager";
                case "manager":
                case "full-manager": return "full-manager";
                default: return null;
            }
        }

        private static bool TryCreateNsfShareOptions(NsfShareRecordOptions options,
            out SharedFolderRecordOptions shareOptions, out string error)
        {
            shareOptions = new SharedFolderRecordOptions();
            error = null;
            if (!string.IsNullOrWhiteSpace(options.ExpireAt) && !string.IsNullOrWhiteSpace(options.ExpireIn))
            {
                error = "--expire-at and --expire-in cannot be used together.";
                return false;
            }

            if (string.Equals(options.ExpireAt, "never", StringComparison.OrdinalIgnoreCase)
                || string.Equals(options.ExpireIn, "never", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            try
            {
                if (!string.IsNullOrWhiteSpace(options.ExpireAt))
                {
                    shareOptions.Expiration = DateTimeOffset.Parse(
                        options.ExpireAt, System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
                }
                else if (!string.IsNullOrWhiteSpace(options.ExpireIn))
                {
                    shareOptions.Expiration = DateTimeOffset.UtcNow + ParseUtils.ParseTimePeriod(options.ExpireIn);
                }
                return true;
            }
            catch (Exception ex)
            {
                error = $"Invalid share expiration: {ex.Message}";
                return false;
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
            var folderDisplay = "root";

            if (!string.IsNullOrEmpty(folderUid))
            {
                var permFolderMatch = NsfHelpers.ResolveNsfFolderByUidOrName(vault, folderUid);
                if (permFolderMatch != null)
                {
                    folderUid = permFolderMatch.FolderUid;
                    folderDisplay = folderUid;
                }
                else
                {
                    Console.WriteLine($"Error: Folder '{folderUid}' not found.");
                    return;
                }
            }
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
                    var recordMatches = vault.KeeperNSFRecordEntries
                        .Where(r => r.Title != null && string.Equals(r.Title, options.Target, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (recordMatches.Count > 1)
                    {
                        var titles = string.Join(", ", recordMatches.Select(r => $"\"{r.Title}\""));
                        Console.WriteLine($"Error: Multiple records matching \"{options.Target}\": {titles}.");
                        return Task.CompletedTask;
                    }
                    if (recordMatches.Count == 1)
                    {
                        recordUid = recordMatches[0].RecordUid;
                    }
                    else
                    {
                        var folderMatch = NsfHelpers.ResolveNsfFolderByUidOrName(vault, options.Target);
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
                var matches = vault.KeeperNSFRecordEntries
                    .Where(r => r.Title != null && string.Equals(r.Title, recordUid, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (matches.Count > 1)
                {
                    var titles = string.Join(", ", matches.Select(r => $"\"{r.Title}\""));
                    Console.WriteLine($"Error: Multiple records matching \"{options.RecordUid}\": {titles}.");
                    return;
                }
                if (matches.Count == 1)
                {
                    recordUid = matches[0].RecordUid;
                }
                else
                {
                    Console.WriteLine($"Error: Record '{options.RecordUid}' not found.");
                    return;
                }
            }

            if (!vault.TryGetKeeperNSFFolder(folderUid, out _))
            {
                var match = NsfHelpers.ResolveNsfFolderByUidOrName(vault, folderUid);
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
                var folderNode = NsfHelpers.ResolveNsfFolderByUidOrName(vault, options.Folder);
                if (folderNode == null)
                {
                    Console.WriteLine($"Keeper NSF folder \"{options.Folder}\" was not found. Run sync-down or nsf-list first.");
                    return;
                }

                resolvedFolderUid = folderNode.FolderUid;
            }
            else if (!string.IsNullOrEmpty(context.CurrentNsfFolder))
            {
                if (vault.TryResolveKeeperNSFFolder(context.CurrentNsfFolder, out var currentFolder))
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

            // Resolve every record before removing anything: a destructive batch either runs in full or not at all,
            // so one ambiguous/missing identifier can't result in a half-done delete of the others.
            var removals = new List<KeeperNSFRecordRemoval>();
            var resolveErrors = new List<string>();
            foreach (var name in records)
            {
                KeeperNSFRecord kdRecord;
                try
                {
                    kdRecord = NsfHelpers.ResolveNsfRecordByUidOrTitle(vault, name);
                }
                catch (AmbiguousNsfRecordException ex)
                {
                    resolveErrors.Add(ex.Message);
                    continue;
                }

                if (kdRecord == null)
                {
                    resolveErrors.Add($"Keeper NSF record \"{name}\" was not found. Run sync-down or nsf-list first.");
                    continue;
                }

                var folderUid = resolvedFolderUid;
                if (string.IsNullOrEmpty(folderUid) && op != KeeperNSFRecordRemoveOperation.OwnerTrash)
                {
                    var folderUids = vault.GetKeeperNSFFoldersForRecord(kdRecord.RecordUid).ToList();
                    if (folderUids.Count == 0)
                    {
                        resolveErrors.Add($"No folder context for record \"{name}\". Use --folder or --operation owner-trash.");
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

            if (resolveErrors.Count > 0)
            {
                foreach (var error in resolveErrors)
                {
                    Console.WriteLine($"Error: {error}");
                }
                Console.WriteLine($"Aborted: {resolveErrors.Count} of {records.Count} record(s) could not be resolved. No records were removed.");
                return;
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

        public static async Task NsfLnCommand(this VaultContext context, NsfLnOptions options)
        {
            var vault = context.Vault;
            var kdRecord = NsfHelpers.ResolveNsfRecordByUidOrTitle(vault, options.Record);
            if (kdRecord == null)
            {
                Console.WriteLine($"Keeper NSF record \"{options.Record}\" was not found. Run sync-down or nsf-list first.");
                return;
            }

            var folderNode = NsfHelpers.ResolveNsfFolderByUidOrName(vault, options.Folder);
            if (folderNode == null)
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
                var kdRecord = NsfHelpers.ResolveNsfRecordByUidOrTitle(vault, name);
                if (kdRecord == null)
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
        [Option("folder", Required = false, HelpText = "folder name or UID to store record")]
        public string FolderUid { get; set; }

        [Option('t', "type", Required = true, HelpText = "record type.")]
        public string RecordType { get; set; }

        [Option("title", Required = true, HelpText = "record title.")]
        public string Title { get; set; }

        [Option("notes", Required = false, HelpText = "record notes")]
        public string Notes { get; set; }

        [Option('g', "generate", Required = false, HelpText = "generate random password")]
        public bool GeneratePassword { get; set; }

        [Value(0, Required = false, HelpText = "Field values as key=value (password=$GEN generates a password)")]
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

        [Value(1, Required = false, HelpText = "Field values as key=value (password=$GEN generates a password)")]
        public IEnumerable<string> Fields { get; set; }
    }

    class NsfConvertOptions
    {
        [Value(0, Min = 1, Required = true, HelpText = "Classic record UID(s), title(s), or path(s) to convert (automatically batched in groups of 100)")]
        public IEnumerable<string> Record { get; set; }

        [Option("folder", Required = false, HelpText = "Existing Keeper NSF folder UID, name, or path; omit for Vault (root)")]
        public string Folder { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip permanent-conversion confirmation")]
        public bool Force { get; set; }
    }

    class NsfShareRecordOptions : VaultForceOptions
    {
        [Value(0, Required = false, MetaName = "record", HelpText = "record path or UID")]
        public string RecordUid { get; set; }

        [Option('e', "email", Required = true, HelpText = "account email. Repeatable: -e user1@example.com -e user2@example.com")]
        public IEnumerable<string> Email { get; set; }

        [Option("contacts-only", Required = false, HelpText = "Share only to known targets")]
        public bool ContactsOnly { get; set; }

        [Option('a', "action", Required = false, Default = "grant", HelpText = "sharing action. 'grant' if omitted (also updates existing shares)")]
        public string Action { get; set; }

        [Option('r', "role", Required = false, HelpText = "permission role. Required for grant/update actions: viewer, share-manager, content-manager, content-share-manager, full-manager")]
        public string Role { get; set; }

        [Option('R', "recursive", Required = false, HelpText = "apply command to all records within a folder and its sub-folders")]
        public bool Recursive { get; set; }

        [Option("dry-run", Required = false, HelpText = "display permission changes without committing them")]
        public bool DryRun { get; set; }

        [Option("expire-at", Required = false, HelpText = "share expiration: never or UTC datetime (e.g. 2027-01-01T00:00:00Z)")]
        public string ExpireAt { get; set; }

        [Option("expire-in", Required = false, HelpText = "share expiration: never or period (e.g. 30d, 6mo, 1y)")]
        public string ExpireIn { get; set; }

        [Option("rotate-on-expiration", Required = false, HelpText = "rotate the password when the share access expires. Only valid on grant; requires a future expiration and a pamUser record with rotation configured")]
        public bool RotateOnExpiration { get; set; }
    }

    class NsfRecordPermissionOptions : VaultForceOptions
    {
        [Value(0, Required = false, HelpText = "Folder UID or name (root if omitted)")]
        public string FolderUid { get; set; }

        [Option("action", Required = true, HelpText = "grant or revoke")]
        public string Action { get; set; }

        [Option("role", Required = false, HelpText = "Access role for grant/revoke filter")]
        public string Role { get; set; }

        [Option('r', "recursive", Required = false, HelpText = "Include subfolders")]
        public bool Recursive { get; set; }

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

    class NsfShortcutKeepOptions : VaultForceOptions
    {
        [Value(0, Required = true, HelpText = "Record UID or title")]
        public string RecordUid { get; set; }

        [Value(1, Required = true, HelpText = "Folder UID or name to keep")]
        public string FolderUid { get; set; }
    }

    class NsfRmOptions : VaultForceOptions
    {
        [Value(0, Min = 1, Required = true, HelpText = "Record UID(s) or title(s)")]
        public IEnumerable<string> Record { get; set; }

        [Option("folder", Required = false, HelpText = "Folder context UID or name")]
        public string Folder { get; set; }

        [Option('o', "operation", Required = false, Default = "owner-trash", HelpText = "owner-trash, folder-trash, unlink")]
        public string Operation { get; set; }

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

    class NsfTransferRecordOptions : VaultForceOptions
    {
        [Value(0, Min = 2, Required = true, HelpText = "Record UID(s) and new owner email")]
        public IEnumerable<string> Arguments { get; set; }
    }

}
