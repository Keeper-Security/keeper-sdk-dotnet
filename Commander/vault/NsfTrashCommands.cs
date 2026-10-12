using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommandLine;
using Cli;
using KeeperSecurity.Vault;

namespace Commander
{
    internal static class NsfTrashCommandExtensions
    {
        public static async Task NsfTrashListCommand(this VaultContext context, NsfTrashListOptions options)
        {
            var result = await context.Vault.GetKeeperNSFTrash(options.Reload);

            if (result.Records.Count == 0 && result.Folders.Count == 0)
            {
                Console.WriteLine("NSF trash is empty");
                return;
            }

            var tab = new Tabulate(5)
            {
                DumpRowNo = true
            };
            tab.AddHeader(new[] { "UID", "Title", "Record Type", "Type", "Deleted At" });

            var items = result.Records.Concat(result.Folders)
                .OrderByDescending(i => i.DateDeleted);

            foreach (var item in items)
            {
                var deletedAt = item.DateDeleted > 0
                    ? DateTimeOffset.FromUnixTimeMilliseconds(item.DateDeleted).LocalDateTime.ToString()
                    : "";
                tab.AddRow(new object[] { item.Uid, item.Title, item.RecordType, item.IsFolder ? "Folder" : "Record", deletedAt });
            }

            tab.Dump();
        }

        public static async Task NsfTrashGetCommand(this VaultContext context, NsfTrashGetOptions options)
        {
            if (string.IsNullOrEmpty(options.Uid))
            {
                Console.WriteLine("A record or folder UID is required.");
                return;
            }

            KeeperNSFTrashGetResult item;
            try
            {
                item = await context.Vault.GetKeeperNSFTrashItem(options.Uid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to look up trash item: {ex.Message}");
                return;
            }

            if (item == null)
            {
                Console.WriteLine($"\"{options.Uid}\" was not found in trash.");
                return;
            }

            var deletedAt = item.DateDeleted > 0
                ? DateTimeOffset.FromUnixTimeMilliseconds(item.DateDeleted).LocalDateTime.ToString()
                : "";

            Console.WriteLine($"{"UID:",-14}{item.Uid}");
            Console.WriteLine($"{"Title:",-14}{item.Title}");
            if (!item.IsFolder)
            {
                Console.WriteLine($"{"Type:",-14}{item.RecordType}");
            }
            Console.WriteLine($"{"Status:",-14}{item.Status}");
            Console.WriteLine($"{"Deleted At:",-14}{deletedAt}");
        }

        public static async Task NsfTrashRestoreCommand(this VaultContext context, NsfTrashRestoreOptions options)
        {
            var uids = options.Uids?.ToList();
            if (uids == null || uids.Count == 0)
            {
                Console.WriteLine("At least one record or folder UID is required.");
                return;
            }

            try
            {
                if (!options.Force)
                {
                    var preview = await context.Vault.RestoreKeeperNSFTrash(uids, options.TargetFolder, options.SourceFolder, dryRun: true);
                    if (preview.RestoredRecordUids.Count == 0 && preview.RestoredFolderUids.Count == 0)
                    {
                        foreach (var error in preview.Errors)
                        {
                            Console.WriteLine($"Error: {error}");
                        }

                        if (preview.Errors.Count == 0)
                        {
                            Console.WriteLine("Nothing matched - nothing to restore.");
                        }

                        return;
                    }

                    var toDo = new List<string>();
                    if (preview.RestoredRecordUids.Count > 0)
                    {
                        toDo.Add($"{preview.RestoredRecordUids.Count} record(s)");
                    }

                    if (preview.RestoredFolderUids.Count > 0)
                    {
                        toDo.Add($"{preview.RestoredFolderUids.Count} folder(s)");
                    }

                    var destination = string.IsNullOrEmpty(options.TargetFolder) ? "" : $" into \"{options.TargetFolder}\"";
                    if (!await NsfHelpers.ConfirmAsync($"Do you want to restore {string.Join(" and ", toDo)}{destination}? (yes/No) "))
                    {
                        Console.WriteLine("Restore cancelled.");
                        return;
                    }
                }

                var result = await context.Vault.RestoreKeeperNSFTrash(uids, options.TargetFolder, options.SourceFolder);

                if (result.RestoredRecordUids.Count > 0)
                {
                    Console.WriteLine($"Restored {result.RestoredRecordUids.Count} record(s): {string.Join(", ", result.RestoredRecordUids)}");
                }

                if (result.RestoredFolderUids.Count > 0)
                {
                    Console.WriteLine($"Restored {result.RestoredFolderUids.Count} folder(s): {string.Join(", ", result.RestoredFolderUids)}");
                }

                foreach (var error in result.Errors)
                {
                    Console.WriteLine($"Error: {error}");
                }

                if (!result.Success && result.Errors.Count == 0)
                {
                    Console.WriteLine("Nothing was restored.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to restore from trash: {ex.Message}");
            }
        }
    }

    class NsfTrashListOptions
    {
        [Option('r', "reload", Required = false, HelpText = "Discard the cached trashcan snapshot and resync from the server")]
        public bool Reload { get; set; }
    }

    class NsfTrashGetOptions
    {
        [Value(0, Required = true, HelpText = "Record or folder UID")]
        public string Uid { get; set; }
    }

    class NsfTrashRestoreOptions
    {
        [Value(0, Min = 1, Required = true, HelpText = "Record/folder UID(s), or a title/wildcard pattern, to restore")]
        public IEnumerable<string> Uids { get; set; }

        [Option("target-folder", Required = false, HelpText = "Folder UID to restore items into instead of their original location")]
        public string TargetFolder { get; set; }

        [Option("source-folder", Required = false, HelpText = "Folder UID (or \"root\"/\"/\" for the Drive root) a record is being restored out of. Only needed if the server rejects the restore with \"source_folder_uid is required\" (the record was trashed under more than one folder)")]
        public string SourceFolder { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation")]
        public bool Force { get; set; }
    }
}
