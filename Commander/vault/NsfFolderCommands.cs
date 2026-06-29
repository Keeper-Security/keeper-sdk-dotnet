using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Vault;

namespace Commander
{
    internal static class NsfFolderCommandExtensions
    {
        public static async Task NsfMkdirCommand(this VaultContext context, NsfMkdirOptions options)
        {
            try
            {
                var folderUid = await context.Vault.CreateKeeperNSFFolder(
                    options.Name,
                    options.ParentFolderUid,
                    options.Color,
                    !options.NoInheritPermissions);
                Console.WriteLine($"Folder '{options.Name}' created successfully (UID: {folderUid}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating folder: {ex.Message}");
            }
        }

        public static async Task NsfRndirCommand(this VaultContext context, NsfRndirOptions options)
        {
            if (options.Name == null && options.Color == null)
            {
                Console.WriteLine("Specify --name and/or --color to update the folder.");
                return;
            }

            if (!context.Vault.TryResolveKeeperNSFFolder(options.Folder, out var folderNode))
            {
                Console.WriteLine($"Keeper NSF folder \"{options.Folder}\" was not found. Run sync-down or nsf-list first.");
                return;
            }

            try
            {
                var result = await context.Vault.UpdateKeeperNSFFolder(folderNode.FolderUid, options.Name, options.Color);
                VaultOnline.ValidateFolderModifyResult(result);
                await context.Vault.SyncDown(false);
                Console.WriteLine("Keeper NSF folder updated.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating folder: {ex.Message}");
            }
        }

        public static async Task NsfRmdirCommand(this VaultContext context, NsfRmdirOptions options)
        {
            var vault = context.Vault;
            var folders = options.Folder?.ToList() ?? new List<string>();
            if (folders.Count == 0)
            {
                Console.WriteLine("At least one folder UID or name is required.");
                return;
            }

            var op = string.Equals(options.Operation, "delete-permanent", StringComparison.OrdinalIgnoreCase)
                ? KeeperNSFFolderRemoveOperation.DeletePermanent
                : KeeperNSFFolderRemoveOperation.FolderTrash;

            var removals = new List<KeeperNSFFolderRemoval>();
            foreach (var name in folders)
            {
                if (!vault.TryResolveKeeperNSFFolder(name, out var folderNode))
                {
                    Console.WriteLine($"Keeper NSF folder \"{name}\" was not found. Run sync-down or nsf-list first.");
                    continue;
                }

                removals.Add(new KeeperNSFFolderRemoval
                {
                    FolderUid = folderNode.FolderUid,
                    Operation = op
                });
            }

            if (removals.Count == 0)
            {
                return;
            }

            if (op == KeeperNSFFolderRemoveOperation.DeletePermanent && !options.Force && !options.DryRun)
            {
                Console.WriteLine();
                Console.WriteLine("*** WARNING ***");
                Console.WriteLine("  delete-permanent is IRREVERSIBLE.");
                Console.WriteLine("  All sub-folders and records inside will be permanently destroyed.");
            }

            Console.WriteLine();
            Console.WriteLine("=== Keeper NSF Folder Remove Preview ===");
            KeeperNSFRemoveResult previewResult;
            try
            {
                previewResult = await vault.RemoveKeeperNSFFolders(removals, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            NsfHelpers.WriteRemoveImpact(previewResult.PreviewResponse, "Folder");

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
                Console.WriteLine("Dry run: no folders were removed.");
                return;
            }

            if (!options.Force)
            {
                var prompt = op == KeeperNSFFolderRemoveOperation.DeletePermanent
                    ? "Are you sure you want to permanently delete the folder(s) above? This action cannot be undone. (yes/No)"
                    : "Are you sure you want to remove the folder(s) above? (yes/No)";
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
            Console.WriteLine("Removing folders...");
            KeeperNSFRemoveResult confirmResult;
            try
            {
                confirmResult = await vault.RemoveKeeperNSFFolders(removals, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return;
            }

            if (!confirmResult.Confirmed)
            {
                Console.WriteLine("Folder removal was not confirmed by the server.");
                return;
            }

            await vault.SyncDown(false);
            Console.WriteLine();
            Console.WriteLine("Keeper NSF folder removal completed.");
        }

        public static async Task NsfShareFolderCommand(this VaultContext context, NsfShareFolderOptions options)
        {
            var vault = context.Vault;
            if (!vault.TryGetKeeperNSFFolder(options.FolderUid, out _))
            {
                Console.WriteLine($"Error: NSF folder '{options.FolderUid}' not found.");
                return;
            }

            var action = options.Action ?? "grant";
            foreach (var recipient in options.Email ?? Array.Empty<string>())
            {
                try
                {
                    var label = await vault.ResolveKeeperNSFShareRecipientLabel(recipient).ConfigureAwait(false);

                    if (string.Equals(action, "grant", StringComparison.OrdinalIgnoreCase))
                    {
                        await vault.GrantKeeperNSFFolderAccess(options.FolderUid, recipient, options.Role ?? "viewer");
                        Console.WriteLine($"Granted '{options.Role ?? "viewer"}' access to '{label}' on folder '{options.FolderUid}'.");
                    }
                    else
                    {
                        await vault.RevokeKeeperNSFFolderAccess(options.FolderUid, recipient);
                        Console.WriteLine($"Revoked access for '{label}' from folder '{options.FolderUid}'.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error {action}ing access for '{recipient}': {ex.Message}");
                }
            }
        }
    }

    class NsfMkdirOptions
    {
        [Value(0, Required = true, HelpText = "Folder name")]
        public string Name { get; set; }

        [Option("parent", Required = false, HelpText = "Parent folder UID")]
        public string ParentFolderUid { get; set; }

        [Option("color", Required = false, HelpText = "Folder color")]
        public string Color { get; set; }

        [Option("no-inherit", Required = false, HelpText = "Do not inherit parent permissions")]
        public bool NoInheritPermissions { get; set; }
    }

    class NsfRndirOptions
    {
        [Value(0, Required = true, HelpText = "Folder UID or name")]
        public string Folder { get; set; }

        [Option('n', "name", Required = false, HelpText = "New folder name")]
        public string Name { get; set; }

        [Option("color", Required = false, HelpText = "Folder color (none, red, orange, yellow, green, blue, gray)")]
        public string Color { get; set; }
    }

    class NsfRmdirOptions
    {
        [Value(0, Min = 1, Required = true, HelpText = "Folder UID(s) or name(s)")]
        public IEnumerable<string> Folder { get; set; }

        [Option('o', "operation", Required = false, Default = "folder-trash", HelpText = "folder-trash or delete-permanent")]
        public string Operation { get; set; }

        [Option('f', "force", Required = false, HelpText = "Skip confirmation")]
        public bool Force { get; set; }

        [Option("dry-run", Required = false, HelpText = "Preview only")]
        public bool DryRun { get; set; }
    }

    class NsfShareFolderOptions
    {
        [Value(0, Required = true, HelpText = "Folder UID")]
        public string FolderUid { get; set; }

        [Option("action", Required = false, Default = "grant", HelpText = "grant or remove")]
        public string Action { get; set; }

        [Option("email", Required = true, HelpText = "User email(s), team name(s), or team UID(s)")]
        public IEnumerable<string> Email { get; set; }

        [Option("role", Required = false, Default = "viewer", HelpText = "viewer, share-manager, content-manager, content-share-manager, full-manager")]
        public string Role { get; set; }
    }
}
