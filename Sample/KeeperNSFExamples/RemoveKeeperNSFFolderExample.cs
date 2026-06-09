using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class RemoveKeeperNSFFolderExample
    {
        /// <summary>
        /// Previews or removes a Keeper NSF folder. Set <paramref name="dryRun"/> to false only after reviewing the preview.
        /// </summary>
        public static async Task Remove(
            VaultOnline vault,
            string folderUidOrName,
            KeeperNSFFolderRemoveOperation operation = KeeperNSFFolderRemoveOperation.FolderTrash,
            bool dryRun = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (!vault.TryResolveKeeperNSFFolder(folderUidOrName, out var folder))
            {
                Console.WriteLine($"Keeper NSF folder '{folderUidOrName}' not found.");
                return;
            }

            var removals = new List<KeeperNSFFolderRemoval>
            {
                new KeeperNSFFolderRemoval
                {
                    FolderUid = folder.FolderUid,
                    Operation = operation,
                },
            };

            try
            {
                var result = await vault.RemoveKeeperNSFFolders(removals, dryRun);
                if (dryRun)
                {
                    Console.WriteLine("Preview complete (dry run). Set dryRun: false to confirm removal.");
                    return;
                }

                if (result.Confirmed)
                {
                    Console.WriteLine($"Keeper NSF folder '{folderUidOrName}' removed.");
                }
                else
                {
                    Console.WriteLine("Folder removal was not confirmed by the server.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing Keeper NSF folder: {ex.Message}");
            }
        }
    }
}
