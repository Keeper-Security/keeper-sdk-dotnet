using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class RemoveKeeperNSFRecord
    {
        /// <summary>
        /// Previews or removes a Keeper NSF record. Set <paramref name="dryRun"/> to false only after reviewing the preview.
        /// </summary>
        public static async Task Remove(
            VaultOnline vault,
            string recordUidOrTitle,
            string folderUidOrName = null,
            KeeperNSFRecordRemoveOperation operation = KeeperNSFRecordRemoveOperation.FolderTrash,
            bool dryRun = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (!vault.TryResolveKeeperNSFRecord(recordUidOrTitle, out var record))
            {
                Console.WriteLine($"Keeper NSF record '{recordUidOrTitle}' not found.");
                return;
            }

            if (!vault.TryResolveKeeperNSFRecordRemovalFolder(
                    record.RecordUid, folderUidOrName, operation, out var folderUid))
            {
                Console.WriteLine("Could not resolve folder context for record removal.");
                return;
            }

            var removals = new List<KeeperNSFRecordRemoval>
            {
                new KeeperNSFRecordRemoval
                {
                    RecordUid = record.RecordUid,
                    FolderUid = folderUid,
                    Operation = operation,
                },
            };

            try
            {
                var result = await vault.RemoveKeeperNSFRecords(removals, dryRun);
                if (dryRun)
                {
                    Console.WriteLine("Preview complete (dry run). Set dryRun: false to confirm removal.");
                    return;
                }

                if (result.Confirmed)
                {
                    Console.WriteLine($"Keeper NSF record '{recordUidOrTitle}' removed.");
                }
                else
                {
                    Console.WriteLine("Record removal was not confirmed by the server.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing Keeper NSF record: {ex.Message}");
            }
        }
    }
}
