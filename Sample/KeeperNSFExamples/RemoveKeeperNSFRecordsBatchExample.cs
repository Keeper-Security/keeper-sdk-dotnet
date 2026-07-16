using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF record removal via <see cref="IVault.RemoveKeeperNSFRecords"/>.
    /// Independent of <see cref="RemoveKeeperNSFRecordExample"/> (single-item helper).
    /// Chunks up to 500 records per API request; check <see cref="KeeperNSFRemoveResult.PartialSuccess"/>.
    /// </summary>
    public static class RemoveKeeperNSFRecordsBatchExample
    {
        /// <summary>
        /// Previews or removes Keeper NSF records in batch.
        /// Set <paramref name="dryRun"/> to false only after reviewing the preview.
        /// </summary>
        public static async Task RemoveBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordRemoval> removals,
            bool dryRun = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (removals == null || removals.Count == 0)
            {
                Console.WriteLine("No removals to process.");
                return;
            }

            try
            {
                Console.WriteLine(
                    $"{(dryRun ? "Previewing" : "Removing")} {removals.Count} Keeper NSF record(s) in batch...");
                var result = await vault.RemoveKeeperNSFRecords(removals, dryRun);

                PrintPreview(result);

                if (dryRun)
                {
                    Console.WriteLine("Preview complete (dry run). Set dryRun: false to confirm removal.");
                    Console.WriteLine("PowerCommander: nsf-records-rm -DownloadSampleRemovals");
                    return;
                }

                if (result.Confirmed)
                {
                    Console.WriteLine(
                        $"Batch remove confirmed ({result.ConfirmedChunkCount} chunk(s)).");
                }
                else if (result.PartialSuccess)
                {
                    Console.WriteLine(
                        $"Partial success: {result.ConfirmedChunkCount} chunk(s) confirmed, " +
                        $"{result.FailedChunkCount} failed.");
                    PrintChunkErrors(result);
                }
                else
                {
                    Console.WriteLine("Record removal was not confirmed by the server.");
                    PrintChunkErrors(result);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample in-memory removal payloads. Replace UIDs (and folder UIDs where required) before running.
        /// </summary>
        public static IReadOnlyList<KeeperNSFRecordRemoval> BuildSampleRemovals()
        {
            return new[]
            {
                new KeeperNSFRecordRemoval
                {
                    RecordUid = "<recordUid_1>",
                    Operation = KeeperNSFRecordRemoveOperation.OwnerTrash,
                },
                new KeeperNSFRecordRemoval
                {
                    RecordUid = "<recordUid_2>",
                    FolderUid = "<folderUid_here>",
                    Operation = KeeperNSFRecordRemoveOperation.FolderTrash,
                },
                new KeeperNSFRecordRemoval
                {
                    RecordUid = "<recordUid_3>",
                    FolderUid = "<folderUid_here>",
                    Operation = KeeperNSFRecordRemoveOperation.Unlink,
                },
            };
        }

        private static void PrintPreview(KeeperNSFRemoveResult result)
        {
            var preview = result?.PreviewResponse;
            if (preview?.Results == null || preview.Results.Count == 0)
            {
                Console.WriteLine("  (no preview results)");
                return;
            }

            foreach (var row in preview.Results)
            {
                var uid = row.ItemUid != null && !row.ItemUid.IsEmpty
                    ? CryptoUtils.Base64UrlEncode(row.ItemUid.ToByteArray())
                    : "-";
                var error = row.Error?.Message;
                if (!string.IsNullOrWhiteSpace(error))
                {
                    Console.WriteLine($"  [FAIL] {uid}  {error}");
                }
                else
                {
                    Console.WriteLine($"  [OK]   {uid}  status={row.Status}");
                }
            }
        }

        private static void PrintChunkErrors(KeeperNSFRemoveResult result)
        {
            if (result?.ChunkErrors == null || result.ChunkErrors.Count == 0)
            {
                return;
            }

            foreach (var error in result.ChunkErrors)
            {
                Console.WriteLine($"  chunk error: {error}");
            }
        }
    }
}
