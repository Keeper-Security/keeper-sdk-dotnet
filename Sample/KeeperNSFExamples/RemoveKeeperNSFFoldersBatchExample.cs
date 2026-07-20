using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder removal via <see cref="IVault.RemoveKeeperNSFFolders"/>.
    /// Independent of <see cref="RemoveKeeperNSFFolderExample"/> (single-item helper).
    /// Chunks up to 100 folders per API request; check <see cref="KeeperNSFRemoveResult.PartialSuccess"/>.
    /// </summary>
    public static class RemoveKeeperNSFFoldersBatchExample
    {
        /// <summary>
        /// Previews or removes Keeper NSF folders in batch.
        /// Set <paramref name="dryRun"/> to false only after reviewing the preview.
        /// </summary>
        public static async Task RemoveBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderRemoval> removals,
            bool dryRun = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (removals == null || removals.Count == 0)
            {
                Console.WriteLine("No folder removals to process.");
                return;
            }

            try
            {
                Console.WriteLine(
                    $"{(dryRun ? "Previewing" : "Removing")} {removals.Count} Keeper NSF folder(s) in batch...");
                var result = await vault.RemoveKeeperNSFFolders(removals, dryRun);

                PrintPreview(result);

                if (dryRun)
                {
                    Console.WriteLine("Preview complete (dry run). Set dryRun: false to confirm removal.");
                    Console.WriteLine("PowerCommander: nsf-rmdirs -DownloadSampleFolders");
                    return;
                }

                if (result.Confirmed)
                {
                    Console.WriteLine(
                        $"Batch folder remove confirmed ({result.ConfirmedChunkCount} chunk(s)).");
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
                    Console.WriteLine("Folder removal was not confirmed by the server.");
                    PrintChunkErrors(result);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing Keeper NSF folders in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Preview then confirm using the preview tokens (no second PREVIEW pass).
        /// </summary>
        public static async Task PreviewAndConfirm(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderRemoval> removals)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (removals == null || removals.Count == 0)
            {
                Console.WriteLine("No folder removals to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Previewing {removals.Count} Keeper NSF folder(s)...");
                var preview = await vault.RemoveKeeperNSFFolders(removals, dryRun: true);
                PrintPreview(preview);

                Console.WriteLine("Confirming with preview token(s)...");
                var result = await vault.ConfirmKeeperNSFFolders(removals, preview);
                if (result.Confirmed)
                {
                    Console.WriteLine(
                        $"Batch folder remove confirmed ({result.ConfirmedChunkCount} chunk(s)).");
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
                    Console.WriteLine("Folder removal was not confirmed by the server.");
                    PrintChunkErrors(result);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing Keeper NSF folders in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample in-memory folder removal payloads. Replace UIDs before running.
        /// </summary>
        public static IReadOnlyList<KeeperNSFFolderRemoval> BuildSampleRemovals()
        {
            return new[]
            {
                new KeeperNSFFolderRemoval
                {
                    FolderUid = "<folderUid_1>",
                    Operation = KeeperNSFFolderRemoveOperation.FolderTrash,
                },
                new KeeperNSFFolderRemoval
                {
                    FolderUid = "<folderUid_2>",
                    Operation = KeeperNSFFolderRemoveOperation.FolderTrash,
                },
                new KeeperNSFFolderRemoval
                {
                    FolderUid = "<folderUid_3>",
                    Operation = KeeperNSFFolderRemoveOperation.DeletePermanent,
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
