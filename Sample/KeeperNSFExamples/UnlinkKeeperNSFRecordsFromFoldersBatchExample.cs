using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder-record unlink via <see cref="IVault.UnlinkKeeperNSFRecordsFromFolders"/>.
    /// Uses vault/folders/v3/record_update RemoveRecords (record remains in other folders).
    /// Max 500 records per folder API request.
    /// </summary>
    public static class UnlinkKeeperNSFRecordsFromFoldersBatchExample
    {
        /// <summary>
        /// Runs the batch unlink-from-folder API and prints per-unlink results.
        /// </summary>
        public static async Task UnlinkBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderRecordUnlinkRequest> unlinks)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (unlinks == null || unlinks.Count == 0)
            {
                Console.WriteLine("No folder-record unlinks to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Unlinking {unlinks.Count} Keeper NSF record(s) from folders in batch...");
                var results = await vault.UnlinkKeeperNSFRecordsFromFolders(unlinks);

                var succeeded = 0;
                foreach (var result in results)
                {
                    var folderLabel = string.IsNullOrEmpty(result.FolderUid) ? "root" : result.FolderUid;
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine($"  [OK]   {result.RecordUid} @ {folderLabel}");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"  [FAIL] {result.RecordUid} @ {folderLabel}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                    }
                }

                Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error unlinking Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample unlink payloads; replace folder and record UIDs before use.
        /// </summary>
        public static IReadOnlyList<KeeperNSFFolderRecordUnlinkRequest> BuildSampleUnlinks()
        {
            return new[]
            {
                new KeeperNSFFolderRecordUnlinkRequest
                {
                    FolderUid = "<folderUid_1>",
                    RecordUid = "<recordUid_1>",
                },
                new KeeperNSFFolderRecordUnlinkRequest
                {
                    FolderUid = "<folderUid_2>",
                    RecordUid = "<recordUid_2>",
                },
            };
        }
    }
}
