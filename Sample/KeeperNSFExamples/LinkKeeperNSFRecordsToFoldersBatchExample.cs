using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder-record linking via <see cref="IVault.LinkKeeperNSFRecordsToFolders"/>.
    /// Independent of <see cref="IVault.LinkKeeperNSFRecordToFolder"/>.
    /// Max 500 records per folder API request.
    /// </summary>
    public static class LinkKeeperNSFRecordsToFoldersBatchExample
    {
        /// <summary>
        /// Runs the batch link-to-folder API and prints per-link results.
        /// </summary>
        public static async Task LinkBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderRecordLinkRequest> links)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (links == null || links.Count == 0)
            {
                Console.WriteLine("No folder-record links to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Linking {links.Count} Keeper NSF record(s) into folders in batch...");
                var results = await vault.LinkKeeperNSFRecordsToFolders(links);

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
                Console.WriteLine($"Error linking Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample link payloads; replace folder and record UIDs before use.
        /// </summary>
        public static IReadOnlyList<KeeperNSFFolderRecordLinkRequest> BuildSampleLinks()
        {
            return new[]
            {
                new KeeperNSFFolderRecordLinkRequest
                {
                    FolderUid = "<folderUid_1>",
                    RecordUid = "<recordUid_1>",
                },
                new KeeperNSFFolderRecordLinkRequest
                {
                    FolderUid = "<folderUid_1>",
                    RecordUid = "<recordUid_2>",
                },
            };
        }
    }
}
