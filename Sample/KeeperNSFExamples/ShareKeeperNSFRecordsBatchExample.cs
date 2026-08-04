using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF record sharing via <see cref="IVault.ShareKeeperNSFRecords"/>.
    /// Independent of <see cref="IVault.ShareKeeperNSFRecord"/>.
    /// </summary>
    public static class ShareKeeperNSFRecordsBatchExample
    {
        /// <summary>
        /// Runs the batch record-share API and prints per-share results.
        /// </summary>
        public static async Task ShareBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordShareRequest> shares)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (shares == null || shares.Count == 0)
            {
                Console.WriteLine("No shares to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Sharing {shares.Count} Keeper NSF record access(es) in batch...");
                var results = await vault.ShareKeeperNSFRecords(shares);

                var succeeded = 0;
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine($"  [OK]   {result.RecordUid} -> {result.UserEmail} ({result.Role})");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"  [FAIL] {result.RecordUid} -> {result.UserEmail}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                    }
                }

                Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sharing Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample in-memory share payloads. Replace UIDs and emails before running.
        /// </summary>
        public static IReadOnlyList<KeeperNSFRecordShareRequest> BuildSampleShares()
        {
            return new[]
            {
                new KeeperNSFRecordShareRequest
                {
                    RecordUid = "<recordUid_1>",
                    UserEmail = "<userEmail_here>",
                    Role = "viewer",
                },
                new KeeperNSFRecordShareRequest
                {
                    RecordUid = "<recordUid_2>",
                    UserEmail = "<userEmail_here>",
                    Role = "content-manager",
                },
            };
        }
    }
}
