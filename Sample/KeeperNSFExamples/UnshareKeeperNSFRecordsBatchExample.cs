using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF record unshare via <see cref="IVault.UnshareKeeperNSFRecords"/>.
    /// Independent of <see cref="IVault.UnshareKeeperNSFRecord"/>.
    /// </summary>
    public static class UnshareKeeperNSFRecordsBatchExample
    {
        /// <summary>
        /// Runs the batch record-unshare API and prints per-entry results.
        /// </summary>
        public static async Task UnshareBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordUnshareRequest> unshares)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (unshares == null || unshares.Count == 0)
            {
                Console.WriteLine("No unshares to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Revoking {unshares.Count} Keeper NSF record access(es) in batch...");
                var results = await vault.UnshareKeeperNSFRecords(unshares);

                var succeeded = 0;
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine($"  [OK]   {result.RecordUid} -> {result.UserEmail}");
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
                Console.WriteLine($"Error unsharing Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample in-memory unshare payloads. Replace UIDs and emails before running.
        /// </summary>
        public static IReadOnlyList<KeeperNSFRecordUnshareRequest> BuildSampleUnshares()
        {
            return new[]
            {
                new KeeperNSFRecordUnshareRequest
                {
                    RecordUid = "<recordUid_1>",
                    UserEmail = "<userEmail_here>",
                },
                new KeeperNSFRecordUnshareRequest
                {
                    RecordUid = "<recordUid_2>",
                    UserEmail = "<userEmail_here>",
                },
            };
        }
    }
}
