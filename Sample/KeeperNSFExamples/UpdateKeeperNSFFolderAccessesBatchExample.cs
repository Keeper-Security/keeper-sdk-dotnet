using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder access updates via <see cref="IVault.UpdateKeeperNSFFolderAccesses"/>.
    /// Max 500 access entries per API request.
    /// </summary>
    public static class UpdateKeeperNSFFolderAccessesBatchExample
    {
        public static async Task UpdateBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderAccessUpdateRequest> updates)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (updates == null || updates.Count == 0)
            {
                Console.WriteLine("No folder access updates to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Updating {updates.Count} Keeper NSF folder access(es) in batch...");
                var results = await vault.UpdateKeeperNSFFolderAccesses(updates);

                var succeeded = 0;
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine(
                            $"  [OK]   {result.FolderUid} -> {result.Accessor} ({result.AccessType}/{result.Role})");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"  [FAIL] {result.FolderUid} -> {result.Accessor}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                    }
                }

                Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF folder access in batch: {ex.Message}");
            }
        }

        public static IReadOnlyList<KeeperNSFFolderAccessUpdateRequest> BuildSampleUpdates()
        {
            return new[]
            {
                new KeeperNSFFolderAccessUpdateRequest
                {
                    FolderUid = "<folderUid_1>",
                    Accessor = "<userEmail_here>",
                    Role = "content-manager",
                },
                new KeeperNSFFolderAccessUpdateRequest
                {
                    FolderUid = "<folderUid_1>",
                    Accessor = "<teamNameOrUid_here>",
                    Role = "full-manager",
                    AsTeam = true,
                },
            };
        }
    }
}
