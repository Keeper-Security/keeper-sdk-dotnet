using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder access revoke via <see cref="IVault.RevokeKeeperNSFFolderAccesses"/>.
    /// Independent of <see cref="IVault.RevokeKeeperNSFFolderAccess"/>.
    /// Max 500 access entries per API request.
    /// </summary>
    public static class RevokeKeeperNSFFolderAccessesBatchExample
    {
        public static async Task RevokeBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderAccessRevokeRequest> revokes)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (revokes == null || revokes.Count == 0)
            {
                Console.WriteLine("No folder access revokes to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Revoking {revokes.Count} Keeper NSF folder access(es) in batch...");
                var results = await vault.RevokeKeeperNSFFolderAccesses(revokes);

                var succeeded = 0;
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine(
                            $"  [OK]   {result.FolderUid} -> {result.Accessor} ({result.AccessType})");
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
                Console.WriteLine($"Error revoking Keeper NSF folder access in batch: {ex.Message}");
            }
        }

        public static IReadOnlyList<KeeperNSFFolderAccessRevokeRequest> BuildSampleRevokes()
        {
            return new[]
            {
                new KeeperNSFFolderAccessRevokeRequest
                {
                    FolderUid = "<folderUid_1>",
                    Accessor = "<userEmail_here>",
                },
                new KeeperNSFFolderAccessRevokeRequest
                {
                    FolderUid = "<folderUid_1>",
                    Accessor = "<teamNameOrUid_here>",
                    AsTeam = true,
                },
            };
        }
    }
}
