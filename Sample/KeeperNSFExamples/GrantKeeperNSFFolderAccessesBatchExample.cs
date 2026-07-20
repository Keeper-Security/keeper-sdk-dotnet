using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder access grants via <see cref="IVault.GrantKeeperNSFFolderAccesses"/>.
    /// Independent of <see cref="IVault.GrantKeeperNSFFolderAccess"/>.
    /// Max 500 access entries per API request.
    /// </summary>
    public static class GrantKeeperNSFFolderAccessesBatchExample
    {
        public static async Task GrantBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderAccessGrantRequest> grants)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (grants == null || grants.Count == 0)
            {
                Console.WriteLine("No folder access grants to process.");
                return;
            }

            try
            {
                Console.WriteLine($"Granting {grants.Count} Keeper NSF folder access(es) in batch...");
                var results = await vault.GrantKeeperNSFFolderAccesses(grants);

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
                Console.WriteLine($"Error granting Keeper NSF folder access in batch: {ex.Message}");
            }
        }

        public static IReadOnlyList<KeeperNSFFolderAccessGrantRequest> BuildSampleGrants()
        {
            return new[]
            {
                new KeeperNSFFolderAccessGrantRequest
                {
                    FolderUid = "<folderUid_1>",
                    Accessor = "<userEmail_here>",
                    Role = "viewer",
                },
                new KeeperNSFFolderAccessGrantRequest
                {
                    FolderUid = "<folderUid_1>",
                    Accessor = "<teamNameOrUid_here>",
                    Role = "content-manager",
                    AsTeam = true,
                },
            };
        }
    }
}
