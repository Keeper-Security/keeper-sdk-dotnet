using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder update via <see cref="IVault.UpdateKeeperNSFFolders(System.Collections.Generic.IReadOnlyList{KeeperNSFFolderUpdateRequest})"/>.
    /// Independent of <see cref="UpdateKeeperNSFFolderExample"/>.
    /// Up to 100 folders per API request; larger lists are chunked automatically.
    /// </summary>
    public static class UpdateKeeperNSFFoldersBatchExample
    {
        /// <summary>
        /// Runs the batch folder-update API and prints per-folder results.
        /// </summary>
        public static async Task UpdateBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderUpdateRequest> folders)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (folders == null || folders.Count == 0)
            {
                Console.WriteLine("No folders to update.");
                return;
            }

            try
            {
                Console.WriteLine($"Updating {folders.Count} Keeper NSF folder(s) in batch...");
                var results = await vault.UpdateKeeperNSFFolders(folders);

                var succeeded = 0;
                foreach (var result in results)
                {
                    if (result.Success)
                    {
                        succeeded++;
                        Console.WriteLine($"  [OK]   {result.Name}  UID: {result.FolderUid}");
                    }
                    else
                    {
                        Console.WriteLine(
                            $"  [FAIL] {result.Name}  UID: {result.FolderUid}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                    }
                }

                Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF folders in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample in-memory folder update payloads. Replace UIDs before running.
        /// </summary>
        public static IReadOnlyList<KeeperNSFFolderUpdateRequest> BuildSampleUpdates()
        {
            return new[]
            {
                new KeeperNSFFolderUpdateRequest
                {
                    FolderUid = "<folderUid_1>",
                    Name = "Batch Update Demo - Renamed",
                    Color = "#4A90D9",
                },
                new KeeperNSFFolderUpdateRequest
                {
                    FolderUid = "<folderUid_2>",
                    Color = "none",
                },
                new KeeperNSFFolderUpdateRequest
                {
                    FolderUid = "<folderUid_3>",
                    InheritPermissions = false,
                },
            };
        }
    }
}
