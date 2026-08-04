using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch NSF folder creation via <see cref="IVault.CreateKeeperNSFFolders"/>.
    /// Independent of <see cref="CreateKeeperNSFFolderExample"/>.
    /// Up to 100 folders per API request; larger lists are chunked automatically.
    /// </summary>
    public static class CreateKeeperNSFFoldersBatchExample
    {
        /// <summary>
        /// Runs the batch folder-create API and prints per-folder results.
        /// </summary>
        public static async Task CreateBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFFolderCreateRequest> folders)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (folders == null || folders.Count == 0)
            {
                Console.WriteLine("No folders to create.");
                return;
            }

            try
            {
                Console.WriteLine($"Creating {folders.Count} Keeper NSF folder(s) in batch...");
                var results = await vault.CreateKeeperNSFFolders(folders);

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
                            $"  [FAIL] {result.Name}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                    }
                }

                Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating Keeper NSF folders in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Sample in-memory folder payloads. Replace parent UIDs before running child folders.
        /// </summary>
        public static IReadOnlyList<KeeperNSFFolderCreateRequest> BuildSampleFolders()
        {
            return new[]
            {
                new KeeperNSFFolderCreateRequest
                {
                    Name = "Batch Demo - Root Folder",
                    Color = "red",
                    InheritPermissions = true,
                },
                new KeeperNSFFolderCreateRequest
                {
                    Name = "Batch Demo - Child Folder",
                    ParentFolderUid = "<parentFolderUid_here>",
                    Color = "green",
                    InheritPermissions = true,
                },
                new KeeperNSFFolderCreateRequest
                {
                    Name = "Batch Demo - No Inherit",
                    ParentFolderUid = "<parentFolderUid_here>",
                    InheritPermissions = false,
                },
            };
        }
    }
}
