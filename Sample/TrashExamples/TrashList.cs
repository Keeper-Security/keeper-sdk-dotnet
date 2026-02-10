using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.TrashExamples
{
    public static class TrashList
    {
        public static async Task TrashListAsync()
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Authentication failed. Vault is null.");
                return;
            }

            await TrashManagement.EnsureDeletedRecordsLoaded(vault);

            if (TrashManagement.IsTrashEmpty())
            {
                Console.WriteLine("Trash is empty.");
                return;
            }

            var deletedRecords = TrashManagement.GetDeletedRecords().ToList();
            var orphanedRecords = TrashManagement.GetOrphanedRecords().ToList();
            var sharedFolders = TrashManagement.GetSharedFolders();

            Console.WriteLine("======== Trash Contents ========\n");

            if (deletedRecords.Count > 0)
            {
                Console.WriteLine($"-- Deleted Records ({deletedRecords.Count}) --");
                foreach (var record in deletedRecords)
                {
                    Console.WriteLine($"  UID: {record.UID,-30} Title: {record.Title}");
                }
                Console.WriteLine();
            }

            if (orphanedRecords.Count > 0)
            {
                Console.WriteLine($"-- Orphaned Records ({orphanedRecords.Count}) --");
                foreach (var record in orphanedRecords)
                {
                    Console.WriteLine($"  UID: {record.UID,-30} Title: {record.Title}");
                }
                Console.WriteLine();
            }

            if (sharedFolders?.Folders != null && sharedFolders.Folders.Any())
            {
                Console.WriteLine($"-- Shared Folders ({sharedFolders.Folders.Count()}) --");
                foreach (var folder in sharedFolders.Folders)
                {
                    Console.WriteLine($"  UID: {folder.UID,-30} Name: {folder.Name}");
                }
                Console.WriteLine();
            }

            Console.WriteLine("================================");
            Console.WriteLine($"Total: {deletedRecords.Count} deleted, {orphanedRecords.Count} orphaned, {sharedFolders?.Folders?.Count() ?? 0} shared folders");
        }
    }
}
