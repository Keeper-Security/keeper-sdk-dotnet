using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.TrashExamples
{
    public static class TrashList
    {
        public static async Task TrashListAsync()
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            await TrashManagement.EnsureDeletedRecordsLoaded(vault);
            var deletedRecords = TrashManagement.GetDeletedRecords();
            var orphanedRecords = TrashManagement.GetOrphanedRecords();
            var sharedFolders = TrashManagement.GetSharedFolders();

            if (TrashManagement.IsTrashEmpty())
            {
                Console.WriteLine("Trash is empty");
                return;
            }

            foreach (var record in deletedRecords)
            {
                Console.WriteLine($"Deleted Record: {record.Key}");
            }

            foreach (var record in orphanedRecords)
            {
                Console.WriteLine($"Orphaned Record: {record.Key}");
            }

            foreach (var folder in sharedFolders.Folders)
            {
                Console.WriteLine($"Shared Folder: {folder.Key}");
            }
        }
    }
}