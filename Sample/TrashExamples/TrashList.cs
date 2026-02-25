using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
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

            var deletedRecords = TrashManagement.GetDeletedRecords().Values.ToList();
            var orphanedRecords = TrashManagement.GetOrphanedRecords().Values.ToList();
            var sharedFolders = TrashManagement.GetSharedFolders();

            Console.WriteLine("======== Trash Contents ========\n");

            if (deletedRecords.Count > 0)
            {
                Console.WriteLine($"-- Deleted Records ({deletedRecords.Count}) --");
                foreach (var record in deletedRecords)
                {
                    var title = GetRecordTitle(record);
                    Console.WriteLine($"  UID: {record.RecordUid,-30} Title: {title}");
                }
                Console.WriteLine();
            }

            if (orphanedRecords.Count > 0)
            {
                Console.WriteLine($"-- Orphaned Records ({orphanedRecords.Count}) --");
                foreach (var record in orphanedRecords)
                {
                    var title = GetRecordTitle(record);
                    Console.WriteLine($"  UID: {record.RecordUid,-30} Title: {title}");
                }
                Console.WriteLine();
            }

            if (sharedFolders?.Folders != null && sharedFolders.Folders.Any())
            {
                Console.WriteLine($"-- Shared Folders ({sharedFolders.Folders.Count}) --");
                foreach (var folder in sharedFolders.Folders.Values)
                {
                    var name = GetFolderName(folder);
                    Console.WriteLine($"  UID: {folder.SharedFolderUidString,-30} Name: {name}");
                }
                Console.WriteLine();
            }

            Console.WriteLine("================================");
            Console.WriteLine($"Total: {deletedRecords.Count} deleted, {orphanedRecords.Count} orphaned, {sharedFolders?.Folders?.Count ?? 0} shared folders");
        }

        private static string GetRecordTitle(DeletedRecord record)
        {
            if (record?.DataUnencrypted == null || record.DataUnencrypted.Length == 0)
            {
                return "";
            }

            try
            {
                var data = JsonUtils.ParseJson<Dictionary<string, object>>(record.DataUnencrypted);
                if (data != null && data.TryGetValue("title", out var titleObj))
                {
                    return titleObj?.ToString() ?? "";
                }
            }
            catch { }

            return "";
        }
        
        private static string GetFolderName(DeletedSharedFolder folder)
        {
            if (folder?.DataUnEncrypted == null || folder.DataUnEncrypted.Length == 0)
            {
                return folder?.SharedFolderUidString ?? "";
            }

            try
            {
                var folderData = JsonUtils.ParseJson<FolderData>(folder.DataUnEncrypted);
                return folderData?.name ?? folder.SharedFolderUidString ?? "";
            }
            catch { }

            return folder?.SharedFolderUidString ?? "";
        }
    }
}
