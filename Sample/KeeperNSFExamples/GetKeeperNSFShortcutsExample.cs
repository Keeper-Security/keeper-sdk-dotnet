using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class GetKeeperNSFShortcutsExample
    {
        public static async Task ListShortcuts(
            VaultOnline vault = null,
            string recordUid = null,
            string folderUid = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var shortcuts = vault.GetKeeperNSFShortcuts(recordUid, folderUid);
            if (shortcuts == null || shortcuts.Count == 0)
            {
                Console.WriteLine("No Keeper NSF shortcuts found.");
                return;
            }

            foreach (var entry in shortcuts)
            {
                Console.WriteLine($"Record: {entry.RecordUid} ({entry.Title})");
                foreach (var folder in entry.Folders)
                {
                    Console.WriteLine($"  Folder: {folder.FolderUid} ({folder.Name})");
                }
            }

            Console.WriteLine($"\nTotal: {shortcuts.Count} shortcut(s)");
        }
    }
}
