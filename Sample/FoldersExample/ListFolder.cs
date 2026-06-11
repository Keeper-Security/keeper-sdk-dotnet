using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.FoldersExample
{
    public static class ListFolderExample
    {
        public static async Task ListFolder(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            ListFolderSimple(vault);
        }

        public static void ListFolderSimple(VaultOnline vault)
        {
            var folders = new List<(string Uid, string Name, string Category, int Subfolders, int Records)>();

            foreach (var nsfFolder in vault.KeeperNSFFolderNodes)
            {
                folders.Add((
                    nsfFolder.FolderUid,
                    nsfFolder.Name,
                    "Nested Shared Folder",
                    nsfFolder.Subfolders.Count,
                    nsfFolder.Records.Count));
            }

            foreach (var folder in vault.Folders)
            {
                if (string.IsNullOrEmpty(folder.FolderUid))
                    continue;

                folders.Add((
                    folder.FolderUid,
                    folder.Name,
                    "Classic",
                    folder.Subfolders.Count,
                    folder.Records.Count));
            }

            folders = folders.OrderBy(f => f.Name).ToList();

            if (folders.Count == 0)
            {
                Console.WriteLine("No folders found.");
                return;
            }

            Console.WriteLine("Found {0} folder(s)", folders.Count);
            Console.WriteLine("{0,-30}  {1,-46}  {2,-22}  {3,-10}  {4,-8}",
                "Folder Name", "Folder UID", "Category", "Subfolders", "Records");
            Console.WriteLine(new string('-', 30) + "  " + new string('-', 46) + "  " +
                              new string('-', 22) + "  " + new string('-', 10) + "  " + new string('-', 8));

            foreach (var folder in folders)
            {
                Console.WriteLine("{0,-30}  {1,-46}  {2,-22}  {3,-10}  {4,-8}",
                    folder.Name, folder.Uid, folder.Category, folder.Subfolders, folder.Records);
            }
        }
    }
}