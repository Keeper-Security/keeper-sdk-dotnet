using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class ListKeeperNSFFolders
    {
        public static async Task ListAll(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var folders = vault.KeeperNSFFolderNodes.ToList();
            if (folders.Count == 0)
            {
                Console.WriteLine("No Keeper NSF folders found.");
                return;
            }

            Console.WriteLine("{0,-4}  {1,-40}  {2,-30}  {3,-10}  {4,-10}",
                "#", "Folder UID", "Name", "Subfolders", "Records");
            Console.WriteLine(new string('-', 100));

            var index = 1;
            foreach (var folder in folders)
            {
                Console.WriteLine("{0,-4}  {1,-40}  {2,-30}  {3,-10}  {4,-10}",
                    index, folder.FolderUid, folder.Name, folder.Subfolders.Count, folder.Records.Count);
                index++;
            }

            Console.WriteLine($"\nTotal: {folders.Count} Keeper NSF folder(s)");
        }
    }
}
