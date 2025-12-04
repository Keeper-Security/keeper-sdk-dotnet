using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;


namespace Sample.FoldersExample
{
    public static class ListFolderExample
    {
        public static async Task ListFolder()
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            ListFolderSimple(vault);
        }

        public static void ListFolderSimple(VaultOnline vault)
        {
            Console.WriteLine("{0,-30}  {1,-46}", "Folder Name", "Folder UID");
            Console.WriteLine(new string('-', 30) + "  " + new string('-', 46));

            foreach (var folder in vault.Folders)
            {
                Console.WriteLine("{0,-30}  {1,-46}", folder.Name, folder.FolderUid);
            }
        }

    }
}