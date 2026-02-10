using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderExamples
{
    public static class ListSharedFolder
    {
        public static async Task ListAllSharedFolders()
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Authentication failed. Vault is null.");
                return;
            }

            var sharedFolders = vault.SharedFolders.ToList();

            if (sharedFolders.Count == 0)
            {
                Console.WriteLine("No shared folders found.");
                return;
            }

            Console.WriteLine("{0,-4}  {1,-40}  {2,-30}", "#", "Folder UID", "Folder Name");
            Console.WriteLine(new string('-', 80));

            int index = 1;
            foreach (var folder in sharedFolders)
            {
                Console.WriteLine("{0,-4}  {1,-40}  {2,-30}", index, folder.Uid, folder.Name);
                index++;
            }

            Console.WriteLine($"\nTotal: {sharedFolders.Count} shared folder(s)");
        }
    }
}
