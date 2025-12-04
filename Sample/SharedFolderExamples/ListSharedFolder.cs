using System;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderExamples
{
    public static class ListSharedFolder
    {
        public static async Task ListAllSharedFolders()
        {
            var Vault = await AuthenticateAndGetVault.GetVault();
            var sharedFolders = Vault.SharedFolders;
            Console.WriteLine("{0,-30}  {1,-46}", "Record UID", "Record Title");
            Console.WriteLine(new string('-', 30) + "  " + new string('-', 46));
            foreach (var folder in sharedFolders)
            {
                Console.WriteLine("{0,-30}  {1,-46}", folder.Name, folder.Uid);
            }

        }
    }
}