using System;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;


namespace Sample.FoldersExample
{
    internal static class CreateFolder
    {
        public static async Task CreateNewFolder(string folderName, string parentFolderUid = null, SharedFolderOptions sharedFolderOptions = null)
        {
            var Vault = await AuthenticateAndGetVault.GetVault();
            var result = await Vault.CreateFolder(folderName, parentFolderUid: parentFolderUid, sharedFolderOptions: sharedFolderOptions);
            Console.WriteLine($"Folder '{folderName}' created with UID: {result.FolderUid}");
        }
    }
}
