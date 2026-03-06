using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;


namespace Sample.FoldersExample
{
    internal static class CreateFolder
    {
        public static async Task CreateNewFolder(VaultOnline vault, string folderName, string parentFolderUid = null, SharedFolderOptions sharedFolderOptions = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var result = await vault.CreateFolder(folderName, parentFolderUid: parentFolderUid, sharedFolderOptions: sharedFolderOptions);
            Console.WriteLine($"Folder '{folderName}' created with UID: {result.FolderUid}");
        }
    }
}
