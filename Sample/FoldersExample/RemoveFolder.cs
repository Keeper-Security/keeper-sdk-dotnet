using System;
using System.IO;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Drawing;

namespace Sample.FoldersExample
{
    public static class RemoveFolderExample
    {
        public static async Task RemoveFolder(string folderUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var folder = vault.GetFolder(folderUid);

            if (folder == null)
            {
                Console.WriteLine($"Folder with UID '{folderUid}' not found.");
                return;
            }

            try
            {
                await vault.DeleteFolder(folderUid);
                Console.WriteLine($"Folder '{folder.Name}' ({folderUid}) removed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to remove folder '{folder.Name}': {ex.Message}");
            }
        }
    }
}