using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.FoldersExample
{
    public static class RemoveFolderExample
    {
        public static async Task RemoveFolder(VaultOnline vault, string folderUid)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
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