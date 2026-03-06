using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.FoldersExample
{
    internal static class MoveFolderExample
    {
        public static async Task MoveExistingFolder(VaultOnline vault, string folderUid, string newParentFolderUid, bool link = false)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            await vault.MoveFolder(folderUid, newParentFolderUid, link);
        }
    }
}