using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;

namespace Sample.FoldersExample
{
    internal static class MoveFolderExample
    {
        public static async Task MoveExistingFolder(string folderUid, string newParentFolderUid, bool link = false)
        {
            var Vault = await AuthenticateAndGetVault.GetVault();
            await Vault.MoveFolder(folderUid, newParentFolderUid, link);
        }
    }
}