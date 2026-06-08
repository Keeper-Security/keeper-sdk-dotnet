using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class CreateKeeperNSFFolder
    {
        public static async Task Create(
            VaultOnline vault,
            string folderName,
            string parentFolderUid = null,
            string color = null,
            bool inheritPermissions = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                var folderUid = await vault.CreateKeeperNSFFolder(
                    folderName, parentFolderUid, color, inheritPermissions);
                Console.WriteLine($"Keeper NSF folder '{folderName}' created (UID: {folderUid}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating Keeper NSF folder: {ex.Message}");
            }
        }
    }
}
