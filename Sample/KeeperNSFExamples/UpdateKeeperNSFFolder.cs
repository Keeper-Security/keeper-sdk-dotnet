using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class UpdateKeeperNSFFolder
    {
        public static async Task RenameOrRecolor(
            VaultOnline vault,
            string folderUidOrName,
            string newName = null,
            string color = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.UpdateKeeperNSFFolder(folderUidOrName, newName, color);
                Console.WriteLine($"Keeper NSF folder '{folderUidOrName}' updated.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF folder: {ex.Message}");
            }
        }
    }
}
