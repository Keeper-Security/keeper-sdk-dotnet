using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class LinkKeeperNSFRecordToFolder
    {
        public static async Task Link(
            VaultOnline vault,
            string recordUidOrTitle,
            string folderUidOrName)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.LinkKeeperNSFRecordToFolder(recordUidOrTitle, folderUidOrName);
                Console.WriteLine($"Linked record '{recordUidOrTitle}' into folder '{folderUidOrName}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error linking Keeper NSF record: {ex.Message}");
            }
        }
    }
}
