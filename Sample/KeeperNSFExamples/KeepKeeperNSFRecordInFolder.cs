using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class KeepKeeperNSFRecordInFolder
    {
        public static async Task KeepInFolder(
            VaultOnline vault,
            string recordUid,
            string keepFolderUid)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                var result = await vault.KeepKeeperNSFRecordInFolder(recordUid, keepFolderUid);
                Console.WriteLine($"Kept record {recordUid} in folder {keepFolderUid}.");
                Console.WriteLine($"  Removed from {result.Removals?.Count ?? 0} other folder(s).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error keeping record in folder: {ex.Message}");
            }
        }
    }
}
