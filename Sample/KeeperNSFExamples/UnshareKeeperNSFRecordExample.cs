using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class UnshareKeeperNSFRecordExample
    {
        public static async Task Unshare(VaultOnline vault, string recordUid, string userEmail)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.UnshareKeeperNSFRecord(recordUid, userEmail);
                Console.WriteLine($"Removed share of record {recordUid} from {userEmail}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error unsharing Keeper NSF record: {ex.Message}");
            }
        }
    }
}
