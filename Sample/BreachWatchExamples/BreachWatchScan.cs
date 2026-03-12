using System;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Vault;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchScanExample
    {
        public static async Task BreachWatchScan(VaultOnline vault,
            string recordUid,
            byte[] recordKey,
            string password)
        {
            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID is required.");
                return;
            }

            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {

                if (!vault.Auth.IsBreachWatchEnabled())
                {
                    Console.WriteLine("BreachWatch is not enabled for this account.");
                    return;
                }

                var result = await vault.ScanAndStoreRecordStatusAsync(recordUid, recordKey, password);
                if (result == null)
                {
                    Console.WriteLine("BreachWatch Scan: No result returned.");
                    Console.WriteLine("  (Password may be empty or already scanned)");
                    return;
                }

                Console.WriteLine("======== BreachWatch Scan Result ========");
                Console.WriteLine($"Record UID:  {recordUid}");
                Console.WriteLine($"Status:      {result.Status}");
                Console.WriteLine("=========================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
