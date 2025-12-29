using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchScanExample
    {
        public static async Task BreachWatchScan(
            string recordUids,
            byte[] recordKey,
            string password)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var result = await vault.ScanAndStoreRecordStatusAsync(recordUids, recordKey, password);
                if (result == null)
                {
                    Console.WriteLine("BreachWatch Scan: No result returned.");
                    Console.WriteLine("  (Password may be empty or already scanned)");
                    return;
                }
                Console.WriteLine("======== BreachWatch Scan Result ========");
                Console.WriteLine($"Record UID:  {recordUids}");
                Console.WriteLine($"Status:      {result.Status}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
