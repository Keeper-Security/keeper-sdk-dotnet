using System;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Vault;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchScanExample
    {
        public static async Task BreachWatchScan(
            string recordUid,
            byte[] recordKey,
            string password)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(recordUid))
                {
                    Console.WriteLine("Record UID is required.");
                    return;
                }

                var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Authentication failed. Vault is null.");
                    return;
                }

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
