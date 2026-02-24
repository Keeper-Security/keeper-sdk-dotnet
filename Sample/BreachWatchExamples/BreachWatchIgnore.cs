using System;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using BWIgnore = KeeperSecurity.BreachWatch.BreachWatchIgnore;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchIgnoreExample
    {
        public static async Task IgnoreRecord(string recordUid)
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

                await BWIgnore.IgnoreRecord(vault, recordUid);
                Console.WriteLine($"Record '{recordUid}' has been ignored in BreachWatch.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task CheckIfIgnored(string recordUid)
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

                var isIgnored = BWIgnore.IsRecordIgnored(vault, recordUid);
                Console.WriteLine($"Record '{recordUid}' ignored: {isIgnored}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
