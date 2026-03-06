using System;
using KeeperSecurity.Vault;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using BWIgnore = KeeperSecurity.BreachWatch.BreachWatchIgnore;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchIgnoreExample
    {
        public static async Task IgnoreRecord(VaultOnline vault, string recordUid)
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

                await BWIgnore.IgnoreRecord(vault, recordUid);
                Console.WriteLine($"Record '{recordUid}' has been ignored in BreachWatch.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task CheckIfIgnored(VaultOnline vault, string recordUid)
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
