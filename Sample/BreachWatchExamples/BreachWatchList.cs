using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Vault;
using Tokens;

namespace Sample.BreachWatchExamples
{
    public static class BreachWatchListExample
    {
        public static async Task BreachWatchList(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {

                if (!vault.Auth.IsBreachWatchEnabled())
                {
                    Console.WriteLine("BreachWatch is not enabled for this account.");
                    return;
                }

                var records = vault.BreachWatchRecords()
                    .Where(x => x.Status == BWStatus.Weak || x.Status == BWStatus.Breached)
                    .Where(x => !BreachWatchIgnore.IsRecordIgnored(vault, x.RecordUid))
                    .ToList();

                if (!records.Any())
                {
                    Console.WriteLine("No weak or breached records found.");
                    return;
                }

                Console.WriteLine($"Found {records.Count} weak or breached record(s):\n");
                Console.WriteLine($"{"Title",-30} {"Record UID",-25} {"Status",-12} {"Total",-8} {"Resolved"}");
                Console.WriteLine(new string('-', 90));

                foreach (var bwRecord in records)
                {
                    var title = "Unknown";
                    if (vault.TryGetKeeperRecord(bwRecord.RecordUid, out var record))
                    {
                        title = record.Title ?? "Untitled";
                    }

                    Console.WriteLine($"{title,-30} {bwRecord.RecordUid,-25} {bwRecord.Status,-12} {bwRecord.Total,-8} {bwRecord.Resolved}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
