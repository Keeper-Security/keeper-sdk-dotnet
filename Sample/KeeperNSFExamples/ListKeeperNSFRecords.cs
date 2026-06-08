using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class ListKeeperNSFRecords
    {
        public static async Task ListAll(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var records = vault.KeeperNSFRecordEntries.ToList();
            if (records.Count == 0)
            {
                Console.WriteLine("No Keeper NSF records found.");
                return;
            }

            Console.WriteLine("{0,-4}  {1,-40}  {2,-30}  {3,-15}  {4,-8}",
                "#", "Record UID", "Title", "Type", "Shared");
            Console.WriteLine(new string('-', 105));

            var index = 1;
            foreach (var record in records)
            {
                Console.WriteLine("{0,-4}  {1,-40}  {2,-30}  {3,-15}  {4,-8}",
                    index, record.RecordUid, record.Title, record.Type ?? "(none)", record.Shared);
                index++;
            }

            Console.WriteLine($"\nTotal: {records.Count} Keeper NSF record(s)");
        }
    }
}
