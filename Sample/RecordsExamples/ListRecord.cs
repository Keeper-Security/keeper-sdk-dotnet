using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    public class ListRecordExample
    {
        public static async Task ListAllRecords(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var records = new List<(string Uid, string Name, string Type, string Category, bool Shared)>();

            foreach (var record in vault.KeeperNSFRecordEntries)
            {
                records.Add((
                    record.RecordUid,
                    record.Title ?? string.Empty,
                    record.Type ?? "Unknown",
                    "Nested",
                    record.Shared));
            }

            foreach (var record in vault.KeeperRecords)
            {
                if (record.Version != 2 && record.Version != 3)
                    continue;

                records.Add((
                    record.Uid,
                    record.Title ?? string.Empty,
                    record.KeeperRecordType(),
                    "Classic",
                    record.Shared));
            }

            records = records.OrderBy(r => r.Name).ToList();

            if (records.Count == 0)
            {
                Console.WriteLine("No records found.");
                return;
            }

            Console.WriteLine("Found {0} record(s)", records.Count);
            Console.WriteLine("{0,-30}  {1,-46}  {2,-16}  {3,-22}  {4,-8}",
                "Record Title", "Record UID", "Type", "Category", "Shared");
            Console.WriteLine(new string('-', 30) + "  " + new string('-', 46) + "  " +
                              new string('-', 16) + "  " + new string('-', 22) + "  " + new string('-', 8));

            foreach (var record in records)
            {
                Console.WriteLine("{0,-30}  {1,-46}  {2,-16}  {3,-22}  {4,-8}",
                    record.Name, record.Uid, record.Type, record.Category, record.Shared);
            }
        }
    }
}
