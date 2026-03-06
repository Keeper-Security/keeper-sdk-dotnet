using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    public class ListRecordExample
    {
        public static async Task ListAllRecords(VaultOnline vault = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var records = vault.KeeperRecords;

            Console.WriteLine($"Total Records: {records.Count()}");
            Console.WriteLine("{0,-30}  {1,-46}", "Record UID", "Record Title");
            Console.WriteLine(new string('-', 30) + "  " + new string('-', 46));
            foreach (var record in records)
            {
                Console.WriteLine("{0,-30}  {1,-46}", record.Uid, record.Title);

            }
        }
    }
}