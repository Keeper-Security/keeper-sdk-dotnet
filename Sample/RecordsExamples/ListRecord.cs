using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    public class ListRecordExample
    {
        public static async Task ListAllRecords()
        {
            var vault = await AuthenticateAndGetVault.GetVault();
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