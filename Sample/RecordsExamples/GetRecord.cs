using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    class GetRecordExample
    {
        public async Task GetRecordDetails(string recordUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var requiredRecord = GetRecordFromVaultWithUid(vault, recordUid);

            if (requiredRecord != null)
            {
                Console.WriteLine($"Record found: {requiredRecord.Uid}");
                PrintRecordDetails(requiredRecord);
            }
            else
            {
                Console.WriteLine("Record not found.");
            }
        }

        private KeeperRecord GetRecordFromVaultWithUid(VaultOnline vault, string recordUid)
        {
            var cleanedUid = recordUid.Trim();
            return vault.KeeperRecords
                .Where(x => x.Version == 2 || x.Version == 3)
                .FirstOrDefault(x => string.Equals(
                    x.Uid, cleanedUid, StringComparison.InvariantCultureIgnoreCase));
        }

        private static void PrintRecordDetails(KeeperRecord record)
        {
            Console.WriteLine("---- Record Details ----");

            var props = record.GetType().GetProperties();
            foreach (var prop in props)
            {
                var value = prop.GetValue(record);

                if (value is System.Collections.IEnumerable list && !(value is string))
                {

                    if (prop.Name == "Fields")
                    {
                        continue;
                    }
                    Console.WriteLine($"{prop.Name}:");
                    foreach (var item in list)
                    {
                        Console.WriteLine($"  - {item}");
                    }
                }
                else
                {
                    Console.WriteLine($"{prop.Name}: {value}");
                }
            }

            Console.WriteLine("------------------------");
        }


    }
}