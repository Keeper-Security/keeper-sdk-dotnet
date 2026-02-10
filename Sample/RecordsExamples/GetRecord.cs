using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    class GetRecordExample
    {
        public async Task GetRecordDetails(string recordUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var found = vault.TryGetKeeperRecord(recordUid, out var record);

            if (!found || record == null)
            {
                Console.WriteLine("Record not found.");
                return;
            }

            Console.WriteLine("======== Record Details ========");

            Console.WriteLine($"UID:             {record.Uid}");
            Console.WriteLine($"Title:           {record.Title}");
            Console.WriteLine($"Version:         {record.Version}");
            Console.WriteLine($"Revision:        {record.Revision}");
            Console.WriteLine($"ClientModified:  {record.ClientModified}");
            Console.WriteLine($"Owner:           {record.Owner}");
            Console.WriteLine($"Shared:          {record.Shared}");

            switch (record)
            {
                case PasswordRecord pr:
                    Console.WriteLine("\n-- Password Record Specific --");
                    Console.WriteLine($"Has Notes:       {!string.IsNullOrEmpty(pr.Notes)}");
                    Console.WriteLine($"Has Link:        {!string.IsNullOrEmpty(pr.Link)}");
                    Console.WriteLine($"Custom Fields:   {pr.Custom?.Count ?? 0}");
                    Console.WriteLine($"Attachments:     {pr.Attachments?.Count ?? 0}");
                    break;

                case TypedRecord tr:
                    Console.WriteLine("\n-- Typed Record Specific --");
                    Console.WriteLine($"TypeName:        {tr.TypeName}");
                    Console.WriteLine($"Has Notes:       {!string.IsNullOrEmpty(tr.Notes)}");
                    Console.WriteLine($"Fields Count:    {tr.Fields?.Count ?? 0}");
                    Console.WriteLine($"Custom Fields:   {tr.Custom?.Count ?? 0}");
                    break;
            }

            Console.WriteLine("================================");
        }
    }
}
