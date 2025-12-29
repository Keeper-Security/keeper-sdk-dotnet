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
            Console.WriteLine($"RecordKey:       {(record.RecordKey != null ? Convert.ToBase64String(record.RecordKey) : "N/A")}");

            Console.WriteLine($"Login:           {record.ExtractLogin() ?? "N/A"}");
            Console.WriteLine($"Password:        {record.ExtractPassword() ?? "N/A"}");
            Console.WriteLine($"URL:             {record.ExtractUrl() ?? "N/A"}");

            
            switch (record)
            {
                case PasswordRecord pr:
                    Console.WriteLine("\n-- Password Record Specific --");
                    Console.WriteLine($"Notes:           {pr.Notes}");
                    Console.WriteLine($"Link:            {pr.Link}");
                    Console.WriteLine($"Totp:            {pr.Totp}");
                    if (pr.Custom?.Any() == true)
                    {
                        Console.WriteLine("Custom Fields:");
                        foreach (var field in pr.Custom)
                        {
                            Console.WriteLine($"  {field.Name}: {field.Value}");
                        }
                    }
                    if (pr.Attachments?.Any() == true)
                    {
                        Console.WriteLine($"Attachments:     {pr.Attachments.Count} file(s)");
                    }
                    break;

                case TypedRecord tr:
                    Console.WriteLine("\n-- Typed Record Specific --");
                    Console.WriteLine($"TypeName:        {tr.TypeName}");
                    Console.WriteLine($"Notes:           {tr.Notes}");
                    if (tr.Fields?.Any() == true)
                    {
                        Console.WriteLine("Fields:");
                        foreach (var field in tr.Fields)
                        {
                            Console.WriteLine($"  [{field.FieldName}] {field.FieldLabel}");
                        }
                    }
                    if (tr.Custom?.Any() == true)
                    {
                        Console.WriteLine("Custom Fields:");
                        foreach (var field in tr.Custom)
                        {
                            Console.WriteLine($"  [{field.FieldName}] {field.FieldLabel}");
                        }
                    }
                    break;
            }

            Console.WriteLine("================================");
        }
    }
}