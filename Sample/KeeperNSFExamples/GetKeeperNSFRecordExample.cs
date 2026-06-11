using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class GetKeeperNSFRecordExample
    {
        public static async Task ShowDetails(VaultOnline vault, string recordUidOrTitle)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (!vault.TryResolveKeeperNSFRecord(recordUidOrTitle, out var record))
            {
                Console.WriteLine($"Keeper NSF record '{recordUidOrTitle}' not found.");
                return;
            }

            Console.WriteLine("======== Keeper NSF Record ========");
            Console.WriteLine($"UID:       {record.RecordUid}");
            Console.WriteLine($"Title:     {record.Title}");
            Console.WriteLine($"Type:      {record.Type}");
            Console.WriteLine($"Version:   {record.Version}");
            Console.WriteLine($"Revision:  {record.Revision}");
            Console.WriteLine($"Shared:    {record.Shared}");
            if (!string.IsNullOrEmpty(record.Notes))
            {
                Console.WriteLine($"Notes:     {record.Notes}");
            }

            var folders = vault.GetKeeperNSFFoldersForRecord(record.RecordUid).ToList();
            if (folders.Count > 0)
            {
                Console.WriteLine("Folders:   " + string.Join(", ", folders));
            }

            if (record.Fields != null && record.Fields.Count > 0)
            {
                Console.WriteLine("Fields:");
                foreach (var field in record.Fields)
                {
                    var value = field.Value != null ? string.Join(", ", field.Value) : "";
                    Console.WriteLine($"  {field.Type}: {value}");
                }
            }

            Console.WriteLine("===================================");
        }
    }
}
