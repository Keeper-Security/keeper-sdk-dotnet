using KeeperSecurity.Vault;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Sample.RecordsExamples
{
    public static class UpdateRecordExample
    {
        public static async Task UpdateRecord(VaultOnline vault, string recordUid, string newTitle, string newRecordType)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            await UpdateRecordSimple(
                vault,
                recordUid,
                newTitle,
                newRecordType
            );


        }
        private static async Task UpdateRecordSimple(
            VaultOnline vault,
            string recordUid,
            string newTitle,
            string newRecordType
        )
        {
            if (vault == null)
            {
                Console.WriteLine("Vault reference is null.");
                return;
            }

            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID is required.");
                return;
            }

            if (!vault.TryGetKeeperRecord(recordUid, out var record))
            {
                Console.WriteLine($"Record '{recordUid}' not found.");
                return;
            }

            Console.WriteLine($"Record loaded: {record.Title} ({recordUid})");

            if (!string.IsNullOrWhiteSpace(newRecordType))
            {
                if (record is TypedRecord typed)
                {
                    var rt = vault.RecordTypes
                        .FirstOrDefault(x =>
                            x.Name.Equals(newRecordType, StringComparison.OrdinalIgnoreCase));

                    if (rt == null)
                    {
                        Console.WriteLine($"Record type '{newRecordType}' not found.");
                        return;
                    }

                    typed.TypeName = rt.Name;
                    Console.WriteLine($"Record type changed to {rt.Name}");
                }
                else
                {
                    Console.WriteLine("Cannot change type of legacy/general record.");
                    return;
                }
            }

            if (!string.IsNullOrWhiteSpace(newTitle))
            {
                record.Title = newTitle;
                Console.WriteLine($"Title updated → {newTitle}");
            }
            await vault.UpdateRecord(record);
            Console.WriteLine("Record updated successfully.");
        }
    }
}
