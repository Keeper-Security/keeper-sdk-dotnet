using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    public static class AddRecordExample
    {
        public static async Task AddRecord(VaultOnline vault, string name, string type, string folderUid)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var createdRecord = await CreateRecordSimple(vault, name, type, folderUid);

            if (createdRecord == null)
            {
                Console.WriteLine("Record creation failed.");
                return;
            }

            Console.WriteLine($"Record Created: {createdRecord.Uid}");
        }

        private static async Task<KeeperRecord> CreateRecordSimple(
            VaultOnline vault,
            string title,
            string recordType,
            string folderUid)
        {
            if (vault == null)
            {
                Console.WriteLine("Vault reference is null.");
                return null;
            }

            if (string.IsNullOrWhiteSpace(title))
            {
                Console.WriteLine("Title is required.");
                return null;
            }

            if (string.IsNullOrWhiteSpace(recordType))
            {
                Console.WriteLine("Record type is required.");
                return null;
            }

            if (!string.IsNullOrWhiteSpace(folderUid) &&
                !vault.Folders.Any(f => f.FolderUid == folderUid))
            {
                Console.WriteLine($"Folder UID '{folderUid}' not found.");
                return null;
            }

            KeeperRecord record;
            if (string.Equals(recordType, "general", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(recordType, "legacy", StringComparison.OrdinalIgnoreCase))
            {
                record = new PasswordRecord
                {
                    Title = title
                };
            }
            else
            {
                var recordTypeDefinition = vault.RecordTypes
                    .FirstOrDefault(x => x.Name.Equals(recordType, StringComparison.OrdinalIgnoreCase));

                if (recordTypeDefinition == null)
                {
                    Console.WriteLine($"Record type '{recordType}' not found.");
                    return null;
                }

                var typed = new TypedRecord(recordTypeDefinition.Name)
                {
                    Title = title
                };

                foreach (var fieldDef in recordTypeDefinition.Fields)
                {
                    try
                    {
                        typed.Fields.Add(fieldDef.CreateTypedField());
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to create field '{fieldDef.FieldName}': {ex.Message}");
                    }
                }

                record = typed;
            }

            try
            {
                return await vault.CreateRecord(record, folderUid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to create record: {ex.Message}");
                return null;
            }
        }
    }
}