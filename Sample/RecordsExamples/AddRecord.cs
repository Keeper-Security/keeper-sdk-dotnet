using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;



namespace Sample.RecordsExamples
{
    class AddRecordExample
    {
        public static async Task AddRecord(string name, string type, string folderUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var CreatedRecord = await CreateRecordSimple(vault, name, type, folderUid);
            if (CreatedRecord == null)
            {
                Console.WriteLine("Record creation failed.");
                return;
            }
            else
            {
                Console.WriteLine($"Record Created: {CreatedRecord.Uid}");
            }
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
                var rt1 = vault.RecordTypes.FirstOrDefault(x => x.Name.Equals(recordType, StringComparison.OrdinalIgnoreCase));

                // foreach (var rt in vault.RecordTypes)
                // {
                //     Console.WriteLine(rt.Name);
                // }

                if (rt1 == null)
                {
                    Console.WriteLine($"Record type '{recordType}' not found.");
                    return null;
                }

                var typed = new TypedRecord(rt1.Name)
                {
                    Title = title
                };

                // Add all fields
                foreach (var fieldDef in rt1.Fields)
                {
                    try
                    {
                        typed.Fields.Add(fieldDef.CreateTypedField());
                    }
                    catch { }
                }

                record = typed;
            }

            try
            {
                var created = await vault.CreateRecord(record, folderUid);
                return created;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to create record: {ex.Message}");
                return null;
            }
        }
    }
}