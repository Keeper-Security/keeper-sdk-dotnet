using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class CreateKeeperNSFRecord
    {
        public static async Task Create(
            VaultOnline vault,
            string title,
            string recordType = "general",
            string folderUid = null,
            string notes = null,
            IDictionary<string, string> fields = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                var recordUid = await vault.CreateKeeperNSFRecord(title, recordType, folderUid, notes, fields);
                Console.WriteLine($"Keeper NSF record '{title}' created (UID: {recordUid}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating Keeper NSF record: {ex.Message}");
            }
        }
    }
}
