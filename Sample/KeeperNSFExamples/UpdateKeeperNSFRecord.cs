using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class UpdateKeeperNSFRecord
    {
        public static async Task Update(
            VaultOnline vault,
            string recordUid,
            string title = null,
            string recordType = null,
            string notes = null,
            IDictionary<string, string> fields = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.UpdateKeeperNSFRecord(recordUid, title, recordType, notes, fields);
                Console.WriteLine($"Keeper NSF record '{recordUid}' updated.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF record: {ex.Message}");
            }
        }
    }
}
