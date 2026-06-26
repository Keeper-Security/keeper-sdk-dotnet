using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class UpdateKeeperNSFRecordExample
    {
        public static async Task Update(
            VaultOnline vault,
            string recordUid,
            string title = null,
            string recordType = null,
            string notes = null,
            IDictionary<string, object> fields = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.UpdateKeeperNSFRecord(
                    recordUid, title, recordType, notes, ToStringFields(fields));
                Console.WriteLine($"Keeper NSF record '{recordUid}' updated.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF record: {ex.Message}");
            }
        }

        private static IDictionary<string, object> ToStringFields(IDictionary<string, object> fields)
        {
            if (fields == null) return null;

            var result = new Dictionary<string, object>();
            foreach (var kvp in fields)
            {
                result[kvp.Key] = kvp.Value?.ToString();
            }

            return result;
        }
    }
}
