using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class DeleteRecordTypeExample
    {
        public static async Task DeleteRecordType(VaultOnline vault, string recordTypeId)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var deletedRecord = await vault.DeleteRecordTypeAsync(recordTypeId);

            Console.WriteLine($"Deleted Record Type UID: {deletedRecord}");
        }
    }
}
