using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class LoadRecordTypeExample
    {
        public static async Task LoadRecordType(VaultOnline vault, string recordTypeData)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var createdRecord = await vault.AddRecordType(recordTypeData);

            Console.WriteLine($"Created Record Type UID: {createdRecord}");
        }
    }
}
