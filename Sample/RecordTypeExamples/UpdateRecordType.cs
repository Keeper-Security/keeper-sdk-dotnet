using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class UpdateRecordTypeExample
    {
        public static async Task UpdateRecordType(string recordTypeId, string recordTypeData)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            var updatedRecord = await vault.UpdateRecordTypeAsync(recordTypeId, recordTypeData);

            Console.WriteLine($"Updated Record Type UID: {updatedRecord}");
        }
    }
}
