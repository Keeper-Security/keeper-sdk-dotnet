using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class DeleteRecordTypeExample
    {
        public static async Task DeleteRecordType(string recordTypeId)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            var deletedRecord = await vault.DeleteRecordTypeAsync(recordTypeId);

            Console.WriteLine($"Deleted Record Type UID: {deletedRecord}");
        }
    }
}
