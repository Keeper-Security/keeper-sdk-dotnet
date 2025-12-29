using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class CreateRecordTypeExample
    {
        public static async Task CreateRecordType(string recordTypeData)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            var createdRecord = await vault.AddRecordType(recordTypeData);

            Console.WriteLine($"Created Record Type UID: {createdRecord}");
        }
    }
}
