using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class LoadRecordTypeExample
    {
        public static async Task LoadRecordType(string recordTypeData)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            var createdRecord = await vault.AddRecordType(recordTypeData);

            Console.WriteLine($"Created Record Type UID: {createdRecord}");
        }
    }
}
