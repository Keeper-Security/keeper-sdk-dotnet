using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    class GetRecordHistoryExample
    {
        public async Task GetRecordHistory1(string recordUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            await GetRecordHistorySimple(
                vault,
                recordUid
            );
        }

        private static async Task GetRecordHistorySimple(
            VaultOnline vault,
            string recordUid)
        {
            if (vault == null)
            {
                Console.WriteLine("Vault reference is null.");
                return;
            }

            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID is required.");
                return;
            }

            if (!vault.TryGetKeeperRecord(recordUid, out var record))
            {
                Console.WriteLine($"Record '{recordUid}' not found.");
                return;
            }

            var history = await vault.GetRecordHistory(recordUid);
            Console.WriteLine("{0,-25}  {1,-30} {2,-10} {3,-35} {4,-20}", "Record UID", "Record Title", "Version", "Modified By", "Change Type");
            Console.WriteLine(new string('-', 25) + "  " + new string('-', 30) + "  " + new string('-', 10) + "  " + new string('-', 35) + "  " + new string('-', 20));

            foreach (var entry in history)
            {
                var record1 = entry.KeeperRecord;
                Console.WriteLine("{0,-25}  {1,-30} {2,-10} {3,-35} {4,-20}", record1.Uid, record1.Title, record1.Version, entry.Username, entry.RecordChange);
            }
        }
    }
}