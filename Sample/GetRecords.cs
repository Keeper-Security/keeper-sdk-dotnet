using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample
{
    class GetRecordsExample
    {
        public async Task GetRecordsWithName(VaultOnline vault, string name)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var requiredRecord = GetRecordFromVaultWithNameAsync(vault, name);
            Console.WriteLine($"records found : {requiredRecord.Title}");
        }

        private KeeperRecord GetRecordFromVaultWithNameAsync(VaultOnline vault, String name)
        {
            var cleanedName = name.Trim();
            var searchResult = vault
                .KeeperRecords
                .Where(x => x.Version == 2 || x.Version == 3)
                .FirstOrDefault(x => string.Compare(x.Title, cleanedName, StringComparison.InvariantCultureIgnoreCase) == 0);
            return searchResult;
        }
    }
}