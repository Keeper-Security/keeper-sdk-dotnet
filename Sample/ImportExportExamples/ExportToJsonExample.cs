using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections.Generic;

namespace Sample.ImportExportExamples
{
    public static class ExportToJsonExample
    {
        public static async Task ExportToJson(VaultOnline vault = null,
            IEnumerable<string> recordUids = null,
            bool includeSharedFolders = true,
            Action<Severity, string> logger = null)

        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var result = KeeperExport.ExportVaultToJson(vault, recordUids, includeSharedFolders);
            Console.WriteLine(result);


        }

    }
}