using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections.Generic;

namespace Sample.ImportExportExamples
{
    public static class ExportToFileExample
    {
        public static async Task ExportToFile(VaultOnline vault,
            string filename,
            IEnumerable<string> recordUids = null,
            bool includeSharedFolders = true,
            Action<Severity, string> logger = null)

        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            await KeeperExport.ExportVaultToFile(vault, filename, recordUids, includeSharedFolders);


        }

    }
}