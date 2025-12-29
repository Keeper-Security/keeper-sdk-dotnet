using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections.Generic;
using KeeperSecurity.Commands;

namespace Sample.ImportExportExamples
{
    public static class ExportToJsonExample
    {
        public static async Task ExportToJson(
            IEnumerable<string> recordUids = null,
            bool includeSharedFolders = true,
            Action<Severity, string> logger = null)

        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var result = KeeperExport.ExportVaultToJson(vault, recordUids, includeSharedFolders, logger);
            Console.WriteLine(result);


        }

    }
}