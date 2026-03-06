using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToJsonExample
    {
        public static async Task DownloadToJson(VaultOnline vault = null,
            DownloadMembershipOptions options = null)

        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var exportFile = await KeeperMembershipDownload.DownloadMembershipToJson(
                vault,
                options);
            Console.WriteLine(exportFile);
        }

    }
}