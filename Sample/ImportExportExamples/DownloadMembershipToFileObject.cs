using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;


namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToFileObjectExample
    {
        public static async Task DownloadMembershipToFileObject(VaultOnline vault = null,
           DownloadMembershipOptions options = null)

        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var exportFile = await KeeperMembershipDownload.DownloadMembership(
                vault,
                options);
            Console.WriteLine($"Export file object: {exportFile}");
        }

    }
}