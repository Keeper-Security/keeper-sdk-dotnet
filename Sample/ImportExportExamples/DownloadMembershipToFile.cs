using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToFileExample
    {
        public static async Task DownloadToFile(
            string filename,
            DownloadMembershipOptions options = null,
            Action<Severity, string> logger = null)

        {
            var vault = await AuthenticateAndGetVault.GetVault();
            await KeeperMembershipDownload.DownloadMembershipToFile(
                vault,
                filename,
                options);
        }
    }
}