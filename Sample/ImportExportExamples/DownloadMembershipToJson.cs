using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToJsonExample
    {
        public static async Task DownloadToJson(
            DownloadMembershipOptions options = null)

        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var exportFile = await KeeperMembershipDownload.DownloadMembershipToJson(
                vault,
                options);
            Console.WriteLine(exportFile);
        }

    }
}