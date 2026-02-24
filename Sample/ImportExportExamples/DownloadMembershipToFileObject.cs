using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;


namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToFileObjectExample
    {
        public static async Task DownloadMembershipToFileObject(
           DownloadMembershipOptions options = null)

        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var exportFile = await KeeperMembershipDownload.DownloadMembership(
                vault,
                options);
            Console.WriteLine($"Export file object: {exportFile}");
        }

    }
}