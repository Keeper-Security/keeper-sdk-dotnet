using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToMergeExample
    {
        public static async Task MergeDownloadMembershipFile(
            string filename,
            DownloadMembershipOptions options = null,
            Action<Severity, string> logger = null)

        {
            var vault = await AuthenticateAndGetVault.GetVault();
            await KeeperMembershipDownload.MergeMembershipToFile(
                vault,
                filename,
                options
            );
        }
    }
}