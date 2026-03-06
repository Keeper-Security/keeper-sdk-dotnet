using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToMergeExample
    {
        public static async Task MergeDownloadMembershipFile(VaultOnline vault,
            string filename,
            DownloadMembershipOptions options = null)

        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            await KeeperMembershipDownload.MergeMembershipToFile(
                vault,
                filename,
                options
            );
        }
    }
}