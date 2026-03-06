using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ImportExportExamples
{
    public static class DownloadMembershipToFileExample
    {
        public static async Task DownloadToFile(VaultOnline vault,
            string filename,
            DownloadMembershipOptions options = null)

        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            await KeeperMembershipDownload.DownloadMembershipToFile(
                vault,
                filename,
                options);
        }
    }
}