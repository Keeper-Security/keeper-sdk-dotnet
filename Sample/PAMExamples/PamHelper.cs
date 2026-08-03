using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;
using Sample.Helpers;

namespace Sample.PAMExamples
{
    /// <summary>
    /// Shared setup for PAM samples (enterprise admin + PamPlugin sync).
    /// </summary>
    internal static class PamHelper
    {
        public static async Task<(VaultOnline Vault, PamPlugin Plugin)> PrepareAsync(VaultOnline vault)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null)
            {
                return (null, null);
            }

            if (!EnterpriseHelper.RequireEnterpriseAdmin(vault))
            {
                return (null, null);
            }

            var plugin = new PamPlugin(vault.Auth);
            await plugin.SyncDownAsync();
            return (vault, plugin);
        }
    }
}
