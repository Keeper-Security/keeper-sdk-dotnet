using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ConfigExamples
{
    /// <summary>
    /// Removes a PAM configuration record via <see cref="ConfigUtils.RemovePamConfigurationAsync"/>.
    /// </summary>
    public static class RemoveConfigExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="configId">PAM configuration UID or title.</param>
        public static async Task RemoveConfig(VaultOnline vault, string configId)
        {
            try
            {
                var (resolvedVault, _) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null)
                {
                    return;
                }

                vault = resolvedVault;

                if (string.IsNullOrWhiteSpace(configId))
                {
                    Console.WriteLine("Configuration UID or title is required.");
                    return;
                }

                TypedRecord config;
                try
                {
                    config = PamVaultHelpers.ResolveRecord(vault, configId.Trim(), PamRecordTypes.Configuration);
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }

                if (config == null)
                {
                    Console.WriteLine($"PAM configuration '{configId}' not found.");
                    return;
                }

                await ConfigUtils.RemovePamConfigurationAsync(vault, config.Uid);
                await vault.SyncDown();

                Console.WriteLine($"PAM configuration \"{config.Title}\" removed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
