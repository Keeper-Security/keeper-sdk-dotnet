using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ConfigExamples
{
    /// <summary>
    /// Edits a PAM configuration's title, gateway, and/or tunneling permissions using
    /// <see cref="ConfigUtils"/> and <see cref="PamConfigurationFacade"/>.
    /// </summary>
    public static class EditConfigExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="configId">PAM configuration UID or title.</param>
        /// <param name="newTitle">Optional new title.</param>
        /// <param name="gatewayId">Optional gateway UID or name to attach to the configuration.</param>
        /// <param name="connections">Tri-state: on, off, or default.</param>
        /// <param name="tunneling">Tri-state: on, off, or default.</param>
        /// <param name="rotation">Tri-state: on, off, or default.</param>
        /// <param name="connectionsRecording">Tri-state: on, off, or default.</param>
        /// <param name="typescriptRecording">Tri-state: on, off, or default.</param>
        /// <param name="remoteBrowserIsolation">Tri-state: on, off, or default.</param>
        /// <param name="aiThreatDetection">Tri-state: on, off, or default.</param>
        /// <param name="aiTerminateSessionOnDetection">Tri-state: on, off, or default.</param>
        public static async Task EditConfig(
            VaultOnline vault,
            string configId,
            string newTitle = null,
            string gatewayId = null,
            string connections = null,
            string tunneling = null,
            string rotation = null,
            string connectionsRecording = null,
            string typescriptRecording = null,
            string remoteBrowserIsolation = null,
            string aiThreatDetection = null,
            string aiTerminateSessionOnDetection = null)
        {
            try
            {
                var (resolvedVault, plugin) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
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

                vault.AdjustTypedRecord(config);
                var facade = new PamConfigurationFacade(config);
                var dirty = false;

                if (!string.IsNullOrWhiteSpace(newTitle))
                {
                    config.Title = newTitle.Trim();
                    dirty = true;
                }

                string newGatewayUid = null;
                if (!string.IsNullOrWhiteSpace(gatewayId))
                {
                    var controller = GatewayUtils.FindGateway(plugin.Controllers.GetAll(), gatewayId.Trim());
                    if (controller == null)
                    {
                        throw new PamGatewayNotFoundException(gatewayId);
                    }

                    newGatewayUid = controller.ControllerUid;
                    if (!string.Equals(facade.ControllerUid, newGatewayUid, StringComparison.Ordinal))
                    {
                        facade.ControllerUid = newGatewayUid;
                        dirty = true;
                    }
                }

                if (dirty)
                {
                    await vault.UpdateRecord(config);
                }

                if (!string.IsNullOrEmpty(newGatewayUid))
                {
                    await ConfigUtils.SetConfigurationGatewayAsync(vault.Auth, config.Uid, newGatewayUid);
                }

                var hasTunnelingOptions = connections != null || tunneling != null || rotation != null
                    || connectionsRecording != null || typescriptRecording != null
                    || remoteBrowserIsolation != null || aiThreatDetection != null
                    || aiTerminateSessionOnDetection != null;
                if (hasTunnelingOptions)
                {
                    await ConfigUtils.ConfigureTunnelingAsync(
                        vault.Auth,
                        config.Uid,
                        ConfigUtils.ParseTriState(connections),
                        ConfigUtils.ParseTriState(tunneling),
                        ConfigUtils.ParseTriState(rotation),
                        ConfigUtils.ParseTriState(connectionsRecording),
                        ConfigUtils.ParseTriState(typescriptRecording),
                        ConfigUtils.ParseTriState(remoteBrowserIsolation),
                        ConfigUtils.ParseTriState(aiThreatDetection),
                        ConfigUtils.ParseTriState(aiTerminateSessionOnDetection));
                }

                await vault.SyncDown();
                Console.WriteLine($"PAM configuration \"{config.Title}\" updated.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
