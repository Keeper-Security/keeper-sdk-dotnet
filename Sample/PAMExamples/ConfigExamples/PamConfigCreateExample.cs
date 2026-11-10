using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ConfigExamples
{
    /// <summary>
    /// Creates a PAM configuration record and places it in a shared folder or NSF folder. 
    /// Uses <see cref="ConfigUtils"/> and <see cref="PamVaultHelpers"/>. 
    /// Environment-specific details, such as AWS keys, Azure IDs, and domain hostnames, 
    /// are left for the caller to add later using the regular vault record update APIs.
    /// </summary>
    public static class PamConfigCreateExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="environment">PAM environment type, such as local, network, AWS, Azure, GCP, domain, OCI, or GitHub.</param>
        /// <param name="title">Title of the new PAM configuration.</param>
        /// <param name="sharedFolder">Shared folder or NSF folder UID, name, or path where the configuration will be added (for example, PAM/TestFolder).</param>
        /// <param name="gatewayId">Optional gateway ID or name to link to the configuration.</param>
        /// <param name="connections">Tri-state: on, off, or default.</param>
        /// <param name="tunneling">Tri-state: on, off, or default.</param>
        /// <param name="rotation">Tri-state: on, off, or default.</param>
        /// <param name="connectionsRecording">Tri-state: on, off, or default.</param>
        /// <param name="typescriptRecording">Tri-state: on, off, or default.</param>
        /// <param name="remoteBrowserIsolation">Tri-state: on, off, or default.</param>
        /// <param name="aiThreatDetection">Tri-state: on, off, or default.</param>
        /// <param name="aiTerminateSessionOnDetection">Tri-state: on, off, or default.</param>
        public static async Task CreateConfig(
            VaultOnline vault,
            string environment,
            string title,
            string sharedFolder,
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

                if (!PamConfigTypes.TryResolveRecordType(environment, out var recordType))
                {
                    Console.WriteLine(
                        $"Unsupported environment '{environment}'. Supported: {PamConfigTypes.GetSupportedConfigTypes()}");
                    return;
                }

                if (PamConfigTypes.IsComingSoonEnvironment(environment, out var comingSoonName))
                {
                    Console.WriteLine($"Environment {comingSoonName} is not supported yet.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(title))
                {
                    Console.WriteLine("Title is required.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(sharedFolder))
                {
                    Console.WriteLine("Shared folder is required.");
                    return;
                }

                var folderUid = PamVaultHelpers.ResolvePamConfigurationFolderUid(vault, sharedFolder.Trim());
                if (string.IsNullOrEmpty(folderUid))
                {
                    Console.WriteLine(
                        $"Could not resolve shared folder \"{sharedFolder}\". Provide a shared folder or NSF folder UID, name, or path.");
                    return;
                }

                string gatewayUid = null;
                if (!string.IsNullOrWhiteSpace(gatewayId))
                {
                    var controller = GatewayUtils.FindGateway(plugin.Controllers.GetAll(), gatewayId.Trim());
                    if (controller == null)
                    {
                        throw new PamGatewayNotFoundException(gatewayId);
                    }

                    gatewayUid = controller.ControllerUid;
                }

                await vault.EnsurePamRecordTypesAsync();
                var record = ConfigUtils.CreateConfigurationRecord(vault, recordType, title.Trim());

                var facade = new PamConfigurationFacade(record);
                var sharedFolderRefUid = PamVaultHelpers.ResolvePamResourcesFolderUid(vault, folderUid);
                if (!string.IsNullOrEmpty(sharedFolderRefUid))
                {
                    facade.FolderUid = sharedFolderRefUid;
                }

                if (!string.IsNullOrEmpty(gatewayUid))
                {
                    facade.ControllerUid = gatewayUid;
                }

                var isNsfFolder = PamVaultHelpers.IsKeeperNSFFolder(vault, folderUid);
                await ConfigUtils.AddConfigurationRecordAsync(vault, record, isNsfFolder ? folderUid : null);
                await ConfigUtils.EnsureConfigurationNetworkGraphAsync(vault.Auth, record.Uid);

                await vault.SyncDown();
                if (!isNsfFolder)
                {
                    await PamVaultHelpers.PlacePamConfigurationInFolderAsync(vault, record, folderUid);
                }

                if (!string.IsNullOrEmpty(gatewayUid))
                {
                    await ConfigUtils.SetConfigurationGatewayAsync(vault.Auth, record.Uid, gatewayUid);
                }

                var hasTunnelingOptions = connections != null || tunneling != null || rotation != null
                    || connectionsRecording != null || typescriptRecording != null
                    || remoteBrowserIsolation != null || aiThreatDetection != null
                    || aiTerminateSessionOnDetection != null;
                if (hasTunnelingOptions)
                {
                    await ConfigUtils.ConfigureTunnelingAsync(
                        vault.Auth,
                        record.Uid,
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
                Console.WriteLine($"PAM configuration \"{title.Trim()}\" created: {record.Uid}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
