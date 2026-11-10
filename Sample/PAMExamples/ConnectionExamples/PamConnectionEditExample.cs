using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.ConnectionExamples
{
    /// <summary>
    /// Configures connection settings on a PAM resource or PAM configuration record via
    /// <see cref="ConnectionUtils.EditConnectionAsync"/>.
    /// </summary>
    public static class PamConnectionEditExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="record">PAM resource (pamMachine/pamDatabase/pamDirectory/pamRemoteBrowser) or PAM configuration UID/title.</param>
        /// <param name="configuration">PAM Configuration UID or title to link the resource to.</param>
        /// <param name="adminUser">PAM User UID/title used as the admin credential on the resource.</param>
        /// <param name="launchUser">PAM User UID/title used as the launch credential on the resource.</param>
        /// <param name="clearLaunchUser">Remove the launch credential from the resource.</param>
        /// <param name="protocol">Connection protocol (ssh, rdp, mysql, postgresql, sql-server, ...). Empty clears it.</param>
        /// <param name="connections">Tri-state: on, off, or default.</param>
        /// <param name="connectionsRecording">Tri-state: on, off, or default.</param>
        /// <param name="typescriptRecording">Tri-state: on, off, or default.</param>
        /// <param name="connectionsOverridePort">Port override for connections. Empty clears. Null skips.</param>
        /// <param name="keyEvents">recordingIncludeKeys tri-state: on, off, or default.</param>
        /// <param name="scrollback">Terminal scrollback size. Empty clears. Null skips.</param>
        /// <param name="rotateOnTermination">Rotate launch credentials when the session ends: on/off.</param>
        /// <param name="silent">Suppress the summary output.</param>
        public static async Task EditConnection(
            VaultOnline vault,
            string record,
            string configuration = null,
            string adminUser = null,
            string launchUser = null,
            bool clearLaunchUser = false,
            string protocol = null,
            string connections = null,
            string connectionsRecording = null,
            string typescriptRecording = null,
            string connectionsOverridePort = null,
            string keyEvents = null,
            string scrollback = null,
            string rotateOnTermination = null,
            bool silent = false)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(record))
                {
                    Console.WriteLine("Record is required.");
                    return;
                }

                var result = await ConnectionUtils.EditConnectionAsync(vault, new PamConnectionEditOptions
                {
                    Record = record,
                    Configuration = configuration,
                    AdminUser = adminUser,
                    LaunchUser = launchUser,
                    ClearLaunchUser = clearLaunchUser,
                    Protocol = protocol,
                    Connections = connections,
                    ConnectionsRecording = connectionsRecording,
                    TypescriptRecording = typescriptRecording,
                    ConnectionsOverridePort = connectionsOverridePort,
                    KeyEvents = keyEvents,
                    Scrollback = scrollback,
                    RotateOnTermination = rotateOnTermination,
                    Silent = silent,
                });

                if (silent)
                {
                    return;
                }

                foreach (var message in result.Messages)
                {
                    Console.WriteLine(message);
                }

                if (result.RecordUpdated || result.GraphUpdated)
                {
                    Console.WriteLine($"Connection settings updated for {result.RecordUid}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
