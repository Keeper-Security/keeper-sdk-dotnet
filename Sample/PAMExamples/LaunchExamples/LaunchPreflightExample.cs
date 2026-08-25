using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.LaunchExamples
{
    /// <summary>
    /// Resolves record, protocol, config, credential, host, and gateway for a PAM launch via
    /// <see cref="LaunchUtils.PrepareAsync"/>. Does not start an interactive session.
    /// </summary>
    public static class LaunchPreflightExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="record">pamMachine/pamDatabase/pamDirectory record UID, title, or search text.</param>
        /// <param name="credential">pamUser to use as the launch credential.</param>
        /// <param name="gateway">Gateway UID or name override.</param>
        /// <param name="host">Optional host:port override. For IPv6 use [address]:port, like [::1]:22.</param>
        /// <param name="hostRecord">Record to pull the host from (host / pamHostname field).</param>
        /// <param name="debug">Print resolve steps to the console.</param>
        public static async Task Preflight(
            VaultOnline vault,
            string record,
            string credential = null,
            string gateway = null,
            string host = null,
            string hostRecord = null,
            bool debug = false)
        {
            try
            {
                var (resolvedVault, plugin) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
                {
                    return;
                }

                vault = resolvedVault;

                if (string.IsNullOrWhiteSpace(record))
                {
                    Console.WriteLine("Record is required.");
                    return;
                }

                var options = new PamLaunchOptions
                {
                    Record = record,
                    Credential = credential,
                    Gateway = gateway,
                    Host = host,
                    HostRecord = hostRecord,
                    Debug = debug,
                    AvailableControllers = plugin.Controllers.GetAll().ToList(),
                };

                var prepare = await LaunchUtils.PrepareAsync(vault, options);

                Console.WriteLine("PAM launch preflight");
                Console.WriteLine("---------------------");
                Console.WriteLine($"Record UID: {prepare.Record?.Uid}");
                Console.WriteLine($"Record type: {prepare.Record?.TypeName}");
                Console.WriteLine($"Protocol: {prepare.Protocol}");
                Console.WriteLine($"Configuration UID: {prepare.ConfigUid ?? "(not found)"}");

                if (!string.IsNullOrEmpty(prepare.Host))
                {
                    var hostText = prepare.Port.HasValue ? $"{prepare.Host}:{prepare.Port.Value}" : prepare.Host;
                    Console.WriteLine($"Target host: {hostText} ({prepare.HostSource})");
                }

                Console.WriteLine(prepare.LaunchCredential == null
                    ? "Launch credential: (not set)"
                    : $"Launch credential: {prepare.LaunchCredential.Uid} ({prepare.LaunchCredential.Title})");

                if (string.IsNullOrEmpty(prepare.GatewayUid))
                {
                    Console.WriteLine("Gateway: (not resolved)");
                    return;
                }

                var status = prepare.GatewayOnline switch
                {
                    true => PamGatewayStatus.Online,
                    false => PamGatewayStatus.Offline,
                    _ => PamGatewayStatus.Unknown,
                };
                Console.WriteLine($"Gateway: {prepare.GatewayUid} ({prepare.GatewayName})");
                Console.WriteLine($"Gateway status: {status}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
