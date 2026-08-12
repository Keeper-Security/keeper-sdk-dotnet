using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.GatewayExamples
{
    /// <summary>
    /// Edits a PAM gateway name and/or enterprise node.
    /// </summary>
    public static class EditGatewayExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="gatewayId">Gateway UID or name.</param>
        /// <param name="newName">Optional new gateway name.</param>
        /// <param name="nodeNameOrId">Optional enterprise node ID or display name.</param>
        public static async Task EditGateway(
            VaultOnline vault,
            string gatewayId,
            string newName = null,
            string nodeNameOrId = null)
        {
            try
            {
                var (resolvedVault, plugin) = await PamGatewayHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
                {
                    return;
                }

                vault = resolvedVault;

                if (string.IsNullOrWhiteSpace(gatewayId))
                {
                    Console.WriteLine("Gateway UID or name is required.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(newName) && string.IsNullOrWhiteSpace(nodeNameOrId))
                {
                    Console.WriteLine("Nothing to do. Provide newName and/or nodeNameOrId.");
                    return;
                }

                var controller = PamGatewayHelper.ResolveGateway(plugin, gatewayId);
                if (controller == null)
                {
                    throw new PamGatewayNotFoundException(gatewayId);
                }

                var nodeId = controller.NodeId;
                if (!string.IsNullOrWhiteSpace(nodeNameOrId))
                {
                    nodeId = await ResolveNodeIdAsync(vault, nodeNameOrId.Trim());
                    if (nodeId <= 0)
                    {
                        return;
                    }
                }

                var gatewayName = string.IsNullOrWhiteSpace(newName)
                    ? controller.ControllerName
                    : newName.Trim();

                await GatewayUtils.EditGatewayAsync(vault.Auth, controller.ControllerUid, gatewayName, nodeId);
                await plugin.SyncDownAsync(reload: true);

                Console.WriteLine($"Gateway {gatewayName} has been edited.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static async Task<long> ResolveNodeIdAsync(VaultOnline vault, string nodeNameOrId)
        {
            var enterpriseData = new EnterpriseData();
            var enterpriseLoader = new EnterpriseLoader(vault.Auth, new EnterpriseDataPlugin[] { enterpriseData });
            await enterpriseLoader.Load();

            if (long.TryParse(nodeNameOrId, out var nodeId) && enterpriseData.TryGetNode(nodeId, out _))
            {
                return nodeId;
            }

            var nodes = enterpriseData.Nodes
                .Where(x => string.Equals(x.DisplayName, nodeNameOrId, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (nodes.Length == 1)
            {
                return nodes[0].Id;
            }

            if (nodes.Length > 1)
            {
                Console.WriteLine($"Multiple nodes found with name '{nodeNameOrId}'. Please use node ID instead:");
                foreach (var n in nodes)
                {
                    Console.WriteLine($"  - {n.DisplayName} (ID: {n.Id})");
                }

                return 0;
            }

            Console.WriteLine($"Node '{nodeNameOrId}' not found.");
            return 0;
        }
    }
}
