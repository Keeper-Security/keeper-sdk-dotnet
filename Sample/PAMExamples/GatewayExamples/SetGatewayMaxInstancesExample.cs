using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.GatewayExamples
{
    /// <summary>
    /// Sets the maximum instance count for a PAM gateway.
    /// </summary>
    public static class SetGatewayMaxInstancesExample
    {
        public static async Task SetMaxInstances(VaultOnline vault, string gatewayId, int maxInstances)
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

                if (maxInstances < 1)
                {
                    Console.WriteLine("maxInstances must be at least 1.");
                    return;
                }

                var controller = PamGatewayHelper.ResolveGateway(plugin, gatewayId);
                if (controller == null)
                {
                    throw new PamGatewayNotFoundException(gatewayId);
                }

                await GatewayUtils.SetGatewayMaxInstancesAsync(
                    vault.Auth,
                    controller.ControllerUid,
                    maxInstances);
                await plugin.SyncDownAsync(reload: true);

                Console.WriteLine($"{controller.ControllerName}: max instance count set to {maxInstances}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
