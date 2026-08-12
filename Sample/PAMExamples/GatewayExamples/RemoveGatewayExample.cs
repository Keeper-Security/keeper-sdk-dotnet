using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.GatewayExamples
{
    /// <summary>
    /// Removes a PAM gateway controller.
    /// </summary>
    public static class RemoveGatewayExample
    {
        public static async Task RemoveGateway(VaultOnline vault, string gatewayId)
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

                var controller = PamGatewayHelper.ResolveGateway(plugin, gatewayId);
                if (controller == null)
                {
                    throw new PamGatewayNotFoundException(gatewayId);
                }

                await GatewayUtils.RemoveGatewayAsync(vault.Auth, controller.ControllerUid);
                await plugin.SyncDownAsync(reload: true);

                Console.WriteLine($"Gateway {controller.ControllerName} has been removed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
