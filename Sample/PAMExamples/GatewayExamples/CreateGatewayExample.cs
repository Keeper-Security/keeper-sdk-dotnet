using System;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.GatewayExamples
{
    /// <summary>
    /// Creates a PAM Gateway client on a KSM application and returns a one-time token (or initialized config).
    /// </summary>
    public static class CreateGatewayExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="gatewayName">Name for the new gateway.</param>
        /// <param name="applicationId">KSM application UID or title.</param>
        /// <param name="tokenExpiresInMinutes">One-time token expiration (1–1440). Default 60.</param>
        /// <param name="configInit">Optional: "json" or "b64" to return initialized config instead of raw OTT.</param>
        public static async Task CreateGateway(
            VaultOnline vault,
            string gatewayName,
            string applicationId,
            int tokenExpiresInMinutes = 60,
            string configInit = null)
        {
            try
            {
                var (resolvedVault, plugin) = await PamGatewayHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
                {
                    return;
                }

                vault = resolvedVault;

                if (string.IsNullOrWhiteSpace(gatewayName))
                {
                    Console.WriteLine("Gateway name is required.");
                    return;
                }

                if (tokenExpiresInMinutes < 1 || tokenExpiresInMinutes > 1440)
                {
                    Console.WriteLine("tokenExpiresInMinutes must be between 1 and 1440.");
                    return;
                }

                string normalizedConfigInit = null;
                if (!string.IsNullOrWhiteSpace(configInit))
                {
                    normalizedConfigInit = configInit.Trim().ToLowerInvariant();
                    if (normalizedConfigInit != "json" && normalizedConfigInit != "b64")
                    {
                        Console.WriteLine("configInit must be \"json\", \"b64\", or null.");
                        return;
                    }
                }

                var application = PamGatewayHelper.ResolveKsmApplication(vault, applicationId);
                var token = await GatewayUtils.CreateGatewayAsync(
                    vault,
                    gatewayName.Trim(),
                    application.Uid,
                    tokenExpiresInMinutes,
                    normalizedConfigInit);

                await plugin.SyncDownAsync(reload: true);

                Console.WriteLine($"The one time token has been created in application [{application.Title}] ({application.Uid}).");
                Console.WriteLine();
                Console.WriteLine($"The new Gateway named {gatewayName.Trim()} will show up in the gateway list once it is initialized.");
                Console.WriteLine();
                if (!string.IsNullOrWhiteSpace(normalizedConfigInit))
                {
                    Console.WriteLine("Use the following initialized config in the Gateway:");
                }
                else
                {
                    Console.WriteLine($"Following one time token will expire in {tokenExpiresInMinutes} minutes:");
                }

                Console.WriteLine("-----------------------------------------------");
                Console.WriteLine(token);
                Console.WriteLine("-----------------------------------------------");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
