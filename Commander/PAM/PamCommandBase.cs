using System;
using System.Linq;
using System.Threading.Tasks;
using Commander;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
    internal abstract class PamCommandBase
    {
        protected IEnterpriseContext Context { get; }
        protected PamPlugin Plugin { get; private set; }

        protected PamCommandBase(IEnterpriseContext context)
        {
            Context = context;
        }

        protected VaultOnline GetVault()
        {
            return (Context as ConnectedContext)?.Vault;
        }

        protected async Task<bool> EnsurePluginAsync(bool syncIfNeeded = true)
        {
            Plugin = Context.GetPamPlugin() as PamPlugin;
            if (Plugin == null)
            {
                Console.WriteLine("PAM plugin is not available. Enterprise admin access is required.");
                return false;
            }

            if (syncIfNeeded && !Plugin.Controllers.GetAll().Any())
            {
                Console.WriteLine("Syncing PAM data...");
                await Plugin.SyncDownAsync();
            }

            return true;
        }

        protected PamController ResolveGateway(string identifier)
        {
            var controller = GatewayUtils.FindGateway(Plugin.Controllers.GetAll(), identifier, out var errorMessage);
            if (!string.IsNullOrEmpty(errorMessage))
            {
                Console.WriteLine(errorMessage);
            }

            return controller;
        }

        protected async Task SyncPamAsync()
        {
            if (Plugin == null)
            {
                Plugin = Context.GetPamPlugin() as PamPlugin;
            }

            if (Plugin != null)
            {
                await Plugin.SyncDownAsync();
            }
        }
    }
}
