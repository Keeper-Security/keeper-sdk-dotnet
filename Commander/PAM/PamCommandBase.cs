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
        protected IPamPlugin Plugin { get; private set; }

        protected PamCommandBase(IEnterpriseContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
        }

        protected async Task<bool> EnsurePluginAsync(bool syncIfNeeded = true)
        {
            Plugin = Context.GetPamPlugin();
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
            if (string.IsNullOrWhiteSpace(identifier))
            {
                return null;
            }

            var controllers = Plugin.Controllers.GetAll();
            var controller = GatewayUtils.FindGateway(controllers, identifier);
            if (controller != null)
            {
                return controller;
            }

            var trimmed = identifier.Trim();
            var nameMatches = controllers
                .Count(c => string.Equals(c.ControllerName, trimmed, StringComparison.OrdinalIgnoreCase));
            if (nameMatches > 1)
            {
                throw new PamGatewayAmbiguousException(trimmed);
            }

            return null;
        }

        protected async Task SyncPamAsync()
        {
            if (Plugin == null)
            {
                Plugin = Context.GetPamPlugin();
            }

            if (Plugin != null)
            {
                await Plugin.SyncDownAsync();
            }
        }
    }
}
