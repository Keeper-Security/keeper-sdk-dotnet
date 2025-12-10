using System;
using System.Threading.Tasks;
using Commander;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.PEDM;

namespace Commander.PEDM
{
    internal abstract class PedmCommandBase
    {
        protected IEnterpriseContext Context { get; }
        protected PedmPlugin Plugin { get; private set; }

        protected PedmCommandBase(IEnterpriseContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
        }

        protected async Task<bool> EnsurePluginAsync(bool syncIfNeeded = true)
        {
            Plugin = Context.GetPedmPlugin() as PedmPlugin;
            if (Plugin == null)
            {
                Console.WriteLine("PEDM plugin is not available. Enterprise admin access is required.");
                return false;
            }

            if (syncIfNeeded && Plugin.NeedSync)
            {
                Console.WriteLine("Syncing PEDM data...");
                await Plugin.SyncDown();
            }

            return true;
        }

        protected static bool? ParseBoolOption(string value)
        {
            if (string.IsNullOrEmpty(value))
                return null;

            if (bool.TryParse(value, out var result))
                return result;

            var lower = value.ToLowerInvariant();
            if (lower == "true" || lower == "1" || lower == "yes" || lower == "on")
                return true;
            if (lower == "false" || lower == "0" || lower == "no" || lower == "off")
                return false;

            return null;
        }

        protected static void PrintModifyStatus(ModifyStatus status)
        {
            if (status.Add?.Count > 0)
            {
                Console.WriteLine($"  Added: {string.Join(", ", status.Add)}");
            }
            if (status.Update?.Count > 0)
            {
                Console.WriteLine($"  Updated: {string.Join(", ", status.Update)}");
            }
            if (status.Remove?.Count > 0)
            {
                Console.WriteLine($"  Removed: {string.Join(", ", status.Remove)}");
            }
        }
    }
}

