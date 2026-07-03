using System;
using System.Threading.Tasks;
using Commander;
using CommandLine;

namespace Commander.PAM
{
    internal class PamSyncDownCommand : PamCommandBase
    {
        public PamSyncDownCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PamSyncDownOptions options)
        {
            if (options == null)
            {
                Console.WriteLine("Invalid PAM sync-down command arguments.");
                return;
            }

            if (!await EnsurePluginAsync(syncIfNeeded: false))
            {
                return;
            }

            Console.WriteLine(options.Reload
                ? "Performing full PAM sync (gateways and record rotations)..."
                : "Syncing PAM gateway data...");
            try
            {
                await Plugin.SyncDownAsync(options.Reload);
                Console.WriteLine("PAM sync completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error syncing PAM data: {ex.Message}");
            }
        }
    }

    internal class PamSyncDownOptions
    {
        [Option('r', "reload", Required = false, Default = false,
            HelpText = "Also reload record rotation metadata from vault (default syncs gateways only)")]
        public bool Reload { get; set; }
    }
}
