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
                return;
            }

            if (!await EnsurePluginAsync(syncIfNeeded: false))
            {
                return;
            }

            Console.WriteLine(options.Reload ? "Performing full PAM sync..." : "Syncing PAM data...");
            await Plugin.SyncDownAsync(options.Reload);
            Console.WriteLine("PAM sync completed.");
        }
    }

    internal class PamSyncDownOptions : EnterpriseGenericOptions
    {
        [Option('r', "reload", Required = false, Default = false, HelpText = "Perform full sync instead of incremental")]
        public bool Reload { get; set; }
    }
}
