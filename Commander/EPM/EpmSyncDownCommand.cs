using System;
using System.Threading.Tasks;
using Commander;
using CommandLine;
using KeeperSecurity.Enterprise;

namespace Commander.EPM
{
    internal class EpmSyncDownCommand : EpmCommandBase
    {
        public EpmSyncDownCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(EpmSyncDownOptions options)
        {
            if (options == null)
                return;
            if (!await EnsurePluginAsync(syncIfNeeded: false))
                return;

            Console.WriteLine(options.Reload ? "Performing full sync..." : "Syncing EPM data...");
            await Plugin.SyncDown(options.Reload);
            Console.WriteLine("EPM sync completed.");
        }
    }

    internal class EpmSyncDownOptions : EnterpriseGenericOptions
    {
        [Option('r', "reload", Required = false, Default = false, HelpText = "Perform full sync instead of incremental")]
        public bool Reload { get; set; }
    }
}

