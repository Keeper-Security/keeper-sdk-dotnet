using System;
using System.Threading.Tasks;
using Commander;
using CommandLine;
using KeeperSecurity.Enterprise;

namespace Commander.PEDM
{
    internal class PedmSyncDownCommand : PedmCommandBase
    {
        public PedmSyncDownCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmSyncDownOptions options)
        {
            if (!await EnsurePluginAsync(syncIfNeeded: false))
                return;

            Console.WriteLine(options.Reload ? "Performing full sync..." : "Syncing PEDM data...");
            await Plugin.SyncDown(options.Reload);
            Console.WriteLine("PEDM sync completed.");
        }
    }

    internal class PedmSyncDownOptions : EnterpriseGenericOptions
    {
        [Option('r', "reload", Required = false, Default = false, HelpText = "Perform full sync instead of incremental")]
        public bool Reload { get; set; }
    }
}

