using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Commander;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
    /// <summary>
    /// pam-launch: run preflight and print a short summary.
    /// </summary>
    internal class PamLaunchCommand : PamCommandBase
    {
        public PamLaunchCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PamLaunchCliOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available.");
            }

            if (string.IsNullOrWhiteSpace(options.Record))
            {
                Console.WriteLine(
                    "Record is required. Usage: pam-launch <record> [--credential <pamUser>] "
                    + "[--gateway <uid>] [--host host:port] [--host-record <uid>] [--debug]");
                return;
            }

            if (!await EnsurePluginAsync())
            {
                return;
            }

            var launchOptions = new PamLaunchOptions
            {
                Record = options.Record,
                Credential = FirstNonEmpty(options.Credential, options.CredentialAlias),
                Gateway = options.Gateway,
                Host = options.Host,
                HostRecord = FirstNonEmpty(options.HostRecord, options.HostRecordAlias),
                Debug = options.Debug,
                AvailableControllers = Plugin.Controllers.GetAll().ToList(),
            };

            try
            {
                var prepare = await LaunchUtils.PrepareAsync(vault, launchOptions);
                PrintPrepareSummary(prepare);
                Console.WriteLine();
                Console.WriteLine("Interactive terminal session is not available yet in this Commander build.");
            }
            catch (PamException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentNullException ex)
            {
                Console.WriteLine($"PAM launch failed: {ex.Message}");
            }
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !string.IsNullOrWhiteSpace(first) ? first : second;
        }

        private static void PrintPrepareSummary(PamLaunchPrepareResult prepare)
        {
            Console.WriteLine("PAM launch");
            Console.WriteLine("----------");
            Console.WriteLine($"Record UID: {prepare.Record?.Uid}");
            Console.WriteLine($"Record type: {prepare.Record?.TypeName}");
            Console.WriteLine($"Protocol: {prepare.Protocol}");
            Console.WriteLine($"Configuration UID: {prepare.ConfigUid ?? "(not found)"}");

            if (!string.IsNullOrEmpty(prepare.Host))
            {
                var hostText = prepare.Port.HasValue
                    ? $"{prepare.Host}:{prepare.Port.Value}"
                    : prepare.Host;
                Console.WriteLine($"Target host: {hostText} ({prepare.HostSource})");
            }

            Console.WriteLine(prepare.LaunchCredential == null
                ? "Launch credential: (not set)"
                : $"Launch credential: {prepare.LaunchCredential.Uid} ({prepare.LaunchCredential.Title})");

            if (string.IsNullOrEmpty(prepare.GatewayUid))
            {
                Console.WriteLine("Gateway: (not resolved)");
            }
            else
            {
                var status = prepare.GatewayOnline switch
                {
                    true => PamGatewayStatus.Online,
                    false => PamGatewayStatus.Offline,
                    _ => PamGatewayStatus.Unknown
                };
                Console.WriteLine($"Gateway: {prepare.GatewayUid} ({prepare.GatewayName})");
                Console.WriteLine($"Gateway status: {status}");
            }
        }
    }

    internal class PamLaunchCliOptions
    {
        [Value(0, Required = false, HelpText = "PAM resource UID or title")]
        public string Record { get; set; }

        [Option("credential", Required = false, HelpText = "Launch credential PAM User UID or title")]
        public string Credential { get; set; }

        [Option("cr", Required = false, HelpText = "Alias for --credential")]
        public string CredentialAlias { get; set; }

        [Option('g', "gateway", Required = false, HelpText = "Gateway UID or name override")]
        public string Gateway { get; set; }

        [Option('H', "host", Required = false, HelpText = "Custom host override in host:port format")]
        public string Host { get; set; }

        [Option("host-record", Required = false, HelpText = "Record UID/title to source host from host/pamHostname field")]
        public string HostRecord { get; set; }

        [Option("hr", Required = false, HelpText = "Alias for --host-record")]
        public string HostRecordAlias { get; set; }

        [Option("debug", Required = false, HelpText = "Print pam-launch resolve diagnostics")]
        public bool Debug { get; set; }
    }
}
