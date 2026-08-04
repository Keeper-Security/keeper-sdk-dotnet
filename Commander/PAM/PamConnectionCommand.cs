using System;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Commander;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
    /// <summary>
    /// pam-connection: edit connection settings on PAM resources.
    /// </summary>
    internal class PamConnectionCommand : PamCommandBase
    {
        public PamConnectionCommand(IEnterpriseContext context) : base(context)
        {
        }

        /// <summary>
        /// Runs the edit subcommand (default when no subcommand is given).
        /// </summary>
        public async Task ExecuteAsync(PamConnectionOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options),
                    "Invalid pam-connection command arguments. Available commands: edit");
            }

            var command = string.IsNullOrEmpty(options.Command) ? "" : options.Command.Trim().ToLowerInvariant();
            if (command is "edit" or "e")
            {
                await EditAsync(options);
                return;
            }

            if (!string.IsNullOrEmpty(options.Command) && string.IsNullOrEmpty(options.Record))
            {
                options.Record = options.Command;
                await EditAsync(options);
                return;
            }

            if (string.IsNullOrEmpty(command))
            {
                await EditAsync(options);
                return;
            }

            Console.WriteLine("Unsupported command. Available commands: edit");
        }

        private async Task EditAsync(PamConnectionOptions options)
        {
            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available.");
            }

            if (string.IsNullOrWhiteSpace(options.Record))
            {
                Console.WriteLine(
                    "Record is required. Usage: pam-connection edit <record> [--configuration UID] [options]");
                return;
            }

            try
            {
                var result = await ConnectionUtils.EditConnectionAsync(vault, new PamConnectionEditOptions
                {
                    Record = options.Record,
                    Configuration = options.Configuration,
                    AdminUser = options.AdminUser,
                    LaunchUser = options.LaunchUser,
                    ClearLaunchUser = options.ClearLaunchUser,
                    Protocol = options.Protocol,
                    Connections = options.Connections,
                    ConnectionsRecording = options.ConnectionsRecording,
                    TypescriptRecording = options.TypescriptRecording,
                    ConnectionsOverridePort = options.ConnectionsOverridePort,
                    KeyEvents = options.KeyEvents,
                    Scrollback = options.Scrollback,
                    RotateOnTermination = options.RotateOnTermination,
                    Silent = options.Silent,
                });

                foreach (var message in result.Messages)
                {
                    Console.WriteLine(message);
                }

                if (options.Silent)
                {
                    return;
                }

                if (result.RecordUpdated || result.GraphUpdated)
                {
                    Console.WriteLine($"Connection settings updated for {result.RecordUid}");
                }
            }
            catch (PamException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }

    internal class PamConnectionOptions
    {
        [Value(0, Required = false, HelpText = "Command: edit (default)")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "PAM resource or configuration record UID / title")]
        public string Record { get; set; }

        [Option('c', "configuration", Required = false, HelpText = "PAM Configuration UID or title")]
        public string Configuration { get; set; }

        [Option('a', "admin-user", Required = false, HelpText = "PAM User UID/title for admin credential")]
        public string AdminUser { get; set; }

        [Option("launch-user", Required = false, HelpText = "PAM User UID/title for launch credential")]
        public string LaunchUser { get; set; }

        [Option("clear-launch-user", Required = false, HelpText = "Remove launch credential from the resource")]
        public bool ClearLaunchUser { get; set; }

        [Option('p', "protocol", Required = false,
            HelpText = "Connection protocol (ssh, rdp, mysql, postgresql, sql-server, ...). Empty clears.")]
        public string Protocol { get; set; }

        [Option("connections", Required = false, HelpText = "Connections permission: on, off, or default. Prefer --connections=on")]
        public string Connections { get; set; }

        [Option("connections-recording", Required = false,
            HelpText = "Session recording permission: on, off, or default")]
        public string ConnectionsRecording { get; set; }

        [Option("typescript-recording", Required = false,
            HelpText = "TypeScript recording permission: on, off, or default")]
        public string TypescriptRecording { get; set; }

        [Option("connections-override-port", Required = false,
            HelpText = "Port override for connections. Empty clears.")]
        public string ConnectionsOverridePort { get; set; }

        [Option('k', "key-events", Required = false, HelpText = "Key events (recordingIncludeKeys): on, off, default")]
        public string KeyEvents { get; set; }

        [Option("scrollback", Required = false, HelpText = "Terminal scrollback size. Empty clears.")]
        public string Scrollback { get; set; }

        [Option("rotate-on-termination", Required = false, HelpText = "Rotate launch credentials on session end: on/off")]
        public string RotateOnTermination { get; set; }

        [Option('s', "silent", Required = false, HelpText = "Silent mode")]
        public bool Silent { get; set; }
    }
}
