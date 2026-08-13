using System;
using System.Collections.Generic;
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
    /// pam-rbi: edit Remote Browser Isolation settings.
    /// </summary>
    internal class PamRbiCommand : PamCommandBase
    {
        public PamRbiCommand(IEnterpriseContext context) : base(context)
        {
        }

        /// <summary>
        /// Runs the edit subcommand (default when no subcommand is given).
        /// </summary>
        public async Task ExecuteAsync(PamRbiOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options),
                    "Invalid pam-rbi command arguments. Available commands: edit");
            }

            var command = string.IsNullOrEmpty(options.Command) ? "" : options.Command.Trim().ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(options.RecordFlag))
            {
                options.Record = options.RecordFlag;
            }

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

        private async Task EditAsync(PamRbiOptions options)
        {
            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available.");
            }

            if (string.IsNullOrWhiteSpace(options.Record))
            {
                Console.WriteLine(
                    "Record is required. Usage: pam-rbi edit --record <UID> [--configuration UID] [options]");
                return;
            }

            try
            {
                var result = await RbiUtils.EditRbiAsync(vault, new PamRbiEditOptions
                {
                    Record = options.Record,
                    Configuration = options.Configuration,
                    RemoteBrowserIsolation = options.RemoteBrowserIsolation,
                    ConnectionsRecording = options.ConnectionsRecording,
                    KeyEvents = options.KeyEvents,
                    AutofillCredentials = options.AutofillCredentials,
                    AllowUrlNavigation = options.AllowUrlNavigation,
                    IgnoreServerCert = options.IgnoreServerCert,
                    AllowFileUploads = options.AllowFileUploads,
                    AllowFileDownloads = options.AllowFileDownloads,
                    AllowedUrls = ToListOrNull(options.AllowedUrls),
                    AllowedResourceUrls = ToListOrNull(options.AllowedResourceUrls),
                    AutofillTargets = ToListOrNull(options.AutofillTargets),
                    AllowCopy = options.AllowCopy,
                    AllowPaste = options.AllowPaste,
                    DisableAudio = options.DisableAudio,
                    AudioChannels = options.AudioChannels,
                    AudioBitDepth = options.AudioBitDepth,
                    AudioSampleRate = options.AudioSampleRate,
                    SessionPersistence = options.SessionPersistence,
                    Silent = options.Silent,
                });

                if (options.Silent)
                {
                    return;
                }
                
                foreach (var message in result.Messages)
                {
                    Console.WriteLine(message);
                }

                if (result.RecordUpdated || result.GraphUpdated)
                {
                    Console.WriteLine($"RBI settings updated for {result.RecordUid}");
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

        private static IList<string> ToListOrNull(IEnumerable<string> values)
        {
            if (values == null)
            {
                return null;
            }

            var list = values.ToList();
            return list.Count == 0 ? null : list;
        }
    }

    internal class PamRbiOptions
    {
        [Value(0, Required = false, HelpText = "Command: edit (default)")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "pamRemoteBrowser record UID / title")]
        public string Record { get; set; }

        [Option('r', "record", Required = false, HelpText = "pamRemoteBrowser record UID or path")]
        public string RecordFlag { get; set; }

        [Option('c', "configuration", Required = false, HelpText = "PAM Configuration UID or title")]
        public string Configuration { get; set; }

        [Option("remote-browser-isolation", Required = false,
            HelpText = "Set RBI permissions on the resource: on, off, or default")]
        public string RemoteBrowserIsolation { get; set; }

        [Option("connections-recording", Required = false,
            HelpText = "Session recording permission: on, off, or default")]
        public string ConnectionsRecording { get; set; }

        [Option('k', "key-events", Required = false, HelpText = "Key events (recordingIncludeKeys): on, off, default")]
        public string KeyEvents { get; set; }

        [Option("allow-url-navigation", Required = false,
            HelpText = "Allow navigation via direct URL manipulation: on, off, default")]
        public string AllowUrlNavigation { get; set; }

        [Option("ignore-server-cert", Required = false,
            HelpText = "Ignore server certificate errors: on, off, default")]
        public string IgnoreServerCert { get; set; }

        [Option("allow-file-uploads", Required = false,
            HelpText = "Allow file uploads in RBI sessions: on, off, default")]
        public string AllowFileUploads { get; set; }

        [Option("allow-file-downloads", Required = false,
            HelpText = "Allow file downloads in RBI sessions: on, off, default")]
        public string AllowFileDownloads { get; set; }

        [Option("allowed-urls", Separator = ',', Required = false,
            HelpText = "Allowed URL patterns (repeatable / comma-separated; replaces existing). Use empty string to clear.")]
        public IEnumerable<string> AllowedUrls { get; set; }

        [Option("allowed-resource-urls", Separator = ',', Required = false,
            HelpText = "Allowed resource URL patterns (repeatable / comma-separated; replaces existing). Use empty string to clear.")]
        public IEnumerable<string> AllowedResourceUrls { get; set; }

        [Option('a', "autofill-credentials", Required = false,
            HelpText = "login or pamUser record UID/title for RBI autofill credentials")]
        public string AutofillCredentials { get; set; }

        [Option("autofill-targets", Separator = ',', Required = false,
            HelpText = "Autofill target selectors (repeatable / comma-separated; replaces existing). Use empty string to clear.")]
        public IEnumerable<string> AutofillTargets { get; set; }

        [Option("allow-copy", Required = false, HelpText = "Allow copying to clipboard: on, off, default")]
        public string AllowCopy { get; set; }

        [Option('p', "allow-paste", Required = false, HelpText = "Allow pasting from clipboard: on, off, default")]
        public string AllowPaste { get; set; }

        [Option("disable-audio", Required = false, HelpText = "Disable audio for RBI sessions: on, off, default")]
        public string DisableAudio { get; set; }

        [Option("audio-channels", Required = false, HelpText = "Number of audio channels: 1 (mono) or 2 (stereo)")]
        public int? AudioChannels { get; set; }

        [Option("audio-bit-depth", Required = false, HelpText = "Audio bit depth: 8 or 16")]
        public int? AudioBitDepth { get; set; }

        [Option("audio-sample-rate", Required = false, HelpText = "Audio sample rate in Hz (e.g. 44100, 48000)")]
        public int? AudioSampleRate { get; set; }

        [Option("session-persistence", Required = false,
            HelpText = "RBI session persistence: none, user, resource, or default")]
        public string SessionPersistence { get; set; }

        [Option('s', "silent", Required = false, HelpText = "Silent mode")]
        public bool Silent { get; set; }
    }
}
