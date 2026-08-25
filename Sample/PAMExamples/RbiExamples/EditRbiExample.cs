using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.RbiExamples
{
    /// <summary>
    /// Configures Remote Browser Isolation settings on a pamRemoteBrowser record via
    /// <see cref="RbiUtils.EditRbiAsync"/>.
    /// </summary>
    public static class EditRbiExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="record">pamRemoteBrowser record UID or title.</param>
        /// <param name="configuration">PAM Configuration UID or title to link the resource to.</param>
        /// <param name="remoteBrowserIsolation">Enable RBI on the resource graph: on, off, or default.</param>
        /// <param name="connectionsRecording">Session recording permission: on, off, or default.</param>
        /// <param name="keyEvents">recordingIncludeKeys tri-state: on, off, or default.</param>
        /// <param name="autofillCredentials">login or pamUser record UID/title for HTTP autofill credentials.</param>
        /// <param name="allowUrlNavigation">Allow navigating URLs in the remote browser: on, off, or default.</param>
        /// <param name="ignoreServerCert">Ignore the initial SSL certificate check: on, off, or default.</param>
        /// <param name="allowFileUploads">Allow file uploads in the RBI session: on, off, or default.</param>
        /// <param name="allowFileDownloads">Allow file downloads in the RBI session: on, off, or default.</param>
        /// <param name="allowedUrls">URL allow-list patterns (replaces existing). Pass a single empty string to clear.</param>
        /// <param name="allowedResourceUrls">Resource URL allow-list patterns (replaces existing). Pass a single empty string to clear.</param>
        /// <param name="autofillTargets">Autofill target selectors (replaces existing). Pass a single empty string to clear.</param>
        /// <param name="allowCopy">Allow clipboard copy: on, off, or default.</param>
        /// <param name="allowPaste">Allow clipboard paste: on, off, or default.</param>
        /// <param name="disableAudio">Mute audio in the RBI session: on, off, or default.</param>
        /// <param name="audioChannels">Audio channel count: 1 or 2.</param>
        /// <param name="audioBitDepth">Audio bit depth: 8 or 16.</param>
        /// <param name="audioSampleRate">Audio sample rate in Hz (e.g. 44100, 48000).</param>
        /// <param name="sessionPersistence">none, user, resource, or default.</param>
        /// <param name="silent">Suppress the PAM configuration warning output.</param>
        public static async Task EditRbi(
            VaultOnline vault,
            string record,
            string configuration = null,
            string remoteBrowserIsolation = null,
            string connectionsRecording = null,
            string keyEvents = null,
            string autofillCredentials = null,
            string allowUrlNavigation = null,
            string ignoreServerCert = null,
            string allowFileUploads = null,
            string allowFileDownloads = null,
            IList<string> allowedUrls = null,
            IList<string> allowedResourceUrls = null,
            IList<string> autofillTargets = null,
            string allowCopy = null,
            string allowPaste = null,
            string disableAudio = null,
            int? audioChannels = null,
            int? audioBitDepth = null,
            int? audioSampleRate = null,
            string sessionPersistence = null,
            bool silent = false)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(record))
                {
                    Console.WriteLine("Record is required.");
                    return;
                }

                var result = await RbiUtils.EditRbiAsync(vault, new PamRbiEditOptions
                {
                    Record = record,
                    Configuration = configuration,
                    RemoteBrowserIsolation = remoteBrowserIsolation,
                    ConnectionsRecording = connectionsRecording,
                    KeyEvents = keyEvents,
                    AutofillCredentials = autofillCredentials,
                    AllowUrlNavigation = allowUrlNavigation,
                    IgnoreServerCert = ignoreServerCert,
                    AllowFileUploads = allowFileUploads,
                    AllowFileDownloads = allowFileDownloads,
                    AllowedUrls = allowedUrls,
                    AllowedResourceUrls = allowedResourceUrls,
                    AutofillTargets = autofillTargets,
                    AllowCopy = allowCopy,
                    AllowPaste = allowPaste,
                    DisableAudio = disableAudio,
                    AudioChannels = audioChannels,
                    AudioBitDepth = audioBitDepth,
                    AudioSampleRate = audioSampleRate,
                    SessionPersistence = sessionPersistence,
                    Silent = silent,
                });

                if (silent)
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
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
