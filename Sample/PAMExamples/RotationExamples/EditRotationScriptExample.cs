using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Updates a post-rotation script command and/or linked credentials.
    /// Only the record owner can edit scripts.
    /// </summary>
    public static class EditRotationScriptExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="recordId">pamUser / pamDirectory UID or title.</param>
        /// <param name="scriptId">Script file UID, title, or file name.</param>
        /// <param name="runCommand">Optional new command line.</param>
        /// <param name="addCredentialUids">Optional credential UIDs to add.</param>
        /// <param name="removeCredentialUids">Optional credential UIDs to remove.</param>
        public static async Task EditScript(
            VaultOnline vault,
            string recordId,
            string scriptId,
            string runCommand = null,
            IEnumerable<string> addCredentialUids = null,
            IEnumerable<string> removeCredentialUids = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(recordId))
                {
                    Console.WriteLine("Record UID or title is required.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(scriptId))
                {
                    Console.WriteLine("Script UID or name is required.");
                    return;
                }

                TypedRecord record;
                try
                {
                    record = PamRotationScriptHelper.ResolveScriptRecord(vault, recordId);
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }

                if (record == null)
                {
                    Console.WriteLine($"Record '{recordId}' not found (expected pamUser or pamDirectory).");
                    return;
                }

                var scriptValue = PamRotationScriptHelper.FindScriptValue(
                    vault,
                    record,
                    scriptId.Trim(),
                    out var scriptField);
                if (scriptField == null)
                {
                    Console.WriteLine($"Record '{record.Title}' has no rotation scripts.");
                    return;
                }

                if (scriptValue == null)
                {
                    Console.WriteLine($"Record '{record.Title}' does not have script '{scriptId}'.");
                    return;
                }

                var modified = false;
                var refs = new HashSet<string>(
                    scriptValue.RecordRef ?? Array.Empty<string>(),
                    StringComparer.Ordinal);

                string[] removeRefs;
                string[] addRefs;
                try
                {
                    removeRefs = PamRotationScriptHelper.ResolveCredentialUids(vault, removeCredentialUids);
                    addRefs = PamRotationScriptHelper.ResolveCredentialUids(vault, addCredentialUids);
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }

                foreach (var cred in removeRefs)
                {
                    if (refs.Remove(cred))
                    {
                        modified = true;
                    }
                }

                foreach (var cred in addRefs)
                {
                    if (refs.Add(cred))
                    {
                        modified = true;
                    }
                }

                if (modified)
                {
                    scriptValue.RecordRef = refs.ToArray();
                }

                if (!string.IsNullOrWhiteSpace(runCommand))
                {
                    scriptValue.Command = runCommand;
                    modified = true;
                }

                if (!modified)
                {
                    Console.WriteLine("Nothing to do. Provide runCommand and/or credential changes.");
                    return;
                }

                try
                {
                    await vault.UpdateRecord(record);
                }
                catch (KeeperApiException ex) when (PamRotationScriptHelper.IsOwnerScriptError(ex.Code))
                {
                    Console.WriteLine("Only the record owner can edit post-rotation scripts.");
                    return;
                }

                Console.WriteLine($"Script updated on record '{record.Title}' ({record.Uid}).");
                if (!string.IsNullOrWhiteSpace(scriptValue.Command))
                {
                    Console.WriteLine($"Command: {scriptValue.Command}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
