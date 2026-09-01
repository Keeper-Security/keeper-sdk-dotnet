using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Uploads a local file and attaches it as a post-rotation script on a pamUser / pamDirectory record.
    /// Only the record owner can attach scripts.
    /// </summary>
    public static class PamRotationScriptAddExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="recordId">pamUser / pamDirectory UID or title.</param>
        /// <param name="scriptFilePath">Local script file path to upload.</param>
        /// <param name="runCommand">Optional command line to run after rotation.</param>
        /// <param name="addCredentialUids">Optional credential record UIDs to link.</param>
        public static async Task AddScript(
            VaultOnline vault,
            string recordId,
            string scriptFilePath,
            string runCommand = null,
            IEnumerable<string> addCredentialUids = null)
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

                if (string.IsNullOrWhiteSpace(scriptFilePath))
                {
                    Console.WriteLine("Script file path is required.");
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

                var filePath = Environment.ExpandEnvironmentVariables(scriptFilePath.Trim());
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"File \"{scriptFilePath}\" not found.");
                    return;
                }

                string[] credentialRefs;
                try
                {
                    credentialRefs = PamRotationScriptHelper.ResolveCredentialUids(vault, addCredentialUids);
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }

                var scriptField = PamRotationScriptHelper.GetOrCreateScriptField(record);
                var facade = new TypedRecordFacade<TypedRecordFileRef>(record);
                var preRefs = PamRotationScriptHelper.GetFileRefUids(facade.Fields.FileRef);

                using (var uploadTask = new FileAttachmentUploadTask(filePath, isScript: true))
                {
                    try
                    {
                        await vault.UploadAttachment(record, uploadTask);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                        return;
                    }
                }

                var postRefs = PamRotationScriptHelper.GetFileRefUids(facade.Fields.FileRef);
                var newUids = postRefs.Except(preRefs).ToList();
                if (newUids.Count != 1)
                {
                    Console.WriteLine(
                        "Failed to determine uploaded script file UID. "
                        + "Only the record owner can attach post-rotation scripts.");
                    return;
                }

                if (facade.Fields.FileRef != null)
                {
                    facade.Fields.FileRef.Values.Remove(newUids[0]);
                }

                var scriptValue = new FieldScript
                {
                    FileRef = newUids[0],
                    RecordRef = credentialRefs,
                    Command = runCommand ?? "",
                };

                scriptField.Values.Add(scriptValue);
                try
                {
                    await vault.UpdateRecord(record);
                }
                catch (KeeperApiException ex) when (PamRotationScriptHelper.IsOwnerScriptError(ex.Code))
                {
                    Console.WriteLine("Only the record owner can attach post-rotation scripts.");
                    return;
                }

                Console.WriteLine($"Script added to record '{record.Title}' ({record.Uid}).");
                Console.WriteLine($"Script UID: {newUids[0]}");
                if (!string.IsNullOrWhiteSpace(runCommand))
                {
                    Console.WriteLine($"Command: {runCommand}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
