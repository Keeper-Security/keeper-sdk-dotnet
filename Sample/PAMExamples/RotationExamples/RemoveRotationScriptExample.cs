using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Removes a post-rotation script from a pamUser / pamDirectory record.
    /// Only the record owner can remove scripts.
    /// </summary>
    public static class RemoveRotationScriptExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="recordId">pamUser / pamDirectory UID or title.</param>
        /// <param name="scriptId">Script file UID, title, or file name.</param>
        public static async Task RemoveScript(VaultOnline vault, string recordId, string scriptId)
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

                scriptField.Values.Remove(scriptValue);
                try
                {
                    await vault.UpdateRecord(record);
                }
                catch (KeeperApiException ex) when (PamRotationScriptHelper.IsOwnerScriptError(ex.Code))
                {
                    Console.WriteLine("Only the record owner can remove post-rotation scripts.");
                    return;
                }

                Console.WriteLine($"Script removed from record '{record.Title}' ({record.Uid}).");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
