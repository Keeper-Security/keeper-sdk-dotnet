using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Lists post-rotation scripts on pamUser / pamDirectory records.
    /// </summary>
    public static class PamRotationScriptListExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="pattern">Optional record UID or title filter.</param>
        public static async Task ListScripts(VaultOnline vault = null, string pattern = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                Console.WriteLine(
                    $"{"Record UID",-28}  {"Title",-24}  {"Type",-14}  {"Script UID",-28}  {"Script Name",-24}  {"Records",-28}  Command");
                Console.WriteLine(new string('-', 180));

                var count = 0;
                foreach (var record in vault.KeeperRecords.OfType<TypedRecord>()
                             .Where(r => PamRecordTypes.Script.Contains(r.TypeName ?? "")))
                {
                    if (!PamRotationScriptHelper.MatchesPattern(record, pattern))
                    {
                        continue;
                    }

                    foreach (var scriptField in record.Fields
                                 .OfType<TypedField<FieldScript>>()
                                 .Where(PamRotationScriptHelper.IsRotationScriptField))
                    {
                        foreach (var script in scriptField.Values)
                        {
                            if (string.IsNullOrEmpty(script?.FileRef))
                            {
                                continue;
                            }

                            vault.TryGetKeeperRecord(script.FileRef, out var fileKeeper);
                            var fileRecord = fileKeeper as FileRecord;
                            var scriptName = !string.IsNullOrEmpty(fileRecord?.Name)
                                ? fileRecord.Name
                                : fileRecord?.Title ?? "[inaccessible]";
                            var recordRefs = script.RecordRef != null
                                ? string.Join(", ", script.RecordRef)
                                : "";

                            Console.WriteLine(
                                $"{record.Uid,-28}  {Truncate(record.Title, 24),-24}  {record.TypeName,-14}  {script.FileRef,-28}  {Truncate(scriptName, 24),-24}  {Truncate(recordRefs, 28),-28}  {script.Command ?? ""}");
                            count++;
                        }
                    }
                }

                Console.WriteLine();
                if (count == 0)
                {
                    Console.WriteLine("No post-rotation scripts found.");
                }
                else
                {
                    Console.WriteLine($"Total: {count} post-rotation script(s)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value ?? "";
            }

            return value.Substring(0, maxLength - 3) + "...";
        }
    }
}
