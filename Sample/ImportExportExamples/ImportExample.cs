using System;
using System.Globalization;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System.Collections.Generic;
using KeeperSecurity.Commands;
namespace Sample.ImportExportExamples
{
    public static class ImportExample
    {
        /// <summary>
        /// Imports records from a JSON string into the Keeper vault.
        /// </summary>
        /// <param name="jsonContent">The raw JSON string content to import</param>
        /// <returns>BatchResult with import statistics</returns>
        public static async Task<BatchResult> Import(string jsonContent)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            // Step 1: Deserialize JSON using ZeroDep.Json (same as Commander)
            var jOptions = new ZeroDep.JsonOptions
            {
                DateTimeStyles = DateTimeStyles.None,
            };
            jOptions.SerializationOptions &= ~ZeroDep.JsonSerializationOptions.AutoParseDateTime;
            var jsonDict = ZeroDep.Json.Deserialize<Dictionary<string, object>>(jsonContent, jOptions);
            // Step 2: Parse the JSON dictionary into an ImportFile object
            ImportFile import = KeeperImport.LoadJsonDictionary(jsonDict);
            // Step 3: Logger callback for import messages
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Warning || severity == Severity.Error)
                {
                    Console.WriteLine($"[{severity}] {message}");
                }
            }
            // Step 4: Actually import the records into the vault
            var result = await vault.ImportJson(import, Logger);
            // Print summary
            Console.WriteLine($"Import completed:");
            Console.WriteLine($"  Shared Folders: {result.SharedFolderCount}");
            Console.WriteLine($"  Folders: {result.FolderCount}");
            Console.WriteLine($"  Records: {result.TypedRecordCount}");
            Console.WriteLine($"  Legacy Records: {result.LegacyRecordCount}");
            Console.WriteLine($"  Updated Records: {result.UpdatedRecordCount}");
            return result;
        }
    }
}
