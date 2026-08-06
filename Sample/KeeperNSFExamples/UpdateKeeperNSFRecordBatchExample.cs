using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Sample.KeeperNSFExamples
{
    /// <summary>
    /// Demonstrates batch update of Keeper NSF records via <see cref="IVault.UpdateKeeperNSFRecords"/> /
    /// <see cref="IVault.UpdateKeeperNSFRecordsFromImport"/>.
    /// Uses the same JSON record shape as Import-KeeperVault / Export-KeeperVault; each record requires <c>uid</c>.
    /// </summary>
    public static class UpdateKeeperNSFRecordsBatchExample
    {
        /// <summary>
        /// Updates records using an in-memory list of <see cref="KeeperNSFRecordUpdateRequest"/>.
        /// </summary>
        public static async Task UpdateBatch(
            VaultOnline vault,
            IReadOnlyList<KeeperNSFRecordUpdateRequest> records)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (records == null || records.Count == 0)
            {
                Console.WriteLine("No records to update.");
                return;
            }

            try
            {
                Console.WriteLine($"Updating {records.Count} Keeper NSF record(s) in batch...");
                var results = await vault.UpdateKeeperNSFRecords(records);
                PrintResults(results);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates records from an <see cref="ImportFile"/> payload (each record must include <c>uid</c>).
        /// </summary>
        public static async Task UpdateBatch(VaultOnline vault, ImportFile import)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (import?.Records == null || import.Records.Length == 0)
            {
                Console.WriteLine("No records to update.");
                return;
            }

            try
            {
                Console.WriteLine($"Updating {import.Records.Length} Keeper NSF record(s) in batch...");
                var results = await vault.UpdateKeeperNSFRecordsFromImport(import);
                PrintResults(results);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Keeper NSF records in batch: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates records from the embedded sample JSON (same shape as PowerCommander -DownloadSampleRecords).
        /// Replace placeholder UIDs before running.
        /// </summary>
        public static async Task UpdateBatchFromSampleFile(VaultOnline vault)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var import = LoadSampleImportFile();
            await UpdateBatch(vault, import);
        }

        /// <summary>
        /// Loads the embedded sample JSON as an <see cref="ImportFile"/>.
        /// </summary>
        public static ImportFile LoadSampleImportFile()
        {
            var jOptions = new JsonOptions
            {
                DateTimeStyles = DateTimeStyles.None,
            };
            jOptions.SerializationOptions &= ~JsonSerializationOptions.AutoParseDateTime;
            var jsonDict = Json.Deserialize<Dictionary<string, object>>(SampleUpdateImportJson, jOptions);
            return KeeperImport.LoadJsonDictionary(jsonDict);
        }

        // Print OK/FAIL lines from an update batch response.
        private static void PrintResults(IReadOnlyList<KeeperNSFRecordUpdateResult> results)
        {
            var succeeded = 0;
            foreach (var result in results)
            {
                if (result.Success)
                {
                    succeeded++;
                    Console.WriteLine($"  [OK]   {result.Title}  UID: {result.RecordUid}");
                }
                else
                {
                    Console.WriteLine(
                        $"  [FAIL] {result.Title}  UID: {result.RecordUid}  status={result.Status ?? "-"}  {result.Message ?? "(no message)"}");
                }
            }

            Console.WriteLine($"Batch complete: {succeeded} succeeded, {results.Count - succeeded} failed.");
        }

        private const string SampleUpdateImportJson = @"{
  ""records"": [
    {
      ""uid"": ""REPLACE_WITH_EXISTING_RECORD_UID_1"",
      ""title"": ""Batch Update Demo - Login"",
      ""$type"": ""login"",
      ""login"": ""updated.login@example.com"",
      ""password"": ""Replace-With-Your-Password"",
      ""login_url"": ""https://portal.example.com"",
      ""notes"": ""Updated via NSF batch update""
    },
    {
      ""uid"": ""REPLACE_WITH_EXISTING_RECORD_UID_2"",
      ""title"": ""Batch Update Demo - Title Only"",
      ""notes"": ""Only title and notes changed; fields omitted are left as-is""
    }
  ]
}";
    }
}
