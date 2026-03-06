using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class CreateRecordTypeExample
    {
        // Sample record type data format (JSON string)
        // Required fields:
        //   - $id: Unique identifier for the record type
        //   - description: Human-readable description
        //   - categories: Array of categories (e.g., "login", "note", "general")
        //   - fields: Array of field references using $ref
        //
        // Available field types: login, password, url, text, note, oneTimeCode,
        //                        name, phone, email, address, paymentCard, etc.
        //
        // Example:
        // var recordTypeData = @"{
        //     ""$id"": ""customLoginType"",
        //     ""description"": ""Custom Login Record Type"",
        //     ""categories"": [""login""],
        //     ""fields"": [
        //         {""$ref"": ""login""},
        //         {""$ref"": ""password""},
        //         {""$ref"": ""url""},
        //         {""$ref"": ""oneTimeCode""}
        //     ]
        // }";

        public static async Task CreateRecordType(VaultOnline vault, string recordTypeData)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            var createdRecordTypeId = await vault.AddRecordType(recordTypeData);

            Console.WriteLine($"Created Record Type ID: {createdRecordTypeId}");
        }
    }
}
