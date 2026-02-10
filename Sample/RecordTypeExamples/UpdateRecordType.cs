using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class UpdateRecordTypeExample
    {
        // Sample record type data format (JSON string)
        // Required fields:
        //   - $id: Unique identifier for the record type (must match existing type)
        //   - description: Human-readable description
        //   - categories: Array of categories (e.g., "login", "note", "general")
        //   - fields: Array of field references using $ref
        //
        // Available field types: login, password, url, text, note, oneTimeCode,
        //                        name, phone, email, address, paymentCard, etc.
        //
        // Example:
        // var recordTypeId = "12345";
        // var recordTypeData = @"{
        //     ""$id"": ""customLoginType"",
        //     ""description"": ""Updated Custom Login Record Type"",
        //     ""categories"": [""login""],
        //     ""fields"": [
        //         {""$ref"": ""login""},
        //         {""$ref"": ""password""},
        //         {""$ref"": ""url""},
        //         {""$ref"": ""oneTimeCode""},
        //         {""$ref"": ""note""}
        //     ]
        // }";

        public static async Task UpdateRecordType(string recordTypeId, string recordTypeData)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            var updatedRecordTypeId = await vault.UpdateRecordTypeAsync(recordTypeId, recordTypeData);

            Console.WriteLine($"Updated Record Type ID: {updatedRecordTypeId}");
        }
    }
}
