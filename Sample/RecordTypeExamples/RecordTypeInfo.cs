using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.RecordTypeExamples
{
    public static class RecordTypeInfoExample
    {
        public static async Task RecordTypeInfo(string recordTypeName = null)
        {
            var vault = await AuthenticateAndGetVault.GetVault();

            // If no specific record type passed, print all in table format
            if (recordTypeName == null)
            {
                var recordTypes = vault.RecordTypes.ToList();
                Console.WriteLine(
                    $"{"#",4}  " +
                    $"{"ID",-20}" +
                    $"{"Record Type Name",-25}  " +
                    $"{"Description",-40}"
                );

                Console.WriteLine(new string('-', 80));

                int index = 1;

                foreach (var rt in recordTypes)
                {
                    Console.WriteLine(
                        $"{index,4}  " +
                        $"{rt.Id,-20}  " +
                        $"{rt.Name,-25}  " +
                        $"{(rt.Description ?? "N/A"),-40}"
                    );
                    index++;
                }
            }
            else
            {
                // Get the specific record type
                var recordType = vault.RecordTypes
                    .FirstOrDefault(rt => rt.Name.Equals(recordTypeName, StringComparison.OrdinalIgnoreCase));

                if (recordType == null)
                {
                    Console.WriteLine($"Record Type '{recordTypeName}' not found.");
                    return;
                }

                Console.WriteLine($"\nMy Vault> record-type-info \"{recordTypeName}\"");

                Console.WriteLine($"    {"Record Type ID:",-5} {recordType.Id}");
                Console.WriteLine($"         {"Type Name:",-5} {recordType.Name}");
                Console.WriteLine($"             {"Scope:",-5} {recordType.Scope}");
                Console.WriteLine($"       {"Description:",-5} {recordType.Description ?? "N/A"}");
                Console.WriteLine($"            {"Fields:",-5}");
                foreach (var field in recordType.Fields)
                {
                    Console.WriteLine($"                     ({field.FieldName})");
                }
            }
        }
    }
}
