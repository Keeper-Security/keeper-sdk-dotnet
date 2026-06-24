using System;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Sample.RecordsExamples
{
    /// <summary>
    /// Generates a passphrase password and updates an existing record's password field.
    /// </summary>
    public static class PassphraseRecordExample
    {
        public static async Task UpdateRecordPassphrase(
            VaultOnline vault,
            string recordUid,
            PassphraseGenerationOptions options = null)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (string.IsNullOrWhiteSpace(recordUid))
            {
                Console.WriteLine("Record UID is required.");
                return;
            }

            if (!vault.TryGetKeeperRecord(recordUid, out var record))
            {
                Console.WriteLine($"Record '{recordUid}' not found.");
                return;
            }

            options ??= new PassphraseGenerationOptions();
            options.WordCount = PassphraseGenerator.ValidateWordCount(options.WordCount);
            options.Separator = PassphraseGenerator.ValidateSeparator(options.Separator);

            var passphrase = PassphraseGenerator.GeneratePassphrase(options);
            Console.WriteLine($"Record loaded: {record.Title} ({recordUid})");
            Console.WriteLine($"Generated passphrase ({options.WordCount} words): {passphrase}");

            if (!TrySetPassword(record, passphrase))
            {
                Console.WriteLine("Password field not found on this record.");
                return;
            }

            await vault.UpdateRecord(record);
            Console.WriteLine("Record password updated with generated passphrase.");
        }

        private static bool TrySetPassword(KeeperRecord record, string password)
        {
            switch (record)
            {
                case PasswordRecord pr:
                    pr.Password = password;
                    return true;
                case TypedRecord typed when typed.FindTypedField("password", null, out var field):
                    field.ObjectValue = password;
                    return true;
                default:
                    return false;
            }
        }
    }
}
