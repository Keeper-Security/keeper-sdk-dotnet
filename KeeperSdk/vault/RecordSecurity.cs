using System;
using System.Linq;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <summary>Provides a single policy for identifying and masking record secrets in SDK consumers.</summary>
    public static class RecordSecurity
    {
        public static bool IsSensitive(ITypedField field) => IsSensitive(field?.FieldName);

        public static bool IsSensitive(string name) => name?.ToLowerInvariant() switch
        {
            "password" or "secret" or "pincode" or "pin_code" or "privatekey" or "passkey" or "otp" or "totp" or "onetimecode" or "keypair" or "licensenumber" or "note" or "json" => true,
            _ => false,
        };

        public static string Mask(string value, bool unmask) => unmask || string.IsNullOrEmpty(value) ? value : "********";

        public static bool HasPassword(KeeperRecord record) => record switch
        {
            PasswordRecord password => !string.IsNullOrEmpty(password.Password) ||
                (password.Custom ?? Enumerable.Empty<CustomField>()).Any(x => string.Equals(x.Name, "password", StringComparison.OrdinalIgnoreCase) &&
                                         !string.IsNullOrEmpty(x.Value)),
            TypedRecord typed => (typed.Fields ?? Enumerable.Empty<ITypedField>())
                .Concat(typed.Custom ?? Enumerable.Empty<ITypedField>())
                .Where(x => string.Equals(x.FieldName, "password", StringComparison.OrdinalIgnoreCase))
                .SelectMany(x => x.GetTypedFieldValues())
                .Any(x => !string.IsNullOrEmpty(x)),
            _ => false,
        };

        public static bool HasPassword(KeeperNSFRecord record) => record?.Fields?.Any(field =>
            string.Equals(field.Type, "password", StringComparison.OrdinalIgnoreCase) &&
            field.Value?.Any(value => !string.IsNullOrEmpty(value)) == true) == true;
    }
}
