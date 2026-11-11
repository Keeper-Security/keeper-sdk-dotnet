using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <summary>Identifies sensitive Keeper field types and custom field names for display masking.</summary>
    public static class RecordSecurity
    {
        public const string MaskedValue = "********";

        private static readonly HashSet<string> SensitiveFieldTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "password", "secret", "secret2", "pin", "pinCode", "pin_code", "token", "key",
            "apiKey", "api_key", "privateKey", "private_key", "passphrase", "passkey",
            "otp", "totp", "oneTimeCode", "keyPair", "licenseNumber"
        };

        public static bool IsSensitive(ITypedField field) =>
            field != null && IsSensitive(field.FieldName, field.FieldLabel);

        public static bool IsSensitive(KeeperNSFField field) =>
            field != null && IsSensitive(field.Type, field.Label);

        public static bool IsSensitive(string fieldTypeOrName, string label) =>
            IsSensitive(fieldTypeOrName) || IsSensitive(label);

        public static bool IsSensitive(string fieldTypeOrName) =>
            fieldTypeOrName != null && SensitiveFieldTypes.Contains(fieldTypeOrName);

        public static bool IsPassword(ITypedField field) =>
            field != null && IsPassword(field.FieldName, field.FieldLabel);

        public static bool IsPassword(string fieldTypeOrName, string label = null) =>
            string.Equals(fieldTypeOrName, "password", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(label, "password", StringComparison.OrdinalIgnoreCase);

        public static string Mask(string value, bool unmask) =>
            unmask || string.IsNullOrEmpty(value) ? value : MaskedValue;

        public static bool HasPassword(KeeperRecord record)
        {
            if (record is PasswordRecord password)
            {
                return !string.IsNullOrEmpty(password.Password) ||
                    (password.Custom ?? Enumerable.Empty<CustomField>()).Any(x =>
                        IsPassword(x.Name) && !string.IsNullOrEmpty(x.Value));
            }

            if (record is TypedRecord typed)
            {
                return (typed.Fields ?? Enumerable.Empty<ITypedField>())
                    .Concat(typed.Custom ?? Enumerable.Empty<ITypedField>())
                    .Where(IsPassword)
                    .SelectMany(x => x.GetTypedFieldValues())
                    .Any(x => !string.IsNullOrEmpty(x));
            }

            return false;
        }

        public static bool HasPassword(KeeperNSFRecord record) => record?.Fields?.Any(field =>
            IsPassword(field.Type, field.Label) &&
            field.Value?.Any(value => !string.IsNullOrEmpty(value)) == true) == true;
    }
}
