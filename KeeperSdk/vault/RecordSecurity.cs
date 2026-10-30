using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <summary>Mirrors keeper-sdk-python keepercli/helpers/record_utils.SENSITIVE_FIELD_TYPES.</summary>
    public static class RecordSecurity
    {
        public const string MaskedValue = "********";

        private static readonly HashSet<string> SensitiveFieldTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "password", "secret", "otp", "privateKey", "pinCode", "pin_code", "oneTimeCode", "keyPair", "licenseNumber"
        };

        public static bool IsSensitive(ITypedField field) => IsSensitive(field?.FieldName);

        public static bool IsSensitive(string fieldTypeOrName) =>
            fieldTypeOrName != null && SensitiveFieldTypes.Contains(fieldTypeOrName);

        public static string Mask(string value, bool unmask) =>
            unmask || string.IsNullOrEmpty(value) ? value : MaskedValue;

        public static bool HasPassword(KeeperRecord record)
        {
            if (record is PasswordRecord password)
            {
                return !string.IsNullOrEmpty(password.Password) ||
                    (password.Custom ?? Enumerable.Empty<CustomField>()).Any(x =>
                        IsSensitivePassword(x.Name) && !string.IsNullOrEmpty(x.Value));
            }

            if (record is TypedRecord typed)
            {
                return (typed.Fields ?? Enumerable.Empty<ITypedField>())
                    .Concat(typed.Custom ?? Enumerable.Empty<ITypedField>())
                    .Where(x => IsSensitivePassword(x.FieldName))
                    .SelectMany(x => x.GetTypedFieldValues())
                    .Any(x => !string.IsNullOrEmpty(x));
            }

            return false;
        }

        public static bool HasPassword(KeeperNSFRecord record) => record?.Fields?.Any(field =>
            IsSensitivePassword(field.Type) &&
            field.Value?.Any(value => !string.IsNullOrEmpty(value)) == true) == true;

        private static bool IsSensitivePassword(string name) =>
            string.Equals(name, "password", StringComparison.OrdinalIgnoreCase);
    }
}
