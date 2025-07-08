namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Utility class for common record operations.
    /// </summary>
    public static class RecordUtils
    {
        /// <summary>
        /// Extracts the password from a KeeperRecord regardless of its type.
        /// </summary>
        /// <param name="record">The record to extract password from.</param>
        /// <returns>The password string, or null if not found.</returns>
        public static string ExtractPassword(this KeeperRecord record)
        {
            return record switch
            {
                null => null,
                PasswordRecord pr => pr.Password,
                TypedRecord tr when tr.FindTypedField("password", null, out var rf) => rf.GetExternalValue(),
                _ => "",
            };
        }

        /// <summary>
        /// Extracts the login/username from a KeeperRecord regardless of its type.
        /// </summary>
        /// <param name="record">The record to extract login from.</param>
        /// <returns>The login string, or null if not found.</returns>
        public static string ExtractLogin(this KeeperRecord record)
        {
            return record switch
            {
                null => null,
                PasswordRecord pr => pr.Login,
                TypedRecord tr when tr.FindTypedField("login", null, out var rf) => rf.GetExternalValue(),
                _ => "",
            };
        }

        /// <summary>
        /// Extracts the URL from a KeeperRecord regardless of its type.
        /// </summary>
        /// <param name="record">The record to extract URL from.</param>
        /// <returns>The URL string, or null if not found.</returns>
        public static string ExtractUrl(this KeeperRecord record)
        {
            return record switch
            {
                null => null,
                PasswordRecord pr => pr.Link,
                TypedRecord tr when tr.FindTypedField("url", null, out var rf) => rf.GetExternalValue(),
                _ => "",
            };
        }

        /// <summary>
        /// Extracts the notes from a KeeperRecord regardless of its type.
        /// </summary>
        /// <param name="record">The record to extract notes from.</param>
        /// <returns>The notes string, or null if not found.</returns>
        public static string ExtractNotes(this KeeperRecord record)
        {
            switch (record)
            {
                case null:
                    return null;
                case PasswordRecord pr:
                    return pr.Notes;
                case TypedRecord tr:
                {
                    var notes = tr.Notes ?? "";
                    if (tr.FindTypedField("note", null, out var rf))
                    {
                        notes += rf.GetExternalValue();
                    }
                    return notes;
                }
                default:
                    return "";
            }
        }

        /// <summary>
        /// Extracts the TOTP from a KeeperRecord regardless of its type.
        /// </summary>
        /// <param name="record">The record to extract TOTP from.</param>
        /// <returns>The TOTP string, or null if not found.</returns>
        public static string ExtractTotp(this KeeperRecord record)
        {
            switch (record)
            {
                case null:
                    return null;
                case PasswordRecord pr:
                    return pr.Totp;
                case TypedRecord tr when tr.FindTypedField("oneTimeCode", null, out var rf):
                    return rf.GetExternalValue();
                default:
                    return "";
            }
        }
    }
} 