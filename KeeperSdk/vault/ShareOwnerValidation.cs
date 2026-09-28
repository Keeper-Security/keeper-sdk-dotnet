namespace KeeperSecurity.Vault
{
    internal static class ShareOwnerValidation
    {
        internal const string OwnerStatus = "owner";

        // Sharing an owner was previously allowed to reach the API. Keep the intentional
        // client-side rejection and its user-facing text consistent across all share APIs.
        internal static string RecordOwnerMessage(string username)
        {
            return $"'{username}' is the owner of this record and already has full access. " +
                   "Share permissions cannot be granted, changed, or revoked for the owner.";
        }

        internal static VaultException RecordOwner(string username)
        {
            return new VaultException(RecordOwnerMessage(username));
        }

        internal static string FolderOwnerMessage(string username, bool sharedFolder)
        {
            var item = sharedFolder ? "shared folder" : "folder";
            return $"'{username}' is the owner of this {item} and already has full access. " +
                   "Share permissions cannot be granted, changed, or revoked for the owner.";
        }

        internal static VaultException FolderOwner(string username, bool sharedFolder)
        {
            return new VaultException(FolderOwnerMessage(username, sharedFolder));
        }
    }
}
