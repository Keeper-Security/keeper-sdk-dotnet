namespace KeeperSecurity.Vault
{
    internal static class ShareOwnerValidation
    {
        internal static VaultException RecordOwner(string username)
        {
            return new VaultException(
                $"'{username}' is the owner of this record and already has full access. " +
                "Share permissions cannot be granted, changed, or revoked for the owner.");
        }

        internal static VaultException FolderOwner(string username, bool sharedFolder)
        {
            var item = sharedFolder ? "shared folder" : "folder";
            return new VaultException(
                $"'{username}' is the owner of this {item} and already has full access. " +
                "Share permissions cannot be granted, changed, or revoked for the owner.");
        }
    }
}
