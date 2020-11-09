namespace KeeperSecurity.Vault
{
    /// <exclude/>
    public static class VaultDataExtensions
    {
        public static FolderNode GetFolder(this IVaultData vaultData, string folderUid)
        {
            if (string.IsNullOrEmpty(folderUid))
            {
                return vaultData.RootFolder;
            }

            if (vaultData.TryGetFolder(folderUid, out var folder))
            {
                return folder;
            }

            throw new VaultException($"Folder UID \"{folderUid}\" not found.");
        }

        public static SharedFolder GetSharedFolder(this IVaultData vaultData, string sharedFolderUid)
        {
            if (string.IsNullOrEmpty(sharedFolderUid))
            {
                throw new VaultException("Shared Folder UID cannot be empty.");
            }

            if (vaultData.TryGetSharedFolder(sharedFolderUid, out var folder))
            {
                return folder;
            }

            throw new VaultException($"Shared Folder UID \"{sharedFolderUid}\" not found.");
        }

        public static PasswordRecord GetRecord(this IVaultData vaultData, string recordUid)
        {
            if (string.IsNullOrEmpty(recordUid))
            {
                throw new VaultException("Record UID cannot be empty.");
            }

            if (vaultData.TryGetRecord(recordUid, out var record))
            {
                return record;
            }

            throw new VaultException($"Record UID \"{recordUid}\" not found.");
        }

    }
}
