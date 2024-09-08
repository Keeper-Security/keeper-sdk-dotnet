using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Provides in memory implementation of IKeeperStorage interface.
    /// </summary>
    /// <seealso cref="IKeeperStorage" />
    public class InMemoryKeeperStorage : IKeeperStorage
    {
        private readonly InMemoryRecordStorage<IVaultSettings> _vaultSettings =
            new InMemoryRecordStorage<IVaultSettings>();

        private readonly InMemoryEntityStorage<IStorageRecord> _recordStorage =
            new InMemoryEntityStorage<IStorageRecord>();

        private readonly InMemoryEntityStorage<IStorageSharedFolder> _sharedFolderStorage =
            new InMemoryEntityStorage<IStorageSharedFolder>();

        private readonly InMemoryEntityStorage<IStorageTeam> _teamStorage =
            new InMemoryEntityStorage<IStorageTeam>();

        private readonly InMemoryEntityStorage<IStorageNonSharedData> _nonSharedDataStorage =
            new InMemoryEntityStorage<IStorageNonSharedData>();

        private readonly InMemoryLinkStorage<IStorageRecordKey> _recordKeyStorage =
            new InMemoryLinkStorage<IStorageRecordKey>();

        private readonly InMemoryLinkStorage<IStorageSharedFolderKey> _sharedFolderKeyStorage =
            new InMemoryLinkStorage<IStorageSharedFolderKey>();

        private readonly InMemoryLinkStorage<ISharedFolderPermission> _sharedFolderPermissions =
            new InMemoryLinkStorage<ISharedFolderPermission>();

        private readonly InMemoryEntityStorage<IStorageFolder> _folderStorage =
            new InMemoryEntityStorage<IStorageFolder>();

        private readonly InMemoryLinkStorage<IStorageFolderRecord> _folderRecordStorage =
            new InMemoryLinkStorage<IStorageFolderRecord>();

        private readonly InMemoryEntityStorage<IStorageRecordType> _recordTypeStorage =
            new InMemoryEntityStorage<IStorageRecordType>();

        private readonly InMemoryLinkStorage<IStorageUserEmail> _userEmailStorage =
            new InMemoryLinkStorage<IStorageUserEmail>();

        /// <inheritdoc/>
        public string PersonalScopeUid => "PersonalScopeUid";

        /// <inheritdoc/>
        public IRecordStorage<IVaultSettings> VaultSettings => _vaultSettings;

        /// <inheritdoc/>
        public IEntityStorage<IStorageRecord> Records => _recordStorage;

        /// <inheritdoc/>
        public IEntityStorage<IStorageSharedFolder> SharedFolders => _sharedFolderStorage;

        /// <inheritdoc/>
        public IEntityStorage<IStorageTeam> Teams => _teamStorage;

        /// <inheritdoc/>
        public IEntityStorage<IStorageNonSharedData> NonSharedData => _nonSharedDataStorage;

        /// <inheritdoc/>
        public ILinkStorage<IStorageRecordKey> RecordKeys => _recordKeyStorage;

        /// <inheritdoc/>
        public ILinkStorage<IStorageSharedFolderKey> SharedFolderKeys => _sharedFolderKeyStorage;

        /// <inheritdoc/>
        public ILinkStorage<ISharedFolderPermission> SharedFolderPermissions => _sharedFolderPermissions;

        /// <inheritdoc/>
        public IEntityStorage<IStorageFolder> Folders => _folderStorage;

        /// <inheritdoc/>
        public ILinkStorage<IStorageFolderRecord> FolderRecords => _folderRecordStorage;

        /// <inheritdoc/>
        public IEntityStorage<IStorageRecordType> RecordTypes => _recordTypeStorage;

        /// <inheritdoc/>
        public ILinkStorage<IStorageUserEmail> UserEmails => _userEmailStorage;

        /// <inheritdoc/>
        public void Clear()
        {
            _vaultSettings.Clear();
            _recordStorage.Clear();
            _sharedFolderStorage.Clear();
            _teamStorage.Clear();
            _nonSharedDataStorage.Clear();
            _recordKeyStorage.Clear();
            _sharedFolderKeyStorage.Clear();
            _sharedFolderPermissions.Clear();
            _folderStorage.Clear();
            _folderRecordStorage.Clear();
            _recordStorage.Clear();
            _userEmailStorage.Clear();
        }
    }
}