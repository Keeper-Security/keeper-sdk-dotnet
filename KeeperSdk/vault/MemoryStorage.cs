using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Provides in memory implementation of IKeeperStorage interface.
    /// </summary>
    /// <seealso cref="IKeeperStorage" />
    public class InMemoryKeeperStorage : IKeeperStorage
    {
        private readonly InMemoryRecordStorage<IVaultSettings> _vaultSettings = new();
        private readonly InMemoryEntityStorage<IStorageRecord> _recordStorage = new();
        private readonly InMemoryEntityStorage<IStorageSharedFolder> _sharedFolderStorage = new();
        private readonly InMemoryEntityStorage<IStorageTeam> _teamStorage = new();
        private readonly InMemoryEntityStorage<IStorageNonSharedData> _nonSharedDataStorage = new();
        private readonly InMemoryLinkStorage<IStorageRecordKey> _recordKeyStorage = new();
        private readonly InMemoryLinkStorage<IStorageSharedFolderKey> _sharedFolderKeyStorage = new();
        private readonly InMemoryLinkStorage<ISharedFolderPermission> _sharedFolderPermissions = new();
        private readonly InMemoryEntityStorage<IStorageFolder> _folderStorage = new();
        private readonly InMemoryLinkStorage<IStorageFolderRecord> _folderRecordStorage = new();
        private readonly InMemoryEntityStorage<IStorageRecordType> _recordTypeStorage = new();
        private readonly InMemoryLinkStorage<IStorageUserEmail> _userEmailStorage = new();
        private readonly InMemoryEntityStorage<IStorageBreachWatchRecord> _breachWatchRecordStorage = new();

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
        public IEntityStorage<IStorageBreachWatchRecord> BreachWatchRecords => _breachWatchRecordStorage;


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
            _breachWatchRecordStorage.Clear();
        }
    }
}