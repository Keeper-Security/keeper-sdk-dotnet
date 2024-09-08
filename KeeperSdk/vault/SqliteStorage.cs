using System;
using System.Collections.Generic;
using System.Data;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    public class SqliteKeeperStorage : IKeeperStorage
    {
        private const string OwnerColumnName = "PartitionUid";

        private readonly SqliteRecordStorage<IVaultSettings, VaultSettings> _settings;
        private readonly SqliteEntityStorage<IStorageRecord, StorageRecord> _records;
        private readonly SqliteEntityStorage<IStorageSharedFolder, StorageSharedFolder> _sharedFolders;
        private readonly SqliteEntityStorage<IStorageTeam, StorageTeam> _teams;
        private readonly SqliteEntityStorage<IStorageNonSharedData, StorageNonSharedData> _nonSharedData;
        private readonly SqliteLinkStorage<IStorageRecordKey, StorageRecordKey> _recordKeys;
        private readonly SqliteLinkStorage<IStorageSharedFolderKey, StorageSharedFolderKey> _sharedFolderKeys;
        private readonly SqliteLinkStorage<ISharedFolderPermission, StorageSharedFolderPermission>
            _sharedFolderPermissions;
        private readonly SqliteEntityStorage<IStorageFolder, StorageFolder> _folders;
        private readonly SqliteLinkStorage<IStorageFolderRecord, StorageFolderRecord> _folderRecords;
        private readonly SqliteEntityStorage<IStorageRecordType, StorageRecordType> _recordTypes;
        private readonly SqliteLinkStorage<IStorageUserEmail, StorageUserEmail> _userEmails;

        public SqliteKeeperStorage(Func<IDbConnection> getConnection, string ownerId)
        {
            PersonalScopeUid = ownerId;

            _settings = new SqliteRecordStorage<IVaultSettings, VaultSettings>(getConnection, OwnerColumnName,
                ownerId);
            _records = new SqliteEntityStorage<IStorageRecord, StorageRecord>(getConnection, OwnerColumnName, ownerId);
            _sharedFolders =
                new SqliteEntityStorage<IStorageSharedFolder, StorageSharedFolder>(getConnection, OwnerColumnName,
                    ownerId);
            _teams = new SqliteEntityStorage<IStorageTeam, StorageTeam>(getConnection, OwnerColumnName, ownerId);
            _nonSharedData =
                new SqliteEntityStorage<IStorageNonSharedData, StorageNonSharedData>(getConnection, OwnerColumnName,
                    ownerId);
            _recordKeys =
                new SqliteLinkStorage<IStorageRecordKey, StorageRecordKey>(getConnection, OwnerColumnName, ownerId);
            _sharedFolderKeys =
                new SqliteLinkStorage<IStorageSharedFolderKey, StorageSharedFolderKey>(getConnection, OwnerColumnName,
                    ownerId);
            _sharedFolderPermissions =
                new SqliteLinkStorage<ISharedFolderPermission, StorageSharedFolderPermission>(getConnection,
                    OwnerColumnName, ownerId);
            _folders = new SqliteEntityStorage<IStorageFolder, StorageFolder>(getConnection, OwnerColumnName, ownerId);
            _folderRecords =
                new SqliteLinkStorage<IStorageFolderRecord, StorageFolderRecord>(getConnection, OwnerColumnName,
                    ownerId);
            _recordTypes =
                new SqliteEntityStorage<IStorageRecordType, StorageRecordType>(getConnection, OwnerColumnName,
                    ownerId);
            _userEmails =
                new SqliteLinkStorage<IStorageUserEmail, StorageUserEmail>(getConnection, OwnerColumnName, ownerId);
        }

        public IEnumerable<SqliteStorage> GetStorages()
        {
            yield return _settings;
            yield return _records;
            yield return _sharedFolders;
            yield return _teams;
            yield return _nonSharedData;
            yield return _recordKeys;
            yield return _sharedFolderKeys;
            yield return _sharedFolderPermissions;
            yield return _folders;
            yield return _folderRecords;
            yield return _recordTypes;
            yield return _userEmails;
        }

        public string PersonalScopeUid { get; }

        public IRecordStorage<IVaultSettings> VaultSettings => _settings;
        public IEntityStorage<IStorageRecord> Records => _records;
        public IEntityStorage<IStorageSharedFolder> SharedFolders => _sharedFolders;
        public IEntityStorage<IStorageTeam> Teams => _teams;
        public IEntityStorage<IStorageNonSharedData> NonSharedData => _nonSharedData;
        public ILinkStorage<IStorageRecordKey> RecordKeys => _recordKeys;
        public ILinkStorage<IStorageSharedFolderKey> SharedFolderKeys => _sharedFolderKeys;
        public ILinkStorage<ISharedFolderPermission> SharedFolderPermissions => _sharedFolderPermissions;
        public IEntityStorage<IStorageFolder> Folders => _folders;
        public ILinkStorage<IStorageFolderRecord> FolderRecords => _folderRecords;
        public IEntityStorage<IStorageRecordType> RecordTypes => _recordTypes;
        public ILinkStorage<IStorageUserEmail> UserEmails => _userEmails;

        public void Clear()
        {
            foreach (var storage in GetStorages())
            {
                storage.DeleteAll();
            }
        }
    }
}