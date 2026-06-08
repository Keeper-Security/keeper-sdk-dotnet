using System;
using System.Collections.Generic;
using System.Data;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    public class SqlKeeperStorage : IKeeperStorage
    {
        private const string OwnerColumnName = "PartitionUid";

        private readonly SqlRecordStorage<IVaultSettings, VaultSettings> _settings;
        private readonly SqlEntityStorage<IStorageRecord, StorageRecord> _records;
        private readonly SqlEntityStorage<IStorageSharedFolder, StorageSharedFolder> _sharedFolders;
        private readonly SqlEntityStorage<IStorageTeam, StorageTeam> _teams;
        private readonly SqlEntityStorage<IStorageNonSharedData, StorageNonSharedData> _nonSharedData;
        private readonly SqlLinkStorage<IStorageRecordKey, StorageRecordKey> _recordKeys;
        private readonly SqlLinkStorage<IStorageSharedFolderKey, StorageSharedFolderKey> _sharedFolderKeys;
        private readonly SqlLinkStorage<ISharedFolderPermission, StorageSharedFolderPermission>
            _sharedFolderPermissions;
        private readonly SqlEntityStorage<IStorageFolder, StorageFolder> _folders;
        private readonly SqlLinkStorage<IStorageFolderRecord, StorageFolderRecord> _folderRecords;
        private readonly SqlEntityStorage<IStorageRecordType, StorageRecordType> _recordTypes;
        private readonly SqlLinkStorage<IStorageUserEmail, StorageUserEmail> _userEmails;
        private readonly SqlEntityStorage<IStorageBreachWatchRecord, StorageBreachWatchRecord> _breachWatchRecords;

        /// <summary>
        /// Constructor with custom SQL dialect.
        /// </summary>
        public SqlKeeperStorage(Func<IDbConnection> getConnection, ISqlDialect dialect, string ownerId)
        {
            PersonalScopeUid = ownerId;
            _settings = new SqlRecordStorage<IVaultSettings, VaultSettings>(getConnection, dialect, OwnerColumnName,
                ownerId);
            _records = new SqlEntityStorage<IStorageRecord, StorageRecord>(getConnection, dialect, OwnerColumnName,
                ownerId);
            _sharedFolders =
                new SqlEntityStorage<IStorageSharedFolder, StorageSharedFolder>(getConnection, dialect, OwnerColumnName,
                    ownerId);
            _teams = new SqlEntityStorage<IStorageTeam, StorageTeam>(getConnection, dialect, OwnerColumnName, ownerId);
            _nonSharedData =
                new SqlEntityStorage<IStorageNonSharedData, StorageNonSharedData>(getConnection, dialect,
                    OwnerColumnName,
                    ownerId);
            _recordKeys =
                new SqlLinkStorage<IStorageRecordKey, StorageRecordKey>(getConnection, dialect, OwnerColumnName,
                    ownerId);
            _sharedFolderKeys =
                new SqlLinkStorage<IStorageSharedFolderKey, StorageSharedFolderKey>(getConnection, dialect,
                    OwnerColumnName,
                    ownerId);
            _sharedFolderPermissions =
                new SqlLinkStorage<ISharedFolderPermission, StorageSharedFolderPermission>(getConnection, dialect,
                    OwnerColumnName, ownerId);
            _folders = new SqlEntityStorage<IStorageFolder, StorageFolder>(getConnection, dialect, OwnerColumnName,
                ownerId);
            _folderRecords =
                new SqlLinkStorage<IStorageFolderRecord, StorageFolderRecord>(getConnection, dialect, OwnerColumnName,
                    ownerId);
            _recordTypes =
                new SqlEntityStorage<IStorageRecordType, StorageRecordType>(getConnection, dialect, OwnerColumnName,
                    ownerId);
            _userEmails =
                new SqlLinkStorage<IStorageUserEmail, StorageUserEmail>(getConnection, dialect, OwnerColumnName,
                    ownerId);
            _breachWatchRecords =
                new SqlEntityStorage<IStorageBreachWatchRecord, StorageBreachWatchRecord>(getConnection, dialect,
                    OwnerColumnName, ownerId);
        }

        public IEnumerable<SqlStorage> GetStorages()
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
            yield return _breachWatchRecords;
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
        public IEntityStorage<IStorageBreachWatchRecord> BreachWatchRecords => _breachWatchRecords;

        public void Clear()
        {
            foreach (var storage in GetStorages())
            {
                storage.DeleteAll();
            }
        }
    }
}