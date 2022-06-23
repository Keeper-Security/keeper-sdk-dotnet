using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Data;
using System.Linq;

namespace KeeperSecurity.OfflineStorage.Sqlite
{
    [SqlTable(Name = "UserSettings")]
    internal class InternalUserAccount
    {
        [SqlColumn]
        public long Revision { get; set; }
    }


    internal class SqliteKeeperStorage : IKeeperStorage
    {
        public const string OwnerColumnName = "OwnerId";
        private readonly Func<IDbConnection> GetConnection;

        public SqliteKeeperStorage(Func<IDbConnection> getConnection, string ownerId)
        {
            GetConnection = getConnection;
            PersonalScopeUid = ownerId;

            var owner = Tuple.Create<string, object>(OwnerColumnName, ownerId);

            Records = new SqliteEntityStorage<IStorageRecord, ExternalRecord>(getConnection, owner);
            SharedFolders = new SqliteEntityStorage<ISharedFolder, ExternalSharedFolder>(getConnection, owner);
            Teams = new SqliteEntityStorage<IEnterpriseTeam, ExternalEnterpriseTeam>(getConnection, owner);
            NonSharedData = new SqliteEntityStorage<INonSharedData, ExternalNonSharedData>(getConnection, owner);
            RecordKeys = new SqliteLinkStorage<IRecordMetadata, ExternalRecordMetadata>(getConnection, owner);
            SharedFolderKeys = new SqliteLinkStorage<ISharedFolderKey, ExternalSharedFolderKey>(getConnection, owner);
            SharedFolderPermissions = new SqliteLinkStorage<ISharedFolderPermission, ExternalSharedFolderPermission>(getConnection, owner);
            Folders = new SqliteEntityStorage<IFolder, ExternalFolder>(getConnection, owner);
            FolderRecords = new SqliteLinkStorage<IFolderRecordLink, ExternalFolderRecordLink>(getConnection, owner);
            RecordTypes = new SqliteEntityStorage<IRecordType, ExternalRecordType>(getConnection, owner);

            _userStorage = new SqliteRecordStorage<InternalUserAccount>(getConnection, owner);
        }

        public string PersonalScopeUid { get; }

        private SqliteRecordStorage<InternalUserAccount> _userStorage;

        public long Revision
        {
            get => _userStorage.Get()?.Revision ?? 0;
            set
            {
                var user = _userStorage.Get() ?? new InternalUserAccount();
                user.Revision = value;
                _userStorage.Put(user);
            }
        }

        public IEntityStorage<IStorageRecord> Records { get; }
        public IEntityStorage<ISharedFolder> SharedFolders { get; }
        public IEntityStorage<IEnterpriseTeam> Teams { get; }
        public IEntityStorage<INonSharedData> NonSharedData { get; }
        public IPredicateStorage<IRecordMetadata> RecordKeys { get; }
        public IPredicateStorage<ISharedFolderKey> SharedFolderKeys { get; }
        public IPredicateStorage<ISharedFolderPermission> SharedFolderPermissions { get; }
        public IEntityStorage<IFolder> Folders { get; }
        public IPredicateStorage<IFolderRecordLink> FolderRecords { get; }
        public IEntityStorage<IRecordType> RecordTypes { get; }

        public void Clear()
        {
            Revision = 0;
            var tables = new object[]
            {
                Records, SharedFolders, Teams, NonSharedData, RecordKeys, SharedFolderKeys,
                SharedFolderPermissions, Folders, FolderRecords, _userStorage
            };
            using (var txn = GetConnection().BeginTransaction())
            {
                foreach (var table in tables.Cast<SqliteStorage>())
                {
                    var cmd = table.GetDeleteStatement();
                    cmd.Transaction = txn;
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }
    }
}
