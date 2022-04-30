using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.OfflineStorage.Sqlite
{
    internal class SqliteEntityStorage<T, TD> : SqliteDataStorage<TD>, IEntityStorage<T>
        where T : IUid
        where TD : class, IEntity, T, IEntityCopy<T>, new()
    {

        protected string EntityColumnName { get; }

        public SqliteEntityStorage(Func<IDbConnection> getConnection, string ownerId) : base(getConnection, ownerId)
        {
            EntityColumnName = PrimaryKey[0];
        }

        public T GetEntity(string uid)
        {
            var cmd = GetSelectStatement();
            cmd.CommandText += $" AND {EntityColumnName} = @{EntityColumnName}";
            var entityParameter = cmd.CreateParameter();
            entityParameter.ParameterName = $"@{EntityColumnName}";
            entityParameter.DbType = DbType.String;
            entityParameter.Direction = ParameterDirection.Input;
            entityParameter.Value = uid;
            cmd.Parameters.Add(entityParameter);

            using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
            {
                return this.PopulateDataObjects<TD>(reader).FirstOrDefault();
            }
        }

        public void PutEntities(IEnumerable<T> entities)
        {
            var cmd = GetPutStatement();
            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                foreach (var entity in entities)
                {
                    var data = new TD();
                    data.CopyFields(entity);
                    PopulateCommandParameters(cmd, data);
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }

        public void DeleteUids(IEnumerable<string> uids)
        {
            var cmd = GetDeleteStatement();
            cmd.CommandText += $" AND {EntityColumnName} = @{EntityColumnName}";
            var entityParameter = cmd.CreateParameter();
            entityParameter.ParameterName = $"@{EntityColumnName}";
            entityParameter.DbType = DbType.String;
            entityParameter.Direction = ParameterDirection.Input;
            cmd.Parameters.Add(entityParameter);

            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                foreach (var uid in uids)
                {
                    entityParameter.Value = uid;
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }

        public IEnumerable<T> GetAll()
        {
            var cmd = GetSelectStatement();
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return this.PopulateDataObjects<TD>(reader).ToArray();
            }
        }
    }

    internal class SqliteLinkStorage<T, TD> : SqliteDataStorage<TD>, IPredicateStorage<T>
        where T : IUidLink
        where TD : class, IEntityLink, T, IEntityCopy<T>, new()
    {
        protected string SubjectColumnName { get; }
        protected string ObjectColumnName { get; }

        public SqliteLinkStorage(Func<IDbConnection> getConnection, string ownerId)
            : base(getConnection, ownerId)
        {
            SubjectColumnName = PrimaryKey[0];
            ObjectColumnName = PrimaryKey[1];
        }

        public void PutLinks(IEnumerable<T> links)
        {
            var cmd = GetPutStatement();
            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                foreach (var link in links)
                {
                    var data = new TD();
                    data.CopyFields(link);
                    PopulateCommandParameters(cmd, data);
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }

        public void DeleteLinks(IEnumerable<IUidLink> links)
        {
            var cmd = GetDeleteStatement();
            cmd.CommandText += $" AND {SubjectColumnName} = @{SubjectColumnName} AND {ObjectColumnName} = @{ObjectColumnName}";

            var subjectParameter = cmd.CreateParameter();
            subjectParameter.ParameterName = $"@{SubjectColumnName}";
            subjectParameter.DbType = DbType.String;
            subjectParameter.Direction = ParameterDirection.Input;
            cmd.Parameters.Add(subjectParameter);

            var objectParameter = cmd.CreateParameter();
            objectParameter.ParameterName = $"@{ObjectColumnName}";
            objectParameter.DbType = DbType.String;
            objectParameter.Direction = ParameterDirection.Input;
            cmd.Parameters.Add(objectParameter);

            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                foreach (var link in links)
                {
                    subjectParameter.Value = link.SubjectUid;
                    objectParameter.Value = link.ObjectUid;
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }

        public void DeleteLinksForSubjects(IEnumerable<string> subjectUids)
        {
            var cmd = GetDeleteStatement();
            cmd.CommandText += $" AND {SubjectColumnName} = @{SubjectColumnName}";

            var subjectParameter = cmd.CreateParameter();
            subjectParameter.ParameterName = $"@{SubjectColumnName}";
            subjectParameter.DbType = DbType.String;
            subjectParameter.Direction = ParameterDirection.Input;
            cmd.Parameters.Add(subjectParameter);

            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                foreach (var subjectUid in subjectUids)
                {
                    subjectParameter.Value = subjectUid;
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }

        public void DeleteLinksForObjects(IEnumerable<string> objectUids)
        {
            var cmd = GetDeleteStatement();
            cmd.CommandText += $" AND {ObjectColumnName} = @{ObjectColumnName}";

            var objectParameter = cmd.CreateParameter();
            objectParameter.ParameterName = $"@{ObjectColumnName}";
            objectParameter.DbType = DbType.String;
            objectParameter.Direction = ParameterDirection.Input;
            cmd.Parameters.Add(objectParameter);

            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                foreach (var objectUid in objectUids)
                {
                    objectParameter.Value = objectUid;
                    cmd.ExecuteNonQuery();
                }

                txn.Commit();
            }
        }

        public IEnumerable<T> GetLinksForSubject(string subjectUid)
        {
            var cmd = GetSelectStatement();
            cmd.CommandText += $" AND {SubjectColumnName} = @{SubjectColumnName}";
            var subjectParameter = cmd.CreateParameter();
            subjectParameter.ParameterName = $"@{SubjectColumnName}";
            subjectParameter.DbType = DbType.String;
            subjectParameter.Direction = ParameterDirection.Input;
            subjectParameter.Value = subjectUid;
            cmd.Parameters.Add(subjectParameter);
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return this.PopulateDataObjects<TD>(reader).ToArray();
            }
        }

        public IEnumerable<T> GetLinksForObject(string objectUid)
        {
            var cmd = GetSelectStatement();
            cmd.CommandText += $" AND {ObjectColumnName} = @{ObjectColumnName}";
            var objectParameter = cmd.CreateParameter();
            objectParameter.ParameterName = $"@{ObjectColumnName}";
            objectParameter.DbType = DbType.String;
            objectParameter.Direction = ParameterDirection.Input;
            objectParameter.Value = objectUid;
            cmd.Parameters.Add(objectParameter);
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return this.PopulateDataObjects<TD>(reader).ToArray();
            }
        }

        public IEnumerable<T> GetAllLinks()
        {
            var cmd = GetSelectStatement();
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return this.PopulateDataObjects<TD>(reader).ToArray();
            }
        }
    }

    [SqlTable(Name = "UserSettings")]
    internal class InternalUserAccount
    {
        [SqlColumn]
        public long Revision { get; set; }
    }


    internal class SqliteKeeperStorage : IKeeperStorage
    {
        private readonly Func<IDbConnection> GetConnection;

        public SqliteKeeperStorage(Func<IDbConnection> getConnection, string ownerId)
        {
            GetConnection = getConnection;
            PersonalScopeUid = ownerId;

            Records = new SqliteEntityStorage<IStorageRecord, ExternalRecord>(getConnection, ownerId);
            SharedFolders = new SqliteEntityStorage<ISharedFolder, ExternalSharedFolder>(getConnection, ownerId);
            Teams = new SqliteEntityStorage<IEnterpriseTeam, ExternalEnterpriseTeam>(getConnection, ownerId);
            NonSharedData = new SqliteEntityStorage<INonSharedData, ExternalNonSharedData>(getConnection, ownerId);
            RecordKeys = new SqliteLinkStorage<IRecordMetadata, ExternalRecordMetadata>(getConnection, ownerId);
            SharedFolderKeys = new SqliteLinkStorage<ISharedFolderKey, ExternalSharedFolderKey>(getConnection, ownerId);
            SharedFolderPermissions = new SqliteLinkStorage<ISharedFolderPermission, ExternalSharedFolderPermission>(getConnection, ownerId);
            Folders = new SqliteEntityStorage<IFolder, ExternalFolder>(getConnection, ownerId);
            FolderRecords = new SqliteLinkStorage<IFolderRecordLink, ExternalFolderRecordLink>(getConnection, ownerId);
            RecordTypes = new SqliteEntityStorage<IRecordType, ExternalRecordType>(getConnection, ownerId);

            _userStorage = new SqliteRecordStorage<InternalUserAccount>(getConnection, ownerId);
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
