using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using KeeperSecurity.Utils;
using KeeperSecurity.OfflineStorage.Sqlite;

namespace EnterpriseBackup
{
    [SqlTable(Name = "BackupRecord", PrimaryKey = new[] {"RecordUid"}, Index1 = new[] {"UserId"})]
    internal class BackupRecord
    {
        [SqlColumn(Length = 32)]
        public string RecordUid { get; set; }

        [SqlColumn]
        public int UserId { get; set; }

        [SqlColumn]
        public string RecordKey { get; set; }

        [SqlColumn]
        public int KeyType { get; set; }

        [SqlColumn]
        public int Version { get; set; }

        [SqlColumn]
        public string Data { get; set; }

        [SqlColumn]
        public string Extra { get; set; }
    }

    [SqlTable(Name = "BackupUser", PrimaryKey = new[] {"UserId"}, Index1 = new[] {"Username"})]
    internal class BackupUser
    {
        [SqlColumn]
        public int UserId { get; set; }

        [SqlColumn(Length = 64)]
        public string Username { get; set; }

        [SqlColumn]
        public string DataKey { get; set; }

        [SqlColumn]
        public int DataKeyType { get; set; }

        [SqlColumn]
        public string PrivateKey { get; set; }

        internal byte[] DecryptedDataKey { get; set; }
        internal byte[] DecryptedPrivateKey { get; set; }

    }

    [SqlTable(Name = "BackupAdminKey", PrimaryKey = new[] {"UserId"})]
    internal class BackupAdminKey
    {
        [SqlColumn]
        public int UserId { get; set; }

        [SqlColumn]
        public string TreeKey { get; set; }

        [SqlColumn]
        public int TreeKeyType { get; set; }

        [SqlColumn]
        public string EnterpriseEccPrivateKey { get; set; }

        [SqlColumn]
        public string BackupKey { get; set; }

        internal byte[] DecryptedBackupKey { get; set; }
    }

    [SqlTable(Name = "Info", PrimaryKey = new[] { "Name" })]
    internal class BackupInfo
    {
        [SqlColumn(Length = 64)]
        public string Name { get; set; }

        [SqlColumn]
        public string Value { get; set; }
    }

    internal class BackupDataWriter<TD> : TableSchema
    {
        protected Func<IDbConnection> GetConnection { get; }

        public BackupDataWriter(Func<IDbConnection> getConnection)
        {
            LoadSchema(typeof(TD));
            GetConnection = getConnection;
        }

        public void Put(IEnumerable<TD> data)
        {
            using var txn = GetConnection().BeginTransaction();
            var cmd = GetPutStatement();
            cmd.Transaction = txn;
            foreach (var row in data)
            {
                PopulateCommandParameters(cmd, row);
                cmd.ExecuteNonQuery();
            }

            txn.Commit();
        }

        private void PopulateCommandParameters(IDbCommand command, TD data)
        {
            foreach (IDataParameter parameter in command.Parameters)
            {
                var parameterName = parameter.ParameterName[1..];
                var column = ColumnMap[parameterName];
                parameter.Value = column.GetMethod?.Invoke(data, null);
            }
        }

        private string _putStatement;

        private IDbCommand GetPutStatement()
        {
            lock (this)
            {
                if (string.IsNullOrEmpty(_putStatement))
                {
                    _putStatement = $"INSERT OR REPLACE INTO {TableName} ({string.Join(", ", Columns)}) "
                        + $"VALUES ({string.Join(", ", Columns.Select(x => "@" + x))})";
                }
            }

            var cmd = GetConnection().CreateCommand();
            cmd.CommandText = _putStatement;

            foreach (var column in Columns)
            {
                var prop = ColumnMap[column];
                var parameter = cmd.CreateParameter();
                parameter.ParameterName = $"@{column}";
                parameter.Direction = ParameterDirection.Input;
                DbType dbType;
                var columnType = DatabaseUtils.TypeMap[prop.PropertyType];
                switch (columnType)
                {
                    case ColumnType.Boolean:
                        dbType = DbType.Boolean;
                        break;
                    case ColumnType.Integer:
                        dbType = DbType.Int32;
                        break;
                    case ColumnType.Long:
                        dbType = DbType.Int64;
                        break;
                    case ColumnType.Decimal:
                        dbType = DbType.Decimal;
                        break;
                    case ColumnType.String:
                        dbType = DbType.String;
                        break;
                    default:
                        dbType = DbType.String;
                        break;
                }

                parameter.DbType = dbType;
                cmd.Parameters.Add(parameter);
            }

            return cmd;
        }

    }

    internal class BackupDataReader<TD> : TableSchema
        where TD : new()
    {
        protected Func<IDbConnection> GetConnection { get; }

        public BackupDataReader(Func<IDbConnection> getConnection)
        {
            GetConnection = getConnection;
            LoadSchema(typeof(TD));
        }

        public IEnumerable<TD> GetByUserId(int userId)
        {
            var cmd = GetSelectStatement();
            cmd.CommandText += $" WHERE {Index1[0]} = @{Index1[0]}";
            var userParameter = cmd.CreateParameter();
            userParameter.ParameterName = $"@{Index1[0]}";
            userParameter.DbType = DbType.Int32;
            userParameter.Direction = ParameterDirection.Input;
            userParameter.Value = userId;
            cmd.Parameters.Add(userParameter);
            using var reader = cmd.ExecuteReader(CommandBehavior.Default);
            return this.PopulateDataObjects<TD>(reader).ToArray();
        }

        public IEnumerable<TD> GetAll()
        {
            var cmd = GetSelectStatement();
            using var reader = cmd.ExecuteReader(CommandBehavior.Default);
            return this.PopulateDataObjects<TD>(reader).ToArray();
        }

        private string _selectStatement;

        private IDbCommand GetSelectStatement()
        {
            lock (this)
            {
                if (string.IsNullOrEmpty(_selectStatement))
                {
                    _selectStatement = $"SELECT {string.Join(", ", Columns)} FROM {TableName}";
                }
            }

            var cmd = GetConnection().CreateCommand();
            cmd.CommandText = _selectStatement;
            return cmd;
        }

    }
}
