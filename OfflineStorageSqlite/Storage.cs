using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.OfflineStorage.Sqlite
{

    public abstract class SqliteStorage
    {
        private readonly TableSchema _schema;

        protected SqliteStorage(Func<IDbConnection> getConnection, TableSchema schema, object ownerId = null)
        {
            _schema = schema;
            GetConnection = getConnection;
            if (!string.IsNullOrEmpty(Schema.OwnerColumnName))
            {
                OwnerId = ownerId ?? throw new Exception($"Schema {Schema.TableName} requires owner column value");
            }
        }

        private string _selectStatement;

        public IDbCommand GetSelectStatement(IEnumerable<string> filterColumns = null)
        {
            lock (this)
            {
                if (string.IsNullOrEmpty(_selectStatement))
                {
                    _selectStatement = $"SELECT {string.Join(", ", Schema.Columns)} "
                        + $"FROM {Schema.TableName}";
                }
            }

            var cmd = GetConnection().CreateCommand();

            if (filterColumns == null && string.IsNullOrEmpty(Schema.OwnerColumnName))
            {
                cmd.CommandText = _selectStatement;
                return cmd;
            }

            StringBuilder selectQuery = new StringBuilder(_selectStatement);
            var whereAdded = false;
            if (!string.IsNullOrEmpty(Schema.OwnerColumnName))
            {
                selectQuery.Append($" WHERE {Schema.OwnerColumnName} = @{Schema.OwnerColumnName}");
                whereAdded = true;
                var ownerParameter = cmd.CreateParameter();
                ownerParameter.ParameterName = $"@{Schema.OwnerColumnName}";
                ownerParameter.DbType =
                    DatabaseUtils.GetDbType(DatabaseUtils.TypeMap[OwnerId.GetType()]);
                ownerParameter.Direction = ParameterDirection.Input;
                ownerParameter.Value = OwnerId;
                cmd.Parameters.Add(ownerParameter);
            }

            if (filterColumns != null)
            {
                foreach (var column in filterColumns)
                {
                    if (Schema.ColumnMap.TryGetValue(column, out var prop))
                    {
                        if (whereAdded)
                        {
                            selectQuery.Append(" AND ");
                        }
                        else
                        {
                            selectQuery.Append(" WHERE ");
                            whereAdded = true;
                        }
                        selectQuery.Append($"{column} = @{column}");

                        var filterParameter = cmd.CreateParameter();
                        filterParameter.ParameterName = $"@{column}";
                        filterParameter.DbType =
                            DatabaseUtils.GetDbType(DatabaseUtils.TypeMap[prop.PropertyType]);
                        filterParameter.Direction = ParameterDirection.Input;
                        cmd.Parameters.Add(filterParameter);
                    }
                    else
                    {
                        throw new Exception($"Schema {Schema.TableName} does not contain column {column}");
                    }
                }
            }
            cmd.CommandText = selectQuery.ToString();
            return cmd;
        }

        public IDbCommand GetDeleteStatement(IEnumerable<string> filterColumns = null)
        {
            var cmd = GetConnection().CreateCommand();

            StringBuilder deleteQuery = new StringBuilder($"DELETE FROM {Schema.TableName}");

            var whereAdded = false;
            if (!string.IsNullOrEmpty(Schema.OwnerColumnName))
            {
                deleteQuery.Append($" WHERE {Schema.OwnerColumnName} = @{Schema.OwnerColumnName}");
                whereAdded = true;
                var ownerParameter = cmd.CreateParameter();
                ownerParameter.ParameterName = $"@{Schema.OwnerColumnName}";
                ownerParameter.DbType =
                    DatabaseUtils.GetDbType(DatabaseUtils.TypeMap[OwnerId.GetType()]);
                ownerParameter.Direction = ParameterDirection.Input;
                ownerParameter.Value = OwnerId;
                cmd.Parameters.Add(ownerParameter);
            }

            if (filterColumns != null)
            {
                foreach (var columnName in filterColumns)
                {
                    if (Schema.ColumnMap.TryGetValue(columnName, out var prop))
                    {

                        if (whereAdded)
                        {
                            deleteQuery.Append(" AND ");
                        }
                        else
                        {
                            deleteQuery.Append(" WHERE ");
                            whereAdded = true;
                        }
                        deleteQuery.Append($"{columnName} = @{columnName}");

                        var filterParameter = cmd.CreateParameter();
                        filterParameter.ParameterName = $"@{columnName}";
                        filterParameter.DbType =
                            DatabaseUtils.GetDbType(DatabaseUtils.TypeMap[prop.PropertyType]);
                        filterParameter.Direction = ParameterDirection.Input;
                        cmd.Parameters.Add(filterParameter);
                    }
                }
            }
            cmd.CommandText = deleteQuery.ToString();

            return cmd;
        }

        private string _putStatement;

        public IDbCommand GetPutStatement()
        {
            lock (this)
            {
                if (string.IsNullOrEmpty(_putStatement))
                {
                    var stmt = new StringBuilder($"INSERT OR REPLACE INTO {Schema.TableName} (");
                    if (!string.IsNullOrEmpty(Schema.OwnerColumnName))
                    {
                        stmt.Append($"{Schema.OwnerColumnName}, ");
                    }
                    stmt.Append(string.Join(", ", Schema.Columns));
                    stmt.Append(") VALUES (");
                    if (!string.IsNullOrEmpty(Schema.OwnerColumnName))
                    {
                        stmt.Append($"@{Schema.OwnerColumnName}, ");
                    }
                    stmt.Append(string.Join(", ", Schema.Columns.Select(x => $"@{x}")));
                    stmt.Append(")");

                    _putStatement = stmt.ToString();
                }
            }

            var cmd = GetConnection().CreateCommand();
            cmd.CommandText = _putStatement;

            if (!string.IsNullOrEmpty(Schema.OwnerColumnName))
            {
                var ownerParameter = cmd.CreateParameter();
                ownerParameter.ParameterName = $"@{Schema.OwnerColumnName}";
                ownerParameter.DbType =
                    DatabaseUtils.GetDbType(DatabaseUtils.TypeMap[OwnerId.GetType()]);
                ownerParameter.Direction = ParameterDirection.Input;
                ownerParameter.Value = OwnerId;
                cmd.Parameters.Add(ownerParameter);
            }

            foreach (var column in Schema.Columns)
            {
                var prop = Schema.ColumnMap[column];
                var parameter = cmd.CreateParameter();
                parameter.ParameterName = $"@{column}";
                parameter.Direction = ParameterDirection.Input;
                parameter.DbType =
                    DatabaseUtils.GetDbType(DatabaseUtils.TypeMap[prop.PropertyType]); ;
                cmd.Parameters.Add(parameter);
            }

            return cmd;
        }

        protected TableSchema Schema => _schema;
        protected object OwnerId { get; }
        protected Func<IDbConnection> GetConnection { get; }
    }

    public class SqliteDataStorage<TD> : SqliteStorage
        where TD : class, new()
    {
        public SqliteDataStorage(Func<IDbConnection> getConnection, Tuple<string, object> owner = null)
            : base(getConnection, new TableSchema(typeof(TD), owner != null ? owner.Item1 : null), 
                  owner != null ? owner.Item2 : null)
        {
        }

        public void PopulateCommandParameters(IDbCommand command, TD data)
        {
            foreach (IDataParameter parameter in command.Parameters)
            {
                var parameterName = parameter.ParameterName.Substring(1);
                if (parameterName == Schema.OwnerColumnName)
                {
                    parameter.Value = OwnerId;
                }
                else
                {
                    var column = Schema.ColumnMap[parameterName];
                    parameter.Value = column.GetMethod.Invoke(data, null);
                }
            }
        }
    }

    public class SqliteRecordStorage<TD> : SqliteDataStorage<TD> where TD : class, new()
    {
        public SqliteRecordStorage(Func<IDbConnection> getConnection, Tuple<string, object> owner = null) 
            : base(getConnection, owner)
        {
        }

        public TD Get()
        {
            var cmd = GetSelectStatement();
            using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
            {
                return Schema.PopulateDataObjects<TD>(reader).FirstOrDefault();
            }
        }

        public void Put(TD data)
        {
            var cmd = GetPutStatement();
            using (var txn = GetConnection().BeginTransaction())
            {
                cmd.Transaction = txn;
                PopulateCommandParameters(cmd, data);
                cmd.ExecuteNonQuery();
                txn.Commit();
            }
        }
    }


    public class SqliteEntityStorage<T, TD> : SqliteDataStorage<TD>, IEntityStorage<T>
        where T : IUid
        where TD : class, IEntity, T, IEntityCopy<T>, new()
    {

        protected string EntityColumnName { get; }

        public SqliteEntityStorage(Func<IDbConnection> getConnection, Tuple<string, object> owner = null) 
            : base(getConnection, owner)
        {
            EntityColumnName = Schema.PrimaryKey[0];
        }

        public T GetEntity(string uid)
        {
            var cmd = GetSelectStatement(new[] { EntityColumnName  });
            var entityParameter = (IDbDataParameter) cmd.Parameters[$"@{EntityColumnName}"];
            entityParameter.Value = uid;

            using (var reader = cmd.ExecuteReader(CommandBehavior.SingleRow))
            {
                return Schema.PopulateDataObjects<TD>(reader).FirstOrDefault();
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
            var cmd = GetDeleteStatement(new[] { EntityColumnName });
            var entityParameter = (IDbDataParameter) cmd.Parameters[$"@{EntityColumnName}"];
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
                return Schema.PopulateDataObjects<TD>(reader).ToArray();
            }
        }
    }

    public class SqliteLinkStorage<T, TD> : SqliteDataStorage<TD>, IPredicateStorage<T>
        where T : IUidLink
        where TD : class, IEntityLink, T, IEntityCopy<T>, new()
    {
        protected string SubjectColumnName { get; }
        protected string ObjectColumnName { get; }

        public SqliteLinkStorage(Func<IDbConnection> getConnection, Tuple<string, object> owner = null)
            : base(getConnection, owner)
        {
            SubjectColumnName = Schema.PrimaryKey[0];
            ObjectColumnName = Schema.PrimaryKey[1];
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
            var cmd = GetDeleteStatement(new[] { SubjectColumnName, ObjectColumnName  });
            var subjectParameter = (IDbDataParameter) cmd.Parameters[$"@{SubjectColumnName}"];
            var objectParameter = (IDbDataParameter) cmd.Parameters[$"@{ObjectColumnName}"];

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
            var cmd = GetDeleteStatement(new[] { SubjectColumnName });
            var subjectParameter = (IDbDataParameter) cmd.Parameters[$"@{SubjectColumnName}"];

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
            var cmd = GetDeleteStatement(new[] { ObjectColumnName });
            var objectParameter = (IDbDataParameter) cmd.Parameters[$"@{ObjectColumnName}"];

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
            var cmd = GetSelectStatement(new[] { SubjectColumnName });
            var subjectParameter = (IDbDataParameter) cmd.Parameters[$"@{SubjectColumnName}"];
            subjectParameter.Value = subjectUid;
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return Schema.PopulateDataObjects<TD>(reader).ToArray();
            }
        }

        public IEnumerable<T> GetLinksForObject(string objectUid)
        {
            var cmd = GetSelectStatement(new[] { ObjectColumnName });
            var objectParameter = (IDbDataParameter) cmd.Parameters[$"@{ObjectColumnName}"];
            objectParameter.Value = objectUid;
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return Schema.PopulateDataObjects<TD>(reader).ToArray();
            }
        }

        public IEnumerable<T> GetAllLinks()
        {
            var cmd = GetSelectStatement();
            using (var reader = cmd.ExecuteReader(CommandBehavior.Default))
            {
                return Schema.PopulateDataObjects<TD>(reader).ToArray();
            }
        }
    }
}
