using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;

namespace KeeperSecurity.Utils
{
    /// <exclude/>
    public enum ColumnType
    {
        Integer,
        Long,
        Boolean,
        String,
        Decimal,
        Binary,
    }

    /// <exclude/>
    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public sealed class SqlTableAttribute : Attribute
    {
        public string Name { get; set; }
        public string[] PrimaryKey { get; set; }
        public string[] Index1 { get; set; }
        public string[] Index2 { get; set; }
    }

    /// <exclude/>
    [AttributeUsage(AttributeTargets.Property)]
    public sealed class SqlColumnAttribute : Attribute
    {
        public string Name { get; set; }
        public int Length { get; set; }
        public bool CanBeNull { get; set; } = true;
    }


    public class TableSchema
    {
        public string TableName { get; }
        public string[] PrimaryKey { get; }
        public string[] Index1 { get; }
        public string[] Index2 { get; }
        public string OwnerColumnName { get; }

        public readonly List<string> Columns = new();

        public readonly Dictionary<string, PropertyInfo> ColumnMap = new(StringComparer.InvariantCultureIgnoreCase);

        public TableSchema(Type tableType, string ownerColumnName = null)
        {
            foreach (var attr in tableType.GetCustomAttributes<SqlTableAttribute>(true))
            {
                TableName = attr.Name;
                PrimaryKey = attr.PrimaryKey;
                Index1 = attr.Index1;
                Index2 = attr.Index2;
            }

            if (string.IsNullOrEmpty(TableName))
            {
                throw new Exception($"Class {tableType.FullName} is SQL table class");
            }

            OwnerColumnName = ownerColumnName;
            foreach (var member in tableType.GetProperties())
            {
                if (member.MemberType != MemberTypes.Property) continue;
                foreach (var attr in member.GetCustomAttributes<SqlColumnAttribute>(false))
                {
                    var name = string.IsNullOrEmpty(attr.Name) ? member.Name : attr.Name;
                    ColumnMap[name] = member;
                    Columns.Add(name);
                }
            }
        }
    }

    public static class DatabaseUtils
    {
        public static readonly Dictionary<Type, ColumnType> TypeMap = new();

        static DatabaseUtils()
        {
            TypeMap[typeof(byte)] = ColumnType.Integer;
            TypeMap[typeof(sbyte)] = ColumnType.Integer;
            TypeMap[typeof(short)] = ColumnType.Integer;
            TypeMap[typeof(ushort)] = ColumnType.Integer;
            TypeMap[typeof(int)] = ColumnType.Integer;
            TypeMap[typeof(uint)] = ColumnType.Integer;
            TypeMap[typeof(long)] = ColumnType.Long;
            TypeMap[typeof(ulong)] = ColumnType.Long;
            TypeMap[typeof(float)] = ColumnType.Decimal;
            TypeMap[typeof(double)] = ColumnType.Decimal;
            TypeMap[typeof(decimal)] = ColumnType.Decimal;
            TypeMap[typeof(bool)] = ColumnType.Boolean;
            TypeMap[typeof(string)] = ColumnType.String;
            TypeMap[typeof(byte[])] = ColumnType.Binary;
        }

        public static DbType GetDbType(ColumnType columnType)
        {
            switch (columnType)
            {
                case ColumnType.Boolean:
                    return DbType.Boolean;
                case ColumnType.Integer:
                    return DbType.Int32;
                case ColumnType.Long:
                    return DbType.Int64;
                case ColumnType.Decimal:
                    return DbType.Decimal;
                case ColumnType.String:
                    return DbType.String;
                case ColumnType.Binary:
                    return DbType.Binary;
                default:
                    return DbType.String;
            }
        }

        private static string GetAddColumnStatement(TableSchema schema, string columnName)
        {
            var columnInfo = schema.ColumnMap
                .Where(x => x.Key.Equals(columnName, StringComparison.InvariantCultureIgnoreCase))
                .Select(x => x.Value)
                .FirstOrDefault();
            if (columnInfo == null)
            {
                return null;
            }

            var sqlAttr = columnInfo.GetCustomAttribute<SqlColumnAttribute>();

            if (!TypeMap.TryGetValue(columnInfo.PropertyType, out var colType))
            {
                colType = ColumnType.String;
            }

            return $"ALTER TABLE {schema.TableName} ADD COLUMN {columnName} {GetSqliteType(colType)} NULL";
        }

        private static IEnumerable<string> GetDdlStatements(TableSchema schema)
        {
            var keys = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
            if (schema.PrimaryKey != null)
            {
                keys.UnionWith(schema.PrimaryKey);
            }

            foreach (var index in new[] {schema.Index1, schema.Index2})
            {
                if (index == null) continue;
                keys.UnionWith(index);
            }

            var sb = new StringBuilder();
            sb.Append($"CREATE TABLE {schema.TableName} (\n");
            if (!string.IsNullOrEmpty(schema.OwnerColumnName))
            {
                sb.Append($"\t{schema.OwnerColumnName} TEXT NOT NULL,\n");
            }

            foreach (var column in schema.Columns)
            {
                var prop = schema.ColumnMap[column];
                var sqlAttr = prop.GetCustomAttribute<SqlColumnAttribute>();

                if (!TypeMap.TryGetValue(prop.PropertyType, out var colType))
                {
                    colType = ColumnType.String;
                }

                var notNull = !sqlAttr.CanBeNull || keys.Contains(column);

                sb.Append($"\t{column} {GetSqliteType(colType)} {(notNull ? "NOT" : "")} NULL,\n");
            }

            var idx = new List<string>();
            if (!string.IsNullOrEmpty(schema.OwnerColumnName))
            {
                idx.Add(schema.OwnerColumnName);
            }

            if (schema.PrimaryKey != null)
            {
                idx.AddRange(schema.PrimaryKey);
            }

            sb.Append($"\tPRIMARY KEY ({string.Join(", ", idx)})\n");

            sb.Append(")\n");
            yield return sb.ToString();

            var indexNo = 0;
            foreach (var index in new [] { schema.Index1, schema.Index2 })
            {
                if (index == null) continue;
                indexNo++;

                sb.Length = 0;
                idx.Clear();
                if (!string.IsNullOrEmpty(schema.OwnerColumnName))
                {
                    idx.Add(schema.OwnerColumnName);
                }

                idx.AddRange(index);
                yield return
                    $"CREATE INDEX {schema.TableName}_Index_{indexNo} ON {schema.TableName} ({string.Join(", ", idx)})";
            }
        }

        private static string GetSqliteType(ColumnType columnType)
        {
            switch (columnType)
            {
                case ColumnType.Integer:
                case ColumnType.Long:
                case ColumnType.Boolean:
                    return "INTEGER";
                case ColumnType.Decimal:
                    return "REAL";
                case ColumnType.String:
                    return "TEXT";
                case ColumnType.Binary:
                    return "BLOB";
                default:
                    throw new ArgumentOutOfRangeException(nameof(columnType), columnType, null);
            }
        }

        public static IEnumerable<TD> PopulateDataObjects<TD>(this TableSchema schema, IDataReader reader)
            where TD : new()
        {
            while (reader.Read())
            {
                var data = new TD();
                for (var i = 0; i < schema.Columns.Count; i++)
                {
                    if (reader.IsDBNull(i)) continue;

                    var column = schema.ColumnMap[schema.Columns[i]];
                    if (column.PropertyType == typeof(string))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetString(i) });
                    }
                    else if (column.PropertyType == typeof(bool))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetBoolean(i) });
                    }
                    else if (column.PropertyType == typeof(int))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetInt32(i) });
                    }
                    else if (column.PropertyType == typeof(uint))
                    {
                        column.SetMethod.Invoke(data, new object[] { (uint) reader.GetInt32(i) });
                    }
                    else if (column.PropertyType == typeof(long))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetInt64(i) });
                    }
                    else if (column.PropertyType == typeof(ulong))
                    {
                        column.SetMethod.Invoke(data, new object[] { (ulong) reader.GetInt64(i) });
                    }
                    else if (column.PropertyType == typeof(byte))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetByte(i) });
                    }
                    else if (column.PropertyType == typeof(sbyte))
                    {
                        column.SetMethod.Invoke(data, new object[] { (sbyte) reader.GetByte(i) });
                    }
                    else if (column.PropertyType == typeof(short))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetInt16(i) });
                    }
                    else if (column.PropertyType == typeof(ushort))
                    {
                        column.SetMethod.Invoke(data, new object[] { (ushort) reader.GetInt16(i) });
                    }
                    else if (column.PropertyType == typeof(float))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetFloat(i) });
                    }
                    else if (column.PropertyType == typeof(double))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetDouble(i) });
                    }
                    else if (column.PropertyType == typeof(decimal))
                    {
                        column.SetMethod.Invoke(data, new object[] { reader.GetDecimal(i) });
                    }
                    else if (column.PropertyType == typeof(byte[]))
                    {
                        var v = reader.GetValue(i);
                        if (v is byte[])
                        {
                            column.SetMethod.Invoke(data, new[] { v });
                        }
                    }
                }

                yield return data;
            }
        }

        public static List<string> VerifyDatabase(DbConnection connection, params TableSchema[] schemas)
        {
            var ddlStatements = new List<string>();
            
            var allTables = new Dictionary<string, ISet<string>>(StringComparer.InvariantCultureIgnoreCase);

            var dbTables = connection.GetSchema("Tables");
            if (dbTables.Columns.Contains("TABLE_NAME"))
            {
                foreach (DataRow row in dbTables.Rows)
                {
                    var tableName = row["TABLE_NAME"].ToString();
                    allTables.Add(tableName, new HashSet<string>(StringComparer.InvariantCultureIgnoreCase));
                }
            }

            var dbColumns = connection.GetSchema("Columns");
            if (dbColumns.Columns.Contains("TABLE_NAME") && dbColumns.Columns.Contains("COLUMN_NAME"))
            {
                foreach (DataRow row in dbColumns.Rows)
                {
                    var tableName = row["TABLE_NAME"].ToString();
                    if (allTables.ContainsKey(tableName))
                    {
                        allTables[tableName].Add(row["COLUMN_NAME"].ToString());
                    }
                }
            }

            var statements = new List<string>();
            foreach (var schema in schemas)
            {
                if (allTables.TryGetValue(schema.TableName, out var columns))
                {
                    if (columns.Count <= 0) continue;
                    foreach (var columnName in schema.Columns)
                    {
                        if (columns.Contains(columnName)) continue;
                        var stmt = GetAddColumnStatement(schema, columnName);
                        if (!string.IsNullOrEmpty(stmt))
                        {
                            statements.Add(stmt);
                        }
                    }
                }
                else
                {
                    statements.AddRange(GetDdlStatements(schema));
                }
            }

            if (statements.Count > 0)
            {
                using (var cmd = connection.CreateCommand())
                {
                    foreach (var stmt in statements)
                    {
                        try
                        {
                            Debug.WriteLine($"[DDL STMT]: {stmt}");
                            cmd.CommandText = stmt;
                            cmd.ExecuteNonQuery();
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message);
                            ddlStatements.Add(stmt);
                        }
                    }
                }
            }

            return ddlStatements;
        }
    }
}
