using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Reflection;
using System.Text;

namespace KeeperSecurity.Storage;

/// <summary>
/// SQLite-specific SQL dialect implementation.
/// </summary>
public class SqliteDialect : ISqlDialect
{
    private static readonly Lazy<SqliteDialect> _instance = new(() => new SqliteDialect());

    /// <summary>
    /// Singleton instance for SQLite dialect.
    /// </summary>
    public static SqliteDialect Instance => _instance.Value;

    public bool SupportsDdlGeneration => true;

    public string GetSqlType(ColumnType columnType)
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

    public string GetUpsertStatement(TableSchema schema, string ownerColumnName)
    {
        var sb = new StringBuilder();
        sb.Append($"INSERT OR REPLACE INTO {schema.TableName} (");

        var columns = new List<string>();
        if (!string.IsNullOrEmpty(ownerColumnName))
        {
            columns.Add(ownerColumnName);
        }
        columns.AddRange(schema.Columns);

        sb.Append(string.Join(", ", columns));
        sb.Append(") VALUES (");
        sb.Append(string.Join(", ", columns.Select(c => $"@{c}")));
        sb.Append(")");

        return sb.ToString();
    }

    public DataTable GetTables(DbConnection connection)
    {
        var schema = new DataTable();
        schema.Columns.Add("TABLE_CATALOG", typeof(string));
        schema.Columns.Add("TABLE_SCHEMA", typeof(string));
        schema.Columns.Add("TABLE_NAME", typeof(string));
        schema.Columns.Add("TABLE_TYPE", typeof(string));

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = schema.NewRow();
            row["TABLE_CATALOG"] = connection.DataSource;
            row["TABLE_SCHEMA"] = DBNull.Value; // SQLite doesn't have schemas
            row["TABLE_NAME"] = reader.GetString(0);
            row["TABLE_TYPE"] = "TABLE";
            schema.Rows.Add(row);
        }
        return schema;
    }

    public DataTable GetColumns(DbConnection connection, IEnumerable<string> tableNames)
    {
        // Create a DataTable that matches the schema of GetSchema("Columns")
        var schema = new DataTable();
        schema.Columns.Add("TABLE_CATALOG", typeof(string));
        schema.Columns.Add("TABLE_SCHEMA", typeof(string));
        schema.Columns.Add("TABLE_NAME", typeof(string));
        schema.Columns.Add("COLUMN_NAME", typeof(string));
        schema.Columns.Add("DATA_TYPE", typeof(string));
        schema.Columns.Add("COLUMN_DEFAULT", typeof(string));
        schema.Columns.Add("IS_NULLABLE", typeof(bool));
        schema.Columns.Add("ORDINAL_POSITION", typeof(int));

        // Then get column info for each table
        foreach (var tableName in tableNames)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = $"PRAGMA table_info('{tableName}')";

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var row = schema.NewRow();
                row["TABLE_CATALOG"] = connection.DataSource;
                row["TABLE_SCHEMA"] = DBNull.Value; // SQLite doesn't have schemas
                row["TABLE_NAME"] = tableName;
                row["COLUMN_NAME"] = reader["name"];
                row["DATA_TYPE"] = reader["type"];
                row["COLUMN_DEFAULT"] = reader["dflt_value"] == DBNull.Value ? DBNull.Value : reader["dflt_value"];
                row["IS_NULLABLE"] = Convert.ToInt32(reader["notnull"]) == 0;
                row["ORDINAL_POSITION"] = Convert.ToInt32(reader["cid"]);
                schema.Rows.Add(row);
            }
        }
        return schema;
    }

    public IEnumerable<string> GetDdlStatements(TableSchema schema, string ownerColumnName)
    {
        var keys = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
        if (schema.PrimaryKey != null)
        {
            keys.UnionWith(schema.PrimaryKey);
        }

        foreach (var index in new[] { schema.Index1, schema.Index2 })
        {
            if (index == null) continue;
            keys.UnionWith(index);
        }

        var sb = new StringBuilder();
        sb.Append($"CREATE TABLE {schema.TableName} (\n");
        if (!string.IsNullOrEmpty(ownerColumnName))
        {
            sb.Append($"\t{ownerColumnName} TEXT NOT NULL,\n");
        }

        foreach (var column in schema.Columns)
        {
            var prop = schema.ColumnMap[column];
            var sqlAttr = prop.GetCustomAttribute<SqlColumnAttribute>();

            if (!DatabaseUtils.TypeMap.TryGetValue(prop.PropertyType, out var colType))
            {
                colType = ColumnType.String;
            }

            var notNull = !sqlAttr.CanBeNull || keys.Contains(column);

            sb.Append($"\t{column} {GetSqlType(colType)} {(notNull ? "NOT" : "")} NULL,\n");
        }

        var idx = new List<string>();
        if (!string.IsNullOrEmpty(ownerColumnName))
        {
            idx.Add(ownerColumnName);
        }

        if (schema.PrimaryKey != null)
        {
            idx.AddRange(schema.PrimaryKey);
        }

        sb.Append($"\tPRIMARY KEY ({string.Join(", ", idx)})\n");

        sb.Append(")\n");
        yield return sb.ToString();

        var indexNo = 0;
        foreach (var index in new[] { schema.Index1, schema.Index2 })
        {
            if (index == null) continue;
            indexNo++;

            sb.Length = 0;
            idx.Clear();
            if (!string.IsNullOrEmpty(ownerColumnName))
            {
                idx.Add(ownerColumnName);
            }

            idx.AddRange(index);
            yield return
                $"CREATE INDEX {schema.TableName}_Index_{indexNo} ON {schema.TableName} ({string.Join(", ", idx)})";
        }
    }
}