using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Reflection;
using System.Text;

namespace KeeperSecurity.Storage;

/// <summary>
/// MySQL-specific SQL dialect implementation.
/// </summary>
/// <remarks>
/// This dialect generates proper MySQL DDL via GetDdlStatements() for documentation/manual setup,
/// but SupportsDdlGeneration = false means VerifyDatabase() will NOT auto-execute the DDL.
/// Users must manually create tables before using MySqlKeeperStorage.
/// </remarks>
public class MySqlDialect : ISqlDialect
{
    private static readonly Lazy<MySqlDialect> _instance = new Lazy<MySqlDialect>(() => new MySqlDialect());

    /// <summary>
    /// Singleton instance for MySQL dialect.
    /// </summary>
    public static MySqlDialect Instance => _instance.Value;

    public bool SupportsDdlGeneration => false;

    public string GetSqlType(ColumnType columnType)
    {
        switch (columnType)
        {
            case ColumnType.Integer:
                return "INT";
            case ColumnType.Long:
                return "BIGINT";
            case ColumnType.Boolean:
                return "TINYINT(1)";
            case ColumnType.Decimal:
                return "DOUBLE";
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
        // MySQL uses REPLACE INTO for UPSERT (simpler than ON DUPLICATE KEY UPDATE)
        var sb = new StringBuilder();
        sb.Append($"REPLACE INTO {schema.TableName} (");

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
        cmd.CommandText = @"
                SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_TYPE = 'BASE TABLE'";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = schema.NewRow();
            row["TABLE_CATALOG"] = connection.Database;
            row["TABLE_SCHEMA"] = reader.GetString(0);
            row["TABLE_NAME"] = reader.GetString(1);
            row["TABLE_TYPE"] = reader.GetString(2);
            schema.Rows.Add(row);
        }
        return schema;
    }

    public DataTable GetColumns(DbConnection connection, IEnumerable<string> tableNames)
    {
        var schema = new DataTable();
        schema.Columns.Add("TABLE_CATALOG", typeof(string));
        schema.Columns.Add("TABLE_SCHEMA", typeof(string));
        schema.Columns.Add("TABLE_NAME", typeof(string));
        schema.Columns.Add("COLUMN_NAME", typeof(string));
        schema.Columns.Add("DATA_TYPE", typeof(string));
        schema.Columns.Add("COLUMN_DEFAULT", typeof(string));
        schema.Columns.Add("IS_NULLABLE", typeof(bool));
        schema.Columns.Add("ORDINAL_POSITION", typeof(int));

        var tableNamesList = tableNames.ToList();
        if (!tableNamesList.Any())
        {
            return schema;
        }

        using var cmd = connection.CreateCommand();

        // Build IN clause with parameters
        var paramNames = new List<string>();
        for (int i = 0; i < tableNamesList.Count; i++)
        {
            var paramName = $"@table{i}";
            paramNames.Add(paramName);
            var param = cmd.CreateParameter();
            param.ParameterName = paramName;
            param.Value = tableNamesList[i];
            cmd.Parameters.Add(param);
        }

        cmd.CommandText = $@"
                SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE,
                       COLUMN_DEFAULT, IS_NULLABLE, ORDINAL_POSITION
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME IN ({string.Join(", ", paramNames)})
                ORDER BY TABLE_NAME, ORDINAL_POSITION";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var row = schema.NewRow();
            row["TABLE_CATALOG"] = connection.Database;
            row["TABLE_SCHEMA"] = reader.GetString(0);
            row["TABLE_NAME"] = reader.GetString(1);
            row["COLUMN_NAME"] = reader.GetString(2);
            row["DATA_TYPE"] = reader.GetString(3);
            row["COLUMN_DEFAULT"] = reader.IsDBNull(4) ? DBNull.Value : reader.GetString(4);
            row["IS_NULLABLE"] = reader.GetString(5).Equals("YES", StringComparison.OrdinalIgnoreCase);
            row["ORDINAL_POSITION"] = reader.GetInt32(6);
            schema.Rows.Add(row);
        }
        return schema;
    }

    public IEnumerable<string> GetDdlStatements(TableSchema schema, string ownerColumnName)
    {
        // Generate MySQL DDL statements (for documentation/manual setup)
        // Note: SupportsDdlGeneration = false means these won't be auto-executed

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
            sb.Append($"  {ownerColumnName} VARCHAR(255) NOT NULL,\n");
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
            var sqlType = GetSqlType(colType);

            // MySQL requirement: TEXT/BLOB columns in indexes must use VARCHAR with explicit length
            // If column is used in a key (primary or index) and is a string type, use VARCHAR
            if (colType == ColumnType.String)
            {
                if (keys.Contains(column))
                {
                    // Column is in a key - must use VARCHAR with explicit length
                    var length = sqlAttr.Length > 0 ? sqlAttr.Length : 255;
                    sqlType = $"VARCHAR({length})";
                }
                else if (sqlAttr.Length > 0)
                {
                    // Column has explicit length but not in key - can use VARCHAR
                    sqlType = $"VARCHAR({sqlAttr.Length})";
                }
                // else: Use TEXT for unlimited length strings not in keys
            }

            sb.Append($"  {column} {sqlType} {(notNull ? "NOT" : "")} NULL,\n");
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

        sb.Append($"  PRIMARY KEY ({string.Join(", ", idx)})\n");
        sb.Append(") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

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