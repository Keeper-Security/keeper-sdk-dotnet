using System.Collections.Generic;
using System.Data;
using System.Data.Common;

namespace KeeperSecurity.Storage;

/// <summary>
/// Interface for database-specific SQL generation and schema operations.
/// Abstracts differences between SQLite, MySQL, and other SQL databases.
/// </summary>
public interface ISqlDialect
{
    /// <summary>
    /// Generates an UPSERT (INSERT OR UPDATE) statement for the given table schema.
    /// SQLite uses "INSERT OR REPLACE INTO", MySQL uses "REPLACE INTO" or "ON DUPLICATE KEY UPDATE".
    /// </summary>
    /// <param name="schema">Table schema information</param>
    /// <param name="ownerColumnName">Optional owner column name for multi-tenant storage</param>
    /// <returns>SQL UPSERT statement template with parameter placeholders</returns>
    string GetUpsertStatement(TableSchema schema, string ownerColumnName);

    /// <summary>
    /// Maps a ColumnType to database-specific SQL type string.
    /// SQLite: INTEGER, TEXT, BLOB, REAL
    /// MySQL: INT, VARCHAR, BLOB, DOUBLE
    /// </summary>
    /// <param name="columnType">Generic column type</param>
    /// <returns>Database-specific type string</returns>
    string GetSqlType(ColumnType columnType);

    /// <summary>
    /// Indicates whether this dialect supports DDL (table creation) operations.
    /// False for databases where tables are pre-created externally.
    /// </summary>
    bool SupportsDdlGeneration { get; }

    /// <summary>
    /// Retrieves list of tables from the database.
    /// SQLite: Query sqlite_master
    /// MySQL: Query INFORMATION_SCHEMA.TABLES or SHOW TABLES
    /// </summary>
    /// <param name="connection">Open database connection</param>
    /// <returns>DataTable with TABLE_NAME column</returns>
    DataTable GetTables(DbConnection connection);

    /// <summary>
    /// Retrieves column information for specified tables.
    /// SQLite: PRAGMA table_info()
    /// MySQL: Query INFORMATION_SCHEMA.COLUMNS
    /// </summary>
    /// <param name="connection">Open database connection</param>
    /// <param name="tableNames">Tables to inspect</param>
    /// <returns>DataTable with TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE columns</returns>
    DataTable GetColumns(DbConnection connection, IEnumerable<string> tableNames);

    /// <summary>
    /// Generates DDL statements to create table and indexes.
    /// Only called if SupportsDdlGeneration is true.
    /// </summary>
    /// <param name="schema">Table schema information</param>
    /// <param name="ownerColumnName">Optional owner column name for multi-tenant storage</param>
    /// <returns>Sequence of CREATE TABLE and CREATE INDEX statements</returns>
    IEnumerable<string> GetDdlStatements(TableSchema schema, string ownerColumnName);
}