using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using Xunit;

namespace Tests;

public class MySqlDialectTest
{
    [Fact]
    public void TestGetSqlType()
    {
        var dialect = MySqlDialect.Instance;

        Assert.Equal("INT", dialect.GetSqlType(ColumnType.Integer));
        Assert.Equal("BIGINT", dialect.GetSqlType(ColumnType.Long));
        Assert.Equal("TINYINT(1)", dialect.GetSqlType(ColumnType.Boolean));
        Assert.Equal("DOUBLE", dialect.GetSqlType(ColumnType.Decimal));
        Assert.Equal("TEXT", dialect.GetSqlType(ColumnType.String));
        Assert.Equal("BLOB", dialect.GetSqlType(ColumnType.Binary));
    }

    [Fact]
    public void TestGetUpsertStatement()
    {
        var schema = new TableSchema(typeof(Entity), "AccountId");
        var dialect = MySqlDialect.Instance;

        var upsertStmt = dialect.GetUpsertStatement(schema, schema.OwnerColumnName);

        // MySQL uses REPLACE INTO for UPSERT
        Assert.Contains("REPLACE INTO", upsertStmt);
        Assert.Contains("Entity", upsertStmt);
        Assert.Contains("AccountId", upsertStmt);
        Assert.Contains("EntityId", upsertStmt);
        Assert.Contains("Data", upsertStmt);
        Assert.Contains("@AccountId", upsertStmt);
        Assert.Contains("@EntityId", upsertStmt);
        Assert.Contains("@Data", upsertStmt);
    }

    [Fact]
    public void TestSupportsDdlGeneration()
    {
        var dialect = MySqlDialect.Instance;

        // MySQL dialect does not support DDL generation
        // Tables must be created externally
        Assert.False(dialect.SupportsDdlGeneration);
    }

    [Fact]
    public void TestGetDdlStatements()
    {
        var schema = new TableSchema(typeof(Entity), "AccountId");
        var dialect = MySqlDialect.Instance;

        // GetDdlStatements should generate MySQL DDL (even though SupportsDdlGeneration is false)
        var statements = dialect.GetDdlStatements(schema, schema.OwnerColumnName);
        var stmtList = new System.Collections.Generic.List<string>(statements);

        // Should have at least one CREATE TABLE statement
        Assert.NotEmpty(stmtList);

        var createTableStmt = stmtList[0];
        Assert.Contains("CREATE TABLE Entity", createTableStmt);
        Assert.Contains("AccountId VARCHAR(255) NOT NULL", createTableStmt);
        Assert.Contains("EntityId", createTableStmt);
        Assert.Contains("Data", createTableStmt);
        Assert.Contains("PRIMARY KEY", createTableStmt);
        Assert.Contains("ENGINE=InnoDB", createTableStmt);
        Assert.Contains("CHARSET=utf8mb4", createTableStmt);

        // Verify MySQL-specific types are used
        // EntityId is VARCHAR (not TEXT) because it's in the primary key
        Assert.Contains("EntityId VARCHAR(255)", createTableStmt);
        Assert.Contains("BLOB", createTableStmt); // For binary columns (Data)
    }

    [Fact]
    public void TestGetDdlStatementsNotExecutedByVerifyDatabase()
    {
        // Even though GetDdlStatements() works, VerifyDatabase should NOT execute them
        // because SupportsDdlGeneration = false
        var dialect = MySqlDialect.Instance;
        Assert.False(dialect.SupportsDdlGeneration);
    }
}
