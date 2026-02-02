using KeeperSecurity.Storage;
using Xunit;

namespace Tests;

public class SqliteDialectTest
{
    [Fact]
    public void TestGetSqlType()
    {
        var dialect = SqliteDialect.Instance;

        Assert.Equal("INTEGER", dialect.GetSqlType(ColumnType.Integer));
        Assert.Equal("INTEGER", dialect.GetSqlType(ColumnType.Long));
        Assert.Equal("INTEGER", dialect.GetSqlType(ColumnType.Boolean));
        Assert.Equal("REAL", dialect.GetSqlType(ColumnType.Decimal));
        Assert.Equal("TEXT", dialect.GetSqlType(ColumnType.String));
        Assert.Equal("BLOB", dialect.GetSqlType(ColumnType.Binary));
    }

    [Fact]
    public void TestGetUpsertStatement()
    {
        var schema = new TableSchema(typeof(Entity), "AccountId");
        var dialect = SqliteDialect.Instance;

        var upsertStmt = dialect.GetUpsertStatement(schema, schema.OwnerColumnName);

        // SQLite uses INSERT OR REPLACE INTO for UPSERT
        Assert.Contains("INSERT OR REPLACE INTO", upsertStmt);
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
        var dialect = SqliteDialect.Instance;

        // SQLite dialect supports DDL generation
        Assert.True(dialect.SupportsDdlGeneration);
    }

    [Fact]
    public void TestGetDdlStatements()
    {
        var schema = new TableSchema(typeof(Entity), "AccountId");
        var dialect = SqliteDialect.Instance;

        var statements = dialect.GetDdlStatements(schema, schema.OwnerColumnName);

        var stmtList = new System.Collections.Generic.List<string>(statements);

        // Should have at least one CREATE TABLE statement
        Assert.NotEmpty(stmtList);

        var createTableStmt = stmtList[0];
        Assert.Contains("CREATE TABLE Entity", createTableStmt);
        Assert.Contains("AccountId TEXT NOT NULL", createTableStmt);
        Assert.Contains("EntityId", createTableStmt);
        Assert.Contains("Data", createTableStmt);
        Assert.Contains("PRIMARY KEY", createTableStmt);
    }

    [Fact]
    public void TestSingletonInstance()
    {
        // Verify that Instance always returns the same object
        var instance1 = SqliteDialect.Instance;
        var instance2 = SqliteDialect.Instance;

        Assert.Same(instance1, instance2);
    }
}
