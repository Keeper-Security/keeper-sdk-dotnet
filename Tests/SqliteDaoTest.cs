using System.Data.Common;
using Microsoft.Data.Sqlite;
using KeeperSecurity.Storage;
using Xunit;

namespace Tests;

public interface IRecord
{
    string StingValue { get; }
    long LongValue { get;  }
    byte[] BinaryValue { get; }
    bool BoolValue { get; }
}

public interface IEntity : IUid
{
    string EntityId { get; }
    byte[] Data { get; }
}


public class SqliteDaoTest
{
    [Fact]
    public void TestCreateQuery()
    {
        var recordSchema = new TableSchema(typeof(Record), "AccountId");
        var entitySchema = new TableSchema(typeof(Entity), "AccountId");
        var linkSchema = new TableSchema(typeof(Link), "AccountId");

        var failedStmt = DatabaseUtils.VerifyDatabase(GetSqliteConnection(), SqliteDialect.Instance, recordSchema, entitySchema, linkSchema);
        Assert.Empty(failedStmt);

        var recordStorage = new SqlRecordStorage<IRecord, Record>(GetSqliteConnection, SqliteDialect.Instance,"AccountId", "AAAAAA");
        var r = recordStorage.Load();
        if (r == null)
        {
            r = new Record
            {
                StingValue = "sfsdfsdfsd",
                BoolValue = true,
                LongValue = 231332323,
                BinaryValue = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
            };
            recordStorage.Store(r);
        }

        r = recordStorage.Load();
        Assert.NotNull(r);
        Assert.True(r.BoolValue);
        Assert.Equal("sfsdfsdfsd", r.StingValue);
        Assert.Equal(231332323, r.LongValue);
        Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17], r.BinaryValue);

        var entityStorage = new SqlEntityStorage<IEntity, Entity>(GetSqliteConnection, SqliteDialect.Instance, "AccountId", "AAAAAA");
        var e1 = entityStorage.GetEntity("Entity1");
        if (e1 == null)
        {
            e1 = new Entity
            {
                EntityId = "Entity1",
                Data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            };
            entityStorage.PutEntities([e1]);
        }

        var e2 = entityStorage.GetEntity("Entity1");
        if (e2 == null)
        {
            e2 = new Entity
            {
                EntityId = "Entity2",
                Data = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            };
            entityStorage.PutEntities([e2]);
        }

        foreach (var e in entityStorage.GetAll())
        {
            switch (e.EntityId)
            {
                case "Entity1":
                    Assert.Equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], e.Data);
                    break;
                case "Entity2":
                    Assert.Equal([11, 12, 13, 14, 15, 16, 17, 18, 19, 20], e.Data);
                    break;
                default:
                    Assert.Fail($"Unknown entity ID {e.EntityId}");
                    break;
            }
        }
    }

    [Fact]
    public void TestVerifyDatabaseWithDialect()
    {
        var recordSchema = new TableSchema(typeof(Record), "AccountId");
        var entitySchema = new TableSchema(typeof(Entity), "AccountId");

        // Test with SQLite dialect (should create tables)
        var failedStmt = DatabaseUtils.VerifyDatabase(
            GetSqliteConnection(),
            SqliteDialect.Instance,
            recordSchema,
            entitySchema);
        Assert.Empty(failedStmt);

        // Verify backward compatibility - default overload should work
        var failedStmt2 = DatabaseUtils.VerifyDatabase(
            GetSqliteConnection(), SqliteDialect.Instance, recordSchema, entitySchema);
        Assert.Empty(failedStmt2);
    }

    [Fact]
    public void TestDialectInStorage()
    {
        var recordSchema = new TableSchema(typeof(Record), "AccountId");
        DatabaseUtils.VerifyDatabase(GetSqliteConnection(), SqliteDialect.Instance, recordSchema);

        // Create storage with explicit dialect
        var recordStorage = new SqlRecordStorage<IRecord, Record>(
            GetSqliteConnection, SqliteDialect.Instance, "AccountId", "BBBBB");

        var r = new Record
        {
            StingValue = "test-dialect",
            BoolValue = false,
            LongValue = 999,
            BinaryValue = [1, 2, 3],
        };
        recordStorage.Store(r);

        var loaded = recordStorage.Load();
        Assert.NotNull(loaded);
        Assert.Equal("test-dialect", loaded.StingValue);
        Assert.False(loaded.BoolValue);
        Assert.Equal(999, loaded.LongValue);
    }

    private static DbConnection GetSqliteConnection()
    {
        var connection = new SqliteConnection("Data Source=:memory:;Mode=Memory;Cache=Shared;Pooling=True;");
        connection.Open();

        return connection;
    }
}

[SqlTable(Name = "Record")]
public class Record: IRecord, IEntityCopy<IRecord>
{
    [SqlColumn]
    public string StingValue { get; set; }
    [SqlColumn]
    public long LongValue { get; set; }
    [SqlColumn]
    public byte[] BinaryValue { get; set; }
    [SqlColumn]
    public bool BoolValue { get; set; }

    public void CopyFields(IRecord source)
    {
        StingValue = source.StingValue;
        LongValue = source.LongValue;
        BinaryValue = source.BinaryValue;
        BoolValue = source.BoolValue;
    }
}

[SqlTable(Name = "Entity", PrimaryKey = ["EntityId"])]
public class Entity : IEntity, IEntityCopy<IEntity>
{
    [SqlColumn] public string EntityId { get; set; }
    [SqlColumn] public byte[] Data { get; set; }
    string IUid.Uid => EntityId;
    public void CopyFields(IEntity source)
    {
        EntityId = source.EntityId;
        Data = source.Data;
    }
}


[SqlTable(Name = "Link", PrimaryKey = ["RefId", "ParentRefId"], Index1 = ["ParentRefId"])]
public class Link : IUidLink
{
    [SqlColumn] public string RefId { get; set; }
    [SqlColumn] public string ParentRefId { get; set; }
    [SqlColumn] public byte[] LinkKey { get; set; }
    string IUidLink.SubjectUid => RefId;
    string IUidLink.ObjectUid => ParentRefId;
}