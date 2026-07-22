using System;
using System.Data;
using System.Data.Common;
using Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using PamProto = PAM;

namespace KeeperSecurity.Plugins.PAM
{
  public interface IPamStorageController : IUid
  {
    string ControllerUid { get; set; }
    string ControllerName { get; set; }
    string DeviceToken { get; set; }
    string DeviceName { get; set; }
    long NodeId { get; set; }
    long Created { get; set; }
    long LastModified { get; set; }
    string ApplicationUid { get; set; }
    AppClientType AppClientType { get; set; }
    bool IsInitialized { get; set; }
  }

  public interface IPamStorage
  {
    IEntityStorage<IPamStorageController> Controllers { get; }
    void Reset();
  }

  [SqlTable(Name = "pam_storage_controller", PrimaryKey = new[] { "controller_uid" })]
  internal class PamStorageControllerData : IPamStorageController, IEntityCopy<IPamStorageController>
  {
    [SqlColumn(Name = "controller_uid")]
    public string ControllerUid { get; set; } = "";

    [SqlColumn(Name = "controller_name")]
    public string ControllerName { get; set; } = "";

    [SqlColumn(Name = "device_token")]
    public string DeviceToken { get; set; } = "";

    [SqlColumn(Name = "device_name")]
    public string DeviceName { get; set; } = "";

    [SqlColumn(Name = "node_id")]
    public long NodeId { get; set; }

    [SqlColumn(Name = "created")]
    public long Created { get; set; }

    [SqlColumn(Name = "last_modified")]
    public long LastModified { get; set; }

    [SqlColumn(Name = "application_uid")]
    public string ApplicationUid { get; set; } = "";

    [SqlColumn(Name = "app_client_type")]
    public int AppClientTypeValue { get; set; }

    AppClientType IPamStorageController.AppClientType
    {
      get => (AppClientType)AppClientTypeValue;
      set => AppClientTypeValue = (int)value;
    }

    [SqlColumn(Name = "is_initialized")]
    public bool IsInitialized { get; set; }

    public string Uid => ControllerUid;

    public void CopyFields(IPamStorageController source)
    {
      if (source == null) return;
      ControllerUid = source.ControllerUid;
      ControllerName = source.ControllerName;
      DeviceToken = source.DeviceToken;
      DeviceName = source.DeviceName;
      NodeId = source.NodeId;
      Created = source.Created;
      LastModified = source.LastModified;
      ApplicationUid = source.ApplicationUid;
      ((IPamStorageController)this).AppClientType = source.AppClientType;
      IsInitialized = source.IsInitialized;
    }
  }

  internal static class PamStorageMapper
  {
    public static (PamStorageControllerData Storage, PamController Domain) FromProto(PamProto.PAMController controller)
    {
      var storage = new PamStorageControllerData
      {
        ControllerUid = controller.ControllerUid?.ToByteArray().Base64UrlEncode() ?? "",
        ControllerName = controller.ControllerName ?? "",
        DeviceToken = controller.DeviceToken ?? "",
        DeviceName = controller.DeviceName ?? "",
        NodeId = controller.NodeId,
        Created = controller.Created,
        LastModified = controller.LastModified,
        ApplicationUid = controller.ApplicationUid?.ToByteArray().Base64UrlEncode() ?? "",
        AppClientTypeValue = (int)controller.AppClientType,
        IsInitialized = controller.IsInitialized,
      };

      return (storage, ToDomainController(storage));
    }

    public static PamController ToDomainController(IPamStorageController row)
    {
      return new PamController
      {
        ControllerUid = row.ControllerUid,
        ControllerName = row.ControllerName,
        DeviceToken = row.DeviceToken,
        DeviceName = row.DeviceName,
        NodeId = row.NodeId,
        Created = row.Created,
        LastModified = row.LastModified,
        ApplicationUid = row.ApplicationUid,
        AppClientType = row.AppClientType,
        IsInitialized = row.IsInitialized,
      };
    }
  }

  public class MemoryPamStorage : IPamStorage
  {
    private readonly InMemoryEntityStorage<IPamStorageController> _controllers = new();

    public IEntityStorage<IPamStorageController> Controllers => _controllers;

    public void Reset()
    {
      _controllers.Clear();
    }
  }

  public class SqlitePamStorage : IPamStorage
  {
    private const string OwnerColumn = "enterprise_id";
    private readonly SqlEntityStorage<IPamStorageController, PamStorageControllerData> _controllers;

    public static void VerifyDatabase(DbConnection connection, ISqlDialect dialect)
    {
      var controllerSchema = new TableSchema(typeof(PamStorageControllerData), OwnerColumn);
      DatabaseUtils.VerifyDatabase(connection, dialect, controllerSchema);
    }

    public SqlitePamStorage(Func<IDbConnection> getConnection, int enterpriseId)
    {
      var connection = getConnection();
      if (connection is DbConnection dbConnection)
      {
        VerifyDatabase(dbConnection, SqliteDialect.Instance);
      }
      else
      {
        throw new InvalidOperationException("Connection must be a DbConnection");
      }

      _controllers = new SqlEntityStorage<IPamStorageController, PamStorageControllerData>(
        getConnection, SqliteDialect.Instance, OwnerColumn, enterpriseId);
    }

    public IEntityStorage<IPamStorageController> Controllers => _controllers;

    public void Reset()
    {
      _controllers.DeleteAll();
    }
  }
}
