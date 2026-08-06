using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using PamProto = PAM;
using VaultProto = Vault;

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

  public interface IPamStorageRecordRotation : IUid
  {
    string RecordUid { get; set; }
    long Revision { get; set; }
    string ConfigurationUid { get; set; }
    string Schedule { get; set; }
    byte[] PwdComplexity { get; set; }
    bool Disabled { get; set; }
    string ResourceUid { get; set; }
    long LastRotation { get; set; }
    int LastRotationStatus { get; set; }
  }

  public interface IPamStorage
  {
    IEntityStorage<IPamStorageController> Controllers { get; }
    IEntityStorage<IPamStorageRecordRotation> RecordRotations { get; }
    void Reset();

    /// <summary>
    /// Atomically apply a controller merge to durable storage (delete + put as one unit).
    /// </summary>
    void ApplyControllerMerge(IEnumerable<IPamStorageController> rows, bool replaceAll);

    /// <summary>
    /// Atomically apply a record-rotation merge to durable storage (delete + put as one unit).
    /// </summary>
    /// <param name="rows">Incoming rotation rows (final desired set for non-empty merges).</param>
    /// <param name="replaceAll">When true, clear all existing rotations before writing <paramref name="rows"/>.</param>
    void ApplyRecordRotationMerge(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll);
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

  [SqlTable(
    Name = "pam_storage_record_rotation",
    PrimaryKey = new[] { "record_uid" },
    Index1 = new[] { "configuration_uid" })]
  internal class PamStorageRecordRotationData : IPamStorageRecordRotation, IEntityCopy<IPamStorageRecordRotation>
  {
    [SqlColumn(Name = "record_uid")]
    public string RecordUid { get; set; } = "";

    [SqlColumn(Name = "revision")]
    public long Revision { get; set; }

    [SqlColumn(Name = "configuration_uid")]
    public string ConfigurationUid { get; set; } = "";

    [SqlColumn(Name = "schedule")]
    public string Schedule { get; set; } = "";

    [SqlColumn(Name = "pwd_complexity")]
    public byte[] PwdComplexity { get; set; } = Array.Empty<byte>();

    [SqlColumn(Name = "disabled")]
    public bool Disabled { get; set; }

    [SqlColumn(Name = "resource_uid")]
    public string ResourceUid { get; set; } = "";

    [SqlColumn(Name = "last_rotation")]
    public long LastRotation { get; set; }

    [SqlColumn(Name = "last_rotation_status")]
    public int LastRotationStatus { get; set; }

    public string Uid => RecordUid;

    public void CopyFields(IPamStorageRecordRotation source)
    {
      if (source == null) return;
      RecordUid = source.RecordUid;
      Revision = source.Revision;
      ConfigurationUid = source.ConfigurationUid;
      Schedule = source.Schedule;
      PwdComplexity = source.PwdComplexity ?? Array.Empty<byte>();
      Disabled = source.Disabled;
      ResourceUid = source.ResourceUid;
      LastRotation = source.LastRotation;
      LastRotationStatus = source.LastRotationStatus;
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

    public static PamStorageRecordRotationData FromVaultProto(VaultProto.RecordRotation rotation)
    {
      if (rotation == null)
      {
        return null;
      }

      var recordUid = rotation.RecordUid?.ToByteArray().Base64UrlEncode();
      if (string.IsNullOrEmpty(recordUid))
      {
        return null;
      }

      return new PamStorageRecordRotationData
      {
        RecordUid = recordUid,
        Revision = rotation.Revision,
        ConfigurationUid = rotation.ConfigurationUid?.ToByteArray().Base64UrlEncode() ?? "",
        Schedule = rotation.Schedule ?? "",
        PwdComplexity = rotation.PwdComplexity?.ToByteArray() ?? Array.Empty<byte>(),
        Disabled = rotation.Disabled,
        ResourceUid = rotation.ResourceUid?.ToByteArray().Base64UrlEncode() ?? "",
        LastRotation = rotation.LastRotation,
        LastRotationStatus = (int)rotation.LastRotationStatus,
      };
    }

    public static PamStorageRecordRotationData FromVaultInfo(KeeperSecurity.Vault.RecordRotationInfo info)
    {
      if (info == null || string.IsNullOrEmpty(info.RecordUid))
      {
        return null;
      }

      return new PamStorageRecordRotationData
      {
        RecordUid = info.RecordUid,
        Revision = info.Revision,
        ConfigurationUid = info.ConfigurationUid ?? "",
        Schedule = info.Schedule ?? "",
        PwdComplexity = info.PwdComplexity ?? Array.Empty<byte>(),
        Disabled = info.Disabled,
        ResourceUid = info.ResourceUid ?? "",
        LastRotation = info.LastRotation,
        LastRotationStatus = info.LastRotationStatus,
      };
    }

    public static PamRecordRotationInfo ToDomainRotation(IPamStorageRecordRotation row)
    {
      return new PamRecordRotationInfo
      {
        RecordUid = row.RecordUid,
        Revision = row.Revision,
        ConfigurationUid = row.ConfigurationUid,
        Schedule = row.Schedule,
        PwdComplexity = row.PwdComplexity ?? Array.Empty<byte>(),
        Disabled = row.Disabled,
        ResourceUid = row.ResourceUid,
        LastRotation = row.LastRotation,
        LastRotationStatus = row.LastRotationStatus,
      };
    }
  }

  public class MemoryPamStorage : IPamStorage
  {
    private readonly object _mergeLock = new();
    private readonly InMemoryEntityStorage<IPamStorageController> _controllers = new();
    private readonly InMemoryEntityStorage<IPamStorageRecordRotation> _recordRotations = new();

    public IEntityStorage<IPamStorageController> Controllers => _controllers;
    public IEntityStorage<IPamStorageRecordRotation> RecordRotations => _recordRotations;

    public void Reset()
    {
      lock (_mergeLock)
      {
        _controllers.Clear();
        _recordRotations.Clear();
      }
    }

    public void ApplyControllerMerge(IEnumerable<IPamStorageController> rows, bool replaceAll)
    {
      var rowList = PamStorageMerge.NormalizeControllerRows(rows);
      lock (_mergeLock)
      {
        ApplyInMemoryMerge(_controllers, rowList, replaceAll, r => r.ControllerUid);
      }
    }

    public void ApplyRecordRotationMerge(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll)
    {
      var rowList = PamStorageMerge.NormalizeRotationRows(rows);
      lock (_mergeLock)
      {
        ApplyInMemoryMerge(_recordRotations, rowList, replaceAll, r => r.RecordUid);
      }
    }

    private static void ApplyInMemoryMerge<T>(
      InMemoryEntityStorage<T> store,
      List<T> rowList,
      bool replaceAll,
      Func<T, string> uidSelector) where T : IUid
    {
      if (replaceAll)
      {
        store.Clear();
      }
      else
      {
        var incomingUids = new HashSet<string>(rowList.Select(uidSelector), StringComparer.Ordinal);
        var staleUids = store.GetAll()
          .Select(r => r.Uid)
          .Where(uid => !incomingUids.Contains(uid))
          .ToList();
        if (staleUids.Count > 0)
        {
          store.DeleteUids(staleUids);
        }
      }

      if (rowList.Count > 0)
      {
        store.PutEntities(rowList);
      }
    }
  }

  public class SqlitePamStorage : IPamStorage
  {
    private const string OwnerColumn = "enterprise_id";

    private readonly SqlEntityStorage<IPamStorageController, PamStorageControllerData> _controllers;
    private readonly SqlEntityStorage<IPamStorageRecordRotation, PamStorageRecordRotationData> _recordRotations;

    public static void VerifyDatabase(DbConnection connection, ISqlDialect dialect)
    {
      var controllerSchema = new TableSchema(typeof(PamStorageControllerData), OwnerColumn);
      var rotationSchema = new TableSchema(typeof(PamStorageRecordRotationData), OwnerColumn);
      DatabaseUtils.VerifyDatabase(connection, dialect, controllerSchema, rotationSchema);
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
      _recordRotations = new SqlEntityStorage<IPamStorageRecordRotation, PamStorageRecordRotationData>(
        getConnection, SqliteDialect.Instance, OwnerColumn, enterpriseId);
    }

    public IEntityStorage<IPamStorageController> Controllers => _controllers;
    public IEntityStorage<IPamStorageRecordRotation> RecordRotations => _recordRotations;

    public void Reset()
    {
      _controllers.DeleteAll();
      _recordRotations.DeleteAll();
    }

    public void ApplyControllerMerge(IEnumerable<IPamStorageController> rows, bool replaceAll)
    {
      var rowList = PamStorageMerge.NormalizeControllerRows(rows);
      if (replaceAll)
      {
        _controllers.MutateEntities(uidsToDelete: null, entitiesToPut: rowList, deleteAll: true);
        return;
      }

      var incomingUids = new HashSet<string>(rowList.Select(r => r.ControllerUid), StringComparer.Ordinal);
      var staleUids = _controllers.GetAll()
        .Select(r => r.Uid)
        .Where(uid => !incomingUids.Contains(uid))
        .ToList();
      _controllers.MutateEntities(staleUids, rowList, deleteAll: false);
    }

    public void ApplyRecordRotationMerge(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll)
    {
      var rowList = PamStorageMerge.NormalizeRotationRows(rows);
      if (replaceAll)
      {
        _recordRotations.MutateEntities(uidsToDelete: null, entitiesToPut: rowList, deleteAll: true);
        return;
      }

      var incomingUids = new HashSet<string>(rowList.Select(r => r.RecordUid), StringComparer.Ordinal);
      var staleUids = _recordRotations.GetAll()
        .Select(r => r.Uid)
        .Where(uid => !incomingUids.Contains(uid))
        .ToList();
      _recordRotations.MutateEntities(staleUids, rowList, deleteAll: false);
    }
  }

  internal static class PamStorageMerge
  {
    internal static List<IPamStorageController> NormalizeControllerRows(
      IEnumerable<IPamStorageController> rows)
    {
      return rows?
        .Where(r => r != null && !string.IsNullOrEmpty(r.ControllerUid))
        .ToList() ?? new List<IPamStorageController>();
    }

    internal static List<IPamStorageRecordRotation> NormalizeRotationRows(
      IEnumerable<IPamStorageRecordRotation> rows)
    {
      return rows?
        .Where(r => r != null && !string.IsNullOrEmpty(r.RecordUid))
        .ToList() ?? new List<IPamStorageRecordRotation>();
    }
  }
}
