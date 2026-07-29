using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  public interface IPamPlugin
  {
    IPamStorage Storage { get; }
    IEntityStorage<PamController> Controllers { get; }
    IEntityStorage<PamRecordRotationInfo> RecordRotations { get; }
    string EnterpriseUid { get; }

    Task SyncDownAsync(bool reload = false);
    void SyncRecordRotationsFromStorage();
    void MergeRecordRotations(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll = false);
    void MergeRecordRotationsFromVault(VaultOnline vault, bool replaceAll = false);
  }

  /// <summary>
  /// Caches PAM gateways and record rotations for enterprise admins.
  /// Controllers come from <c>pam/get_controllers</c>; rotations are merged from vault
  /// <c>sync_down</c>.
  /// Uses SQLite when Commander offline storage is on; otherwise keeps everything in memory.
  /// </summary>
  public class PamPlugin : IPamPlugin
  {
    private readonly IAuthentication _auth;
    private readonly int _enterpriseId;
    private readonly InMemoryEntityStorage<PamController> _controllers = new();
    private readonly InMemoryEntityStorage<PamRecordRotationInfo> _recordRotations = new();

    public PamPlugin(IAuthentication auth, Func<IDbConnection> getConnection = null)
    {
      if (auth?.AuthContext == null)
      {
        throw new ArgumentNullException(nameof(auth), "Enterprise admin access is required");
      }

      if (!auth.AuthContext.IsEnterpriseAdmin)
      {
        throw new InvalidOperationException("Enterprise admin access is required");
      }

      _auth = auth;
      _enterpriseId = auth.AuthContext.License?.EnterpriseId ?? 0;
      if (_enterpriseId == 0)
      {
        throw new InvalidOperationException("Enterprise ID is required for PAM plugin");
      }

      var enterpriseIdBytes = BitConverter.GetBytes(_enterpriseId);
      if (BitConverter.IsLittleEndian)
      {
        Array.Reverse(enterpriseIdBytes);
      }

      EnterpriseUid = enterpriseIdBytes.Base64UrlEncode();
      Storage = getConnection != null
        ? new SqlitePamStorage(getConnection, _enterpriseId)
        : new MemoryPamStorage();
      LoadFromStorage();
    }

    public PamPlugin(IEnterpriseLoader loader, Func<IDbConnection> getConnection = null)
      : this(loader?.Auth ?? throw new ArgumentNullException(nameof(loader)), getConnection)
    {
    }

    public IPamStorage Storage { get; }

    public IEntityStorage<PamController> Controllers => _controllers;

    public IEntityStorage<PamRecordRotationInfo> RecordRotations => _recordRotations;

    public string EnterpriseUid { get; }

    public async Task SyncDownAsync(bool reload = false)
    {
      if (reload)
      {
        var existing = Storage.Controllers.GetAll().Select(c => c.Uid).ToList();
        if (existing.Count > 0)
        {
          Storage.Controllers.DeleteUids(existing);
        }

        _controllers.Clear();
      }

      var controllers = await GatewayUtils.GetAllGatewaysAsync(_auth);
      var storageRows = new List<IPamStorageController>();
      var domainRows = new List<PamController>();
      foreach (var controller in controllers)
      {
        if (controller?.ControllerUid == null || controller.ControllerUid.IsEmpty)
        {
          continue;
        }

        var (storageRow, domainRow) = PamStorageMapper.FromProto(controller);
        storageRows.Add(storageRow);
        domainRows.Add(domainRow);
      }

      ApplyGatewayEntities(storageRows, domainRows);
      SyncRecordRotationsFromStorage();
    }

    /// <summary>
    /// Reload rotations from PAM sqlite/memory into the working set (no vault sync).
    /// </summary>
    public void SyncRecordRotationsFromStorage()
    {
      _recordRotations.Clear();
      var rows = Storage.RecordRotations.GetAll()
        .Select(PamStorageMapper.ToDomainRotation)
        .ToList();
      if (rows.Count > 0)
      {
        _recordRotations.PutEntities(rows);
      }
    }

    /// <summary>
    /// Upsert rotation rows into PAM storage + memory (from normal vault sync).
    /// </summary>
    public void MergeRecordRotations(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll = false)
    {
      var rowList = rows?
        .Where(r => r != null && !string.IsNullOrEmpty(r.RecordUid))
        .ToList() ?? new List<IPamStorageRecordRotation>();
      var incomingUids = new HashSet<string>(rowList.Select(r => r.RecordUid), StringComparer.Ordinal);

      if (replaceAll)
      {
        var existing = Storage.RecordRotations.GetAll().Select(r => r.Uid).ToList();
        if (existing.Count > 0)
        {
          Storage.RecordRotations.DeleteUids(existing);
        }

        _recordRotations.Clear();
      }
      else
      {
        var staleUids = Storage.RecordRotations.GetAll()
          .Select(r => r.Uid)
          .Where(uid => !incomingUids.Contains(uid))
          .ToList();

        if (staleUids.Count > 0)
        {
          Storage.RecordRotations.DeleteUids(staleUids);
          _recordRotations.DeleteUids(staleUids);
        }
      }

      if (rowList.Count == 0)
      {
        return;
      }

      Storage.RecordRotations.PutEntities(rowList);
      _recordRotations.PutEntities(rowList.Select(PamStorageMapper.ToDomainRotation));
    }

    /// <summary>
    /// Copy rotations from vault in-memory cache into PAM offline storage.
    /// </summary>
    public void MergeRecordRotationsFromVault(VaultOnline vault, bool replaceAll = false)
    {
      if (vault == null)
      {
        return;
      }

      var rows = vault.RecordRotationCache.Values
        .Select(PamStorageMapper.FromVaultInfo)
        .Where(r => r != null)
        .Cast<IPamStorageRecordRotation>()
        .ToList();
      MergeRecordRotations(rows, replaceAll);
    }

    private void LoadFromStorage()
    {
      var controllers = Storage.Controllers.GetAll()
        .Select(PamStorageMapper.ToDomainController)
        .ToList();
      if (controllers.Count > 0)
      {
        _controllers.PutEntities(controllers);
      }

      SyncRecordRotationsFromStorage();
    }

    private void ApplyGatewayEntities(
      IReadOnlyList<IPamStorageController> storageRows,
      IReadOnlyList<PamController> domainRows)
    {
      var serverUids = new HashSet<string>(
        domainRows.Select(c => c.Uid),
        StringComparer.Ordinal);

      var staleUids = _controllers.GetAll()
        .Select(c => c.Uid)
        .Where(uid => !serverUids.Contains(uid))
        .ToList();

      if (staleUids.Count > 0)
      {
        _controllers.DeleteUids(staleUids);
        Storage.Controllers.DeleteUids(staleUids);
      }

      if (storageRows.Count > 0)
      {
        Storage.Controllers.PutEntities(storageRows);
      }

      if (domainRows.Count > 0)
      {
        _controllers.PutEntities(domainRows);
      }
    }
  }
}
