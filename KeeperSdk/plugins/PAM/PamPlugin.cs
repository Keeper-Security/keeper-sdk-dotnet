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
      // Fetch first so a failed network call never wipes durable/in-memory controllers.
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

      // merge controllers first. If this throws, working cache is left unchanged.
      Storage.ApplyControllerMerge(storageRows, replaceAll: reload);
      // Rebuild cache from the final saved state.
      SyncControllersFromDomain(domainRows);
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
    /// Durable storage is updated atomically; the working cache is then rebuilt from storage.
    /// </summary>
    public void MergeRecordRotations(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll = false)
    {
      // Single atomic durable merge (SQL transaction or locked in-memory store).
      Storage.ApplyRecordRotationMerge(rows, replaceAll);
      // Rebuild working set from durable storage so SQL + memory cannot diverge mid-merge.
      SyncRecordRotationsFromStorage();
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

      var rows = (vault.RecordRotationCache?.Values ?? Enumerable.Empty<RecordRotationInfo>())
        .Select(PamStorageMapper.FromVaultInfo)
        .Where(r => r != null)
        .ToList<IPamStorageRecordRotation>();
      MergeRecordRotations(rows, replaceAll);
    }

    // Only called from the constructor before the plugin is used.
    private void LoadFromStorage()
    {
      var controllers = Storage.Controllers.GetAll()
        .Select(PamStorageMapper.ToDomainController)
        .ToList();
      SyncControllersFromDomain(controllers);
      SyncRecordRotationsFromStorage();
    }

    private void SyncControllersFromDomain(IReadOnlyList<PamController> domainRows)
    {
      _controllers.Clear();
      if (domainRows != null && domainRows.Count > 0)
      {
        _controllers.PutEntities(domainRows);
      }
    }
  }
}
