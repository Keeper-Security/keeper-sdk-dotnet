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
  /// Stores PAM gateways and record rotations for enterprise admins.
  /// Loads controllers from PAM and rotations from vault sync.
  /// Uses SQLite when offline storage is enabled; otherwise uses memory storage.
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

      // Merge controllers first. If it fails, the cache remains unchanged.
      Storage.ApplyControllerMerge(storageRows, replaceAll: reload);
      SyncControllersFromDomain(domainRows);
      SyncRecordRotationsFromStorage();
    }

    /// <summary>
    /// Loads rotations from PAM storage into the working cache.
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
    /// Saves rotation data to PAM storage and updates the in-memory cache.
    /// Storage is updated first, then the cache is refreshed from the saved data.
    /// </summary>
    public void MergeRecordRotations(IEnumerable<IPamStorageRecordRotation> rows, bool replaceAll = false)
    {
      Storage.ApplyRecordRotationMerge(rows, replaceAll);
      SyncRecordRotationsFromStorage();
    }

    /// <summary>
    /// Copies rotation data from the vault cache to PAM offline storage.
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
