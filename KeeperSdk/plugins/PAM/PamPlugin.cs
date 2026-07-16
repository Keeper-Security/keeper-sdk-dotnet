using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Plugins.PAM
{
  public interface IPamPlugin
  {
    IPamStorage Storage { get; }
    IEntityStorage<PamController> Controllers { get; }
    string EnterpriseUid { get; }

    Task SyncDownAsync(bool reload = false);
  }

  /// <summary>
  /// Caches PAM gateways for enterprise admins.
  /// Record rotation metadata comes from normal <see cref="KeeperSecurity.Vault.VaultOnline.SyncDown"/>
  /// (Commander <c>record_rotation_cache</c>), not a separate vault/sync_down.
  /// Uses SQLite when Commander offline storage is on; otherwise keeps everything in memory.
  /// </summary>
  public class PamPlugin : IPamPlugin
  {
    private readonly IAuthentication _auth;
    private readonly int _enterpriseId;
    private readonly InMemoryEntityStorage<PamController> _controllers = new();

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

    public string EnterpriseUid { get; }

    public async Task SyncDownAsync(bool reload = false)
    {
      if (reload)
      {
        Storage.Reset();
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
