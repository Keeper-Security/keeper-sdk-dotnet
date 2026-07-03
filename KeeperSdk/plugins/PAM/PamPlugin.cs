using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using PamProto = PAM;
using VaultProto = Vault;

namespace KeeperSecurity.Plugins.PAM
{
  public interface IPamPlugin
  {
    IPamStorage Storage { get; }
    IEntityStorage<PamController> Controllers { get; }
    IEntityStorage<PamRecordRotationInfo> RecordRotations { get; }
    string EnterpriseUid { get; }

    Task SyncDownAsync(bool reload = false);
    Task SyncRecordRotationsFromVaultAsync();
  }

  /// <summary>
  /// Loads and caches PAM controller and record-rotation data for enterprise administrators.
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
        Storage.Reset();
        _recordRotations.Clear();
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

      if (!reload)
      {
        return;
      }

      try
      {
        await SyncRecordRotationsFromVaultAsync();
      }
      catch (Exception ex)
      {
        Trace.TraceWarning("PAM: loading record rotations from vault/sync_down failed: {0}", ex.Message);
      }
    }

    public async Task SyncRecordRotationsFromVaultAsync()
    {
      var merged = new Dictionary<string, PamStorageRecordRotationData>(StringComparer.Ordinal);
      var request = new VaultProto.SyncDownRequest();
      ByteString token = ByteString.Empty;
      var done = false;

      while (!done)
      {
        request.ContinuationToken = token;
        var response = (VaultProto.SyncDownResponse)await _auth.ExecuteAuthRest(
          "vault/sync_down",
          request,
          typeof(VaultProto.SyncDownResponse));

        if (response == null)
        {
          break;
        }

        done = !response.HasMore;
        token = response.ContinuationToken ?? ByteString.Empty;

        foreach (var rotation in response.RecordRotations)
        {
          var row = PamStorageMapper.FromProto(rotation);
          if (!string.IsNullOrEmpty(row.RecordUid))
          {
            merged[row.RecordUid] = row;
          }
        }
      }

      if (merged.Count == 0)
      {
        return;
      }

      var rows = merged.Values.ToList();
      Storage.RecordRotations.PutEntities(rows);
      _recordRotations.PutEntities(rows.Select(PamStorageMapper.ToDomainRotation));
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
