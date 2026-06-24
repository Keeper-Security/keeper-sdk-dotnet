using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using PamProto = PAM;

namespace KeeperSecurity.Plugins.PAM
{
  public interface IPamPlugin
  {
    IEntityStorage<PamController> Controllers { get; }
    string EnterpriseUid { get; }

    Task SyncDownAsync(bool reload = false);
  }

  public class PamPlugin : IPamPlugin
  {
    private readonly IAuthentication _auth;
    private readonly InMemoryEntityStorage<PamController> _controllers = new();

    public PamPlugin(IAuthentication auth)
    {
      if (auth?.AuthContext == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      if (!auth.AuthContext.IsEnterpriseAdmin)
      {
        throw new InvalidOperationException("Enterprise admin access is required");
      }

      _auth = auth;
      var enterpriseId = auth.AuthContext.License?.EnterpriseId ?? 0;
      if (enterpriseId == 0)
      {
        throw new InvalidOperationException("Enterprise ID is required for PAM plugin");
      }

      var enterpriseIdBytes = BitConverter.GetBytes(enterpriseId);
      if (BitConverter.IsLittleEndian)
      {
        Array.Reverse(enterpriseIdBytes);
      }

      EnterpriseUid = enterpriseIdBytes.Base64UrlEncode();
    }

    public PamPlugin(IEnterpriseLoader loader) : this(loader?.Auth ?? throw new ArgumentNullException(nameof(loader)))
    {
    }

    public IEntityStorage<PamController> Controllers => _controllers;

    public string EnterpriseUid { get; }

    public async Task SyncDownAsync(bool reload = false)
    {
      _ = reload;
      _controllers.Clear();

      var controllers = await GatewayUtils.GetAllGatewaysAsync(_auth);
      if (controllers.Count == 0)
      {
        return;
      }

      _controllers.PutEntities(controllers.Select(FromProto));
    }

    private static PamController FromProto(PamProto.PAMController controller)
    {
      return new PamController
      {
        ControllerUid = controller.ControllerUid?.ToByteArray().Base64UrlEncode() ?? "",
        ControllerName = controller.ControllerName ?? "",
        DeviceToken = controller.DeviceToken ?? "",
        DeviceName = controller.DeviceName ?? "",
        NodeId = controller.NodeId,
        Created = controller.Created,
        LastModified = controller.LastModified,
        ApplicationUid = controller.ApplicationUid?.ToByteArray().Base64UrlEncode() ?? "",
        AppClientType = controller.AppClientType,
        IsInitialized = controller.IsInitialized,
      };
    }
  }
}
