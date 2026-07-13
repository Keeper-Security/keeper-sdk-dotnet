using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using PamProto = PAM;
using RouterProto = Router;

namespace KeeperSecurity.Plugins.PAM
{
  public static class RouterUtils
  {
    private const string GetControllersPath = "get_controllers";

    public static async Task<PamProto.PAMOnlineControllers> GetConnectedGatewaysAsync(IAuthentication auth)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      return await auth.ExecuteRouter<PamProto.PAMOnlineControllers>(GetControllersPath);
    }

    public static IList<byte[]> GetConnectedGatewayUids(PamProto.PAMOnlineControllers onlineControllers)
    {
      if (onlineControllers?.Controllers == null)
      {
        return Array.Empty<byte[]>();
      }

      return onlineControllers.Controllers
        .Where(x => x.ControllerUid != null && x.ControllerUid.Length > 0)
        .Select(x => x.ControllerUid.ToByteArray())
        .ToList();
    }

    public static async Task ConfigureNetworkGraphAsync(
      IAuthentication auth,
      RouterProto.PAMNetworkConfigurationRequest request)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      if (request == null)
      {
        throw new ArgumentNullException(nameof(request));
      }

      if (auth.Endpoint is not KeeperEndpoint keeperEndpoint)
      {
        throw new InvalidOperationException("Endpoint must be KeeperEndpoint to use ConfigureNetworkGraphAsync");
      }

      await keeperEndpoint.ExecuteRouterRest(
        "configure_network_graph",
        auth.AuthContext.SessionToken,
        request.ToByteArray());
    }
  }
}
