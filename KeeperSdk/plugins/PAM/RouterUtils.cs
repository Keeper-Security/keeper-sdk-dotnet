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
  /// <summary>
  /// PAM router helpers for record rotation schedules.
  /// </summary>
  public static class RouterUtils
  {
    private const string GetRotationSchedulesPath = "get_rotation_schedules";
    private const string SetRecordRotationPath = "set_record_rotation";

    public static async Task<PamProto.PAMRotationSchedulesResponse> GetRotationSchedulesAsync(IAuthentication auth)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      var request = new PamProto.PAMGenericUidsRequest();
      return await auth.ExecuteRouter<PamProto.PAMRotationSchedulesResponse>(
        GetRotationSchedulesPath,
        request);
    }

    private const string GetControllersPath = "get_controllers";

    public static async Task<PamProto.PAMOnlineControllers> GetConnectedGatewaysAsync(IAuthentication auth)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      return await auth.ExecuteRouter<PamProto.PAMOnlineControllers>(GetControllersPath);
    }

    public static async Task SetRecordRotationAsync(IAuthentication auth, RouterProto.RouterRecordRotationRequest request)
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
        throw new InvalidOperationException("Endpoint must be KeeperEndpoint to use SetRecordRotationAsync");
      }

      await keeperEndpoint.ExecuteRouterRest(
        SetRecordRotationPath,
        auth.AuthContext.SessionToken,
        request.ToByteArray());
    }

    public static async Task ConfigureResourceAsync(IAuthentication auth, PamProto.PAMResourceConfig request)
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
        throw new InvalidOperationException("Endpoint must be KeeperEndpoint to use ConfigureResourceAsync");
      }

      await keeperEndpoint.ExecuteRouterRest(
        "configure_resource",
        auth.AuthContext.SessionToken,
        request.ToByteArray());
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
