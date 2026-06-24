using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;

namespace KeeperSecurity.Plugins.PAM
{
  public static class GatewayUtils
  {
    private const string GetControllersEndpoint = "pam/get_controllers";
    private const string RemoveControllerEndpoint = "pam/remove_controller";
    private const string SetMaxInstanceCountEndpoint = "pam/set_controller_max_instance_count";
    private const string ModifyControllerEndpoint = "pam/modify_controller";
    private const int DefaultOttExpireMinutes = 60;
    private const char VersionSeparator = ';';

    public static async Task<IList<PamProto.PAMController>> GetAllGatewaysAsync(IAuthentication auth)
    {
      var response = (PamProto.PAMControllersResponse)await auth.ExecuteAuthRest(
        GetControllersEndpoint,
        null,
        typeof(PamProto.PAMControllersResponse));
      return response?.Controllers?.ToList() ?? new List<PamProto.PAMController>();
    }

    public static async Task<string> CreateGatewayAsync(
      VaultOnline vault,
      string gatewayName,
      string ksmAppUid,
      int ottExpireInMinutes = DefaultOttExpireMinutes)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (string.IsNullOrWhiteSpace(gatewayName))
      {
        throw new ArgumentException("Gateway name is required", nameof(gatewayName));
      }

      if (string.IsNullOrWhiteSpace(ksmAppUid))
      {
        throw new ArgumentException("KSM application UID is required", nameof(ksmAppUid));
      }

      var result = await vault.AddSecretManagerClient(
        ksmAppUid,
        unlockIp: true,
        firstAccessExpireInMinutes: ottExpireInMinutes,
        name: gatewayName,
        appClientType: AppClientType.DiscoveryAndRotationController);

      return result?.Item2 ?? throw new InvalidOperationException("Gateway one-time token was not returned");
    }

    public static async Task RemoveGatewayAsync(IAuthentication auth, string gatewayUid)
    {
      var uidBytes = DecodeGatewayUid(gatewayUid);
      var request = new PamProto.PAMGenericUidRequest
      {
        Uid = ByteString.CopyFrom(uidBytes),
      };

      var response = (PamProto.PAMRemoveControllerResponse)await auth.ExecuteAuthRest(
        RemoveControllerEndpoint,
        request,
        typeof(PamProto.PAMRemoveControllerResponse));

      HandleRemoveControllerResponse(response, uidBytes);
    }

    public static async Task SetGatewayMaxInstancesAsync(IAuthentication auth, string gatewayUid, int maxInstanceCount)
    {
      if (maxInstanceCount < 1)
      {
        throw new ArgumentOutOfRangeException(nameof(maxInstanceCount), "Max instances must be at least 1");
      }

      var request = new PamProto.PAMSetMaxInstanceCountRequest
      {
        ControllerUid = ByteString.CopyFrom(DecodeGatewayUid(gatewayUid)),
        MaxInstanceCount = maxInstanceCount,
      };

      await auth.ExecuteAuthRest(SetMaxInstanceCountEndpoint, request, null);
    }

    public static async Task EditGatewayAsync(
      IAuthentication auth,
      string gatewayUid,
      string gatewayName,
      long nodeId)
    {
      if (string.IsNullOrWhiteSpace(gatewayName))
      {
        throw new ArgumentException("Gateway name is required", nameof(gatewayName));
      }

      var request = new PamProto.PAMController
      {
        ControllerUid = ByteString.CopyFrom(DecodeGatewayUid(gatewayUid)),
        ControllerName = gatewayName,
        NodeId = nodeId,
      };

      await auth.ExecuteAuthRest(ModifyControllerEndpoint, request, null);
    }

    public static PamController FindGateway(IEnumerable<PamController> controllers, string identifier)
    {
      return FindGateway(controllers, identifier, out _);
    }

    public static PamController FindGateway(
      IEnumerable<PamController> controllers,
      string identifier,
      out string errorMessage)
    {
      errorMessage = null;
      if (controllers == null || string.IsNullOrWhiteSpace(identifier))
      {
        return null;
      }

      var trimmed = identifier.Trim();
      var byUid = controllers.FirstOrDefault(c =>
        string.Equals(c.ControllerUid, trimmed, StringComparison.OrdinalIgnoreCase));
      if (byUid != null)
      {
        return byUid;
      }

      var byName = controllers
        .Where(c => string.Equals(c.ControllerName, trimmed, StringComparison.OrdinalIgnoreCase))
        .ToList();
      if (byName.Count > 1)
      {
        errorMessage = $"Multiple gateways match name \"{trimmed}\". Please specify Gateway UID.";
        return null;
      }

      return byName.FirstOrDefault();
    }

    public static IList<PamGatewaySummary> BuildGatewaySummaries(
      IEnumerable<PamController> controllers,
      PamProto.PAMOnlineControllers onlineControllers,
      bool routerDown,
      VaultOnline vault = null)
    {
      var connectedByUid = new Dictionary<string, List<PamProto.PAMOnlineController>>(StringComparer.Ordinal);
      if (onlineControllers?.Controllers != null)
      {
        foreach (var online in onlineControllers.Controllers)
        {
          var uid = online.ControllerUid?.ToByteArray().Base64UrlEncode() ?? "";
          if (string.IsNullOrEmpty(uid))
          {
            continue;
          }

          if (!connectedByUid.TryGetValue(uid, out var instances))
          {
            instances = new List<PamProto.PAMOnlineController>();
            connectedByUid[uid] = instances;
          }

          instances.Add(online);
        }
      }

      var summaries = new List<PamGatewaySummary>();
      foreach (var controller in controllers ?? Enumerable.Empty<PamController>())
      {
        connectedByUid.TryGetValue(controller.ControllerUid, out var onlineInstances);
        onlineInstances ??= new List<PamProto.PAMOnlineController>();

        var summary = new PamGatewaySummary
        {
          Controller = controller,
          KsmAppUid = controller.ApplicationUid,
          OnlineInstanceCount = onlineInstances.Count,
          OnlineInstances = onlineInstances.Select(ToOnlineInstance).ToList(),
        };

        ResolveKsmAppInfo(vault, summary);
        summary.Status = DetermineStatus(routerDown, onlineInstances.Count);
        var versionInfo = ParseGatewayVersionInfo(onlineInstances.FirstOrDefault()?.Version);
        summary.GatewayVersion = versionInfo.GatewayVersion;
        summary.SystemInfo = versionInfo.SystemInfo;
        summaries.Add(summary);
      }

      return summaries
        .OrderBy(x => x.Status)
        .ThenBy(x => x.KsmAppName, StringComparer.OrdinalIgnoreCase)
        .ToList();
    }

    private static PamGatewayOnlineInstance ToOnlineInstance(PamProto.PAMOnlineController online)
    {
      var versionInfo = ParseGatewayVersionInfo(online?.Version);
      return new PamGatewayOnlineInstance
      {
        IpAddress = online?.IpAddress ?? "",
        Version = versionInfo.GatewayVersion,
        ConnectedOn = online?.ConnectedOn ?? 0,
        SystemInfo = versionInfo.SystemInfo,
      };
    }

    private static void ResolveKsmAppInfo(VaultOnline vault, PamGatewaySummary summary)
    {
      if (vault == null || string.IsNullOrEmpty(summary.KsmAppUid))
      {
        summary.KsmAppAccessible = false;
        return;
      }

      if (vault.TryGetKeeperRecord(summary.KsmAppUid, out var record))
      {
        summary.KsmAppName = record.Title ?? "";
        summary.KsmAppAccessible = true;
      }
      else
      {
        summary.KsmAppAccessible = false;
      }
    }

    private static string DetermineStatus(bool routerDown, int onlineCount)
    {
      if (routerDown)
      {
        return "UNKNOWN";
      }

      if (onlineCount > 1)
      {
        return $"ONLINE ({onlineCount} instances)";
      }

      return onlineCount > 0 ? "ONLINE" : "OFFLINE";
    }

    public static PamGatewayVersionInfo ParseGatewayVersionInfo(string version)
    {
      if (string.IsNullOrEmpty(version))
      {
        return new PamGatewayVersionInfo();
      }

      var parts = version.Split(VersionSeparator);
      return new PamGatewayVersionInfo
      {
        GatewayVersion = parts.Length > 0 ? parts[0] : version,
        SystemInfo = new PamGatewaySystemInfo
        {
          Os = GetVersionPart(parts, 1),
          OsRelease = GetVersionPart(parts, 2),
          MachineType = GetVersionPart(parts, 3),
          OsVersion = GetVersionPart(parts, 4),
        },
      };
    }

    private static string GetVersionPart(string[] parts, int index)
    {
      return parts.Length > index ? parts[index] : "";
    }

    private static byte[] DecodeGatewayUid(string gatewayUid)
    {
      if (string.IsNullOrWhiteSpace(gatewayUid))
      {
        throw new ArgumentException("Gateway UID is required", nameof(gatewayUid));
      }

      try
      {
        return gatewayUid.Trim().Base64UrlDecode();
      }
      catch (Exception ex)
      {
        throw new ArgumentException($"Invalid gateway UID: {gatewayUid}", nameof(gatewayUid), ex);
      }
    }

    private static void HandleRemoveControllerResponse(PamProto.PAMRemoveControllerResponse response, byte[] gatewayUid)
    {
      if (response?.Controllers == null || response.Controllers.Count == 0)
      {
        return;
      }

      var controller = response.Controllers.FirstOrDefault(x =>
        x.ControllerUid != null && x.ControllerUid.ToByteArray().SequenceEqual(gatewayUid));
      if (controller != null && !string.IsNullOrEmpty(controller.Message))
      {
        throw new InvalidOperationException(controller.Message);
      }
    }
  }
}
