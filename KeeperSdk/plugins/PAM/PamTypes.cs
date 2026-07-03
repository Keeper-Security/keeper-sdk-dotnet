using System.Collections.Generic;
using Enterprise;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Plugins.PAM
{
  public static class PamGatewayStatus
  {
    public const string Unknown = "UNKNOWN";
    public const string Online = "ONLINE";
    public const string Offline = "OFFLINE";
    public const string OnlineMultipleInstancesFormat = "ONLINE ({0} instances)";
  }

  public class PamController : IUid
  {
    public string ControllerUid { get; set; }
    public string ControllerName { get; set; }
    public string DeviceToken { get; set; }
    public string DeviceName { get; set; }
    public long NodeId { get; set; }
    public long Created { get; set; }
    public long LastModified { get; set; }
    public string ApplicationUid { get; set; } = "";
    public AppClientType AppClientType { get; set; }
    public bool IsInitialized { get; set; }

    public string Uid => ControllerUid;
  }

  public class PamGatewaySystemInfo
  {
    public string Os { get; set; } = "";
    public string OsRelease { get; set; } = "";
    public string MachineType { get; set; } = "";
    public string OsVersion { get; set; } = "";
  }

  public class PamGatewayVersionInfo
  {
    public string GatewayVersion { get; set; } = "";
    public PamGatewaySystemInfo SystemInfo { get; set; } = new PamGatewaySystemInfo();
  }

  public class PamGatewayOnlineInstance
  {
    public string IpAddress { get; set; } = "";
    public string Version { get; set; } = "";
    public long ConnectedOn { get; set; }
    public PamGatewaySystemInfo SystemInfo { get; set; } = new PamGatewaySystemInfo();
  }

  public class PamGatewaySummary
  {
    public PamController Controller { get; set; }
    public string Status { get; set; } = PamGatewayStatus.Offline;
    public int OnlineInstanceCount { get; set; }
    public string GatewayVersion { get; set; } = "";
    public PamGatewaySystemInfo SystemInfo { get; set; } = new PamGatewaySystemInfo();
    public string KsmAppName { get; set; } = "";
    public string KsmAppUid { get; set; } = "";
    public bool KsmAppAccessible { get; set; }
    public IList<PamGatewayOnlineInstance> OnlineInstances { get; set; } = new List<PamGatewayOnlineInstance>();
  }

  /// <summary>
  /// Vault record rotation metadata exposed by <see cref="PamPlugin"/>.
  /// </summary>
  public class PamRecordRotationInfo : IUid
  {
    public string RecordUid { get; set; } = "";
    public long Revision { get; set; }
    public string ConfigurationUid { get; set; } = "";
    public string Schedule { get; set; } = "";
    public byte[] PwdComplexity { get; set; } = System.Array.Empty<byte>();
    public bool Disabled { get; set; }
    public string ResourceUid { get; set; } = "";
    public long LastRotation { get; set; }
    public int LastRotationStatus { get; set; }

    public string Uid => RecordUid;
  }
}
