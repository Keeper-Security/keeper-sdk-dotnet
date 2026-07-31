using System.Collections.Generic;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Options for <see cref="LaunchUtils.PrepareAsync"/>.
  /// </summary>
  public class PamLaunchOptions
  {
    /// <summary>Resource UID, title, or search text.</summary>
    public string Record { get; set; }

    /// <summary>pamUser to use as the launch credential.</summary>
    public string Credential { get; set; }

    /// <summary>Gateway UID or name override.</summary>
    public string Gateway { get; set; }

    /// <summary>host:port override. Don't use with <see cref="HostRecord"/>.</summary>
    public string Host { get; set; }

    /// <summary>Record to pull host from (host / pamHostname field).</summary>
    public string HostRecord { get; set; }

    /// <summary>Print resolve steps to the console.</summary>
    public bool Debug { get; set; }

    /// <summary>Cached controllers; used when matching a gateway by name.</summary>
    public IList<PamController> AvailableControllers { get; set; } = new List<PamController>();
  }

  /// <summary>
  /// What preflight resolved for a launch attempt.
  /// </summary>
  public class PamLaunchPrepareResult
  {
    public TypedRecord Record { get; set; }
    public string Protocol { get; set; }
    public string ConfigUid { get; set; }
    public TypedRecord LaunchCredential { get; set; }
    public string Host { get; set; }
    public int? Port { get; set; }
    public string HostSource { get; set; }
    public string GatewayUid { get; set; }
    public string GatewayName { get; set; }
    public bool? GatewayOnline { get; set; }
  }
}
