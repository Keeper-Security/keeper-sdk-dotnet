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
    /// <summary>
    /// Resolved PAM resource record for the launch.
    /// </summary>
    public TypedRecord Record { get; set; }

    /// <summary>
    /// Connection protocol resolved for the resource (for example ssh).
    /// </summary>
    public string Protocol { get; set; }

    /// <summary>
    /// PAM configuration UID for the resource, if found.
    /// </summary>
    public string ConfigUid { get; set; }

    /// <summary>
    /// pamUser credential that will be used for launch, if any.
    /// </summary>
    public TypedRecord LaunchCredential { get; set; }

    /// <summary>
    /// Resolved hostname / IP for the session.
    /// </summary>
    public string Host { get; set; }

    /// <summary>
    /// Resolved port for the session, if known.
    /// </summary>
    public int? Port { get; set; }

    /// <summary>
    /// Where the host came from (record, --host, or --host-record).
    /// </summary>
    public string HostSource { get; set; }

    /// <summary>
    /// Gateway controller UID selected for launch.
    /// </summary>
    public string GatewayUid { get; set; }

    /// <summary>
    /// Display name of the selected gateway.
    /// </summary>
    public string GatewayName { get; set; }

    /// <summary>
    /// Whether that gateway is currently connected; null if unknown.
    /// </summary>
    public bool? GatewayOnline { get; set; }
  }
}
