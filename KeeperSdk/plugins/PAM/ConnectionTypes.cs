using System.Collections.Generic;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Options for <see cref="ConnectionUtils.EditConnectionAsync"/>.
  /// </summary>
  public class PamConnectionEditOptions
  {
    /// <summary>PAM resource or configuration record UID / title.</summary>
    public string Record { get; set; }

    /// <summary>PAM Configuration UID or title.</summary>
    public string Configuration { get; set; }

    /// <summary>PAM User used as admin credential on the resource.</summary>
    public string AdminUser { get; set; }

    /// <summary>PAM User used as launch credential on the resource.</summary>
    public string LaunchUser { get; set; }

    /// <summary>Clear the launch credential from the resource.</summary>
    public bool ClearLaunchUser { get; set; }

    /// <summary>Connection protocol (empty string clears when connections are on).</summary>
    public string Protocol { get; set; }

    /// <summary>Tri-state: on / off / default.</summary>
    public string Connections { get; set; }

    /// <summary>Tri-state: on / off / default.</summary>
    public string ConnectionsRecording { get; set; }

    /// <summary>Tri-state: on / off / default.</summary>
    public string TypescriptRecording { get; set; }

    /// <summary>Override connection port. Empty string clears. Null skips.</summary>
    public string ConnectionsOverridePort { get; set; }

    /// <summary>Tri-state: on / off / default (recordingIncludeKeys).</summary>
    public string KeyEvents { get; set; }

    /// <summary>Scrollback size. Empty string clears. Null skips.</summary>
    public string Scrollback { get; set; }

    /// <summary>Rotate launch credentials when the PAM session ends (on/off).</summary>
    public string RotateOnTermination { get; set; }

    /// <summary>Suppress summary output in Commander.</summary>
    public bool Silent { get; set; }
  }

  /// <summary>
  /// Result of a connection edit.
  /// </summary>
  public class PamConnectionEditResult
  {
    public string RecordUid { get; set; }
    public string ConfigUid { get; set; }
    public bool IsConfigurationRecord { get; set; }
    public bool RecordUpdated { get; set; }
    public bool GraphUpdated { get; set; }
    public IList<string> Messages { get; set; } = new List<string>();
  }
}
