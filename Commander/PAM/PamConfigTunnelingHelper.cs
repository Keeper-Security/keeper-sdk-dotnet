using System.Collections.Generic;

namespace Commander.PAM
{
  /// <summary>
  /// Tunneling / allowedSettings display helpers. DAG read is not available in .NET SDK;
  /// returns empty settings when graph data cannot be loaded.
  /// </summary>
  internal static class PamConfigTunnelingHelper
  {
    public static Dictionary<string, object> GetAllowedSettingsJson(string configUid)
    {
      return new Dictionary<string, object>
      {
        ["connections"] = null,
        ["tunneling"] = null,
        ["rotation"] = null,
        ["remote_browser_isolation"] = null,
        ["connections_recording"] = null,
        ["typescript_recording"] = null,
        ["ai_threat_detection"] = null,
        ["ai_terminate_session_on_detection"] = null,
      };
    }

    public static void PrintTunnelingConfig(string configUid)
    {
      // prints DAG allowedSettings for single-config table list; requires DAG SDK.
    }
  }
}
