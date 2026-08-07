using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Plugins.PAM;

namespace Commander.PAM
{
  /// <summary>
  /// Tunneling / allowedSettings display helpers.
  /// </summary>
  internal static class PamConfigTunnelingHelper
  {
    public static Task<Dictionary<string, object>> GetAllowedSettingsJsonAsync(
      IAuthentication auth,
      string configUid)
    {
      return ConfigUtils.GetConfigurationAllowedSettingsAsync(auth, configUid);
    }

    public static void PrintTunnelingConfig(string configUid)
    {
      // Table detail tunneling print remains a no-op (same as before); JSON -v uses GetAllowedSettingsJsonAsync.
    }
  }
}
