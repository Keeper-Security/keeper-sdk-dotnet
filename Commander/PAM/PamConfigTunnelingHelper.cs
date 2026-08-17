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
    public static async Task<Dictionary<string, object>> GetAllowedSettingsJsonAsync(
      IAuthentication auth,
      string configUid)
    {
      var settings = await ConfigUtils.GetConfigurationAllowedSettingsAsync(auth, configUid)
        .ConfigureAwait(false);
      return settings.ToDictionary();
    }

    public static void PrintTunnelingConfig(string configUid)
    {
      // Table detail tunneling print remains a no-op (same as before); JSON -v uses GetAllowedSettingsJsonAsync.
    }
  }
}
