using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;

namespace Sample.PAMExamples.GatewayExamples
{
    /// <summary>
    /// Shared helpers for PAM Gateway samples.
    /// </summary>
    internal static class PamGatewayHelper
    {
        public static Task<(VaultOnline Vault, PamPlugin Plugin)> PrepareAsync(VaultOnline vault)
        {
            return PamHelper.PrepareAsync(vault);
        }

        public static ApplicationRecord ResolveKsmApplication(VaultOnline vault, string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier))
            {
                throw new ArgumentException("KSM application UID or title is required.", nameof(identifier));
            }

            var trimmed = identifier.Trim();
            var byUid = vault.KeeperRecords.OfType<ApplicationRecord>()
                .FirstOrDefault(x => string.Equals(x.Uid, trimmed, StringComparison.OrdinalIgnoreCase));
            if (byUid != null)
            {
                return byUid;
            }

            var byTitle = vault.KeeperRecords.OfType<ApplicationRecord>()
                .Where(x => string.Equals(x.Title, trimmed, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (byTitle.Count > 1)
            {
                throw new InvalidOperationException(
                    $"KSM application name '{trimmed}' is not unique. Use the application UID.");
            }

            if (byTitle.Count == 0)
            {
                throw new PamApplicationNotFoundException(trimmed);
            }

            return byTitle[0];
        }

        public static PamController ResolveGateway(PamPlugin plugin, string identifier)
        {
            if (plugin == null || string.IsNullOrWhiteSpace(identifier))
            {
                return null;
            }

            var controllers = plugin.Controllers.GetAll().ToList();
            var controller = GatewayUtils.FindGateway(controllers, identifier);
            if (controller != null)
            {
                return controller;
            }

            var trimmed = identifier.Trim();
            var nameMatches = controllers.Count(c =>
                string.Equals(c.ControllerName, trimmed, StringComparison.OrdinalIgnoreCase));
            if (nameMatches > 1)
            {
                throw new PamGatewayAmbiguousException(trimmed);
            }

            return null;
        }

        public static string FormatTimestamp(long timestampMs)
        {
            if (timestampMs <= 0)
            {
                return "";
            }

            return DateTimeOffset.FromUnixTimeMilliseconds(timestampMs).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
        }
    }
}
