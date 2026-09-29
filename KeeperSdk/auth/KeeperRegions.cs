using System;
using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Maps Keeper region codes (like "EU") to real server hostnames (like "keepersecurity.eu").
    /// Commander and PowerCommander both use this so region names only need to be listed once.
    /// </summary>
    public static class KeeperRegions
    {
        /// <summary>
        /// Every known region code and its hostname, covering production, dev, and QA.
        /// </summary>
        public static readonly IReadOnlyDictionary<string, string> Servers =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // Production
                { "US", "keepersecurity.com" },
                { "EU", "keepersecurity.eu" },
                { "AU", "keepersecurity.com.au" },
                { "CA", "keepersecurity.ca" },
                { "JP", "keepersecurity.jp" },
                { "GOV", "govcloud.keepersecurity.us" },
                // Dev environments
                { "US_DEV", "dev.keepersecurity.com" },
                { "EU_DEV", "dev.keepersecurity.eu" },
                { "AU_DEV", "dev.keepersecurity.com.au" },
                { "CA_DEV", "dev.keepersecurity.ca" },
                { "JP_DEV", "dev.keepersecurity.jp" },
                { "GOV_DEV", "govcloud.dev.keepersecurity.us" },
                // QA environments
                { "US_QA", "qa.keepersecurity.com" },
                { "EU_QA", "qa.keepersecurity.eu" },
                { "AU_QA", "qa.keepersecurity.com.au" },
                { "CA_QA", "qa.keepersecurity.ca" },
                { "JP_QA", "qa.keepersecurity.jp" },
                { "GOV_QA", "govcloud.qa.keepersecurity.us" },
            };

        /// <summary>
        /// Turns a region code (e.g. "eu") or a real hostname into the hostname to connect to.
        /// Returns <c>null</c> if <paramref name="input"/> is empty or isn't recognized.
        /// </summary>
        public static string ResolveServer(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;

            var trimmed = input.Trim();
            if (Servers.TryGetValue(trimmed, out var host)) return host;

            return Servers.Values.FirstOrDefault(h => string.Equals(h, trimmed, StringComparison.OrdinalIgnoreCase))
                   ?.ToLowerInvariant();
        }
    }
}
