using System;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Helpers for detecting API rate limits and deciding how long to wait before retrying.
    /// </summary>
    public static class ThrottleHandling
    {
        /// <summary>How many times to retry after the server says we are rate-limited.</summary>
        public const int MaxThrottleRetries = 3;

        /// <summary>How many times to retry when the server asks us to switch encryption keys.</summary>
        public const int MaxKeyRetries = 3;

        /// <summary>Longest wait allowed between throttle retries (seconds).</summary>
        public const int MaxThrottleWaitSeconds = 300;

        /// <summary>Default wait when the server does not say how long to pause (seconds).</summary>
        public const int DefaultThrottleWaitSeconds = 60;

        /// <summary>Maximum time allowed for a single HTTP request (seconds).</summary>
        public const int DefaultTimeoutSeconds = 300;

        /// <summary>How many commands to send in one batch request.</summary>
        public const int BatchChunkSize = 200;

        private static readonly Regex WaitDurationRegex =
            new Regex(@"(\d+)\s*(second|minute)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Returns true for HTTP 429, or when the API error code is "throttled".
        /// </summary>
        public static bool IsThrottleResponse(HttpStatusCode statusCode, string errorCode)
        {
            return statusCode == (HttpStatusCode) 429
                   || string.Equals(errorCode, "throttled", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Figures out how many seconds to wait after a rate-limit response.
        /// Uses the Retry-After header when present; otherwise reads a duration from the message.
        /// Never waits longer than <see cref="MaxThrottleWaitSeconds"/>.
        /// </summary>
        public static int ParseThrottleWaitSeconds(string message = null, HttpResponseHeaders headers = null)
        {
            if (headers != null)
            {
                var retryAfter = ParseRetryAfter(headers);
                if (retryAfter.HasValue)
                {
                    return Math.Min(retryAfter.Value, MaxThrottleWaitSeconds);
                }
            }

            var waitSeconds = DefaultThrottleWaitSeconds;
            var waitMatch = WaitDurationRegex.Match(message ?? "");
            if (waitMatch.Success)
            {
                var waitVal = int.Parse(waitMatch.Groups[1].Value, CultureInfo.InvariantCulture);
                if (waitMatch.Groups[2].Value.StartsWith("minute", StringComparison.OrdinalIgnoreCase))
                {
                    waitSeconds = waitVal * 60;
                }
                else
                {
                    waitSeconds = waitVal;
                }
            }

            return Math.Min(waitSeconds, MaxThrottleWaitSeconds);
        }

        /// <summary>
        /// Wait time for the next retry. Uses the larger of the server suggestion
        /// and a growing backoff (about 30s, then 60s, then 120s).
        /// </summary>
        public static int ThrottleBackoffSeconds(int throttleRetries, int waitSeconds)
        {
            var attempt = Math.Max(throttleRetries, 1);
            var shift = Math.Min(attempt - 1, 10);
            return Math.Max(waitSeconds, 30 * (1 << shift));
        }

        /// <summary>
        /// Reads Retry-After as a number of seconds or an HTTP date.
        /// </summary>
        internal static int? ParseRetryAfter(HttpResponseHeaders headers)
        {
            if (headers == null)
            {
                return null;
            }

            if (headers.RetryAfter != null)
            {
                if (headers.RetryAfter.Delta.HasValue)
                {
                    return Math.Max((int) headers.RetryAfter.Delta.Value.TotalSeconds, 0);
                }

                if (headers.RetryAfter.Date.HasValue)
                {
                    var seconds = (int) (headers.RetryAfter.Date.Value - DateTimeOffset.UtcNow).TotalSeconds;
                    return Math.Max(seconds, 0);
                }
            }

            if (headers.TryGetValues("Retry-After", out var values))
            {
                foreach (var value in values)
                {
                    var parsed = ParseRetryAfterValue(value);
                    if (parsed.HasValue)
                    {
                        return parsed;
                    }
                }
            }

            return null;
        }

        internal static int? ParseRetryAfterValue(string value)
        {
            value = (value ?? "").Trim();
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
            {
                return Math.Max(seconds, 0);
            }

            if (DateTimeOffset.TryParseExact(
                    value,
                    "r",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var retryAt)
                || DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out retryAt))
            {
                return Math.Max((int) (retryAt - DateTimeOffset.UtcNow).TotalSeconds, 0);
            }

            return null;
        }
    }
}
