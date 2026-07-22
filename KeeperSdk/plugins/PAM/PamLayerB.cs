using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Strict by default; legacy graph-sync fallback is opt-in via KEEPER_DAG_LB_FALLBACK=1.
  /// </summary>
  internal static class PamLayerB
  {
    private static readonly ConcurrentDictionary<string, long> FeatureDisabledCache = new();
    private static readonly string[] PermissionDeniedCodes =
    {
      "not_allowed",
      "RRC_NOT_ALLOWED",
      "RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED",
      "RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED",
    };

    internal static bool IsFallbackEnabled()
    {
      var raw = Environment.GetEnvironmentVariable("KEEPER_DAG_LB_FALLBACK")?.Trim().ToLowerInvariant();
      return raw is "1" or "true" or "yes" or "on";
    }

    internal static bool IsFeatureDisabled(string host, string endpoint)
    {
      if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(endpoint))
      {
        return false;
      }

      var ttl = GetFeatureCacheTtlSeconds();
      if (ttl <= 0)
      {
        return false;
      }

      var key = $"{host}|{endpoint}";
      if (!FeatureDisabledCache.TryGetValue(key, out var expiry))
      {
        return false;
      }

      if (expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
      {
        FeatureDisabledCache.TryRemove(key, out _);
        return false;
      }

      return true;
    }

    internal static void MarkFeatureDisabled(string host, string endpoint)
    {
      var ttl = GetFeatureCacheTtlSeconds();
      if (ttl <= 0 || string.IsNullOrEmpty(host) || string.IsNullOrEmpty(endpoint))
      {
        return;
      }

      var key = $"{host}|{endpoint}";
      FeatureDisabledCache[key] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ttl;
    }

    internal static bool ShouldFallbackOnError(Exception ex, string host, string endpoint)
    {
      if (!IsFallbackEnabled())
      {
        return false;
      }

      if (IsHttp404(ex))
      {
        MarkFeatureDisabled(host, endpoint);
        return true;
      }

      if (ex is KeeperApiException keeperEx && IsPermissionDenied(keeperEx.Code))
      {
        return true;
      }

      var message = ex.Message ?? "";
      foreach (var code in PermissionDeniedCodes)
      {
        if (message.IndexOf(code, StringComparison.OrdinalIgnoreCase) >= 0)
        {
          return true;
        }
      }

      return false;
    }

    internal static void TraceFallback(string endpoint, string targetUid, Exception ex)
    {
      Trace.TraceWarning(
        "PAM: {0} denied/unavailable for {1}; falling back to legacy graph write (KEEPER_DAG_LB_FALLBACK enabled): {2}",
        endpoint,
        targetUid,
        ex.Message);
    }

    internal static void TraceNoFallback(string endpoint, Exception ex)
    {
      Trace.TraceError("PAM: {0} failed (no fallback): {1}", endpoint, ex.Message);
    }

    private static bool IsHttp404(Exception ex)
    {
      if (ex is KeeperApiException keeperEx)
      {
        return keeperEx.Message?.IndexOf(": 404", StringComparison.Ordinal) >= 0
               || string.Equals(keeperEx.Code, "404", StringComparison.OrdinalIgnoreCase);
      }

      return ex.Message?.StartsWith("404", StringComparison.Ordinal) == true;
    }

    private static bool IsPermissionDenied(string code)
    {
      if (string.IsNullOrEmpty(code))
      {
        return false;
      }

      foreach (var denied in PermissionDeniedCodes)
      {
        if (string.Equals(code, denied, StringComparison.OrdinalIgnoreCase))
        {
          return true;
        }
      }

      return false;
    }

    private static int GetFeatureCacheTtlSeconds()
    {
      var raw = Environment.GetEnvironmentVariable("KEEPER_DAG_LB_FEATURE_CACHE_TTL")?.Trim() ?? "300";
      return int.TryParse(raw, out var ttl) && ttl > 0 ? ttl : 0;
    }
  }
}
