using System;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Shared vault lookups for PAM record rotation commands.
  /// </summary>
  public static class PamVaultHelpers
  {
    public static Dictionary<string, TypedRecord> GetConfigurationRecords(VaultOnline vault)
    {
      if (vault == null)
      {
        return new Dictionary<string, TypedRecord>();
      }

      return vault.KeeperRecords
        .OfType<TypedRecord>()
        .Where(x => PamRecordTypes.Configuration.Contains(x.TypeName ?? ""))
        .ToDictionary(x => x.Uid, x => x);
    }

    public static TypedRecord ResolveRecord(VaultOnline vault, string identifier, IEnumerable<string> allowedTypes)
    {
      if (vault == null || string.IsNullOrEmpty(identifier))
      {
        return null;
      }

      if (TryGetTypedRecord(vault, identifier, out var typedByUid))
      {
        if (allowedTypes == null || allowedTypes.Contains(typedByUid.TypeName ?? ""))
        {
          return typedByUid;
        }

        return null;
      }

      var allowed = allowedTypes == null
        ? null
        : new HashSet<string>(allowedTypes, StringComparer.Ordinal);
      var matches = vault.KeeperRecords
        .OfType<TypedRecord>()
        .Where(x => allowed == null || allowed.Contains(x.TypeName ?? ""))
        .Where(x => string.Equals(x.Title, identifier, StringComparison.OrdinalIgnoreCase))
        .ToList();

      if (matches.Count == 1)
      {
        return matches[0];
      }

      if (matches.Count > 1)
      {
        throw new InvalidOperationException($"Record name '{identifier}' is not unique. Use record UID.");
      }

      return null;
    }

    private static bool TryGetTypedRecord(VaultOnline vault, string recordUid, out TypedRecord record)
    {
      record = null;
      if (!vault.TryGetKeeperRecord(recordUid, out var keeper))
      {
        return false;
      }

      if (keeper is TypedRecord typed)
      {
        record = typed;
        return true;
      }

      if (vault.TryLoadKeeperRecord(recordUid, out keeper) && keeper is TypedRecord loaded)
      {
        record = loaded;
        return true;
      }

      return false;
    }

    public static bool TryGetUserRecord(VaultOnline vault, string recordUid, out TypedRecord record)
    {
      record = ResolveRecord(vault, recordUid, new[] { "pamUser" });
      return record != null;
    }
  }
}
