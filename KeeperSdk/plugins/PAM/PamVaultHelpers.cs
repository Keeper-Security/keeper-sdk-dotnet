using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Shared vault lookups for PAM rotation and configuration commands.
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
      if (vault == null || string.IsNullOrWhiteSpace(identifier))
      {
        return null;
      }

      if (TryGetTypedRecord(vault, identifier, out var typedByUid))
      {
        if (allowedTypes == null || allowedTypes.Contains(typedByUid.TypeName ?? string.Empty))
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
        .Where(x => allowed == null || allowed.Contains(x.TypeName ?? string.Empty))
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

    public static SharedFolder FindSharedFolderForRecord(VaultOnline vault, string recordUid, string folderUidHint = null)
    {
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        return null;
      }

      if (!string.IsNullOrEmpty(folderUidHint)
          && vault.TryGetSharedFolder(folderUidHint, out var hinted)
          && hinted.RecordPermissions.Any(x => x.RecordUid == recordUid))
      {
        return hinted;
      }

      return vault.SharedFolders.FirstOrDefault(sf =>
        sf.RecordPermissions.Any(x => x.RecordUid == recordUid));
    }

    public static string FindRecordFolderUid(VaultOnline vault, string recordUid, string folderUidHint = null)
    {
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        return null;
      }

      var treeFound = FindInFolder(vault, vault.RootFolder, recordUid);
      if (!string.IsNullOrEmpty(treeFound))
      {
        return treeFound;
      }

      return PickContainingFolder(FindAllContainingFolders(vault, recordUid), folderUidHint);
    }

    /// <summary>
    /// Resolves the source folder for moving a record. Records in the vault cache with no folder
    /// links fall back to the vault root.
    /// </summary>
    public static string ResolveRecordSourceFolderUid(VaultOnline vault, string recordUid)
    {
      var folderUid = FindRecordFolderUid(vault, recordUid);
      if (!string.IsNullOrEmpty(folderUid))
      {
        return folderUid;
      }

      return vault != null && vault.TryGetKeeperRecord(recordUid, out _)
        ? vault.RootFolder.FolderUid
        : null;
    }

    /// <summary>
    /// Resolves the folder UID for deleting a record. Falls back to root_folder
    /// when a record exists in record_cache but has no folder link, and shared-folder permission
    /// lookup when pamResources.folderUid is available.
    /// </summary>
    public static string ResolveRecordDeleteFolderUid(VaultOnline vault, string recordUid, string folderUidHint = null)
    {
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        return null;
      }

      var folderUid = FindRecordFolderUid(vault, recordUid, folderUidHint);
      if (!string.IsNullOrEmpty(folderUid))
      {
        return folderUid;
      }

      var sharedFolder = FindSharedFolderForRecord(vault, recordUid, folderUidHint);
      if (sharedFolder != null)
      {
        if (vault.TryGetFolder(sharedFolder.Uid, out var sfFolder))
        {
          return sfFolder.FolderUid;
        }

        return sharedFolder.Uid;
      }

      return ResolveRecordSourceFolderUid(vault, recordUid);
    }

    /// <summary>
    /// Finds shared folders that contain the record via folder links.
    /// </summary>
    public static IList<SharedFolder> FindParentTopSharedFolders(VaultOnline vault, string recordUid)
    {
      var sharedFolders = new List<SharedFolder>();
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        return sharedFolders;
      }

      var seen = new HashSet<string>(StringComparer.Ordinal);
      foreach (var folder in FindAllContainingFolders(vault, recordUid))
      {
        SharedFolder sharedFolder = null;
        if (folder.FolderType == FolderType.SharedFolder)
        {
          vault.TryGetSharedFolder(folder.FolderUid, out sharedFolder);
        }
        else if (folder.FolderType == FolderType.SharedFolderFolder
                 && !string.IsNullOrEmpty(folder.SharedFolderUid))
        {
          vault.TryGetSharedFolder(folder.SharedFolderUid, out sharedFolder);
        }

        if (sharedFolder != null && seen.Add(sharedFolder.Uid))
        {
          sharedFolders.Add(sharedFolder);
        }
      }

      return sharedFolders;
    }

    /// <summary>
    /// Deletes a PAM configuration record. Falls back to root_folder.
    /// RecordRemoveCommand(record=uid, force=True).
    /// </summary>
    public static async Task DeletePamConfigurationRecordAsync(VaultOnline vault, string configurationUid)
    {
      if (vault == null || string.IsNullOrEmpty(configurationUid))
      {
        throw new ArgumentException("Configuration UID is required.", nameof(configurationUid));
      }

      if (!EnsureKeeperRecordLoaded(vault, configurationUid))
      {
        throw new InvalidOperationException($"Configuration \"{configurationUid}\" not found");
      }

      var paths = BuildRecordRemovePaths(vault, configurationUid);
      if (paths.Count == 0)
      {
        throw new InvalidOperationException($"Could not resolve folder for configuration \"{configurationUid}\"");
      }

      await vault.DeleteVaultObjects(paths, forceDelete: true);
    }

    /// <summary>
    /// Deletes a vault record. Falls back to root_folder.
    /// </summary>
    public static async Task DeleteRecordAsync(
      VaultOnline vault,
      string recordUid,
      bool forceDelete = false)
    {
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        throw new ArgumentException("Record UID is required.", nameof(recordUid));
      }

      if (!EnsureKeeperRecordLoaded(vault, recordUid))
      {
        throw new InvalidOperationException($"Record \"{recordUid}\" not found");
      }

      var paths = BuildRecordRemovePaths(vault, recordUid);
      if (paths.Count == 0)
      {
        throw new InvalidOperationException($"Could not resolve folder for record \"{recordUid}\"");
      }

      await vault.DeleteVaultObjects(paths, forceDelete);
    }

    public static SharedFolder GetConfigurationSharedFolder(VaultOnline vault, TypedRecord config)
    {
      if (vault == null || config == null)
      {
        return null;
      }

      return FindParentTopSharedFolders(vault, config.Uid).FirstOrDefault();
    }

    public static bool IsConfigurationInSharedFolder(VaultOnline vault, TypedRecord config)
    {
      return GetConfigurationSharedFolder(vault, config) != null;
    }

    public static void WarnConfigurationNotInSharedFolder(TypedRecord config)
    {
      if (config == null)
      {
        return;
      }

      Console.WriteLine(
        $"Warning: Following configuration is not in the shared folder: UID: {config.Uid}, Title: {config.Title}");
    }

    /// <summary>
    /// pamResources.folderUid is the top-level shared folder UID.
    /// </summary>
    public static string ResolvePamResourcesFolderUid(VaultOnline vault, string destinationFolderUid)
    {
      if (vault == null || string.IsNullOrEmpty(destinationFolderUid))
      {
        return null;
      }

      if (vault.TryGetSharedFolder(destinationFolderUid, out _))
      {
        return destinationFolderUid;
      }

      if (vault.TryGetFolder(destinationFolderUid, out var folderNode))
      {
        return ResolveSharedFolderUid(vault, folderNode) ?? destinationFolderUid;
      }

      return destinationFolderUid;
    }

    /// <summary>
    /// Resolves the destination folder UID for pamResources.folderUid.
    /// </summary>
    public static string ResolvePamConfigurationFolderUid(
      VaultOnline vault,
      string identifier,
      Func<string, FolderNode> tryResolveFolderNode = null)
    {
      if (vault == null || string.IsNullOrWhiteSpace(identifier))
      {
        return null;
      }

      var trimmed = identifier.Trim();
      if (vault.TryGetSharedFolder(trimmed, out _))
      {
        return trimmed;
      }

      var nameMatches = vault.SharedFolders
        .Where(sf => string.Equals(sf.Name, trimmed, StringComparison.OrdinalIgnoreCase))
        .ToList();
      if (nameMatches.Count == 1)
      {
        return nameMatches[0].Uid;
      }

      if (vault.TryGetFolder(trimmed, out var folderByUid) && IsPamSharedFolderDestination(folderByUid))
      {
        return folderByUid.FolderUid;
      }

      var folderByPath = new BatchVaultOperations(vault);
      foreach (var path in GetFolderPathVariants(trimmed))
      {
        var node = tryResolveFolderNode?.Invoke(path) ?? folderByPath.GetFolderByPath(path);
        if (node != null && IsPamSharedFolderDestination(node))
        {
          return node.FolderUid;
        }
      }

      return null;
    }

    public static bool IsPamSharedFolderDestination(FolderNode folderNode)
    {
      return folderNode != null
             && folderNode.FolderType is FolderType.SharedFolder or FolderType.SharedFolderFolder;
    }

    public static string ResolveSharedFolderUid(VaultOnline vault, FolderNode folderNode)
    {
      if (vault == null || folderNode == null)
      {
        return null;
      }

      if (folderNode.FolderType == FolderType.SharedFolder)
      {
        return folderNode.FolderUid;
      }

      if (!string.IsNullOrEmpty(folderNode.SharedFolderUid))
      {
        return folderNode.SharedFolderUid;
      }

      return null;
    }

    private static IEnumerable<string> GetFolderPathVariants(string path)
    {
      yield return path;

      var backslashPath = path.Replace('/', BatchVaultOperations.PathDelimiter);
      if (!string.Equals(backslashPath, path, StringComparison.Ordinal))
      {
        yield return backslashPath;
      }

      if (!path.StartsWith("/") && !path.StartsWith("\\"))
      {
        yield return "/" + path;
        yield return BatchVaultOperations.PathDelimiter + backslashPath.TrimStart(BatchVaultOperations.PathDelimiter);
      }
    }

    private static List<RecordPath> BuildRecordRemovePaths(VaultOnline vault, string recordUid)
    {
      var containingFolders = FindAllContainingFolders(vault, recordUid);
      if (containingFolders.Count > 0)
      {
        return containingFolders
          .Select(f => new RecordPath { RecordUid = recordUid, FolderUid = f.FolderUid })
          .ToList();
      }

      if (EnsureKeeperRecordLoaded(vault, recordUid))
      {
        return new List<RecordPath>
        {
          new RecordPath { RecordUid = recordUid, FolderUid = vault.RootFolder.FolderUid },
        };
      }

      return new List<RecordPath>();
    }

    private static bool EnsureKeeperRecordLoaded(VaultOnline vault, string recordUid)
    {
      return vault.TryGetKeeperRecord(recordUid, out _)
             || vault.TryLoadKeeperRecord(recordUid, out _);
    }

    private static List<FolderNode> FindAllContainingFolders(VaultOnline vault, string recordUid)
    {
      return Enumerable.Repeat(vault.RootFolder, 1)
        .Concat(vault.Folders)
        .Where(f => f.Records != null && f.Records.Contains(recordUid))
        .ToList();
    }

    private static string PickContainingFolder(IReadOnlyList<FolderNode> containingFolders, string folderUidHint)
    {
      if (containingFolders == null || containingFolders.Count == 0)
      {
        return null;
      }

      if (containingFolders.Count == 1)
      {
        return containingFolders[0].FolderUid;
      }

      if (!string.IsNullOrEmpty(folderUidHint))
      {
        var hinted = containingFolders.FirstOrDefault(f =>
          string.Equals(f.FolderUid, folderUidHint, StringComparison.Ordinal)
          || string.Equals(f.SharedFolderUid, folderUidHint, StringComparison.Ordinal));
        if (hinted != null)
        {
          return hinted.FolderUid;
        }
      }

      return (containingFolders.FirstOrDefault(f => f.FolderType == FolderType.UserFolder)
              ?? containingFolders[0]).FolderUid;
    }

    private static string FindInFolder(VaultOnline vault, FolderNode folder, string recordUid)
    {
      if (folder.Records.Contains(recordUid))
      {
        return folder.FolderUid;
      }

      foreach (var subUid in folder.Subfolders)
      {
        if (!vault.TryGetFolder(subUid, out var subFolder))
        {
          continue;
        }

        var found = FindInFolder(vault, subFolder, recordUid);
        if (!string.IsNullOrEmpty(found))
        {
          return found;
        }
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
