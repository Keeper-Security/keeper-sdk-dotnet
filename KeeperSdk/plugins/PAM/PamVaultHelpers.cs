using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Folder display info for PAM configuration list/detail output.
  /// </summary>
  public sealed class PamConfigurationFolderInfo
  {
    public string Uid { get; set; }
    public string Name { get; set; }
    public bool IsNsf { get; set; }
  }

  /// <summary>
  /// Shared vault lookups for PAM rotation and configuration commands.
  /// Resolves classic vault and Nested Shared Folder (NSF) records/folders.
  /// </summary>
  public static class PamVaultHelpers
  {
    public static Dictionary<string, TypedRecord> GetConfigurationRecords(VaultOnline vault)
    {
      if (vault == null)
      {
        return new Dictionary<string, TypedRecord>(StringComparer.Ordinal);
      }

      return EnumerateTypedRecords(vault)
        .Where(x => !string.IsNullOrEmpty(x.Uid))
        .Where(x => PamRecordTypes.Configuration.Contains(x.TypeName ?? ""))
        .GroupBy(x => x.Uid, StringComparer.Ordinal)
        .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
    }

    public static TypedRecord ResolveRecord(VaultOnline vault, string identifier, IEnumerable<string> allowedTypes)
    {
      if (vault == null || string.IsNullOrWhiteSpace(identifier))
      {
        return null;
      }

      var trimmed = identifier.Trim();
      var allowed = allowedTypes == null
        ? null
        : new HashSet<string>(allowedTypes, StringComparer.Ordinal);

      if (TryGetTypedRecord(vault, trimmed, out var typedByUid))
      {
        if (allowed == null || allowed.Contains(typedByUid.TypeName ?? string.Empty))
        {
          return typedByUid;
        }

        return null;
      }

      var matches = EnumerateTypedRecords(vault)
        .Where(x => allowed == null || allowed.Contains(x.TypeName ?? string.Empty))
        .Where(x => string.Equals(x.Title, trimmed, StringComparison.OrdinalIgnoreCase))
        .GroupBy(x => x.Uid, StringComparer.Ordinal)
        .Select(g => g.First())
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

      var classic = PickContainingFolder(FindAllContainingFolders(vault, recordUid), folderUidHint);
      if (!string.IsNullOrEmpty(classic))
      {
        return classic;
      }

      return vault.GetKeeperNSFFoldersForRecord(recordUid).FirstOrDefault();
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

      if (vault != null
          && !vault.TryGetKeeperRecord(recordUid, out _)
          && IsKeeperNSFRecord(vault, recordUid))
      {
        return null;
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
    /// Deletes a PAM configuration record from classic vault or NSF.
    /// </summary>
    public static async Task DeletePamConfigurationRecordAsync(VaultOnline vault, string configurationUid)
    {
      if (vault == null || string.IsNullOrEmpty(configurationUid))
      {
        throw new ArgumentException("Configuration UID is required.", nameof(configurationUid));
      }

      if (IsKeeperNSFRecord(vault, configurationUid))
      {
        var folderUid = vault.GetKeeperNSFFoldersForRecord(configurationUid).FirstOrDefault();
        var result = await vault.RemoveKeeperNSFRecords(
          new[]
          {
            new KeeperNSFRecordRemoval
            {
              RecordUid = configurationUid,
              FolderUid = folderUid,
              Operation = KeeperNSFRecordRemoveOperation.OwnerTrash,
            },
          }).ConfigureAwait(false);

        if (!result.Confirmed)
        {
          throw new InvalidOperationException(
            $"PAM Configuration NSF removal was not confirmed for \"{configurationUid}\".");
        }

        return;
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

    /// <summary>
    /// Returns classic shared folder or NSF folder display info for a PAM configuration.
    /// </summary>
    public static bool TryGetConfigurationFolderInfo(
      VaultOnline vault,
      TypedRecord config,
      out PamConfigurationFolderInfo folderInfo)
    {
      folderInfo = null;
      if (vault == null || config == null || string.IsNullOrEmpty(config.Uid))
      {
        return false;
      }

      var sharedFolder = GetConfigurationSharedFolder(vault, config)
                        ?? FindSharedFolderForRecord(vault, config.Uid);
      if (sharedFolder != null)
      {
        folderInfo = new PamConfigurationFolderInfo
        {
          Uid = sharedFolder.Uid,
          Name = sharedFolder.Name ?? string.Empty,
          IsNsf = false,
        };
        return true;
      }

      var facadeFolderUid = new PamConfigurationFacade(config).FolderUid;
      if (!string.IsNullOrEmpty(facadeFolderUid)
          && vault.TryGetKeeperNSFFolder(facadeFolderUid, out var nsfByFacade)
          && nsfByFacade != null)
      {
        folderInfo = new PamConfigurationFolderInfo
        {
          Uid = nsfByFacade.FolderUid,
          Name = nsfByFacade.Name ?? string.Empty,
          IsNsf = true,
        };
        return true;
      }

      foreach (var nsfFolderUid in vault.GetKeeperNSFFoldersForRecord(config.Uid))
      {
        if (vault.TryGetKeeperNSFFolder(nsfFolderUid, out var nsfFolder) && nsfFolder != null)
        {
          folderInfo = new PamConfigurationFolderInfo
          {
            Uid = nsfFolder.FolderUid,
            Name = nsfFolder.Name ?? string.Empty,
            IsNsf = true,
          };
          return true;
        }
      }

      return false;
    }

    public static bool IsConfigurationInSharedFolder(VaultOnline vault, TypedRecord config)
    {
      return TryGetConfigurationFolderInfo(vault, config, out _);
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
    /// pamResources.folderUid is the top-level shared folder UID, or NSF folder UID.
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

      if (vault.TryGetKeeperNSFFolder(destinationFolderUid, out _))
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
    /// Resolves classic shared folder or NSF folder UID for PAM configuration placement.
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

      if (vault.TryGetKeeperNSFFolder(trimmed, out var nsfByUid) && nsfByUid != null)
      {
        return nsfByUid.FolderUid;
      }

      var nameMatches = vault.SharedFolders
        .Where(sf => string.Equals(sf.Name, trimmed, StringComparison.OrdinalIgnoreCase))
        .ToList();
      if (nameMatches.Count == 1)
      {
        return nameMatches[0].Uid;
      }

      if (vault.TryResolveKeeperNSFFolder(trimmed, out var nsfByName) && nsfByName != null)
      {
        return nsfByName.FolderUid;
      }

      if (vault.TryGetFolder(trimmed, out var folderByUid) && IsPamSharedFolderDestination(folderByUid))
      {
        return folderByUid.FolderUid;
      }

      var folderByPath = new BatchVaultOperations(vault);
      foreach (var path in GetFolderPathVariants(trimmed))
      {
        var node = tryResolveFolderNode?.Invoke(path) ?? folderByPath.GetFolderByPath(path);
        if (node != null && IsPamConfigurationFolderDestination(vault, node))
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

    public static bool IsPamConfigurationFolderDestination(VaultOnline vault, FolderNode folderNode)
    {
      if (IsPamSharedFolderDestination(folderNode))
      {
        return true;
      }

      return vault != null
             && folderNode != null
             && !string.IsNullOrEmpty(folderNode.FolderUid)
             && vault.TryGetKeeperNSFFolder(folderNode.FolderUid, out _);
    }

    public static bool IsKeeperNSFFolder(VaultOnline vault, string folderUid)
    {
      return vault != null
             && !string.IsNullOrEmpty(folderUid)
             && vault.TryGetKeeperNSFFolder(folderUid, out _);
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

    /// <summary>
    /// Places a PAM configuration into a classic shared folder or NSF folder.
    /// </summary>
    public static async Task PlacePamConfigurationInFolderAsync(
      VaultOnline vault,
      TypedRecord record,
      string destinationFolderUid)
    {
      if (vault == null || record == null || string.IsNullOrEmpty(destinationFolderUid))
      {
        return;
      }

      if (IsKeeperNSFFolder(vault, destinationFolderUid))
      {
        if (IsKeeperNSFRecord(vault, record.Uid))
        {
          var currentFolders = vault.GetKeeperNSFFoldersForRecord(record.Uid).ToList();
          if (currentFolders.Any(x => string.Equals(x, destinationFolderUid, StringComparison.Ordinal)))
          {
            return;
          }

          await vault.LinkKeeperNSFRecordToFolder(record.Uid, destinationFolderUid).ConfigureAwait(false);
          return;
        }

        throw new InvalidOperationException(
          "Cannot move a classic PAM configuration into an NSF folder. Create the configuration in the NSF folder.");
      }

      vault.CacheKeeperRecord(record);
      var sourceFolderUid = ResolveRecordSourceFolderUid(vault, record.Uid);
      if (sourceFolderUid == null)
      {
        throw new VaultException("Cannot move PAM configuration: record is not initialized.");
      }

      if (string.Equals(sourceFolderUid, destinationFolderUid, StringComparison.Ordinal))
      {
        return;
      }

      await vault.MoveRecordToFolder(
        new RecordPath { RecordUid = record.Uid, FolderUid = sourceFolderUid },
        destinationFolderUid).ConfigureAwait(false);
    }

    public static bool TryGetUserRecord(VaultOnline vault, string recordUid, out TypedRecord record)
    {
      record = ResolveRecord(vault, recordUid, new[] { "pamUser" });
      return record != null;
    }

    /// <summary>
    /// Resolves a classic or NSF folder by UID or unique name.
    /// </summary>
    public static bool TryResolveFolder(VaultOnline vault, string identifier, out FolderNode folder)
    {
      folder = null;
      if (vault == null || string.IsNullOrWhiteSpace(identifier))
      {
        return false;
      }

      var trimmed = identifier.Trim();
      if (vault.TryGetFolder(trimmed, out folder) && folder != null)
      {
        return true;
      }

      return vault.TryResolveKeeperNSFFolder(trimmed, out folder) && folder != null;
    }

    /// <summary>
    /// Looks up a folder node in classic or NSF trees by UID.
    /// </summary>
    public static bool TryGetFolderNode(VaultOnline vault, string folderUid, out FolderNode folder)
    {
      folder = null;
      if (vault == null || string.IsNullOrEmpty(folderUid))
      {
        return false;
      }

      if (vault.TryGetFolder(folderUid, out folder) && folder != null)
      {
        return true;
      }

      return vault.TryGetKeeperNSFFolder(folderUid, out folder) && folder != null;
    }

    public static bool IsKeeperNSFRecord(VaultOnline vault, string recordUid)
    {
      return vault != null
             && !string.IsNullOrEmpty(recordUid)
             && vault.TryGetKeeperNSFRecord(recordUid, out _);
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
             || vault.TryLoadKeeperRecord(recordUid, out _)
             || IsKeeperNSFRecord(vault, recordUid);
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

    private static IEnumerable<TypedRecord> EnumerateTypedRecords(VaultOnline vault)
    {
      var seen = new HashSet<string>(StringComparer.Ordinal);

      foreach (var record in vault.KeeperRecords?.OfType<TypedRecord>() ?? Enumerable.Empty<TypedRecord>())
      {
        if (!string.IsNullOrEmpty(record.Uid) && seen.Add(record.Uid))
        {
          yield return record;
        }
      }

      foreach (var nsf in vault.KeeperNSFRecordEntries ?? Enumerable.Empty<KeeperNSFRecord>())
      {
        if (!VaultExtensions.TryConvertKeeperNSFRecordToTypedRecord(nsf, out var typed)
            || typed == null
            || string.IsNullOrEmpty(typed.Uid)
            || !seen.Add(typed.Uid))
        {
          continue;
        }

        yield return typed;
      }
    }

    /// <summary>
    /// Resolve a typed vault record by UID, loading from storage when it is not yet decrypted in memory.
    /// </summary>
    public static bool TryGetTypedRecord(VaultOnline vault, string recordUid, out TypedRecord record)
    {
      record = null;
      if (vault == null || string.IsNullOrEmpty(recordUid))
      {
        return false;
      }

      if (vault.TryGetKeeperRecord(recordUid, out var keeper))
      {
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
      }

      if (vault.TryGetKeeperNSFRecord(recordUid, out var nsf)
          && VaultExtensions.TryConvertKeeperNSFRecordToTypedRecord(nsf, out record)
          && record != null)
      {
        return true;
      }

      // Fallback: scan in case dictionary lookup missed a matching UID.
      record = vault.KeeperRecords?
        .OfType<TypedRecord>()
        .Where(x => !string.IsNullOrEmpty(x.Uid))
        .FirstOrDefault(x => string.Equals(x.Uid, recordUid, StringComparison.Ordinal));
      return record != null;
    }

    /// <summary>
    /// Read the <c>pamResources</c> field from a PAM configuration record by UID.
    /// </summary>
    public static bool TryGetPamResources(VaultOnline vault, string configUid, out FieldPamResources resources)
    {
      resources = null;
      if (vault == null || string.IsNullOrEmpty(configUid))
      {
        return false;
      }

      if (!TryGetTypedRecord(vault, configUid, out var config))
      {
        return false;
      }

      return TryGetPamResources(config, out resources);
    }

    /// <summary>
    /// Read the <c>pamResources</c> field from an already-resolved configuration record.
    /// </summary>
    public static bool TryGetPamResources(TypedRecord record, out FieldPamResources resources)
    {
      resources = null;
      if (record == null || !record.FindTypedField("pamResources", null, out var field))
      {
        return false;
      }

      if (field is TypedField<FieldPamResources> typed && typed.Values.Count > 0)
      {
        resources = typed.Values[0];
        return resources != null;
      }

      if (field.ObjectValue is FieldPamResources pam)
      {
        resources = pam;
        return true;
      }

      return false;
    }
  }
}
