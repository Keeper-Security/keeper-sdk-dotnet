using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;
using RouterProto = Router;

namespace KeeperSecurity.Plugins.PAM
{
  public static class PamConfigTypes
  {
    public const string EnvironmentLocal = "local";
    public const string EnvironmentNetwork = "network";
    public const string EnvironmentAws = "aws";
    public const string EnvironmentAzure = "azure";
    public const string EnvironmentGcp = "gcp";
    public const string EnvironmentDomain = "domain";
    public const string EnvironmentOci = "oci";
    public const string EnvironmentGithub = "github";

    private static readonly Dictionary<string, string> ConfigTypeToRecordType =
      new(StringComparer.OrdinalIgnoreCase)
      {
        [EnvironmentAws] = "pamAwsConfiguration",
        [EnvironmentAzure] = "pamAzureConfiguration",
        [EnvironmentLocal] = "pamNetworkConfiguration",
        [EnvironmentNetwork] = "pamNetworkConfiguration",
        [EnvironmentGcp] = "pamGcpConfiguration",
        [EnvironmentDomain] = "pamDomainConfiguration",
        [EnvironmentOci] = "pamOciConfiguration",
        [EnvironmentGithub] = "pamGitHubConfiguration",
      };

    private static readonly Dictionary<string, string> ComingSoonEnvironments =
      new(StringComparer.OrdinalIgnoreCase)
      {
        [EnvironmentOci] = "OCI",
        [EnvironmentGithub] = "GitHub",
      };

    public static bool TryResolveRecordType(string configType, out string recordType)
    {
      recordType = null;
      if (string.IsNullOrWhiteSpace(configType))
      {
        return false;
      }

      return ConfigTypeToRecordType.TryGetValue(configType.Trim(), out recordType);
    }

    public static bool IsComingSoonEnvironment(string configType, out string displayName)
    {
      displayName = null;
      if (string.IsNullOrWhiteSpace(configType))
      {
        return false;
      }

      return ComingSoonEnvironments.TryGetValue(configType.Trim(), out displayName);
    }

    public static string GetSupportedConfigTypes()
    {
      return string.Join(", ", ConfigTypeToRecordType.Keys);
    }
  }

  public enum PamTriStateSetting
  {
    On,
    Off,
    Default,
  }

  public static class ConfigUtils
  {
    private const string AddConfigurationRecordEndpoint = "pam/add_configuration_record";
    private const string AddPamConfigurationNsfEndpoint = "vault/records/v3/add_pam_configuration";
    private const string SetConfigurationControllerEndpoint = "pam/set_configuration_controller";

    /// <summary>Record version used for PAM configuration typed records.</summary>
    private const int PamConfigurationRecordVersion = 6;

    private const int MaxPamConfigurationNsfAddBatchSize = 1000;

    public static TypedRecord CreateConfigurationRecord(VaultOnline vault, string recordType, string title)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (string.IsNullOrWhiteSpace(recordType))
      {
        throw new ArgumentException("Record type is required", nameof(recordType));
      }

      if (string.IsNullOrWhiteSpace(title))
      {
        throw new ArgumentException("Title is required", nameof(title));
      }

      var record = new TypedRecord(recordType)
      {
        Title = title.Trim(),
        Version = PamConfigurationRecordVersion,
      };
      vault.AdjustTypedRecord(record);
      return record;
    }

    /// <summary>
    /// Adds a PAM configuration record to the classic vault root via <c>pam/add_configuration_record</c>.
    /// </summary>
    public static async Task AddConfigurationRecordAsync(VaultOnline vault, TypedRecord record)
    {
      await AddConfigurationRecordAsync(vault, record, destinationFolderUid: null).ConfigureAwait(false);
    }

    /// <summary>
    /// Adds a PAM configuration record. When <paramref name="destinationFolderUid"/> is an NSF folder,
    /// creates the record with <c>vault/records/v3/add_pam_configuration</c>; otherwise uses the classic
    /// <c>pam/add_configuration_record</c> endpoint.
    /// </summary>
    public static async Task AddConfigurationRecordAsync(
      VaultOnline vault,
      TypedRecord record,
      string destinationFolderUid)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (record == null)
      {
        throw new ArgumentNullException(nameof(record));
      }

      await AddConfigurationRecordsAsync(
          vault,
          new[] { (record, destinationFolderUid) }).ConfigureAwait(false);
    }

    /// <summary>
    /// Adds one or more PAM configuration records. NSF destinations are batched on
    /// <c>vault/records/v3/add_pam_configuration</c>; classic destinations are added one at a time.
    /// </summary>
    public static async Task AddConfigurationRecordsAsync(
      VaultOnline vault,
      IReadOnlyList<(TypedRecord Record, string DestinationFolderUid)> records)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (records == null || records.Count == 0)
      {
        throw new ArgumentException("At least one configuration record is required.", nameof(records));
      }

      var nsfBatch = new List<(TypedRecord Record, string FolderUid, FolderNode Folder)>();
      foreach (var item in records)
      {
        if (item.Record == null)
        {
          throw new ArgumentException("Configuration record cannot be null.", nameof(records));
        }

        EnsureConfigurationRecordIdentity(item.Record);

        if (PamVaultHelpers.IsKeeperNSFFolder(vault, item.DestinationFolderUid))
        {
          if (!vault.TryGetKeeperNSFFolder(item.DestinationFolderUid, out var folder) || folder == null)
          {
            throw new VaultException($"Keeper NSF folder '{item.DestinationFolderUid}' not found");
          }

          if (folder.FolderKey == null || folder.FolderKey.Length == 0)
          {
            throw new VaultException($"Folder key not available for folder '{item.DestinationFolderUid}'");
          }

          nsfBatch.Add((item.Record, item.DestinationFolderUid, folder));
          continue;
        }

        await AddClassicConfigurationRecordAsync(vault, item.Record).ConfigureAwait(false);
      }

      if (nsfBatch.Count == 0)
      {
        return;
      }

      var folderUids = nsfBatch.Select(x => x.FolderUid).Distinct(StringComparer.Ordinal).ToList();
      foreach (var folderUid in folderUids)
      {
        await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(vault, folderUid)
          .ConfigureAwait(false);
      }

      for (var offset = 0; offset < nsfBatch.Count; offset += MaxPamConfigurationNsfAddBatchSize)
      {
        var chunk = nsfBatch.Skip(offset).Take(MaxPamConfigurationNsfAddBatchSize).ToList();
        await AddPamConfigurationsToNsfBatchAsync(vault, chunk).ConfigureAwait(false);
      }
    }

    private static void EnsureConfigurationRecordIdentity(TypedRecord record)
    {
      if (string.IsNullOrEmpty(record.Uid))
      {
        record.Uid = CryptoUtils.GenerateUid();
      }

      if (record.RecordKey == null || record.RecordKey.Length == 0)
      {
        record.RecordKey = CryptoUtils.GenerateEncryptionKey();
      }
    }

    private static async Task AddClassicConfigurationRecordAsync(VaultOnline vault, TypedRecord record)
    {
      record.Version = PamConfigurationRecordVersion;
      vault.AdjustTypedRecord(record);
      var recordData = record.ExtractRecordV3Data();
      var jsonData = JsonUtils.DumpJson(recordData);
      jsonData = VaultExtensions.PadRecordData(jsonData);

      var request = new PamProto.ConfigurationAddRequest
      {
        ConfigurationUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
        RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(record.RecordKey, vault.Auth.AuthContext.DataKey)),
        Data = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(jsonData, record.RecordKey)),
      };

      await vault.Auth.ExecuteAuthRest(AddConfigurationRecordEndpoint, request);
      vault.CacheKeeperRecord(record);
    }

    /// <summary>
    /// Creates PAM configuration records inside NSF folders and registers PAM config context.
    /// </summary>
    private static async Task AddPamConfigurationsToNsfBatchAsync(
      VaultOnline vault,
      IReadOnlyList<(TypedRecord Record, string FolderUid, FolderNode Folder)> batch)
    {
      var items = new List<(TypedRecord Record, FolderNode Folder)>(batch.Count);
      foreach (var item in batch)
      {
        item.Record.Version = PamConfigurationRecordVersion;
        items.Add((item.Record, item.Folder));
      }

      var results = await VaultOnlineFunctions.ExecuteNsfTypedRecordsAddAsync(
        vault, AddPamConfigurationNsfEndpoint, items).ConfigureAwait(false);

      foreach (var result in results)
      {
        if (!result.Success)
        {
          throw new VaultException(string.IsNullOrEmpty(result.Message)
            ? $"Failed to create NSF PAM configuration: {result.Status ?? "unknown error"}"
            : $"Failed to create NSF PAM configuration: {result.Message}");
        }
      }
    }

    public static async Task SetConfigurationGatewayAsync(
      IAuthentication auth,
      string configurationUid,
      string gatewayUid)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      if (string.IsNullOrEmpty(configurationUid) || string.IsNullOrEmpty(gatewayUid))
      {
        return;
      }

      var request = new PamProto.PAMConfigurationController
      {
        ConfigurationUid = ByteString.CopyFrom(configurationUid.Base64UrlDecode()),
        ControllerUid = ByteString.CopyFrom(gatewayUid.Base64UrlDecode()),
      };

      await auth.ExecuteAuthRest(SetConfigurationControllerEndpoint, request);
    }

    public static async Task RemovePamConfigurationAsync(VaultOnline vault, string configurationUid)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (string.IsNullOrEmpty(configurationUid))
      {
        throw new ArgumentException("Configuration UID is required", nameof(configurationUid));
      }

      await PamVaultHelpers.DeletePamConfigurationRecordAsync(vault, configurationUid);
    }

    public static async Task EnsureConfigurationNetworkGraphAsync(
      IAuthentication auth,
      string configurationUid)
    {
      if (auth == null || string.IsNullOrEmpty(configurationUid))
      {
        return;
      }

      var request = new RouterProto.PAMNetworkConfigurationRequest
      {
        RecordUid = ByteString.CopyFrom(configurationUid.Base64UrlDecode()),
        NetworkSettings = new RouterProto.PAMNetworkSettings
        {
          AllowedSettings = ByteString.CopyFrom(System.Text.Encoding.UTF8.GetBytes("{}")),
        },
      };

      await RouterUtils.ConfigureNetworkGraphAsync(auth, request);
    }

    public static async Task ConfigureTunnelingAsync(
      IAuthentication auth,
      string configurationUid,
      PamTriStateSetting? connections = null,
      PamTriStateSetting? tunneling = null,
      PamTriStateSetting? rotation = null,
      PamTriStateSetting? sessionRecording = null,
      PamTriStateSetting? typescriptRecording = null,
      PamTriStateSetting? remoteBrowserIsolation = null,
      PamTriStateSetting? aiThreatDetection = null,
      PamTriStateSetting? aiTerminateSessionOnDetection = null,
      IDictionary<string, object> existingAllowedSettings = null)
    {
      if (auth == null || string.IsNullOrEmpty(configurationUid))
      {
        return;
      }

      var allowedSettings = existingAllowedSettings != null
        ? new Dictionary<string, object>(existingAllowedSettings)
        : new Dictionary<string, object>();

      ApplyTriState(allowedSettings, "connections", connections);
      ApplyTriState(allowedSettings, "portForwards", tunneling);
      ApplyTriState(allowedSettings, "rotation", rotation);
      ApplyTriState(allowedSettings, "sessionRecording", sessionRecording);
      ApplyTriState(allowedSettings, "typescriptRecording", typescriptRecording);
      ApplyTriState(allowedSettings, "remoteBrowserIsolation", remoteBrowserIsolation);
      ApplyTriState(allowedSettings, "aiEnabled", aiThreatDetection);
      ApplyTriState(allowedSettings, "aiSessionTerminate", aiTerminateSessionOnDetection);

      if (connections == null && tunneling == null && rotation == null && sessionRecording == null
          && typescriptRecording == null && remoteBrowserIsolation == null
          && aiThreatDetection == null && aiTerminateSessionOnDetection == null)
      {
        return;
      }

      var request = new RouterProto.PAMNetworkConfigurationRequest
      {
        RecordUid = ByteString.CopyFrom(configurationUid.Base64UrlDecode()),
        NetworkSettings = new RouterProto.PAMNetworkSettings
        {
          AllowedSettings = ByteString.CopyFrom(JsonUtils.DumpJson(allowedSettings)),
        },
      };

      await RouterUtils.ConfigureNetworkGraphAsync(auth, request);
    }

    /// <summary>
    /// Reads PAM configuration allowed settings from the PAM linking graph (when available).
    /// Property names match Python <c>pam config list -c --format json -v</c> output.
    /// </summary>
    public static async Task<PamConfigurationAllowedSettingsDisplay> GetConfigurationAllowedSettingsAsync(
      IAuthentication auth,
      string configurationUid)
    {
      var empty = MapAllowedSettingsForDisplay(null);
      if (auth == null || string.IsNullOrEmpty(configurationUid))
      {
        return empty;
      }

      try
      {
        var data = await PamGraphSyncClient.MultiSyncAsync(auth, configurationUid).ConfigureAwait(false);
        foreach (var item in data)
        {
          var edge = item?.Data;
          if (edge == null || edge.Type != GraphSync.GraphSyncDataType.GseData)
          {
            continue;
          }

          var uid = edge.Ref?.Value?.ToByteArray().Base64UrlEncode();
          if (!string.Equals(uid, configurationUid, StringComparison.Ordinal))
          {
            continue;
          }

          if (edge.Content == null || edge.Content.IsEmpty)
          {
            continue;
          }

          var content = JsonUtils.ParseJson<PamConfigVertexContent>(edge.Content.ToByteArray());
          return MapAllowedSettingsForDisplay(content?.AllowedSettings);
        }
      }
      catch (Exception ex)
      {
        Debug.WriteLine($"PAM config allowedSettings: {ex.Message}");
      }

      return empty;
    }

    private static PamConfigurationAllowedSettingsDisplay MapAllowedSettingsForDisplay(
      PamConfigAllowedSettings allowed)
    {
      allowed ??= new PamConfigAllowedSettings();
      return new PamConfigurationAllowedSettingsDisplay
      {
        Connections = allowed.Connections,
        Tunneling = allowed.PortForwards ?? allowed.Tunneling,
        Rotation = allowed.Rotation,
        RemoteBrowserIsolation = allowed.RemoteBrowserIsolation,
        ConnectionsRecording = allowed.SessionRecording,
        TypescriptRecording = allowed.TypescriptRecording,
        AiThreatDetection = allowed.AiEnabled,
        AiTerminateSessionOnDetection = allowed.AiSessionTerminate,
      };
    }

    public static PamTriStateSetting? ParseTriState(string value)
    {
      if (string.IsNullOrWhiteSpace(value))
      {
        return null;
      }

      return value.Trim().ToLowerInvariant() switch
      {
        "on" => PamTriStateSetting.On,
        "off" => PamTriStateSetting.Off,
        "default" => PamTriStateSetting.Default,
        _ => null,
      };
    }

    private static void ApplyTriState(
      IDictionary<string, object> allowedSettings,
      string key,
      PamTriStateSetting? setting)
    {
      if (setting == null)
      {
        return;
      }

      var converted = ConvertTriState(setting.Value);
      if (converted == null)
      {
        allowedSettings.Remove(key);
      }
      else
      {
        allowedSettings[key] = converted.Value;
      }
    }

    private static bool? ConvertTriState(PamTriStateSetting setting)
    {
      return setting switch
      {
        PamTriStateSetting.On => true,
        PamTriStateSetting.Off => false,
        PamTriStateSetting.Default => null,
        _ => null,
      };
    }

    [DataContract]
    private sealed class PamConfigAllowedSettings
    {
      [DataMember(Name = "rotation", EmitDefaultValue = false)]
      public bool? Rotation { get; set; }

      [DataMember(Name = "connections", EmitDefaultValue = false)]
      public bool? Connections { get; set; }

      [DataMember(Name = "sessionRecording", EmitDefaultValue = false)]
      public bool? SessionRecording { get; set; }

      [DataMember(Name = "typescriptRecording", EmitDefaultValue = false)]
      public bool? TypescriptRecording { get; set; }

      [DataMember(Name = "portForwards", EmitDefaultValue = false)]
      public bool? PortForwards { get; set; }

      [DataMember(Name = "tunneling", EmitDefaultValue = false)]
      public bool? Tunneling { get; set; }

      [DataMember(Name = "aiEnabled", EmitDefaultValue = false)]
      public bool? AiEnabled { get; set; }

      [DataMember(Name = "aiSessionTerminate", EmitDefaultValue = false)]
      public bool? AiSessionTerminate { get; set; }

      [DataMember(Name = "remoteBrowserIsolation", EmitDefaultValue = false)]
      public bool? RemoteBrowserIsolation { get; set; }
    }

    [DataContract]
    private sealed class PamConfigVertexContent
    {
      [DataMember(Name = "allowedSettings", EmitDefaultValue = false)]
      public PamConfigAllowedSettings AllowedSettings { get; set; }
    }
  }

  /// <summary>
  /// Display model for PAM configuration allowed settings (JSON list/detail -v).
  /// </summary>
  [DataContract]
  public sealed class PamConfigurationAllowedSettingsDisplay
  {
    [DataMember(Name = "connections", EmitDefaultValue = true)]
    public bool? Connections { get; set; }

    [DataMember(Name = "tunneling", EmitDefaultValue = true)]
    public bool? Tunneling { get; set; }

    [DataMember(Name = "rotation", EmitDefaultValue = true)]
    public bool? Rotation { get; set; }

    [DataMember(Name = "remote_browser_isolation", EmitDefaultValue = true)]
    public bool? RemoteBrowserIsolation { get; set; }

    [DataMember(Name = "connections_recording", EmitDefaultValue = true)]
    public bool? ConnectionsRecording { get; set; }

    [DataMember(Name = "typescript_recording", EmitDefaultValue = true)]
    public bool? TypescriptRecording { get; set; }

    [DataMember(Name = "ai_threat_detection", EmitDefaultValue = true)]
    public bool? AiThreatDetection { get; set; }

    [DataMember(Name = "ai_terminate_session_on_detection", EmitDefaultValue = true)]
    public bool? AiTerminateSessionOnDetection { get; set; }

    /// <summary>Converts to a dictionary for Commander JSON row payloads.</summary>
    public Dictionary<string, object> ToDictionary()
    {
      return new Dictionary<string, object>
      {
        ["connections"] = Connections,
        ["tunneling"] = Tunneling,
        ["rotation"] = Rotation,
        ["remote_browser_isolation"] = RemoteBrowserIsolation,
        ["connections_recording"] = ConnectionsRecording,
        ["typescript_recording"] = TypescriptRecording,
        ["ai_threat_detection"] = AiThreatDetection,
        ["ai_terminate_session_on_detection"] = AiTerminateSessionOnDetection,
      };
    }
  }
}
