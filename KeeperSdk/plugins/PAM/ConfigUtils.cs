using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Records;
using PamProto = PAM;
using RouterProto = Router;
using RecordProto = Record.V3;
using FolderProto = Folder;

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

      var record = new TypedRecord(recordType) { Title = title.Trim(), Version = 6 };
      vault.AdjustTypedRecord(record);
      return record;
    }

    public static async Task AddConfigurationRecordAsync(VaultOnline vault, TypedRecord record)
    {
      await AddConfigurationRecordAsync(vault, record, destinationFolderUid: null).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a PAM configuration in classic vault, or in an NSF folder via
    /// vault/records/v3/add_pam_configuration (registers PAM config context).
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

      if (string.IsNullOrEmpty(record.Uid))
      {
        record.Uid = CryptoUtils.GenerateUid();
      }

      if (record.RecordKey == null || record.RecordKey.Length == 0)
      {
        record.RecordKey = CryptoUtils.GenerateEncryptionKey();
      }

      if (PamVaultHelpers.IsKeeperNSFFolder(vault, destinationFolderUid))
      {
        await AddPamConfigurationToNsfAsync(vault, record, destinationFolderUid).ConfigureAwait(false);
        return;
      }

      record.Version = 6;
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
    /// Creates a PAM configuration record inside an NSF folder and registers PAM config context.
    /// </summary>
    private static async Task AddPamConfigurationToNsfAsync(
      VaultOnline vault,
      TypedRecord record,
      string folderUid)
    {
      if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder) || folder == null)
      {
        throw new VaultException($"Keeper NSF folder '{folderUid}' not found");
      }

      if (folder.FolderKey == null || folder.FolderKey.Length == 0)
      {
        throw new VaultException($"Folder key not available for folder '{folderUid}'");
      }

      await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(vault, folderUid)
        .ConfigureAwait(false);

      record.Version = 6;
      vault.AdjustTypedRecord(record);
      var recordData = record.ExtractRecordV3Data();
      var jsonData = VaultExtensions.PadRecordData(JsonUtils.DumpJson(recordData));
      var encryptedData = CryptoUtils.EncryptAesV2(jsonData, record.RecordKey);
      var encryptedRecordKey = CryptoUtils.EncryptAesV2(record.RecordKey, folder.FolderKey);
      var clientModified = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

      var ra = new RecordProto.RecordAdd
      {
        RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
        RecordKey = ByteString.CopyFrom(encryptedRecordKey),
        RecordKeyType = FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm,
        RecordKeyEncryptedBy = FolderProto.FolderKeyEncryptionType.EncryptedByParentKey,
        ClientModifiedTime = clientModified,
        Data = ByteString.CopyFrom(encryptedData),
        FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
      };

      foreach (var recordRef in record.ExtractTypedRecordRefs() ?? Enumerable.Empty<string>())
      {
        if (string.IsNullOrEmpty(recordRef))
        {
          continue;
        }

        byte[] refKey = null;
        record.LinkedKeys?.TryGetValue(recordRef, out refKey);
        if (refKey == null && vault.TryGetKeeperRecord(recordRef, out var linked))
        {
          refKey = linked.RecordKey;
        }

        if (refKey == null && vault.TryGetKeeperNSFRecord(recordRef, out var linkedNsf))
        {
          refKey = linkedNsf.RecordKey;
        }

        if (refKey == null)
        {
          Trace.TraceError($"Lost record reference while creating NSF PAM configuration: \"{recordRef}\"");
          continue;
        }

        ra.RecordLinks.Add(new RecordLink
        {
          RecordUid = ByteString.CopyFrom(recordRef.Base64UrlDecode()),
          RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(refKey, record.RecordKey)),
        });
      }

      var rq = new RecordProto.RecordsAddRequest();
      rq.Records.Add(ra);
      rq.ClientTime = clientModified;

      var rs = await vault.Auth.ExecuteAuthRest<RecordProto.RecordsAddRequest, RecordsModifyResponse>(
        AddPamConfigurationNsfEndpoint, rq).ConfigureAwait(false);

      if (rs.Records.Count > 0)
      {
        var result = rs.Records[0];
        if (result.Status != RecordModifyResult.RsSuccess)
        {
          throw new VaultException($"Failed to create NSF PAM configuration: {result.Message}");
        }
      }

      vault.KeeperNSFRecords[record.Uid] = new KeeperNSFRecord
      {
        RecordUid = record.Uid,
        RecordKey = record.RecordKey,
        Title = record.Title,
        Type = record.TypeName,
        Notes = record.Notes,
        Version = record.Version,
        Revision = 0,
        ClientModifiedTime = clientModified,
        Data = JsonUtils.ParseJson<NsfRecordData>(JsonUtils.DumpJson(recordData, indent: false)),
      };
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
    /// Reads PAM configuration allowedSettings from the PAM linking graph (when available).
    /// Keys match Python <c>pam config list -c --format json -v</c> output.
    /// </summary>
    public static async Task<Dictionary<string, object>> GetConfigurationAllowedSettingsAsync(
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

    private static Dictionary<string, object> MapAllowedSettingsForDisplay(IDictionary<string, object> allowed)
    {
      allowed ??= new Dictionary<string, object>();
      return new Dictionary<string, object>
      {
        ["connections"] = ReadAllowedBool(allowed, "connections"),
        ["tunneling"] = ReadAllowedBool(allowed, "portForwards") ?? ReadAllowedBool(allowed, "tunneling"),
        ["rotation"] = ReadAllowedBool(allowed, "rotation"),
        ["remote_browser_isolation"] = ReadAllowedBool(allowed, "remoteBrowserIsolation"),
        ["connections_recording"] = ReadAllowedBool(allowed, "sessionRecording"),
        ["typescript_recording"] = ReadAllowedBool(allowed, "typescriptRecording"),
        ["ai_threat_detection"] = ReadAllowedBool(allowed, "aiEnabled"),
        ["ai_terminate_session_on_detection"] = ReadAllowedBool(allowed, "aiSessionTerminate"),
      };
    }

    private static object ReadAllowedBool(IDictionary<string, object> allowed, string key)
    {
      if (allowed == null || !allowed.TryGetValue(key, out var value) || value == null)
      {
        return null;
      }

      return value switch
      {
        bool b => b,
        string s when bool.TryParse(s, out var parsed) => parsed,
        _ => value,
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

    [System.Runtime.Serialization.DataContract]
    private class PamConfigVertexContent
    {
      [System.Runtime.Serialization.DataMember(Name = "allowedSettings", EmitDefaultValue = false)]
      public Dictionary<string, object> AllowedSettings { get; set; }
    }
  }
}
