using System;
using System.Collections.Generic;
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

    public static async Task SetConfigurationControllerAsync(
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
  }
}
