using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Commander;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander.PAM
{
  internal sealed class PamConfigEditService
  {
    private readonly VaultOnline _vault;
    private readonly VaultContext _vaultContext;
    private readonly Func<string, PamController> _resolveGateway;
    private readonly List<string> _warnings = new();

    public PamConfigEditService(
      VaultOnline vault,
      VaultContext vaultContext,
      Func<string, PamController> resolveGateway)
    {
      _vault = vault ?? throw new ArgumentNullException(nameof(vault));
      _vaultContext = vaultContext;
      _resolveGateway = resolveGateway;
    }

    public void ClearWarnings() => _warnings.Clear();

    public void LogWarnings()
    {
      foreach (var warning in _warnings)
      {
        Console.WriteLine($"Warning: {warning}");
      }
    }

    public void ApplyProperties(TypedRecord record, PamConfigOptions options, bool isEdit)
    {
      PamConfigFieldPlacement.EnsureSchemaFields(_vault, record);
      ApplyPamResources(record, options, isEdit);
      var properties = BuildExtraProperties(record, options, isEdit);
      PamConfigFieldAssigner.AssignProperties(_vault, record, properties);
      PamConfigScheduleHelper.ApplyDefaultRotationSchedule(record, options, isEdit);
      PamConfigFieldPlacement.RelocateCustomToFields(_vault, record);
    }

    public void VerifyRequired(TypedRecord record)
    {
      foreach (var field in record.Fields)
      {
        if (!field.Required || field.Count > 0)
        {
          continue;
        }

        if (string.Equals(field.FieldName, "schedule", StringComparison.Ordinal))
        {
          PamConfigScheduleHelper.EnsureDefaultRotationScheduleIfEmpty(record);
        }
        else
        {
          _warnings.Add($"Empty required field: \"{PamConfigScheduleHelper.GetPamFieldDisplayName(field)}\"");
        }
      }

      foreach (var custom in record.Custom)
      {
        custom.Required = false;
      }
    }

    private void ApplyPamResources(TypedRecord record, PamConfigOptions options, bool isEdit)
    {
      var facade = new PamConfigurationFacade(record);

      if (!string.IsNullOrWhiteSpace(options.Gateway))
      {
        var gateway = _resolveGateway?.Invoke(options.Gateway.Trim());
        if (gateway != null)
        {
          facade.ControllerUid = gateway.Uid;
        }
        else if (!isEdit)
        {
          _warnings.Add($"Gateway \"{options.Gateway}\" not found.");
        }
      }

      if (!string.IsNullOrWhiteSpace(options.SharedFolder))
      {
        var folderUid = ResolveSharedFolderUid(options.SharedFolder.Trim());
        if (!string.IsNullOrEmpty(folderUid))
        {
          facade.FolderUid = PamVaultHelpers.ResolvePamResourcesFolderUid(_vault, folderUid) ?? folderUid;
        }
      }
      else if (isEdit && string.IsNullOrEmpty(facade.FolderUid))
      {
        throw new InvalidOperationException("Shared Folder not found");
      }

      if (options.RemoveResourceRecords != null && options.RemoveResourceRecords.Count > 0)
      {
        var toRemove = new List<string>();
        foreach (var removeRef in options.RemoveResourceRecords)
        {
          if (string.IsNullOrWhiteSpace(removeRef))
          {
            continue;
          }

          var resolved = PamVaultHelpers.ResolveRecord(_vault, removeRef.Trim(), PamRecordTypes.Rotation);
          if (resolved != null)
          {
            toRemove.Add(resolved.Uid);
            continue;
          }

          var titleMatches = _vault.KeeperRecords
            .OfType<TypedRecord>()
            .Where(x => PamRecordTypes.Rotation.Contains(x.TypeName ?? ""))
            .Where(x => string.Equals(x.Title, removeRef.Trim(), StringComparison.OrdinalIgnoreCase))
            .ToList();
          if (titleMatches.Count == 1)
          {
            toRemove.Add(titleMatches[0].Uid);
          }
          else
          {
            _warnings.Add($"Failed to find PAM record: {removeRef}");
          }
        }

        facade.RemoveResourceRefs(toRemove);
      }
    }

    private List<string> BuildExtraProperties(TypedRecord record, PamConfigOptions options, bool isEdit)
    {
      var properties = new List<string>();

      if (options.PortMapping != null && options.PortMapping.Count > 0)
      {
        properties.Add($"multiline.portMapping={string.Join("\n", options.PortMapping)}");
      }

      if (!string.IsNullOrWhiteSpace(options.IdentityProvider))
      {
        properties.Add($"text.identityProviderUid={options.IdentityProvider.Trim()}");
      }

      switch (record.TypeName)
      {
        case "pamNetworkConfiguration":
          AddTextProperty(properties, "text.networkId", options.NetworkId, isEdit);
          AddTextProperty(properties, "text.networkCIDR", options.NetworkCidr, isEdit);
          break;
        case "pamAwsConfiguration":
          AddTextProperty(properties, "text.awsId", options.AwsId, isEdit);
          AddTextProperty(properties, "secret.accessKeyId", options.AccessKeyId, isEdit);
          AddTextProperty(properties, "secret.accessSecretKey", options.AccessSecretKey, isEdit);
          if (options.RegionNames != null && options.RegionNames.Count > 0)
          {
            properties.Add($"multiline.regionNames={string.Join("\n", options.RegionNames)}");
          }

          break;
        case "pamGcpConfiguration":
          AddTextProperty(properties, "text.pamGcpId", options.GcpId, isEdit);
          AddTextProperty(properties, "json.pamServiceAccountKey", options.ServiceAccountKey, isEdit);
          AddTextProperty(properties, "email.pamGoogleAdminEmail", options.GoogleAdminEmail, isEdit);
          if (options.GcpRegionNames != null && options.GcpRegionNames.Count > 0)
          {
            properties.Add($"multiline.pamGcpRegionName={string.Join("\n", options.GcpRegionNames)}");
          }

          break;
        case "pamAzureConfiguration":
          AddTextProperty(properties, "text.azureId", options.AzureId, isEdit);
          AddTextProperty(properties, "secret.clientId", options.ClientId, isEdit);
          AddTextProperty(properties, "secret.clientSecret", options.ClientSecret, isEdit);
          AddTextProperty(properties, "secret.subscriptionId", options.SubscriptionId, isEdit);
          AddTextProperty(properties, "secret.tenantId", options.TenantId, isEdit);
          if (options.ResourceGroups != null && options.ResourceGroups.Count > 0)
          {
            properties.Add($"multiline.resourceGroups={string.Join("\n", options.ResourceGroups)}");
          }

          break;
        case "pamDomainConfiguration":
          ApplyDomainProperties(record, options, isEdit, properties);
          break;
        case "pamOciConfiguration":
          AddTextProperty(properties, "text.pamOciId", options.OciId, isEdit);
          AddTextProperty(properties, "secret.adminOcid", options.OciAdminId, isEdit);
          AddTextProperty(properties, "secret.adminPublicKey", options.OciAdminPublicKey, isEdit);
          AddTextProperty(properties, "secret.adminPrivateKey", options.OciAdminPrivateKey, isEdit);
          AddTextProperty(properties, "text.tenancyOci", options.OciTenancy, isEdit);
          AddTextProperty(properties, "text.regionOci", options.OciRegion, isEdit);
          break;
      }

      return properties;
    }

    private void ApplyDomainProperties(
      TypedRecord record,
      PamConfigOptions options,
      bool isEdit,
      List<string> properties)
    {
      ApplyDomainTextProperties(options, isEdit, properties);
      ApplyDomainHostnameProperty(record, options, isEdit, properties);
      ApplyDomainCheckboxProperties(record, options);
      ApplyDomainAdminCredential(record, options);
    }

    private static void ApplyDomainTextProperties(
      PamConfigOptions options,
      bool isEdit,
      List<string> properties)
    {
      if (DomainKwargSupplied(options.DomainId, isEdit))
      {
        properties.Add($"text.pamDomainId={options.DomainId ?? ""}");
      }

      if (DomainKwargSupplied(options.DomainNetworkCidr, isEdit))
      {
        properties.Add($"text.networkCIDR={options.DomainNetworkCidr ?? ""}");
      }

      if (DomainKwargSupplied(options.DomainUserMatch, isEdit))
      {
        properties.Add($"text.userMatch={options.DomainUserMatch ?? ""}");
      }
    }

    private static void ApplyDomainHostnameProperty(
      TypedRecord record,
      PamConfigOptions options,
      bool isEdit,
      List<string> properties)
    {
      string host;
      string port;

      if (isEdit)
      {
        if (options.DomainHostname == null && options.DomainPort == null)
        {
          return;
        }

        var existing = PamConfigFieldAssigner.GetPamHostname(record);
        host = options.DomainHostname != null
          ? options.DomainHostname.Trim()
          : existing?.HostName ?? "";
        port = options.DomainPort != null
          ? options.DomainPort.Trim()
          : existing?.Port ?? "";
      }
      else
      {
        host = options.DomainHostname?.Trim() ?? "";
        port = options.DomainPort?.Trim() ?? "";
        if (string.IsNullOrEmpty(host) && string.IsNullOrEmpty(port))
        {
          return;
        }
      }

      properties.Add(BuildPamHostnameProperty(host, port));
    }

    private static string BuildPamHostnameProperty(string host, string port)
    {
      if (string.IsNullOrEmpty(host) && string.IsNullOrEmpty(port))
      {
        return "f.pamHostname=";
      }

      return $"f.pamHostname=$JSON:{{\"hostName\":\"{EscapeJson(host)}\",\"port\":\"{EscapeJson(port)}\"}}";
    }

    private static void ApplyDomainCheckboxProperties(TypedRecord record, PamConfigOptions options)
    {
      var useSsl = ParseTriBool(options.DomainUseSsl);
      if (useSsl.HasValue)
      {
        PamConfigFieldAssigner.SetCheckboxField(record, "useSSL", useSsl);
      }

      var scanDc = ParseTriBool(options.DomainScanDcCidr);
      if (scanDc.HasValue)
      {
        PamConfigFieldAssigner.SetCheckboxField(record, "scanDCCIDR", scanDc);
      }
    }

    private void ApplyDomainAdminCredential(TypedRecord record, PamConfigOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.DomainAdministrativeCredential))
      {
        return;
      }

      var dac = options.DomainAdministrativeCredential.Trim();
      if (options.ForceDomainAdmin)
      {
        if (!Regex.IsMatch(dac, "^[A-Za-z0-9\\-_]{22}$"))
        {
          _warnings.Add($"Invalid Domain Admin User UID: \"{dac}\" (skipped)");
          return;
        }
      }
      else
      {
        var adminRecord = PamVaultHelpers.ResolveRecord(_vault, dac, new[] { "pamUser" });
        if (adminRecord == null)
        {
          _warnings.Add($"Domain Admin User UID: \"{dac}\" not found (skipped).");
          return;
        }

        dac = adminRecord.Uid;
      }

      new PamConfigurationFacade(record).AdminCredentialRef = dac;
    }

    private string ResolveSharedFolderUid(string pathOrUid)
    {
      return PamVaultHelpers.ResolvePamConfigurationFolderUid(_vault, pathOrUid, TryResolveFolderNode);
    }

    private FolderNode TryResolveFolderNode(string path)
    {
      if (PamVaultHelpers.TryResolveFolder(_vault, path, out var folder)
          && PamVaultHelpers.IsPamConfigurationFolderDestination(_vault, folder))
      {
        return folder;
      }

      if (_vaultContext == null)
      {
        return null;
      }

      return _vaultContext.TryResolvePath(path, out var folderNode, out var remainder)
             && string.IsNullOrEmpty(remainder)
             && PamVaultHelpers.IsPamConfigurationFolderDestination(_vault, folderNode)
        ? folderNode
        : null;
    }

    private static void AddTextProperty(List<string> properties, string fieldSpec, string value, bool isEdit)
    {
      if (isEdit)
      {
        if (value != null)
        {
          var parts = fieldSpec.Split('.');
          properties.Add($"{parts[0]}.{parts[1]}={value}");
        }
      }
      else if (!string.IsNullOrWhiteSpace(value))
      {
        var parts = fieldSpec.Split('.');
        properties.Add($"{parts[0]}.{parts[1]}={value.Trim()}");
      }
    }

    private static bool DomainKwargSupplied(string value, bool isEdit)
    {
      return isEdit ? value != null : !string.IsNullOrWhiteSpace(value);
    }

    private static bool? ParseTriBool(string value)
    {
      if (string.IsNullOrWhiteSpace(value))
      {
        return null;
      }

      return value.Trim().ToLowerInvariant() switch
      {
        "true" => true,
        "false" => false,
        _ => null,
      };
    }

    private static string EscapeJson(string value)
    {
      return (value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
  }
}
