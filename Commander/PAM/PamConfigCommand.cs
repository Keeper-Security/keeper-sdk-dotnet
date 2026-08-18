using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using Commander;
using CommandLine;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Commander.PAM
{
  internal class PamConfigCommand : PamCommandBase
  {
    public PamConfigCommand(IEnterpriseContext context) : base(context)
    {
    }

    public async Task ExecuteAsync(PamConfigOptions options)
    {
      if (options == null)
      {
        throw new ArgumentNullException(nameof(options), "Invalid pam config command arguments. Available commands: list, new, edit, remove");
      }

      var command = string.IsNullOrEmpty(options.Command) ? "list" : options.Command.Trim().ToLowerInvariant();
      switch (command)
      {
        case "list":
        case "l":
          await ListConfigurationsAsync(options);
          break;
        case "new":
        case "n":
          await NewConfigurationAsync(options);
          break;
        case "edit":
        case "e":
          if (string.IsNullOrWhiteSpace(options.Uid))
          {
            throw new InvalidOperationException("Configuration UID or name is required for edit");
          }

          await EditConfigurationAsync(options);
          break;
        case "remove":
        case "rm":
        case "delete":
          if (string.IsNullOrWhiteSpace(options.Uid))
          {
            throw new InvalidOperationException("Configuration UID is required for remove");
          }

          await RemoveConfigurationAsync(options);
          break;
        default:
          throw new InvalidOperationException("Unsupported command. Available: list, new, edit, remove");
      }
    }

    private async Task ListConfigurationsAsync(PamConfigOptions options)
    {
      var vault = RequireVault();
      if (!await EnsurePluginAsync(syncIfNeeded: false))
      {
        return;
      }

      if (!string.IsNullOrWhiteSpace(options.Uid))
      {
        await ListSingleConfigurationAsync(vault, options, options.Uid);
        return;
      }

      var configs = PamVaultHelpers.GetConfigurationRecords(vault).Values
        .OrderBy(x => x.Title ?? string.Empty, StringComparer.OrdinalIgnoreCase);

      if (options.isFormatOutputJSON)
      {
        ListConfigurationsAsJson(vault, configs, options.Verbose);
      }
      else
      {
        ListConfigurationsAsTable(vault, configs, options.Verbose);
      }
    }

    private static void ListConfigurationsAsJson(
      VaultOnline vault,
      IEnumerable<TypedRecord> configs,
      bool verbose)
    {
      var rows = new List<Dictionary<string, object>>();
      foreach (var config in configs)
      {
        var folderInfo = TryGetListedConfigurationFolder(vault, config);
        if (folderInfo == null)
        {
          continue;
        }

        rows.Add(BuildConfigListJson(config, folderInfo, verbose));
      }

      Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object> { ["configurations"] = rows }));
    }

    private static void ListConfigurationsAsTable(
      VaultOnline vault,
      IEnumerable<TypedRecord> configs,
      bool verbose)
    {
      var headers = new List<string>
      {
        "UID", "Config Name", "Config Type", "Folder", "Gateway UID", "Resource Record UIDs"
      };
      if (verbose)
      {
        headers.Add("Fields");
      }

      var tab = new Tabulate(headers.Count);
      tab.AddHeader(headers.ToArray());
      foreach (var config in configs)
      {
        var folderInfo = TryGetListedConfigurationFolder(vault, config);
        if (folderInfo == null)
        {
          continue;
        }

        tab.AddRow(BuildConfigTableRow(config, folderInfo, verbose));
      }

      tab.Dump();
    }

    private static PamConfigurationFolderInfo TryGetListedConfigurationFolder(VaultOnline vault, TypedRecord config)
    {
      if (PamVaultHelpers.TryGetConfigurationFolderInfo(vault, config, out var folder) && folder != null)
      {
        return folder;
      }

      PamVaultHelpers.WarnConfigurationNotInSharedFolder(config);
      return null;
    }

    private async Task ListSingleConfigurationAsync(VaultOnline vault, PamConfigOptions options, string configId)
    {
      var config = ResolveConfiguration(vault, configId);
      if (config == null)
      {
        if (options.isFormatOutputJSON)
        {
          Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object> { ["error"] = $"Configuration {configId} not found" }));
        }
        else
        {
          Console.WriteLine($"Configuration \"{configId}\" not found.");
        }

        return;
      }

      if (options.isFormatOutputJSON)
      {
        var detail = await BuildConfigDetailJsonAsync(vault, config, options.Verbose);
        Console.WriteLine(Json.WriteFormatted(detail));
        return;
      }

      var facade = new PamConfigurationFacade(config);
      PamVaultHelpers.TryGetConfigurationFolderInfo(vault, config, out var folder);
      var tab = new Tabulate(2);
      tab.AddRow("UID", config.Uid);
      tab.AddRow("Name", config.Title);
      tab.AddRow("Config Type", config.TypeName);
      tab.AddRow("Folder", FormatFolderDisplay(folder));
      tab.AddRow("Gateway UID", facade.ControllerUid);
      tab.AddRow("Resource Record UIDs", string.Join(", ", facade.ResourceRef));
      foreach (var fieldRow in ExtractDisplayFields(config))
      {
        tab.AddRow(fieldRow.Key, fieldRow.Value);
      }

      tab.Dump();
      PamConfigTunnelingHelper.PrintTunnelingConfig(config.Uid);
    }

    private async Task NewConfigurationAsync(PamConfigOptions options)
    {
      var vault = RequireVault();
      if (!await EnsurePluginAsync())
      {
        return;
      }

      if (!PamConfigTypes.TryResolveRecordType(options.Environment, out var recordType))
      {
        throw new InvalidOperationException(
          $"--environment parameter is required. Supported options: {PamConfigTypes.GetSupportedConfigTypes()}");
      }

      if (PamConfigTypes.IsComingSoonEnvironment(options.Environment, out var comingSoonName))
      {
        Console.WriteLine($"Environment {comingSoonName} is not supported yet. It will be supported in a future release.");
        return;
      }

      if (string.IsNullOrWhiteSpace(options.Title))
      {
        throw new InvalidOperationException("--title parameter is required");
      }

      PreResolveSharedFolderPath(options);
      await vault.EnsurePamRecordTypesAsync();
      var editService = CreateEditService(vault);
      editService.ClearWarnings();

      var record = ConfigUtils.CreateConfigurationRecord(vault, recordType, options.Title);
      editService.ApplyProperties(record, options, isEdit: false);
      editService.VerifyRequired(record);

      var facade = new PamConfigurationFacade(record);
      var moveDestinationUid = PamVaultHelpers.ResolvePamConfigurationFolderUid(
        vault, options.SharedFolder, TryResolveFolderNode);
      var sharedFolderUid = PamVaultHelpers.ResolvePamResourcesFolderUid(vault, facade.FolderUid)
                            ?? PamVaultHelpers.ResolvePamResourcesFolderUid(vault, moveDestinationUid);
      if (!string.IsNullOrEmpty(sharedFolderUid))
      {
        facade.FolderUid = sharedFolderUid;
      }

      if (string.IsNullOrEmpty(sharedFolderUid) || string.IsNullOrEmpty(moveDestinationUid))
      {
        if (string.IsNullOrWhiteSpace(options.SharedFolder))
        {
          throw new InvalidOperationException("--shared-folder parameter is required to create a PAM configuration");
        }

        throw new InvalidOperationException(
          $"Could not resolve shared folder \"{options.SharedFolder}\". " +
          "Provide a shared folder or NSF folder UID, name, or path (e.g. PAM/TestFolder or /PAM/TestFolder).");
      }

      if (string.IsNullOrEmpty(facade.ControllerUid) && !string.IsNullOrWhiteSpace(options.Gateway))
      {
        editService.LogWarnings();
      }

      PamConfigFieldPlacement.EnsureSchemaFields(vault, record);
      PamConfigFieldPlacement.RelocateCustomToFields(vault, record);

      var isNsfFolder = PamVaultHelpers.IsKeeperNSFFolder(vault, moveDestinationUid);
      await ConfigUtils.AddConfigurationRecordAsync(vault, record, isNsfFolder ? moveDestinationUid : null);
      await ConfigUtils.EnsureConfigurationNetworkGraphAsync(Context.Enterprise.Auth, record.Uid);
      await ConfigureTunnelingIfNeededAsync(record.Uid, options);

      await vault.SyncDown();
      if (!isNsfFolder)
      {
        await MoveRecordToSharedFolderAsync(vault, record, moveDestinationUid);
      }

      if (!string.IsNullOrEmpty(facade.ControllerUid))
      {
        await ConfigUtils.SetConfigurationGatewayAsync(Context.Enterprise.Auth, record.Uid, facade.ControllerUid);
      }

      await vault.SyncDown();
      editService.LogWarnings();
      Console.WriteLine(record.Uid);
    }

    private async Task EditConfigurationAsync(PamConfigOptions options)
    {
      var vault = RequireVault();
      if (!await EnsurePluginAsync(syncIfNeeded: false))
      {
        return;
      }

      if (string.IsNullOrWhiteSpace(options.Uid))
      {
        throw new InvalidOperationException("Configuration UID or name is required for edit");
      }

      var configuration = ResolveConfiguration(vault, options.Uid);
      if (configuration == null)
      {
        throw new InvalidOperationException($"PAM configuration \"{options.Uid}\" not found");
      }

      if (PamConfigTypes.IsComingSoonEnvironment(options.Environment, out var comingSoonName))
      {
        Console.WriteLine($"Environment {comingSoonName} is not supported yet. It will be supported in a future release.");
        return;
      }

      await vault.EnsurePamRecordTypesAsync();

      if (!string.IsNullOrWhiteSpace(options.Environment)
          && PamConfigTypes.TryResolveRecordType(options.Environment, out var newType)
          && !string.Equals(newType, configuration.TypeName, StringComparison.Ordinal))
      {
        configuration.TypeName = newType;
        vault.AdjustTypedRecord(configuration);
      }
      else
      {
        vault.AdjustTypedRecord(configuration);
      }

      if (!string.IsNullOrWhiteSpace(options.Title))
      {
        configuration.Title = options.Title.Trim();
      }

      var beforeEdit = new PamConfigurationFacade(configuration);
      var origGatewayUid = beforeEdit.ControllerUid;
      var origSharedFolderUid = beforeEdit.FolderUid;
      var origAdminCredRef = beforeEdit.AdminCredentialRef;

      var editService = CreateEditService(vault);
      editService.ClearWarnings();
      editService.ApplyProperties(configuration, options, isEdit: true);
      editService.VerifyRequired(configuration);
      PamConfigFieldPlacement.EnsureSchemaFields(vault, configuration);
      PamConfigFieldPlacement.RelocateCustomToFields(vault, configuration);
      await vault.UpdateRecord(configuration);

      var afterEdit = new PamConfigurationFacade(configuration);
      if (!string.Equals(afterEdit.ControllerUid, origGatewayUid, StringComparison.Ordinal)
          && !string.IsNullOrEmpty(afterEdit.ControllerUid))
      {
        await ConfigUtils.SetConfigurationGatewayAsync(
          Context.Enterprise.Auth, configuration.Uid, afterEdit.ControllerUid);
      }

      if (!string.Equals(afterEdit.FolderUid, origSharedFolderUid, StringComparison.Ordinal)
          && !string.IsNullOrEmpty(afterEdit.FolderUid))
      {
        await MoveRecordToSharedFolderAsync(vault, configuration, afterEdit.FolderUid);
      }

      if (HasTunnelingOptions(options) || !string.Equals(afterEdit.AdminCredentialRef, origAdminCredRef, StringComparison.Ordinal))
      {
        await ConfigureTunnelingIfNeededAsync(configuration.Uid, options);
      }

      editService.LogWarnings();
      await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
      Console.WriteLine($"PAM configuration \"{configuration.Title}\" updated.");
    }

    private async Task RemoveConfigurationAsync(PamConfigOptions options)
    {
      var vault = RequireVault();
      if (string.IsNullOrWhiteSpace(options.Uid))
      {
        throw new InvalidOperationException("Configuration UID is required for remove");
      }

      var config = ResolveConfiguration(vault, options.Uid);
      if (config == null)
      {
        throw new InvalidOperationException($"Configuration \"{options.Uid}\" not found");
      }

      await ConfigUtils.RemovePamConfigurationAsync(vault, config.Uid);
      await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
      Console.WriteLine($"PAM configuration \"{config.Title}\" removed.");
    }

    private PamConfigEditService CreateEditService(VaultOnline vault)
    {
      return new PamConfigEditService(vault, TryGetVaultContext(), ResolveGateway);
    }

    private VaultOnline RequireVault()
    {
      var vault = Context.GetVault();
      if (vault == null)
      {
        throw new VaultException("Vault is not initialized. Login to initialize the vault.");
      }

      return vault;
    }

    private TypedRecord ResolveConfiguration(VaultOnline vault, string identifier)
    {
      return TryResolvePamRecord(vault, identifier, PamRecordTypes.Configuration);
    }

    private static async Task MoveRecordToSharedFolderAsync(VaultOnline vault, TypedRecord record, string destinationFolderUid)
    {
      await PamVaultHelpers.PlacePamConfigurationInFolderAsync(vault, record, destinationFolderUid);
    }

    private void PreResolveSharedFolderPath(PamConfigOptions options)
    {
      if (string.IsNullOrWhiteSpace(options.SharedFolder))
      {
        return;
      }

      var folderNode = TryResolveFolderNode(options.SharedFolder.Trim());
      if (folderNode != null)
      {
        options.SharedFolder = folderNode.FolderUid;
      }
    }

    private FolderNode TryResolveFolderNode(string path)
    {
      var vault = Context.GetVault();
      if (vault != null && PamVaultHelpers.TryResolveFolder(vault, path, out var folder)
          && PamVaultHelpers.IsPamConfigurationFolderDestination(vault, folder))
      {
        return folder;
      }

      var vaultContext = TryGetVaultContext();
      if (vaultContext == null)
      {
        return null;
      }

      return vaultContext.TryResolvePath(path, out var folderNode, out var remainder)
             && string.IsNullOrEmpty(remainder)
             && PamVaultHelpers.IsPamConfigurationFolderDestination(vault, folderNode)
        ? folderNode
        : null;
    }

    private async Task ConfigureTunnelingIfNeededAsync(string configUid, PamConfigOptions options)
    {
      if (!HasTunnelingOptions(options))
      {
        return;
      }

      await ConfigUtils.ConfigureTunnelingAsync(
        Context.Enterprise.Auth,
        configUid,
        ConfigUtils.ParseTriState(options.Connections),
        ConfigUtils.ParseTriState(options.Tunneling),
        ConfigUtils.ParseTriState(options.Rotation),
        ConfigUtils.ParseTriState(options.ConnectionsRecording),
        ConfigUtils.ParseTriState(options.TypescriptRecording),
        ConfigUtils.ParseTriState(options.RemoteBrowserIsolation),
        ConfigUtils.ParseTriState(options.AiThreatDetection),
        ConfigUtils.ParseTriState(options.AiTerminateSessionOnDetection));
    }

    private static bool HasTunnelingOptions(PamConfigOptions options)
    {
      return options.Connections != null || options.Tunneling != null || options.Rotation != null
             || options.ConnectionsRecording != null || options.TypescriptRecording != null
             || options.RemoteBrowserIsolation != null || options.AiThreatDetection != null
             || options.AiTerminateSessionOnDetection != null;
    }

    private static Dictionary<string, object> BuildConfigListJson(
      TypedRecord config,
      PamConfigurationFolderInfo folder,
      bool verbose)
    {
      var facade = new PamConfigurationFacade(config);
      var row = new Dictionary<string, object>
      {
        ["uid"] = config.Uid,
        ["config_name"] = config.Title,
        ["config_type"] = config.TypeName,
        ["gateway_uid"] = facade.ControllerUid ?? "",
        ["resource_record_uids"] = facade.ResourceRef,
      };
      ApplyFolderJsonPayload(row, folder);

      if (verbose)
      {
        row["fields"] = ExtractDisplayFields(config)
          .ToDictionary(x => x.Key, x => (object) x.Value);
      }

      return row;
    }

    private async Task<Dictionary<string, object>> BuildConfigDetailJsonAsync(
      VaultOnline vault,
      TypedRecord config,
      bool verbose)
    {
      PamVaultHelpers.TryGetConfigurationFolderInfo(vault, config, out var folder);
      var facade = new PamConfigurationFacade(config);
      var row = new Dictionary<string, object>
      {
        ["uid"] = config.Uid,
        ["name"] = config.Title,
        ["config_type"] = config.TypeName,
        ["gateway_uid"] = facade.ControllerUid ?? "",
        ["gateway_name"] = ResolveGatewayName(facade.ControllerUid),
        ["resource_record_uids"] = facade.ResourceRef,
        ["fields"] = ExtractDetailJsonFields(config),
      };
      ApplyFolderJsonPayload(row, folder);

      if (string.Equals(config.TypeName, "pamDomainConfiguration", StringComparison.Ordinal))
      {
        row["domain_administrative_credential"] = facade.AdminCredentialRef;
      }

      if (verbose)
      {
        row["allowed_settings"] = await PamConfigTunnelingHelper
          .GetAllowedSettingsJsonAsync(Context.Enterprise.Auth, config.Uid)
          .ConfigureAwait(false);
      }

      return row;
    }

    private string ResolveGatewayName(string controllerUid)
    {
      if (Plugin == null || string.IsNullOrWhiteSpace(controllerUid))
      {
        return "";
      }

      var gateway = GatewayUtils.FindGateway(Plugin.Controllers.GetAll(), controllerUid);
      return gateway?.ControllerName ?? "";
    }

    private static object[] BuildConfigTableRow(
      TypedRecord config,
      PamConfigurationFolderInfo folder,
      bool verbose)
    {
      var facade = new PamConfigurationFacade(config);
      var row = new List<object>
      {
        config.Uid, config.Title, config.TypeName,
        FormatFolderDisplay(folder),
        facade.ControllerUid, string.Join(", ", facade.ResourceRef),
      };

      if (verbose)
      {
        row.Add(string.Join("; ", ExtractDisplayFields(config).Select(x => $"{x.Key}: {x.Value}")));
      }

      return row.ToArray();
    }

    private static string FormatFolderDisplay(PamConfigurationFolderInfo folder)
    {
      if (folder == null)
      {
        return "";
      }

      var suffix = folder.IsNsf ? " [NSF]" : "";
      return $"{folder.Name} ({folder.Uid}){suffix}";
    }

    private static void ApplyFolderJsonPayload(
      IDictionary<string, object> row,
      PamConfigurationFolderInfo folder)
    {
      if (folder == null)
      {
        return;
      }

      row["folder"] = new Dictionary<string, object>
      {
        ["uid"] = folder.Uid,
        ["name"] = folder.Name,
        ["type"] = folder.IsNsf ? "nested_share_folder" : "shared_folder",
      };

      if (!folder.IsNsf)
      {
        row["shared_folder"] = new Dictionary<string, object>
        {
          ["name"] = folder.Name,
          ["uid"] = folder.Uid,
        };
      }
    }

    private static Dictionary<string, object> ExtractDetailJsonFields(TypedRecord config)
    {
      return config.Fields.Concat(config.Custom)
        .Where(field => field.FieldName is not ("pamResources" or "fileRef"))
        .Select(field => new
        {
          Name = PamConfigScheduleHelper.GetPamFieldJsonName(field),
          Values = GetFieldExternalValues(field).ToList(),
        })
        .Where(x => x.Values.Count > 0)
        .ToDictionary(x => x.Name, x => (object) x.Values);
    }

    private static IEnumerable<KeyValuePair<string, string>> ExtractDisplayFields(TypedRecord config)
    {
      return config.Fields.Concat(config.Custom)
        .Where(field => field.FieldName is not ("pamResources" or "fileRef"))
        .Select(field => new KeyValuePair<string, string>(
          PamConfigScheduleHelper.GetPamFieldDisplayName(field),
          string.Join(", ", GetFieldExternalValues(field))))
        .Where(x => !string.IsNullOrEmpty(x.Value));
    }

    private static IEnumerable<string> GetFieldExternalValues(ITypedField field)
    {
      return string.Equals(field.FieldName, "schedule", StringComparison.Ordinal)
        ? PamConfigScheduleHelper.GetDisplayValues(field)
        : field.GetTypedFieldInformation();
    }
  }

  internal class PamConfigOptions : EnterpriseGenericOptions
  {
    [Value(0, Required = false, HelpText = "Command: list, new, edit, remove")]
    public string Command { get; set; }

    [Value(1, Required = false, HelpText = "Configuration UID or name (list/edit/remove)")]
    public string Uid { get; set; }

    [Option("environment", Required = false, HelpText = "PAM configuration type: local, aws, azure, gcp, domain, oci, github")]
    public string Environment { get; set; }

    [Option('t', "title", Required = false, HelpText = "Title of the PAM configuration")]
    public string Title { get; set; }

    [Option('g', "gateway", Required = false, HelpText = "Gateway UID or name")]
    public string Gateway { get; set; }

    [Option("shared-folder", Required = false, HelpText = "Shared folder path or UID")]
    public string SharedFolder { get; set; }

    [Option("schedule", Required = false, HelpText = "Default schedule CRON (e.g. 0 0 2 * * ?) or On-Demand")]
    public string DefaultSchedule { get; set; }

    [Option("port-mapping", Required = false, HelpText = "Port mapping entry")]
    public IList<string> PortMapping { get; set; }

    [Option("identity-provider", Required = false, HelpText = "Identity Provider UID")]
    public string IdentityProvider { get; set; }

    [Option('c', "connections", Required = false, HelpText = "Connections permissions: on, off, default")]
    public string Connections { get; set; }

    [Option('u', "tunneling", Required = false, HelpText = "Tunneling permissions: on, off, default")]
    public string Tunneling { get; set; }

    [Option('r', "rotation", Required = false, HelpText = "Rotation permissions: on, off, default")]
    public string Rotation { get; set; }

    [Option("remote-browser-isolation", Required = false, HelpText = "Remote browser isolation: on, off, default")]
    public string RemoteBrowserIsolation { get; set; }

    [Option("connections-recording", Required = false, HelpText = "Connection recording: on, off, default")]
    public string ConnectionsRecording { get; set; }

    [Option("typescript-recording", Required = false, HelpText = "TypeScript recording: on, off, default")]
    public string TypescriptRecording { get; set; }

    [Option("ai-threat-detection", Required = false, HelpText = "AI threat detection permissions: on, off, default")]
    public string AiThreatDetection { get; set; }

    [Option("ai-terminate-session-on-detection", Required = false, HelpText = "AI session termination on threat detection: on, off, default")]
    public string AiTerminateSessionOnDetection { get; set; }

    [Option("remove-resource-record", Required = false, HelpText = "Resource record UID to remove (edit)")]
    public IList<string> RemoveResourceRecords { get; set; }

    [Option("network-id", Required = false, HelpText = "Network ID (local/network)")]
    public string NetworkId { get; set; }

    [Option("network-cidr", Required = false, HelpText = "Network CIDR (local/network)")]
    public string NetworkCidr { get; set; }

    [Option("aws-id", Required = false, HelpText = "AWS ID")]
    public string AwsId { get; set; }

    [Option("access-key-id", Required = false, HelpText = "AWS access key ID")]
    public string AccessKeyId { get; set; }

    [Option("access-secret-key", Required = false, HelpText = "AWS access secret key")]
    public string AccessSecretKey { get; set; }

    [Option("region-name", Required = false, HelpText = "AWS region name")]
    public IList<string> RegionNames { get; set; }

    [Option("azure-id", Required = false, HelpText = "Azure ID")]
    public string AzureId { get; set; }

    [Option("client-id", Required = false, HelpText = "Azure client ID")]
    public string ClientId { get; set; }

    [Option("client-secret", Required = false, HelpText = "Azure client secret")]
    public string ClientSecret { get; set; }

    [Option("subscription-id", Required = false, HelpText = "Azure subscription ID")]
    public string SubscriptionId { get; set; }

    [Option("tenant-id", Required = false, HelpText = "Azure tenant ID")]
    public string TenantId { get; set; }

    [Option("resource-group", Required = false, HelpText = "Azure resource group")]
    public IList<string> ResourceGroups { get; set; }

    [Option("gcp-id", Required = false, HelpText = "GCP ID")]
    public string GcpId { get; set; }

    [Option("service-account-key", Required = false, HelpText = "GCP service account key JSON")]
    public string ServiceAccountKey { get; set; }

    [Option("google-admin-email", Required = false, HelpText = "Google Workspace admin email")]
    public string GoogleAdminEmail { get; set; }

    [Option("gcp-region", Required = false, HelpText = "GCP region name")]
    public IList<string> GcpRegionNames { get; set; }

    [Option("domain-id", Required = false, HelpText = "Domain ID")]
    public string DomainId { get; set; }

    [Option("domain-hostname", Required = false, HelpText = "Domain hostname")]
    public string DomainHostname { get; set; }

    [Option("domain-port", Required = false, HelpText = "Domain port")]
    public string DomainPort { get; set; }

    [Option("domain-use-ssl", Required = false, HelpText = "Domain use SSL: true, false")]
    public string DomainUseSsl { get; set; }

    [Option("domain-scan-dc-cidr", Required = false, HelpText = "Domain scan DC CIDR: true, false")]
    public string DomainScanDcCidr { get; set; }

    [Option("domain-network-cidr", Required = false, HelpText = "Domain network CIDR")]
    public string DomainNetworkCidr { get; set; }

    [Option("domain-admin", Required = false, HelpText = "Domain administrative credential")]
    public string DomainAdministrativeCredential { get; set; }

    [Option("domain-user-match", Required = false, HelpText = "Domain user match filter")]
    public string DomainUserMatch { get; set; }

    [Option("force-domain-admin", Required = false, HelpText = "Treat domain-admin as raw UID")]
    public bool ForceDomainAdmin { get; set; }

    [Option("oci-id", Required = false, HelpText = "OCI ID")]
    public string OciId { get; set; }

    [Option("oci-admin-id", Required = false, HelpText = "OCI admin ID")]
    public string OciAdminId { get; set; }

    [Option("oci-admin-public-key", Required = false, HelpText = "OCI admin public key")]
    public string OciAdminPublicKey { get; set; }

    [Option("oci-admin-private-key", Required = false, HelpText = "OCI admin private key")]
    public string OciAdminPrivateKey { get; set; }

    [Option("oci-tenancy", Required = false, HelpText = "OCI tenancy")]
    public string OciTenancy { get; set; }

    [Option("oci-region", Required = false, HelpText = "OCI region")]
    public string OciRegion { get; set; }

    [Option('v', "verbose", Required = false, HelpText = "Verbose output")]
    public bool Verbose { get; set; }

    [Option("format", Required = false, Default = "table", HelpText = "Output format: table, json")]
    public string Format { get; set; }

    internal bool isFormatOutputJSON => string.Equals(Format, "json", StringComparison.OrdinalIgnoreCase);
  }
}
