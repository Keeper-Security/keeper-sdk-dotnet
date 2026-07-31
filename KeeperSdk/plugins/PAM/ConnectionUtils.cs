using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// PAM connection configuration.
  /// </summary>
  public static class ConnectionUtils
  {
    private static readonly HashSet<string> ConnectionRecordTypes = new(StringComparer.Ordinal)
    {
      "pamMachine",
      "pamDatabase",
      "pamDirectory",
      "pamRemoteBrowser",
      "pamNetworkConfiguration",
      "pamAwsConfiguration",
      "pamAzureConfiguration",
    };

    private static readonly HashSet<string> LaunchCredentialRecordTypes = new(StringComparer.Ordinal)
    {
      "pamMachine",
      "pamDatabase",
      "pamDirectory",
    };

    private static readonly HashSet<string> SeedRecordTypes = new(StringComparer.Ordinal)
    {
      "pamDatabase",
      "pamDirectory",
      "pamMachine",
      "pamRemoteBrowser",
    };

    private static readonly HashSet<string> DbProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
      "clickhouse", "dynamodb", "elasticsearch", "mariadb", "mongodb",
      "mysql", "oracle", "postgresql", "redis", "sql-server",
    };

    private static readonly HashSet<string> CliCapableDbProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
      "mysql", "postgresql", "sql-server",
    };

    private static readonly HashSet<string> NonDbProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
      "http", "kubernetes", "rdp", "ssh", "telnet", "vnc",
    };

    private static readonly HashSet<string> TerminalScrollbackProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
      "ssh", "telnet", "kubernetes",
    };

    /// <summary>
    /// Configure connection settings on a PAM resource or PAM configuration record.
    /// </summary>
    public static async Task<PamConnectionEditResult> EditConnectionAsync(
      VaultOnline vault,
      PamConnectionEditOptions options)
    {
      if (vault == null)
      {
        throw new ArgumentNullException(nameof(vault));
      }

      if (options == null)
      {
        throw new ArgumentNullException(nameof(options));
      }

      if (string.IsNullOrWhiteSpace(options.Record))
      {
        throw new PamConnectionException("Record parameter is required.");
      }

      var auth = vault.Auth ?? throw new PamConnectionException("Authentication is required.");
      var record = ResolveConnectionRecord(vault, options.Record.Trim());
      if (record == null)
      {
        throw new PamConnectionException($"Record \"{options.Record}\" not found.");
      }

      var recordType = record.TypeName ?? "";
      if (!ConnectionRecordTypes.Contains(recordType) && !PamRecordTypes.Configuration.Contains(recordType))
      {
        throw new PamConnectionException(
          "This record's type is not supported for connections. "
          + "Connections are only supported on pamMachine, pamDatabase, pamDirectory, "
          + "pamRemoteBrowser, and PAM configuration records.");
      }

      ValidateTriState(options.Connections, "--connections");
      ValidateTriState(options.ConnectionsRecording, "--connections-recording");
      ValidateTriState(options.TypescriptRecording, "--typescript-recording");
      ValidateTriState(options.KeyEvents, "--key-events");

      if (options.ClearLaunchUser && !string.IsNullOrWhiteSpace(options.LaunchUser))
      {
        throw new PamConnectionException("Use either --clear-launch-user or --launch-user, not both.");
      }

      var result = new PamConnectionEditResult
      {
        RecordUid = record.Uid,
        IsConfigurationRecord = PamRecordTypes.Configuration.Contains(recordType),
      };

      if (result.IsConfigurationRecord)
      {
        await EditConfigurationConnectionsAsync(auth, record, options, result);
        return result;
      }

      await EditResourceConnectionsAsync(vault, auth, record, options, result);
      return result;
    }

    private static async Task EditConfigurationConnectionsAsync(
      IAuthentication auth,
      TypedRecord configRecord,
      PamConnectionEditOptions options,
      PamConnectionEditResult result)
    {
      result.ConfigUid = configRecord.Uid;
      var graph = new PamRotationGraph(auth, configRecord.Uid);
      await graph.LoadAsync();
      if (!graph.HasGraph)
      {
        await graph.EnsureConfigGraphAsync(enableRotationOnConfig: false);
      }

      await graph.SetNetworkConnectionAllowedAsync(
        connections: options.Connections,
        sessionRecording: options.ConnectionsRecording,
        typescriptRecording: options.TypescriptRecording);

      result.GraphUpdated = true;
      if (!options.Silent)
      {
        await graph.LoadAsync();
        AppendConfigSummary(result, graph, configRecord.Uid);
      }
    }

    private static async Task EditResourceConnectionsAsync(
      VaultOnline vault,
      IAuthentication auth,
      TypedRecord record,
      PamConnectionEditOptions options,
      PamConnectionEditResult result)
    {
      var recordType = record.TypeName ?? "";
      var connectionsEnabled = string.Equals(options.Connections, "on", StringComparison.OrdinalIgnoreCase);
      var connectionsTri = PamRotationGraph.ConvertAllowedSetting(options.Connections);

      ValidateScrollback(recordType, record, options, connectionsEnabled);

      var recordDirty = EnsureTrafficEncryptionSeed(record);
      recordDirty |= ApplyPamSettings(record, options, connectionsEnabled);

      if (recordDirty)
      {
        await vault.UpdateRecord(record);
        result.RecordUpdated = true;

        if (!record.FindTypedField("trafficEncryptionSeed", null, out _))
        {
          throw new PamConnectionException(
            $"Unable to add Seed to record {record.Uid}. Please make sure you have edit rights to the record.");
        }
      }

      var dagAffecting = !string.IsNullOrWhiteSpace(options.Configuration)
                        || !string.IsNullOrWhiteSpace(options.AdminUser)
                        || !string.IsNullOrWhiteSpace(options.LaunchUser)
                        || options.ClearLaunchUser
                        || options.Connections != null
                        || options.ConnectionsRecording != null
                        || options.TypescriptRecording != null
                        || options.RotateOnTermination != null;
      if (!dagAffecting)
      {
        return;
      }

      var existingConfigUid = ResolveExistingConfigUid(vault, record.Uid);
      var configUid = ResolveConfigUid(vault, options.Configuration, existingConfigUid);
      if (string.IsNullOrEmpty(configUid))
      {
        throw new PamConnectionException(
          "No PAM Configuration UID set. This must be set or supplied for connections to work "
          + "(use --configuration / -c). List configs with pam-config or pam config list.");
      }

      result.ConfigUid = configUid;
      var graph = new PamRotationGraph(auth, configUid);
      await graph.LoadAsync();
      if (!graph.HasGraph)
      {
        await graph.EnsureConfigGraphAsync(enableRotationOnConfig: false);
      }

      var resourceType = PamRotationGraph.GetResourceRefType(recordType);

      if (!graph.CheckConfigAllows(
            enableConnections: connectionsTri == true ? true : null,
            enableSessionRecording: PamRotationGraph.ConvertAllowedSetting(options.ConnectionsRecording) == true
              ? true
              : null,
            enableTypescriptRecording: PamRotationGraph.ConvertAllowedSetting(options.TypescriptRecording) == true
              ? true
              : null))
      {
        throw new PamConnectionException(
          $"The settings are denied by PAM Configuration: {configUid}. "
          + $"Enable them on the configuration first, e.g. "
          + $"pam-connection edit {configUid} --connections=on");
      }

      if (!graph.ResourceBelongsToConfig(record.Uid))
      {
        await graph.LinkResourceToConfigAsync(record.Uid, resourceType);
      }

      if (!graph.ResourceBelongsToConfig(record.Uid))
      {
        throw new PamConnectionException(
          $"No PAM Configuration UID set for record {record.Uid}. "
          + $"Use: pam-connection edit {record.Uid} --configuration {configUid} --connections=on");
      }

      var allowedSettingsName = string.Equals(recordType, "pamRemoteBrowser", StringComparison.Ordinal)
        ? "pamRemoteBrowserSettings"
        : "allowedSettings";

      bool? rotateOnTermination = null;
      if (!string.IsNullOrWhiteSpace(options.RotateOnTermination))
      {
        if (!LaunchCredentialRecordTypes.Contains(recordType))
        {
          throw new PamConnectionException(
            "--rotate-on-termination is only supported for pamMachine, pamDatabase, and pamDirectory records.");
        }

        rotateOnTermination = string.Equals(options.RotateOnTermination, "on", StringComparison.OrdinalIgnoreCase)
          ? true
          : string.Equals(options.RotateOnTermination, "off", StringComparison.OrdinalIgnoreCase)
            ? false
            : throw new PamConnectionException("--rotate-on-termination must be on or off.");
      }

      var needAllowed = options.Connections != null
                        || options.ConnectionsRecording != null
                        || options.TypescriptRecording != null
                        || rotateOnTermination != null;
      if (needAllowed)
      {
        await graph.SetResourceConnectionAllowedAsync(
          record.Uid,
          resourceType,
          connections: options.Connections,
          sessionRecording: options.ConnectionsRecording,
          typescriptRecording: options.TypescriptRecording,
          rotateOnTermination: rotateOnTermination,
          allowedSettingsName: allowedSettingsName);
        result.GraphUpdated = true;
      }

      var adminUid = ResolveAdminUid(vault, options.AdminUser, recordType);
      var applyLaunch = false;
      string launchUid = null;
      if (options.ClearLaunchUser)
      {
        if (!LaunchCredentialRecordTypes.Contains(recordType))
        {
          throw new PamConnectionException(
            "--clear-launch-user is only supported for pamMachine, pamDatabase, and pamDirectory records.");
        }

        applyLaunch = true;
      }
      else if (!string.IsNullOrWhiteSpace(options.LaunchUser))
      {
        var launch = PamVaultHelpers.ResolveRecord(vault, options.LaunchUser.Trim(), new[] { "pamUser" });
        if (launch == null)
        {
          throw new PamConnectionException($"Launch user record \"{options.LaunchUser}\" not found.");
        }

        if (!LaunchCredentialRecordTypes.Contains(recordType))
        {
          throw new PamConnectionException(
            "Launch credentials are only supported for pamMachine, pamDatabase, and pamDirectory records.");
        }

        applyLaunch = true;
        launchUid = launch.Uid;
      }

      if (applyLaunch)
      {
        await graph.SetLaunchCredentialsAsync(record.Uid, launchUid, adminUid);
        result.GraphUpdated = true;
      }
      else if (!string.IsNullOrEmpty(adminUid))
      {
        // so admin flips on an existing ACL without clearing launch credentials.
        var currentLaunch = graph.GetLaunchCredentialUids(record.Uid).FirstOrDefault();
        await graph.SetLaunchCredentialsAsync(record.Uid, currentLaunch, adminUid);
        result.GraphUpdated = true;
      }

      if (!options.Silent)
      {
        await AppendSettingsSummaryAsync(result, graph, record.Uid, configUid);
      }
    }

    private static async Task AppendSettingsSummaryAsync(
      PamConnectionEditResult result,
      PamRotationGraph graph,
      string recordUid,
      string configUid)
    {
      await graph.LoadAsync();

      var resourceHasVertex = graph.ResourceBelongsToConfig(recordUid)
                              || graph.GetResourceAllowedSetting(recordUid, "rotation") != null
                              || graph.GetResourceAllowedSetting(recordUid, "portForwards") != null
                              || graph.GetResourceAllowedSetting(recordUid, "connections") != null;
      PamRotationGraph.PamDebug(
        $"summary resource={recordUid} linked={graph.ResourceBelongsToConfig(recordUid)} "
        + $"hasFlags={resourceHasVertex} "
        + $"rotation={graph.GetResourceAllowedSetting(recordUid, "rotation")} "
        + $"portForwards={graph.GetResourceAllowedSetting(recordUid, "portForwards")} "
        + $"connections={graph.GetResourceAllowedSetting(recordUid, "connections")}");

      result.Messages.Add($"Settings configured for {recordUid}");
      result.Messages.Add(
        $"\tRotation: {PamRotationGraph.FormatRotationStatus(graph.GetResourceAllowedSetting(recordUid, "rotation"))}");
      result.Messages.Add(
        $"\tTunneling: {PamRotationGraph.FormatFlagStatus(graph.GetResourceAllowedSetting(recordUid, "portForwards"))}");
      result.Messages.Add(
        $"\tAI threat detection: {PamRotationGraph.FormatFlagStatus(graph.GetResourceAllowedSetting(recordUid, "aiEnabled"))}");
      result.Messages.Add(
        $"\tAI terminate session on detection: {PamRotationGraph.FormatFlagStatus(graph.GetResourceAllowedSetting(recordUid, "aiSessionTerminate"))}");

      if (!string.IsNullOrEmpty(configUid))
      {
        PamRotationGraph.PamDebug(
          $"summary config={configUid} "
          + $"rotation={graph.GetConfigAllowedSetting("rotation")} "
          + $"portForwards={graph.GetConfigAllowedSetting("portForwards")} "
          + $"connections={graph.GetConfigAllowedSetting("connections")}");

        result.Messages.Add($"Configuration: {configUid}");
        result.Messages.Add(
          $"\tRotation: {PamRotationGraph.FormatRotationStatus(graph.GetConfigAllowedSetting("rotation"))}");
        result.Messages.Add(
          $"\tTunneling: {PamRotationGraph.FormatFlagStatus(graph.GetConfigAllowedSetting("portForwards"))}");
        result.Messages.Add(
          $"\tAI threat detection: {PamRotationGraph.FormatFlagStatus(graph.GetConfigAllowedSetting("aiEnabled"))}");
        result.Messages.Add(
          $"\tAI terminate session on detection: {PamRotationGraph.FormatFlagStatus(graph.GetConfigAllowedSetting("aiSessionTerminate"))}");
      }
    }

    private static void AppendConfigSummary(
      PamConnectionEditResult result,
      PamRotationGraph graph,
      string configUid)
    {
      PamRotationGraph.PamDebug(
        $"config-edit summary config={configUid} "
        + $"rotation={graph.GetConfigAllowedSetting("rotation")} "
        + $"portForwards={graph.GetConfigAllowedSetting("portForwards")} "
        + $"connections={graph.GetConfigAllowedSetting("connections")}");

      result.Messages.Add($"Settings configured for {configUid}");
      result.Messages.Add(
        $"\tRotation: {PamRotationGraph.FormatRotationStatus(graph.GetConfigAllowedSetting("rotation"))}");
      result.Messages.Add(
        $"\tTunneling: {PamRotationGraph.FormatFlagStatus(graph.GetConfigAllowedSetting("portForwards"))}");
      result.Messages.Add(
        $"\tAI threat detection: {PamRotationGraph.FormatFlagStatus(graph.GetConfigAllowedSetting("aiEnabled"))}");
      result.Messages.Add(
        $"\tAI terminate session on detection: {PamRotationGraph.FormatFlagStatus(graph.GetConfigAllowedSetting("aiSessionTerminate"))}");
    }

    private static string ResolveAdminUid(VaultOnline vault, string adminUser, string recordType)
    {
      if (string.IsNullOrWhiteSpace(adminUser) || !LaunchCredentialRecordTypes.Contains(recordType))
      {
        return null;
      }

      var admin = PamVaultHelpers.ResolveRecord(vault, adminUser.Trim(), new[] { "pamUser" });
      if (admin == null)
      {
        throw new PamConnectionException($"Admin user record \"{adminUser}\" not found.");
      }

      return admin.Uid;
    }

    private static string ResolveConfigUid(VaultOnline vault, string configuration, string existingConfigUid)
    {
      if (!string.IsNullOrWhiteSpace(configuration))
      {
        var cfg = PamVaultHelpers.ResolveRecord(vault, configuration.Trim(), PamRecordTypes.Configuration);
        if (cfg != null)
        {
          return cfg.Uid;
        }

        throw new PamConnectionException($"PAM Configuration \"{configuration}\" not found.");
      }

      return existingConfigUid;
    }

    private static string ResolveExistingConfigUid(VaultOnline vault, string recordUid)
    {
      if (vault.TryGetRecordRotation(recordUid, out var rotation)
          && !string.IsNullOrEmpty(rotation.ConfigurationUid))
      {
        return rotation.ConfigurationUid;
      }

      foreach (var config in PamVaultHelpers.GetConfigurationRecords(vault).Values)
      {
        if (!config.FindTypedField("pamResources", null, out var field))
        {
          continue;
        }

        FieldPamResources resources = null;
        if (field is TypedField<FieldPamResources> typed && typed.Values.Count > 0)
        {
          resources = typed.Values[0];
        }
        else if (field.ObjectValue is FieldPamResources pam)
        {
          resources = pam;
        }

        if (resources?.ResourceRef == null)
        {
          continue;
        }

        if (resources.ResourceRef.Any(r => string.Equals(r, recordUid, StringComparison.Ordinal)))
        {
          return config.Uid;
        }
      }

      return null;
    }

    private static TypedRecord ResolveConnectionRecord(VaultOnline vault, string identifier)
    {
      var allowed = ConnectionRecordTypes
        .Concat(PamRecordTypes.Configuration)
        .Distinct(StringComparer.Ordinal)
        .ToArray();
      try
      {
        return PamVaultHelpers.ResolveRecord(vault, identifier, allowed);
      }
      catch (InvalidOperationException ex)
      {
        throw new PamConnectionException(ex.Message, ex);
      }
    }

    private static bool EnsureTrafficEncryptionSeed(TypedRecord record)
    {
      if (record.FindTypedField("trafficEncryptionSeed", null, out var existing))
      {
        var value = existing.GetValueAt(0)?.ToString();
        if (!string.IsNullOrEmpty(value))
        {
          return false;
        }

        if (existing is TypedField<string> typedEmpty)
        {
          typedEmpty.Values.Clear();
          typedEmpty.Values.Add(Convert.ToBase64String(CryptoUtils.GetRandomBytes(32)));
          return true;
        }
      }

      var seed = Convert.ToBase64String(CryptoUtils.GetRandomBytes(32));
      var seedField = new TypedField<string>("trafficEncryptionSeed") { Values = { seed } };
      if (SeedRecordTypes.Contains(record.TypeName ?? ""))
      {
        record.Fields.Add(seedField);
      }
      else
      {
        record.Custom.Add(seedField);
      }

      return true;
    }

    private static bool ApplyPamSettings(TypedRecord record, PamConnectionEditOptions options, bool connectionsOn)
    {
      var dirty = false;
      var protocolRequested = options.Protocol != null;
      var portRequested = options.ConnectionsOverridePort != null;
      var keyEventsRequested = options.KeyEvents != null;
      var scrollbackRequested = options.Scrollback != null;

      if (!protocolRequested && !portRequested && !keyEventsRequested && !scrollbackRequested && !connectionsOn)
      {
        return false;
      }

      var created = GetOrCreatePamSettings(record, out var settingsField, out var settings);
      if (created)
      {
        // marks dirty when creating pamSettings even if only scaffolding for --connections=on.
        dirty = true;
      }

      settings.Connection ??= new FieldPamConnectionSettings();
      settings.PortForward ??= new FieldPamPortForwardSettings();

      if (connectionsOn || PamRotationGraph.ConvertAllowedSetting(options.Connections) == true)
      {
        if (portRequested)
        {
          if (string.IsNullOrEmpty(options.ConnectionsOverridePort))
          {
            if (settings.Connection.Port != null)
            {
              settings.Connection.Port = null;
              dirty = true;
            }
          }
          else if (int.TryParse(options.ConnectionsOverridePort, out var port))
          {
            if (settings.Connection.Port != port)
            {
              settings.Connection.Port = port;
              dirty = true;
            }
          }
          else
          {
            throw new PamConnectionException("--connections-override-port must be an integer.");
          }
        }

        if (protocolRequested)
        {
          if (string.IsNullOrEmpty(options.Protocol))
          {
            if (!string.IsNullOrEmpty(settings.Connection.Protocol))
            {
              settings.Connection.Protocol = null;
              dirty = true;
            }
          }
          else
          {
            ValidateProtocol(options.Protocol);
            if (!string.Equals(settings.Connection.Protocol, options.Protocol, StringComparison.OrdinalIgnoreCase))
            {
              settings.Connection.Protocol = options.Protocol;
              dirty = true;
            }
          }
        }
      }
      else if (protocolRequested || portRequested)
      {
        throw new PamConnectionException(
          "Connection override port and protocol can be set only when connections are enabled with --connections=on.");
      }

      if (keyEventsRequested)
      {
        dirty |= ApplyKeyEvents(settings.Connection, options.KeyEvents);
      }

      if (scrollbackRequested)
      {
        dirty |= ApplyScrollback(settings.Connection, options.Scrollback);
      }

      if (dirty)
      {
        settingsField.Values.Clear();
        settingsField.Values.Add(settings);
      }

      return dirty;
    }

    /// <summary>
    /// Ensures a pamSettings typed field exists. Returns true when a new field was added.
    /// </summary>
    private static bool GetOrCreatePamSettings(
      TypedRecord record,
      out TypedField<FieldPamSettings> settingsField,
      out FieldPamSettings settings)
    {
      if (record.FindTypedField("pamSettings", null, out var field)
          && field is TypedField<FieldPamSettings> typed)
      {
        settingsField = typed;
        settings = typed.Values.FirstOrDefault() ?? new FieldPamSettings();
        if (typed.Values.Count == 0)
        {
          typed.Values.Add(settings);
          return true;
        }

        return false;
      }

      settings = new FieldPamSettings
      {
        Connection = new FieldPamConnectionSettings(),
        PortForward = new FieldPamPortForwardSettings(),
      };
      settingsField = new TypedField<FieldPamSettings>("pamSettings") { Values = { settings } };
      record.Custom.Add(settingsField);
      return true;
    }

    private static bool ApplyKeyEvents(FieldPamConnectionSettings connection, string keyEvents)
    {
      var converted = PamRotationGraph.ConvertAllowedSetting(keyEvents);
      if (string.Equals(keyEvents, "default", StringComparison.OrdinalIgnoreCase) || converted == null)
      {
        if (connection.RecordingIncludeKeys == null)
        {
          return false;
        }

        connection.RecordingIncludeKeys = null;
        return true;
      }

      if (connection.RecordingIncludeKeys == converted.Value)
      {
        return false;
      }

      connection.RecordingIncludeKeys = converted.Value;
      return true;
    }

    private static bool ApplyScrollback(FieldPamConnectionSettings connection, string scrollback)
    {
      if (scrollback == "")
      {
        if (connection.Scrollback == null)
        {
          return false;
        }

        connection.Scrollback = null;
        return true;
      }

      if (!int.TryParse(scrollback, out var value) || value < 0)
      {
        throw new PamConnectionException("--scrollback must be a non-negative integer or empty string.");
      }

      if (connection.Scrollback == value)
      {
        return false;
      }

      connection.Scrollback = value;
      return true;
    }

    private static void ValidateScrollback(
      string recordType,
      TypedRecord record,
      PamConnectionEditOptions options,
      bool connectionsOn)
    {
      if (options.Scrollback == null)
      {
        return;
      }

      HashSet<string> allowedProtocols;
      if (string.Equals(recordType, "pamDatabase", StringComparison.Ordinal))
      {
        allowedProtocols = CliCapableDbProtocols;
      }
      else if (string.Equals(recordType, "pamMachine", StringComparison.Ordinal)
               || string.Equals(recordType, "pamDirectory", StringComparison.Ordinal))
      {
        allowedProtocols = TerminalScrollbackProtocols;
      }
      else
      {
        throw new PamConnectionException(
          "--scrollback is only supported for pamDatabase, pamMachine, and pamDirectory records.");
      }

      var existingProtocol = "";
      if (record.FindTypedField("pamSettings", null, out var field)
          && field is TypedField<FieldPamSettings> typed
          && typed.Values.FirstOrDefault()?.Connection != null)
      {
        existingProtocol = typed.Values[0].Connection.Protocol ?? "";
      }

      var effectiveProtocol = connectionsOn && options.Protocol != null
        ? options.Protocol
        : existingProtocol;
      if (!allowedProtocols.Contains(effectiveProtocol))
      {
        throw new PamConnectionException(
          $"--scrollback is not supported for protocol \"{(string.IsNullOrEmpty(effectiveProtocol) ? "(unset)" : effectiveProtocol)}\" "
          + $"on {recordType} records. Allowed: {string.Join(", ", allowedProtocols.OrderBy(x => x))}.");
      }
    }

    private static void ValidateProtocol(string protocol)
    {
      if (string.IsNullOrEmpty(protocol))
      {
        return;
      }

      if (!DbProtocols.Contains(protocol) && !NonDbProtocols.Contains(protocol))
      {
        throw new PamConnectionException($"Unsupported protocol \"{protocol}\".");
      }
    }

    private static void ValidateTriState(string value, string optionName)
    {
      if (value == null)
      {
        return;
      }

      var normalized = value.Trim().ToLowerInvariant();
      if (normalized is not ("on" or "off" or "default"))
      {
        throw new PamConnectionException($"{optionName} must be on, off, or default.");
      }
    }
  }
}
