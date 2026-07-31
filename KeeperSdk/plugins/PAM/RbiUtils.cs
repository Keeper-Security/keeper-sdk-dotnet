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
  /// PAM Remote Browser Isolation (RBI) configuration.
  /// </summary>
  public static class RbiUtils
  {
    private static readonly HashSet<string> AutofillRecordTypes = new(StringComparer.Ordinal)
    {
      "login",
      "pamUser",
    };

    private static readonly HashSet<string> SessionPersistenceChoices = new(StringComparer.OrdinalIgnoreCase)
    {
      "none",
      "user",
      "resource",
      "default",
    };

    /// <summary>
    /// Configure Remote Browser Isolation settings on a pamRemoteBrowser record.
    /// </summary>
    public static async Task<PamRbiEditResult> EditRbiAsync(VaultOnline vault, PamRbiEditOptions options)
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
        throw new PamRbiException("Record parameter is required.");
      }

      ValidateTriState(options.RemoteBrowserIsolation, "--remote-browser-isolation");
      ValidateTriState(options.ConnectionsRecording, "--connections-recording");
      ValidateTriState(options.KeyEvents, "--key-events");
      ValidateTriState(options.AllowUrlNavigation, "--allow-url-navigation");
      ValidateTriState(options.IgnoreServerCert, "--ignore-server-cert");
      ValidateTriState(options.AllowFileUploads, "--allow-file-uploads");
      ValidateTriState(options.AllowFileDownloads, "--allow-file-downloads");
      ValidateTriState(options.AllowCopy, "--allow-copy");
      ValidateTriState(options.AllowPaste, "--allow-paste");
      ValidateTriState(options.DisableAudio, "--disable-audio");
      ValidateSessionPersistence(options.SessionPersistence);
      ValidateAudioChannels(options.AudioChannels);
      ValidateAudioBitDepth(options.AudioBitDepth);

      var hasRecordSettings = HasAnyRecordSetting(options);
      var hasGraphSettings = !string.IsNullOrWhiteSpace(options.Configuration)
                             || options.RemoteBrowserIsolation != null
                             || options.ConnectionsRecording != null;

      if (!hasRecordSettings && !hasGraphSettings)
      {
        throw new PamRbiException(
          "At least one parameter is required. "
          + "If the record is not linked to a PAM Configuration, --configuration is required.");
      }

      var auth = vault.Auth ?? throw new PamRbiException("Authentication is required.");
      var record = ResolveRbiRecord(vault, options.Record.Trim());
      if (record == null)
      {
        throw new PamRbiException($"Record \"{options.Record}\" not found.");
      }

      if (!string.Equals(record.TypeName, "pamRemoteBrowser", StringComparison.Ordinal))
      {
        throw new PamRbiException(
          $"Record {record.Uid} of type {record.TypeName} cannot be set up for RBI connections. "
          + "RBI connection records must be of type: pamRemoteBrowser");
      }

      var result = new PamRbiEditResult { RecordUid = record.Uid };

      var dirty = EnsureTrafficEncryptionSeed(record);
      dirty |= EnsureRemoteBrowserSettings(record, out var settingsField, out var connection);

      var connectionDirty = false;
      connectionDirty |= ApplyAutofillCredentials(vault, connection, options.AutofillCredentials);
      connectionDirty |= ApplyKeyEvents(connection, options.KeyEvents);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.AllowUrlManipulation),
        v => connection.AllowUrlManipulation = v, () => connection.AllowUrlManipulation,
        options.AllowUrlNavigation);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.IgnoreInitialSslCert),
        v => connection.IgnoreInitialSslCert = v, () => connection.IgnoreInitialSslCert,
        options.IgnoreServerCert);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.AllowFileUploads),
        v => connection.AllowFileUploads = v, () => connection.AllowFileUploads,
        options.AllowFileUploads);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.AllowFileDownloads),
        v => connection.AllowFileDownloads = v, () => connection.AllowFileDownloads,
        options.AllowFileDownloads);
      connectionDirty |= ApplyConnectionString(connection, options.AllowedUrls,
        v => connection.AllowedUrlPatterns = v, () => connection.AllowedUrlPatterns);
      connectionDirty |= ApplyConnectionString(connection, options.AllowedResourceUrls,
        v => connection.AllowedResourceUrlPatterns = v, () => connection.AllowedResourceUrlPatterns);
      connectionDirty |= ApplyConnectionString(connection, options.AutofillTargets,
        v => connection.AutofillConfiguration = v, () => connection.AutofillConfiguration);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.DisableCopy),
        v => connection.DisableCopy = v, () => connection.DisableCopy,
        options.AllowCopy, invert: true);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.DisablePaste),
        v => connection.DisablePaste = v, () => connection.DisablePaste,
        options.AllowPaste, invert: true);
      connectionDirty |= ApplyConnectionToggle(connection, nameof(connection.DisableAudio),
        v => connection.DisableAudio = v, () => connection.DisableAudio,
        options.DisableAudio);
      connectionDirty |= ApplyConnectionInt(connection, options.AudioChannels,
        v => connection.AudioChannels = v, () => connection.AudioChannels);
      connectionDirty |= ApplyConnectionInt(connection, options.AudioBitDepth,
        v => connection.AudioBps = v, () => connection.AudioBps);
      connectionDirty |= ApplyConnectionInt(connection, options.AudioSampleRate,
        v => connection.AudioSampleRate = v, () => connection.AudioSampleRate);
      connectionDirty |= ApplySessionPersistence(connection, options.SessionPersistence);

      if (connectionDirty)
      {
        settingsField.Values.Clear();
        settingsField.Values.Add(new FieldPamRemoteBrowserSettings { Connection = connection });
        dirty = true;
      }

      if (dirty)
      {
        await vault.UpdateRecord(record);
        result.RecordUpdated = true;

        if (!record.FindTypedField("trafficEncryptionSeed", null, out _))
        {
          throw new PamRbiException(
            $"Unable to add Seed to record {record.Uid}. Please make sure you have edit rights to the record.");
        }
      }

      if (!hasGraphSettings)
      {
        return result;
      }

      await ApplyGraphSettingsAsync(vault, auth, record, options, result);
      return result;
    }

    private static async Task ApplyGraphSettingsAsync(
      VaultOnline vault,
      IAuthentication auth,
      TypedRecord record,
      PamRbiEditOptions options,
      PamRbiEditResult result)
    {
      var existingConfigUid = ResolveExistingConfigUid(vault, record.Uid);
      var configUid = ResolveConfigUid(vault, options.Configuration, existingConfigUid);
      if (string.IsNullOrEmpty(configUid))
      {
        throw new PamRbiException("PAM Config record not found.");
      }

      result.ConfigUid = configUid;
      var graph = new PamRotationGraph(auth, configUid);
      await graph.LoadAsync();
      if (!graph.HasGraph)
      {
        throw new PamRbiException(
          "No valid PAM Configuration UID set. This must be set or supplied for connections to work. "
          + "List configurations with pam-config or pam config list.");
      }

      var resourceType = PamRotationGraph.GetResourceRefType(record.TypeName);

      if (!graph.ResourceBelongsToConfig(record.Uid))
      {
        await graph.LinkResourceToConfigAsync(record.Uid, resourceType);
      }

      if (!graph.ResourceBelongsToConfig(record.Uid))
      {
        result.Messages.Add(
          $"No PAM Configuration UID set. This must be set for connections to work. "
          + $"Use: pam-rbi edit {record.Uid} --configuration {configUid} --remote-browser-isolation=on");
        return;
      }

      AppendConfigPermissionWarnings(graph, configUid, options.Silent, result);

      // RBI enablement on the resource uses allowedSettings.connections
      string connectionsVal = null;
      string recordingVal = null;
      if (options.RemoteBrowserIsolation != null)
      {
        var current = FormatTriState(graph.GetResourceAllowedSetting(record.Uid, "connections"));
        if (!string.Equals(options.RemoteBrowserIsolation, current, StringComparison.OrdinalIgnoreCase))
        {
          connectionsVal = options.RemoteBrowserIsolation;
        }
      }

      if (options.ConnectionsRecording != null)
      {
        var current = FormatTriState(graph.GetResourceAllowedSetting(record.Uid, "sessionRecording"));
        if (!string.Equals(options.ConnectionsRecording, current, StringComparison.OrdinalIgnoreCase))
        {
          recordingVal = options.ConnectionsRecording;
        }
      }

      if (connectionsVal != null || recordingVal != null)
      {
        await graph.SetResourceConnectionAllowedAsync(
          record.Uid,
          resourceType,
          connections: connectionsVal,
          sessionRecording: recordingVal,
          allowedSettingsName: "allowedSettings");
        result.GraphUpdated = true;
      }
    }

    private static void AppendConfigPermissionWarnings(
      PamRotationGraph graph,
      string configUid,
      bool silent,
      PamRbiEditResult result)
    {
      var cfgConnections = FormatTriState(graph.GetConfigAllowedSetting("connections"));
      var cfgRbi = FormatTriState(graph.GetConfigAllowedSetting("remoteBrowserIsolation"));
      var cfgRecording = FormatTriState(graph.GetConfigAllowedSetting("sessionRecording"));

      if (string.Equals(cfgConnections, "on", StringComparison.OrdinalIgnoreCase)
          && string.Equals(cfgRbi, "on", StringComparison.OrdinalIgnoreCase)
          && string.Equals(cfgRecording, "on", StringComparison.OrdinalIgnoreCase))
      {
        return;
      }

      if (silent)
      {
        return;
      }

      var command = $"pam-connection edit {configUid}";
      if (!string.Equals(cfgConnections, "on", StringComparison.OrdinalIgnoreCase))
      {
        command += " --connections=on";
      }

      if (!string.Equals(cfgRbi, "on", StringComparison.OrdinalIgnoreCase))
      {
        command += " --remote-browser-isolation=on";
      }

      if (!string.Equals(cfgRecording, "on", StringComparison.OrdinalIgnoreCase))
      {
        command += " --connections-recording=on";
      }

      result.Messages.Add(
        $"Some settings may be denied by PAM Configuration: {configUid} "
        + $"[ --connections={cfgConnections} --remote-browser-isolation={cfgRbi} "
        + $"--connections-recording={cfgRecording} ]. "
        + $"To enable these settings for the configuration run: {command}");
    }

    private static bool HasAnyRecordSetting(PamRbiEditOptions options)
    {
      return !string.IsNullOrWhiteSpace(options.AutofillCredentials)
             || options.KeyEvents != null
             || options.AllowUrlNavigation != null
             || options.IgnoreServerCert != null
             || options.AllowFileUploads != null
             || options.AllowFileDownloads != null
             || HasMultiValueOption(options.AllowedUrls)
             || HasMultiValueOption(options.AllowedResourceUrls)
             || HasMultiValueOption(options.AutofillTargets)
             || options.AllowCopy != null
             || options.AllowPaste != null
             || options.DisableAudio != null
             || options.AudioChannels != null
             || options.AudioBitDepth != null
             || options.AudioSampleRate != null
             || options.SessionPersistence != null;
    }

    /// <summary>
    /// True when the caller explicitly provided a multi-value option.
    /// Empty sequences from the CLI binder are treated as not provided.
    /// An explicit empty string (e.g. --allowed-urls "") is provided and clears the field.
    /// </summary>
    private static bool HasMultiValueOption(IList<string> values)
    {
      if (values == null || values.Count == 0)
      {
        return false;
      }

      return values.Any(v => v != null);
    }

    private static TypedRecord ResolveRbiRecord(VaultOnline vault, string identifier)
    {
      try
      {
        return PamVaultHelpers.ResolveRecord(vault, identifier, new[] { "pamRemoteBrowser" });
      }
      catch (InvalidOperationException ex)
      {
        throw new PamRbiException(ex.Message, ex);
      }
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

        throw new PamRbiException($"PAM Configuration \"{configuration}\" not found.");
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
      record.Fields.Add(new TypedField<string>("trafficEncryptionSeed") { Values = { seed } });
      return true;
    }

    private static bool EnsureRemoteBrowserSettings(
      TypedRecord record,
      out TypedField<FieldPamRemoteBrowserSettings> settingsField,
      out FieldPamRemoteBrowserConnectionSettings connection)
    {
      var dirty = false;
      if (record.FindTypedField("pamRemoteBrowserSettings", null, out var field)
          && field is TypedField<FieldPamRemoteBrowserSettings> typed)
      {
        settingsField = typed;
        var settings = typed.Values.FirstOrDefault() ?? new FieldPamRemoteBrowserSettings();
        if (typed.Values.Count == 0)
        {
          typed.Values.Add(settings);
          dirty = true;
        }

        if (settings.Connection == null)
        {
          settings.Connection = new FieldPamRemoteBrowserConnectionSettings { Protocol = "http" };
          dirty = true;
        }
        else if (string.IsNullOrEmpty(settings.Connection.Protocol))
        {
          settings.Connection.Protocol = "http";
          dirty = true;
        }

        connection = settings.Connection;
        return dirty;
      }

      connection = new FieldPamRemoteBrowserConnectionSettings
      {
        Protocol = "http",
        HttpCredentialsUid = "",
      };
      settingsField = new TypedField<FieldPamRemoteBrowserSettings>("pamRemoteBrowserSettings")
      {
        Values = { new FieldPamRemoteBrowserSettings { Connection = connection } },
      };
      record.Fields.Add(settingsField);
      return true;
    }

    private static bool ApplyAutofillCredentials(
      VaultOnline vault,
      FieldPamRemoteBrowserConnectionSettings connection,
      string autofill)
    {
      if (string.IsNullOrWhiteSpace(autofill))
      {
        return false;
      }

      TypedRecord autofillRecord;
      try
      {
        autofillRecord = PamVaultHelpers.ResolveRecord(vault, autofill.Trim(), AutofillRecordTypes);
      }
      catch (InvalidOperationException ex)
      {
        throw new PamRbiException(ex.Message, ex);
      }

      if (autofillRecord == null)
      {
        throw new PamRbiException($"Record \"{autofill}\" not found.");
      }

      if (!AutofillRecordTypes.Contains(autofillRecord.TypeName ?? ""))
      {
        throw new PamRbiException(
          $"Autofill credentials record \"{autofillRecord.Uid}\" can not be linked. "
          + "RBI autofill credential records must be of type \"login\" or \"pamUser\"");
      }

      if (string.Equals(connection.HttpCredentialsUid, autofillRecord.Uid, StringComparison.Ordinal))
      {
        return false;
      }

      connection.HttpCredentialsUid = autofillRecord.Uid;
      return true;
    }

    private static bool ApplyKeyEvents(FieldPamRemoteBrowserConnectionSettings connection, string keyEvents)
    {
      return ApplyConnectionToggle(
        connection,
        nameof(connection.RecordingIncludeKeys),
        v => connection.RecordingIncludeKeys = v,
        () => connection.RecordingIncludeKeys,
        keyEvents);
    }

    private static bool ApplySessionPersistence(
      FieldPamRemoteBrowserConnectionSettings connection,
      string value)
    {
      if (value == null)
      {
        return false;
      }

      if (string.Equals(value, "default", StringComparison.OrdinalIgnoreCase))
      {
        if (connection.SessionPersistence == null)
        {
          return false;
        }

        connection.SessionPersistence = null;
        return true;
      }

      var normalized = value.Trim().ToLowerInvariant();
      if (string.Equals(connection.SessionPersistence, normalized, StringComparison.Ordinal))
      {
        return false;
      }

      connection.SessionPersistence = normalized;
      return true;
    }

    private static bool ApplyConnectionToggle(
      FieldPamRemoteBrowserConnectionSettings connection,
      string fieldName,
      Action<bool?> assign,
      Func<bool?> current,
      string settingValue,
      bool invert = false)
    {
      if (settingValue == null || connection == null)
      {
        return false;
      }

      _ = fieldName;
      var existing = current();
      if (string.Equals(settingValue, "default", StringComparison.OrdinalIgnoreCase))
      {
        if (existing == null)
        {
          return false;
        }

        assign(null);
        return true;
      }

      var target = string.Equals(settingValue, "on", StringComparison.OrdinalIgnoreCase)
        ? !invert
        : invert;

      if (existing == target)
      {
        return false;
      }

      assign(target);
      return true;
    }

    private static bool ApplyConnectionString(
      FieldPamRemoteBrowserConnectionSettings connection,
      IList<string> values,
      Action<string> assign,
      Func<string> current)
    {
      // null / empty = option not provided (do not touch sibling fields).
      if (values == null || values.Count == 0 || connection == null)
      {
        return false;
      }

      var incoming = NormalizeMultiValues(values);
      var explicitClear = values.Count > 0
                          && values.All(v => v != null && string.IsNullOrWhiteSpace(v));

      // Explicit clear: --allowed-urls "" (or only whitespace / empty tokens).
      if (explicitClear || (incoming.Count == 0 && values.Any(v => v != null)))
      {
        if (string.IsNullOrEmpty(current()))
        {
          return false;
        }

        assign("");
        return true;
      }

      if (incoming.Count == 0)
      {
        return false;
      }

      // Merge with existing patterns so each edit appends instead of replacing.
      var merged = new List<string>();
      var seen = new HashSet<string>(StringComparer.Ordinal);
      foreach (var pattern in NormalizeMultiValues(new[] { current() ?? "" }).Concat(incoming))
      {
        if (string.IsNullOrEmpty(pattern) || !seen.Add(pattern))
        {
          continue;
        }

        merged.Add(pattern);
      }

      var newValue = string.Join("\n", merged);
      if (string.Equals(current() ?? "", newValue, StringComparison.Ordinal))
      {
        return false;
      }

      assign(newValue);
      return true;
    }

    /// <summary>
    /// Splits CLI multi-values on newlines/commas and trims whitespace/trailing commas.
    /// </summary>
    private static List<string> NormalizeMultiValues(IEnumerable<string> values)
    {
      var result = new List<string>();
      if (values == null)
      {
        return result;
      }

      foreach (var raw in values)
      {
        if (raw == null)
        {
          continue;
        }

        foreach (var part in raw.Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
          var trimmed = part.Trim().Trim('"', '\'').Trim();
          if (trimmed.Length > 0)
          {
            result.Add(trimmed);
          }
        }
      }

      return result;
    }

    private static bool ApplyConnectionInt(
      FieldPamRemoteBrowserConnectionSettings connection,
      int? value,
      Action<int?> assign,
      Func<int?> current)
    {
      if (value == null || connection == null)
      {
        return false;
      }

      if (current() == value)
      {
        return false;
      }

      assign(value);
      return true;
    }

    private static string FormatTriState(bool? value)
    {
      return value == null ? "default" : value.Value ? "on" : "off";
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
        throw new PamRbiException($"{optionName} must be on, off, or default.");
      }
    }

    private static void ValidateSessionPersistence(string value)
    {
      if (value == null)
      {
        return;
      }

      if (!SessionPersistenceChoices.Contains(value.Trim()))
      {
        throw new PamRbiException(
          "--session-persistence must be none, user, resource, or default.");
      }
    }

    private static void ValidateAudioChannels(int? value)
    {
      if (value == null)
      {
        return;
      }

      if (value is not (1 or 2))
      {
        throw new PamRbiException("--audio-channels must be 1 or 2.");
      }
    }

    private static void ValidateAudioBitDepth(int? value)
    {
      if (value == null)
      {
        return;
      }

      if (value is not (8 or 16))
      {
        throw new PamRbiException("--audio-bit-depth must be 8 or 16.");
      }
    }
  }
}
