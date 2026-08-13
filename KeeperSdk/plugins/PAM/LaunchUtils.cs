using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Preflight checks for PAM launch. Resolves record, protocol, config, credential, host, and gateway.
  /// Does not start an interactive session.
  /// </summary>
  public static class LaunchUtils
  {
    private static readonly HashSet<string> LaunchRecordTypes = new(StringComparer.Ordinal)
    {
      "pamMachine",
      "pamDatabase",
      "pamDirectory",
    };

    private static readonly HashSet<string> TerminalProtocols = new(StringComparer.OrdinalIgnoreCase)
    {
      "ssh",
      "telnet",
      "kubernetes",
      "mysql",
      "postgresql",
      "sql-server",
      "sqlserver",
    };

    /// <summary>
    /// Run launch preflight and return what was resolved.
    /// </summary>
    public static async Task<PamLaunchPrepareResult> PrepareAsync(VaultOnline vault, PamLaunchOptions options)
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
        throw new PamLaunchException("Record is required.");
      }

      if (!string.IsNullOrWhiteSpace(options.Host) && !string.IsNullOrWhiteSpace(options.HostRecord))
      {
        throw new PamLaunchException("Use either --host or --host-record, not both.");
      }

      var auth = vault.Auth ?? throw new PamLaunchException("Authentication is required.");
      var debug = options.Debug;
      DebugLog(debug, $"record input: {options.Record}");

      var record = ResolveLaunchRecord(vault, options.Record.Trim());
      DebugLog(debug, $"record resolved: uid={record.Uid} type={record.TypeName} title={record.Title}");

      var protocol = ResolveProtocol(record);
      DebugLog(debug, $"protocol: {(string.IsNullOrEmpty(protocol) ? "(unset)" : protocol)}");
      ValidateProtocol(protocol);
      ValidateHostSupplyOptions(record, options.Host, options.HostRecord);
      ValidateCredentialSupplyOptions(record, options.Credential);

      // Without a config we can't check the connections setting — continue anyway.
      var configUid = ResolveConfigUid(vault, record.Uid, debug);
      DebugLog(debug, $"config uid: {(string.IsNullOrEmpty(configUid) ? "(not found)" : configUid)}");

      PamRotationGraph graph = null;
      if (!string.IsNullOrEmpty(configUid))
      {
        try
        {
          graph = new PamRotationGraph(auth, configUid);
          await graph.LoadAsync();
          DebugLog(debug,
            $"graph loaded: hasGraph={graph.HasGraph} connectionsAllowed={graph.GetConfigAllowedSetting("connections")}");
          EnsureConnectionsAllowed(graph, configUid);
        }
        catch (PamLaunchException)
        {
          throw;
        }
        catch (Exception ex)
        {
          DebugLog(debug, $"graph load skipped: {ex.GetType().Name}: {ex.Message}");
          graph = null;
        }
      }
      else
      {
        DebugLog(debug, "graph skipped: no config uid");
      }

      var launchCredential = ResolveLaunchCredential(vault, graph, record, options.Credential);
      DebugLog(debug, launchCredential == null
        ? "launch credential: (none)"
        : $"launch credential: {launchCredential.Uid} ({launchCredential.Title})");

      var (host, port, hostSource) = ResolveLaunchHost(vault, record, options.Host, options.HostRecord);
      DebugLog(debug, string.IsNullOrEmpty(host)
        ? "host: (none)"
        : $"host: {host}{(port.HasValue ? $":{port}" : "")} source={hostSource}");

      var gateway = ResolveLaunchGateway(
        vault,
        options.AvailableControllers,
        options.Gateway,
        configUid,
        record.Uid,
        debug);
      var gatewayOnline = await IsGatewayOnlineAsync(auth, gateway?.ControllerUid);
      DebugLog(debug, $"gateway online: {(gatewayOnline.HasValue ? gatewayOnline.Value.ToString() : "unknown")}");

      return new PamLaunchPrepareResult
      {
        Record = record,
        Protocol = protocol,
        ConfigUid = configUid,
        LaunchCredential = launchCredential,
        Host = host,
        Port = port,
        HostSource = hostSource,
        GatewayUid = gateway?.ControllerUid,
        GatewayName = gateway?.ControllerName,
        GatewayOnline = gatewayOnline,
      };
    }

    private static TypedRecord ResolveLaunchRecord(VaultOnline vault, string identifier)
    {
      var term = identifier.Trim();

      // UID first; only accept pamMachine / pamDatabase / pamDirectory.
      if (LooksLikeRecordUid(term))
      {
        if (PamVaultHelpers.TryGetTypedRecord(vault, term, out var byUid))
        {
          if (LaunchRecordTypes.Contains(byUid.TypeName ?? ""))
          {
            return byUid;
          }

          throw new PamLaunchException(
            $"Record {term} of type \"{byUid.TypeName}\" is not a machine record type "
            + "(pamMachine, pamDirectory, pamDatabase)");
        }

        if (vault.TryGetKeeperRecord(term, out _))
        {
          throw new PamLaunchException(
            $"Record {term} exists in the vault but is not a typed record. pam-launch requires a typed PAM resource.");
        }

        throw new PamLaunchException(
          $"Record not found: {term}. "
          + "It is not in the local vault sync. Run sync-down, then list/search to confirm the UID.");
      }

      var direct = PamVaultHelpers.ResolveRecord(vault, term, LaunchRecordTypes);
      if (direct != null)
      {
        return direct;
      }

      var allPam = vault.KeeperRecords
        .OfType<TypedRecord>()
        .Where(x => LaunchRecordTypes.Contains(x.TypeName ?? ""))
        .ToList();
      if (allPam.Count == 0)
      {
        throw new PamLaunchException("No PAM resources found. Sync vault data and ensure PAM records exist.");
      }

      var matches = allPam.Where(x => MatchesRecordSearch(x, term)).ToList();
      if (matches.Count == 1)
      {
        return matches[0];
      }

      if (matches.Count > 1)
      {
        var samples = string.Join(", ", matches.Take(5).Select(x => $"{x.Uid} ({x.Title})"));
        throw new PamLaunchException(
          $"Record \"{identifier}\" is ambiguous ({matches.Count} matches). Use record UID. Matches: {samples}");
      }

      throw new PamLaunchException($"Record not found: {identifier}");
    }

    private static bool LooksLikeRecordUid(string value)
    {
      if (string.IsNullOrEmpty(value) || value.Length != 22)
      {
        return false;
      }

      foreach (var c in value)
      {
        if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-'))
        {
          return false;
        }
      }

      return true;
    }

    private static bool MatchesRecordSearch(TypedRecord record, string term)
    {
      if (string.IsNullOrEmpty(term))
      {
        return false;
      }

      if (!string.IsNullOrEmpty(record.Title)
          && record.Title.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
      {
        return true;
      }

      var (host, _, _) = TryGetRecordHost(record);
      return !string.IsNullOrEmpty(host)
             && host.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string ResolveProtocol(TypedRecord record)
    {
      FieldPamConnectionSettings connection = null;
      if (record.FindTypedField("pamSettings", null, out var field)
          && field is TypedField<FieldPamSettings> typed
          && typed.Values.Count > 0)
      {
        connection = typed.Values[0]?.Connection;
        var protocol = connection?.Protocol?.Trim();
        if (!string.IsNullOrEmpty(protocol))
        {
          return CanonicalizeProtocol(protocol);
        }
      }

      // pamDatabase often leaves protocol blank — try databaseType / default ports.
      if (string.Equals(record.TypeName, "pamDatabase", StringComparison.Ordinal))
      {
        var inferred = InferDatabaseProtocol(connection, record);
        if (!string.IsNullOrEmpty(inferred))
        {
          return inferred;
        }
      }

      return null;
    }

    private static string CanonicalizeProtocol(string protocol)
    {
      if (string.IsNullOrWhiteSpace(protocol))
      {
        return protocol;
      }

      var lower = protocol.Trim().ToLowerInvariant();
      return lower switch
      {
        "sqlserver" => "sql-server",
        "mssql" => "sql-server",
        "postgres" => "postgresql",
        _ => lower,
      };
    }

    private static string InferDatabaseProtocol(FieldPamConnectionSettings connection, TypedRecord record)
    {
      var dbType = connection?.DatabaseType?.Trim().ToLowerInvariant() ?? "";
      if (dbType.Contains("mysql"))
      {
        return "mysql";
      }

      if (dbType.Contains("postgres"))
      {
        return "postgresql";
      }

      if (dbType.Contains("sql server") || dbType.Contains("sqlserver") || dbType.Contains("mssql"))
      {
        return "sql-server";
      }

      var (_, port, _) = TryGetRecordHost(record);
      return port switch
      {
        3306 => "mysql",
        5432 => "postgresql",
        1433 => "sql-server",
        _ => null,
      };
    }

    private static void ValidateProtocol(string protocol)
    {
      if (string.IsNullOrEmpty(protocol) || !TerminalProtocols.Contains(protocol))
      {
        var shown = string.IsNullOrEmpty(protocol) ? "(unset)" : protocol;
        throw new PamLaunchException(
          $"pam-launch only supports terminal protocols (ssh, telnet, kubernetes, mysql, postgresql, sql-server). "
          + $"Protocol {shown} is not supported; use Web Vault for RDP/VNC/RBI etc.");
      }
    }

    private static void ValidateHostSupplyOptions(TypedRecord record, string host, string hostRecord)
    {
      if (string.IsNullOrWhiteSpace(host) && string.IsNullOrWhiteSpace(hostRecord))
      {
        return;
      }

      if (!IsAllowSupplyHost(record))
      {
        throw new PamLaunchException(
          "--host / --host-record requires allowSupplyHost to be enabled on the record. "
          + "(Web Vault: Record > Allow shared users to select their own host and credential)");
      }
    }

    private static void ValidateCredentialSupplyOptions(TypedRecord record, string credential)
    {
      if (string.IsNullOrWhiteSpace(credential))
      {
        return;
      }

      if (IsAllowSupplyHost(record) || IsAllowSupplyUser(record))
      {
        return;
      }

      throw new PamLaunchException(
        "--credential requires allowSupplyUser or allowSupplyHost to be enabled on the record.");
    }

    private static bool IsAllowSupplyHost(TypedRecord record)
    {
      return TryGetPamSettings(record, out var settings) && settings.AllowSupplyHost == true;
    }

    private static bool IsAllowSupplyUser(TypedRecord record)
    {
      return TryGetPamSettings(record, out var settings) && settings.Connection?.AllowSupplyUser == true;
    }

    private static bool TryGetPamSettings(TypedRecord record, out FieldPamSettings settings)
    {
      settings = null;
      if (record.FindTypedField("pamSettings", null, out var field)
          && field is TypedField<FieldPamSettings> typed
          && typed.Values.Count > 0)
      {
        settings = typed.Values[0];
        return settings != null;
      }

      return false;
    }

    private static void DebugLog(bool debug, string message)
    {
      if (debug)
      {
        Console.WriteLine($"[pam-launch] {message}");
      }
    }

    private static string ResolveConfigUid(VaultOnline vault, string recordUid, bool debug = false)
    {
      if (vault.TryGetRecordRotation(recordUid, out var rotation)
          && !string.IsNullOrEmpty(rotation.ConfigurationUid))
      {
        DebugLog(debug, $"config from rotation cache: {rotation.ConfigurationUid}");
        return rotation.ConfigurationUid;
      }

      DebugLog(debug, "config: not in rotation cache, scanning pam configuration records...");
      var configs = PamVaultHelpers.GetConfigurationRecords(vault);
      DebugLog(debug, $"config: {configs.Count} pam*Configuration record(s) in vault");

      foreach (var config in configs.Values)
      {
        if (!PamVaultHelpers.TryGetPamResources(config, out var resources)
            || resources.ResourceRef == null)
        {
          continue;
        }

        if (resources.ResourceRef.Any(x => string.Equals(x, recordUid, StringComparison.Ordinal)))
        {
          DebugLog(debug,
            $"config from pamResources.resourceRef: {config.Uid} (controllerUid={resources.ControllerUid ?? "(empty)"})");
          return config.Uid;
        }
      }

      DebugLog(debug, "config: not found (rotation cache miss + no pamResources.resourceRef link)");
      return null;
    }

    // Abort only if connections is explicitly turned off on the config.
    private static void EnsureConnectionsAllowed(PamRotationGraph graph, string configUid)
    {
      if (graph == null || !graph.HasGraph)
      {
        return;
      }

      if (graph.GetConfigAllowedSetting("connections") == false)
      {
        throw new PamLaunchException(
          $"pam-launch aborted: connections are disabled by the PAM configuration for {configUid}.");
      }
    }

    private static TypedRecord ResolveLaunchCredential(
      VaultOnline vault,
      PamRotationGraph graph,
      TypedRecord record,
      string credential)
    {
      if (!string.IsNullOrWhiteSpace(credential))
      {
        var user = PamVaultHelpers.ResolveRecord(vault, credential.Trim(), new[] { "pamUser" });
        if (user == null)
        {
          throw new PamLaunchException($"Launch credential record \"{credential}\" was not found.");
        }

        return user;
      }

      var launchUid = graph?.GetLaunchCredentialUids(record.Uid).FirstOrDefault();
      if (string.IsNullOrEmpty(launchUid)
          && TryGetPamSettings(record, out var settings)
          && settings.Connection?.UserRecords != null
          && settings.Connection.UserRecords.Count > 0)
      {
        // No DAG launch user — take the first user listed on pamSettings.
        launchUid = settings.Connection.UserRecords[0];
      }

      if (string.IsNullOrEmpty(launchUid))
      {
        return null;
      }

      return PamVaultHelpers.ResolveRecord(vault, launchUid, new[] { "pamUser" });
    }

    private static (string Host, int? Port, string Source) ResolveLaunchHost(
      VaultOnline vault,
      TypedRecord resourceRecord,
      string customHost,
      string hostRecord)
    {
      if (!string.IsNullOrWhiteSpace(customHost))
      {
        var (host, port) = ParseHostAndPort(customHost.Trim());
        return (host, port, "--host");
      }

      if (!string.IsNullOrWhiteSpace(hostRecord))
      {
        var hostRecordTyped = ResolveHostRecord(vault, hostRecord.Trim());
        var (host, port, _) = TryGetRecordHost(hostRecordTyped);
        if (string.IsNullOrEmpty(host))
        {
          throw new PamLaunchException(
            $"Host record \"{hostRecord}\" does not contain a host/pamHostname field.");
        }

        return (host, port, "--host-record");
      }

      var fromResource = TryGetRecordHost(resourceRecord);
      return (fromResource.Host, fromResource.Port, "record");
    }

    private static TypedRecord ResolveHostRecord(VaultOnline vault, string identifier)
    {
      if (vault.TryGetKeeperRecord(identifier, out var keeper) && keeper is TypedRecord typedByUid)
      {
        return typedByUid;
      }

      var records = vault.KeeperRecords
        .OfType<TypedRecord>()
        .Where(x => string.Equals(x.Title, identifier, StringComparison.OrdinalIgnoreCase))
        .ToList();
      if (records.Count == 1)
      {
        return records[0];
      }

      if (records.Count > 1)
      {
        throw new PamLaunchException($"Host record \"{identifier}\" is ambiguous. Use record UID.");
      }

      throw new PamLaunchException($"Host record \"{identifier}\" was not found.");
    }

    private static (string Host, int? Port, string Source) TryGetRecordHost(TypedRecord record)
    {
      foreach (var field in record.Fields.Concat(record.Custom))
      {
        if (field == null)
        {
          continue;
        }

        var fieldType = field.FieldName;
        if (!string.Equals(fieldType, "pamHostname", StringComparison.Ordinal)
            && !string.Equals(fieldType, "host", StringComparison.Ordinal))
        {
          continue;
        }

        if (field.ObjectValue is FieldTypeHost hostObject
            && !string.IsNullOrWhiteSpace(hostObject.HostName))
        {
          int? parsedPort = int.TryParse(hostObject.Port, out var p) ? p : null;
          return (hostObject.HostName.Trim(), parsedPort, fieldType);
        }

        var text = field.GetValueAt(0)?.ToString();
        if (string.IsNullOrWhiteSpace(text))
        {
          continue;
        }

        var (host, port) = ParseHostAndPortLoose(text.Trim());
        if (!string.IsNullOrWhiteSpace(host))
        {
          return (host, port, fieldType);
        }
      }

      return (null, null, null);
    }

    // Resolve gateway: --gateway override, else pamResources.controllerUid on the config.
    private static PamController ResolveLaunchGateway(
      VaultOnline vault,
      IList<PamController> controllers,
      string gatewayOption,
      string configUid,
      string recordUid,
      bool debug = false)
    {
      var list = controllers?.ToList() ?? new List<PamController>();
      DebugLog(debug, $"gateway: cached controllers={list.Count}");

      if (!string.IsNullOrWhiteSpace(gatewayOption))
      {
        DebugLog(debug, $"gateway: using --gateway '{gatewayOption}'");
        var byOption = GatewayUtils.FindGateway(list, gatewayOption.Trim());
        if (byOption == null)
        {
          var nameMatches = list.Count(c =>
            string.Equals(c.ControllerName, gatewayOption.Trim(), StringComparison.OrdinalIgnoreCase));
          if (nameMatches > 1)
          {
            throw new PamGatewayAmbiguousException(gatewayOption.Trim());
          }

          throw new PamGatewayNotFoundException(gatewayOption.Trim());
        }

        DebugLog(debug, $"gateway: override resolved {byOption.ControllerUid} ({byOption.ControllerName})");
        return byOption;
      }

      string controllerUid = null;
      if (!string.IsNullOrEmpty(configUid)
          && PamVaultHelpers.TryGetPamResources(vault, configUid, out var resources)
          && !string.IsNullOrEmpty(resources.ControllerUid))
      {
        controllerUid = resources.ControllerUid;
        DebugLog(debug, $"gateway: from config pamResources.controllerUid => {controllerUid}");
      }
      else
      {
        DebugLog(debug,
          $"gateway: no controllerUid on config {(configUid ?? "(none)")}");
      }

      if (!string.IsNullOrEmpty(controllerUid))
      {
        var byUid = list.FirstOrDefault(c =>
          string.Equals(c.ControllerUid, controllerUid, StringComparison.Ordinal));
        if (byUid != null)
        {
          DebugLog(debug, $"gateway: matched cached controller {byUid.ControllerUid} ({byUid.ControllerName})");
          return byUid;
        }

        DebugLog(debug, $"gateway: using config controllerUid (not in cache): {controllerUid}");
        return new PamController
        {
          ControllerUid = controllerUid,
          ControllerName = controllerUid,
        };
      }

      if (list.Count == 1)
      {
        DebugLog(debug, $"gateway: fallback to only cached controller {list[0].ControllerUid}");
        return list[0];
      }

      DebugLog(debug,
        $"gateway: FAILED — configUid={(configUid ?? "(null)")}, controllerUid=(null), cachedControllers={list.Count}");

      if (list.Count == 0)
      {
        throw new PamGatewayException(
          $"No gateway found for record {recordUid}. Run pam-sync-down and check gateway setup.");
      }

      throw new PamGatewayException(
        $"No gateway found for record {recordUid}. "
        + "Specify one with --gateway <gateway uid>, or ensure the PAM configuration has a controller.");
    }

    private static async Task<bool?> IsGatewayOnlineAsync(IAuthentication auth, string gatewayUid)
    {
      if (auth == null || string.IsNullOrEmpty(gatewayUid))
      {
        return null;
      }

      try
      {
        var online = await RouterUtils.GetConnectedGatewaysAsync(auth);
        if (online?.Controllers == null)
        {
          return false;
        }

        var expected = gatewayUid.Base64UrlDecode();
        return online.Controllers.Any(c =>
          c.ControllerUid != null
          && c.ControllerUid.Length > 0
          && c.ControllerUid.ToByteArray().SequenceEqual(expected));
      }
      catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or KeeperApiException)
      {
        return null;
      }
    }

    private static (string Host, int Port) ParseHostAndPort(string value)
    {
      if (string.IsNullOrWhiteSpace(value))
      {
        throw new PamLaunchException("Host cannot be empty.");
      }

      // [ipv6]:port
      if (value.StartsWith("[", StringComparison.Ordinal))
      {
        var end = value.IndexOf(']');
        if (end < 0 || end + 1 >= value.Length || value[end + 1] != ':')
        {
          throw new PamLaunchException(
            $"Invalid host \"{value}\". For IPv6 use [address]:port, like [::1]:22.");
        }

        var host6 = value.Substring(1, end - 1);
        if (!int.TryParse(value.Substring(end + 2), out var port6) || port6 is < 1 or > 65535)
        {
          throw new PamLaunchException($"Invalid port in \"{value}\". Use a number from 1 to 65535.");
        }

        return (host6, port6);
      }

      // More than one colon usually means IPv6 — ask for brackets.
      if (value.IndexOf(':') != value.LastIndexOf(':'))
      {
        throw new PamLaunchException(
          $"Invalid host \"{value}\". For IPv6 use [address]:port, like [::1]:22.");
      }

      var index = value.LastIndexOf(':');
      if (index <= 0 || index == value.Length - 1)
      {
        throw new PamLaunchException(
          $"Invalid host \"{value}\". Use host:port, like 192.168.1.1:22 or [::1]:22.");
      }

      var host = value.Substring(0, index).Trim();
      if (!int.TryParse(value.Substring(index + 1), out var port) || port is < 1 or > 65535)
      {
        throw new PamLaunchException($"Invalid port in \"{value}\". Use a number from 1 to 65535.");
      }

      if (string.IsNullOrWhiteSpace(host))
      {
        throw new PamLaunchException("Host cannot be empty.");
      }

      return (host, port);
    }

    private static (string Host, int? Port) ParseHostAndPortLoose(string value)
    {
      var index = value.LastIndexOf(':');
      if (index > 0 && index < value.Length - 1)
      {
        var host = value.Substring(0, index).Trim();
        if (int.TryParse(value.Substring(index + 1), out var port) && !string.IsNullOrWhiteSpace(host))
        {
          return (host, port);
        }
      }

      return (value.Trim(), null);
    }
  }
}
