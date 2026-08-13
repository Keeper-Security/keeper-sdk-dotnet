using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using GraphSyncProto = GraphSync;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;
using RouterProto = Router;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// Rotation-scoped PAM linking graph (resource↔config, user↔resource ACL/LINK edges).
  /// </summary>
  public sealed class PamRotationGraph
  {
    private readonly IAuthentication _auth;
    private readonly string _configUid;
    private readonly Dictionary<string, PamGraphVertex> _vertices = new(StringComparer.Ordinal);
    private readonly List<GraphSyncProto.GraphSyncData> _pendingSave = new();

    public PamRotationGraph(IAuthentication auth, string configUid)
    {
      _auth = auth ?? throw new ArgumentNullException(nameof(auth));
      _configUid = configUid ?? throw new ArgumentNullException(nameof(configUid));
    }

    public string ConfigUid => _configUid;

    public bool HasGraph => _vertices.Count > 0;

    public async Task LoadAsync()
    {
      _vertices.Clear();
      _pendingSave.Clear();

      var data = await PamGraphSyncClient.MultiSyncAsync(_auth, _configUid);
      var linkCount = 0;
      var aclCount = 0;
      var dataCount = 0;
      var otherCount = 0;

      foreach (var item in data)
      {
        var edge = item.Data;
        if (edge == null)
        {
          continue;
        }

        var tailUid = edge.Ref?.Value?.ToByteArray().Base64UrlEncode();
        if (string.IsNullOrEmpty(tailUid))
        {
          continue;
        }

        var headUid = edge.ParentRef?.Value?.ToByteArray().Base64UrlEncode();
        if (string.IsNullOrEmpty(headUid))
        {
          headUid = tailUid;
        }

        if (edge.Type == GraphSyncProto.GraphSyncDataType.GseDeletion)
        {
          if (_vertices.TryGetValue(tailUid, out var deletedTail))
          {
            if (IsMetaPath(edge.Path))
            {
              deletedTail.ClearDataEdge();
            }

            deletedTail.RemoveEdge(headUid, PamGraphEdgeType.Link);
            deletedTail.RemoveEdge(headUid, PamGraphEdgeType.Acl);
            deletedTail.RemoveEdge(headUid, PamGraphEdgeType.Key);
          }

          continue;
        }

        var tail = GetOrCreateVertex(tailUid, edge.Ref?.Type ?? GraphSyncProto.RefType.RftGeneral);
        GetOrCreateVertex(headUid, edge.ParentRef?.Type ?? GraphSyncProto.RefType.RftGeneral);

        // DATA edges carry vertex meta (allowedSettings)
        // Previously skipped here, which made all connection/rotation flags appear Disabled.
        if (edge.Type == GraphSyncProto.GraphSyncDataType.GseData)
        {
          dataCount++;
          var path = string.IsNullOrEmpty(edge.Path) ? "meta" : edge.Path;
          tail.SetEdge(headUid, PamGraphEdgeType.Data, edge.Content?.ToByteArray(), path, modified: false);
          PamDebug($"LoadAsync DATA uid={tailUid} path={path} bytes={edge.Content?.Length ?? 0}");
          continue;
        }

        switch (edge.Type)
        {
          case GraphSyncProto.GraphSyncDataType.GseLink:
            linkCount++;
            break;
          case GraphSyncProto.GraphSyncDataType.GseAcl:
            aclCount++;
            break;
          default:
            otherCount++;
            break;
        }

        tail.SetEdge(headUid, MapEdgeType(edge.Type), edge.Content?.ToByteArray(), edge.Path, modified: false);
      }

      PamDebug(
        $"LoadAsync config={_configUid} vertices={_vertices.Count} "
        + $"data={dataCount} link={linkCount} acl={aclCount} other={otherCount}");
    }

    private static bool IsMetaPath(string path)
    {
      return string.IsNullOrEmpty(path)
             || string.Equals(path, "meta", StringComparison.OrdinalIgnoreCase);
    }

    internal static void PamDebug(string message)
    {
      var line = $"[PAM-connection] {message}";
      System.Diagnostics.Debug.WriteLine(line);
      // Opt-in only: set KEEPER_PAM_DEBUG=1 to print diagnostics to the console.
      if (string.Equals(Environment.GetEnvironmentVariable("KEEPER_PAM_DEBUG"), "1", StringComparison.Ordinal))
      {
        Console.WriteLine(line);
      }
    }

    public bool ResourceBelongsToConfig(string resourceUid)
    {
      if (!HasGraph || string.IsNullOrEmpty(resourceUid))
      {
        return false;
      }

      return _vertices.TryGetValue(resourceUid, out var resource)
             && resource.HasEdge(_configUid, PamGraphEdgeType.Link);
    }

    public bool UserBelongsToResource(string userUid, string resourceUid)
    {
      if (!_vertices.TryGetValue(userUid, out var user))
      {
        return false;
      }

      return user.TryGetAclContent(resourceUid, out var content)
             && ReadBool(content, "belongs_to");
    }

    public bool CheckIfResourceHasAdmin(string resourceUid)
    {
      foreach (var userUid in GetUsersLinkedToResource(resourceUid))
      {
        if (_vertices.TryGetValue(userUid, out var user)
            && user.TryGetAclContent(resourceUid, out var content)
            && ReadBool(content, "is_admin"))
        {
          return true;
        }
      }

      return false;
    }

    public List<string> GetResourceOwners(string userUid)
    {
      if (!_vertices.TryGetValue(userUid, out var user))
      {
        return new List<string>();
      }

      return user.EdgeHeads(PamGraphEdgeType.Acl);
    }

    public string GetBelongingResourceUid(string userUid)
    {
      foreach (var resourceUid in GetResourceOwners(userUid))
      {
        if (UserBelongsToResource(userUid, resourceUid))
        {
          return resourceUid;
        }
      }

      return null;
    }

    public List<string> GetLaunchCredentialUids(string resourceUid)
    {
      var result = new List<string>();
      foreach (var userUid in GetUsersLinkedToResource(resourceUid))
      {
        if (_vertices.TryGetValue(userUid, out var user)
            && user.TryGetAclContent(resourceUid, out var content)
            && ReadBool(content, "is_launch_credential"))
        {
          result.Add(userUid);
        }
      }

      return result;
    }

    private IEnumerable<string> GetUsersLinkedToResource(string resourceUid)
    {
      foreach (var vertex in _vertices.Values)
      {
        if (vertex.HasEdge(resourceUid, PamGraphEdgeType.Acl))
        {
          yield return vertex.Uid;
        }
      }
    }

    public async Task EnsureConfigGraphAsync(bool enableRotationOnConfig = true)
    {
      if (!HasGraph)
      {
        GetOrCreateVertex(_configUid, GraphSyncProto.RefType.RftPamNetwork);
        if (enableRotationOnConfig)
        {
          await SetNetworkRotationAllowedAsync(rotation: true);
        }
      }
    }

    public async Task LinkResourceToConfigAsync(string resourceUid, GraphSyncProto.RefType resourceType)
    {
      GetOrCreateVertex(_configUid, GraphSyncProto.RefType.RftPamNetwork);
      var resource = GetOrCreateVertex(resourceUid, resourceType);
      if (resource.HasEdge(_configUid, PamGraphEdgeType.Link))
      {
        return;
      }

      resource.SetEdge(_configUid, PamGraphEdgeType.Link, null, path: null, modified: true);
      await SaveAsync();
    }

    public async Task LinkUserToResourceAsync(
      string userUid,
      string resourceUid,
      bool? isAdmin = null,
      bool? belongsTo = null)
    {
      if (!ResourceBelongsToConfig(resourceUid))
      {
        throw new InvalidOperationException(
          $"Resource \"{resourceUid}\" does not belong to configuration \"{_configUid}\".");
      }

      if (isAdmin == true)
      {
        var launchUids = GetLaunchCredentialUids(resourceUid);
        var request = new PamProto.PAMResourceConfig
        {
          RecordUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode()),
          NetworkUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
          AdminUid = ByteString.CopyFrom(userUid.Base64UrlDecode()),
          ConnectUsers = new PamProto.UidList
          {
            Uids = { launchUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())) },
          },
        };

        const string endpoint = "configure_resource";
        var host = GetRouterHost();
        if (!PamLayerB.IsFeatureDisabled(host, endpoint))
        {
          try
          {
            await RouterUtils.ConfigureResourceAsync(_auth, request);
            return;
          }
          catch (Exception ex) when (PamLayerB.ShouldFallbackOnError(ex, host, endpoint))
          {
            PamLayerB.TraceFallback(endpoint, resourceUid, ex);
          }
          catch (Exception ex)
          {
            PamLayerB.TraceNoFallback(endpoint, ex);
            throw;
          }
        }
      }

      ApplyUserAclLink(userUid, resourceUid, isAdmin, belongsTo, isLaunchCredential: null);
      await SaveAsync();
    }

    public async Task SetNetworkRotationAllowedAsync(bool? rotation = null)
    {
      if (rotation == null)
      {
        return;
      }

      var allowedSettings = new PamGraphAllowedSettings { Rotation = rotation.Value };
      var request = new RouterProto.PAMNetworkConfigurationRequest
      {
        RecordUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
        NetworkSettings = new RouterProto.PAMNetworkSettings
        {
          AllowedSettings = ByteString.CopyFrom(JsonUtils.DumpJson(allowedSettings, indent: false)),
        },
      };

      const string endpoint = "configure_network_graph";
      var host = GetRouterHost();
      if (!PamLayerB.IsFeatureDisabled(host, endpoint))
      {
        try
        {
          await RouterUtils.ConfigureNetworkGraphAsync(_auth, request);
          return;
        }
        catch (Exception ex) when (PamLayerB.ShouldFallbackOnError(ex, host, endpoint))
        {
          PamLayerB.TraceFallback(endpoint, _configUid, ex);
        }
        catch (Exception ex)
        {
          PamLayerB.TraceNoFallback(endpoint, ex);
          throw;
        }
      }

      var config = GetOrCreateVertex(_configUid, GraphSyncProto.RefType.RftPamNetwork);
      var content = new PamGraphMetaContent { AllowedSettings = allowedSettings };
      config.SetDataEdge("meta", JsonUtils.DumpJson(content), modified: true);
      await SaveAsync();
    }

    private static bool ReadBool(IDictionary<string, object> content, string key)
    {
      if (content == null || !content.TryGetValue(key, out var raw) || raw == null)
      {
        return false;
      }

      return raw switch
      {
        bool value => value,
        string text => bool.TryParse(text, out var parsed) && parsed,
        _ => false,
      };
    }

    private static PamGraphAllowedSettings GetOrCreateAllowedSettings(PamGraphMetaContent metaContent)
    {
      metaContent ??= new PamGraphMetaContent();
      metaContent.AllowedSettings ??= new PamGraphAllowedSettings();
      return metaContent.AllowedSettings;
    }

    public async Task SetResourceRotationAllowedAsync(
      string resourceUid,
      GraphSyncProto.RefType resourceType,
      bool? rotationEnabled)
    {
      if (rotationEnabled == null)
      {
        return;
      }

      var resource = GetOrCreateVertex(resourceUid, resourceType);
      var metaContent = resource.TryGetMetaContent() ?? new PamGraphMetaContent();
      var allowedSettings = GetOrCreateAllowedSettings(metaContent);
      allowedSettings.Rotation = rotationEnabled.Value;

      var request = new PamProto.PAMResourceConfig
      {
        RecordUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode()),
        NetworkUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
        Meta = ByteString.CopyFrom(JsonUtils.DumpJson(metaContent, indent: false)),
      };

      const string endpoint = "configure_resource";
      var host = GetRouterHost();
      if (!PamLayerB.IsFeatureDisabled(host, endpoint))
      {
        try
        {
          await RouterUtils.ConfigureResourceAsync(_auth, request);
          return;
        }
        catch (Exception ex) when (PamLayerB.ShouldFallbackOnError(ex, host, endpoint))
        {
          PamLayerB.TraceFallback(endpoint, resourceUid, ex);
        }
        catch (Exception ex)
        {
          PamLayerB.TraceNoFallback(endpoint, ex);
          throw;
        }
      }

      resource.SetDataEdge("meta", JsonUtils.DumpJson(metaContent), modified: true);
      await SaveAsync();
    }

    /// <summary>
    /// Enable/disable connection-related allowedSettings on the PAM configuration (network) vertex.
    /// Tri-state values: "on", "off", "default" (remove key). Null skips that setting.
    /// </summary>
    public async Task SetNetworkConnectionAllowedAsync(
      string connections = null,
      string sessionRecording = null,
      string typescriptRecording = null)
    {
      if (connections == null && sessionRecording == null && typescriptRecording == null)
      {
        return;
      }

      var config = GetOrCreateVertex(_configUid, GraphSyncProto.RefType.RftPamNetwork);
      var meta = config.TryGetMetaContent() ?? new PamGraphMetaContent();
      var settings = GetOrCreateAllowedSettings(meta);
      var dirty = ApplyTriStateToTyped(settings, nameof(settings.Connections), connections, v => settings.Connections = v)
                  | ApplyTriStateToTyped(settings, nameof(settings.SessionRecording), sessionRecording, v => settings.SessionRecording = v)
                  | ApplyTriStateToTyped(settings, nameof(settings.TypescriptRecording), typescriptRecording, v => settings.TypescriptRecording = v);
      if (!dirty)
      {
        return;
      }

      var resetting = IsDefaultReset(connections)
                      || IsDefaultReset(sessionRecording)
                      || IsDefaultReset(typescriptRecording);
      var settingsJson = JsonUtils.DumpJson(settings, indent: false);

      if (!resetting)
      {
        var request = new RouterProto.PAMNetworkConfigurationRequest
        {
          RecordUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
          NetworkSettings = new RouterProto.PAMNetworkSettings
          {
            AllowedSettings = ByteString.CopyFrom(settingsJson),
          },
        };

        const string endpoint = "configure_network_graph";
        var host = GetRouterHost();
        if (!PamLayerB.IsFeatureDisabled(host, endpoint))
        {
          try
          {
            await RouterUtils.ConfigureNetworkGraphAsync(_auth, request);
            config.SetDataEdge("meta", JsonUtils.DumpJson(meta, indent: false), modified: true);
            await SaveAsync();
            return;
          }
          catch (Exception ex) when (PamLayerB.ShouldFallbackOnError(ex, host, endpoint))
          {
            PamLayerB.TraceFallback(endpoint, _configUid, ex);
          }
          catch (Exception ex)
          {
            PamLayerB.TraceNoFallback(endpoint, ex);
            throw;
          }
        }
      }

      config.SetDataEdge("meta", JsonUtils.DumpJson(meta, indent: false), modified: true);
      await SaveAsync();
    }

    /// <summary>
    /// Enable/disable connection-related allowedSettings on a PAM resource vertex.
    /// </summary>
    public async Task SetResourceConnectionAllowedAsync(
      string resourceUid,
      GraphSyncProto.RefType resourceType,
      string connections = null,
      string sessionRecording = null,
      string typescriptRecording = null,
      bool? rotateOnTermination = null,
      string allowedSettingsName = "allowedSettings")
    {
      if (connections == null
          && sessionRecording == null
          && typescriptRecording == null
          && rotateOnTermination == null)
      {
        return;
      }

      // Resource connection flags always use allowedSettings (or pamRemoteBrowserSettings key
      // via dictionary path below when name differs).
      if (!string.Equals(allowedSettingsName, "allowedSettings", StringComparison.Ordinal))
      {
        await SetResourceConnectionAllowedDictionaryAsync(
          resourceUid, resourceType, connections, sessionRecording, typescriptRecording,
          rotateOnTermination, allowedSettingsName);
        return;
      }

      var resource = GetOrCreateVertex(resourceUid, resourceType);
      var meta = resource.TryGetMetaContent() ?? new PamGraphMetaContent();
      var settings = GetOrCreateAllowedSettings(meta);
      var dirty = ApplyTriStateToTyped(settings, nameof(settings.Connections), connections, v => settings.Connections = v)
                  | ApplyTriStateToTyped(settings, nameof(settings.SessionRecording), sessionRecording, v => settings.SessionRecording = v)
                  | ApplyTriStateToTyped(settings, nameof(settings.TypescriptRecording), typescriptRecording, v => settings.TypescriptRecording = v);

      if (rotateOnTermination != null && meta.RotateOnTermination != rotateOnTermination)
      {
        meta.Version = 1;
        meta.RotateOnTermination = rotateOnTermination;
        dirty = true;
      }

      if (!dirty)
      {
        return;
      }

      var resetting = IsDefaultReset(connections)
                      || IsDefaultReset(sessionRecording)
                      || IsDefaultReset(typescriptRecording);

      if (!resetting)
      {
        var request = new PamProto.PAMResourceConfig
        {
          RecordUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode()),
          NetworkUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
          Meta = ByteString.CopyFrom(JsonUtils.DumpJson(meta, indent: false)),
        };

        const string endpoint = "configure_resource";
        var host = GetRouterHost();
        if (!PamLayerB.IsFeatureDisabled(host, endpoint))
        {
          try
          {
            await RouterUtils.ConfigureResourceAsync(_auth, request);
            resource.SetDataEdge("meta", JsonUtils.DumpJson(meta, indent: false), modified: true);
            await SaveAsync();
            return;
          }
          catch (Exception ex) when (PamLayerB.ShouldFallbackOnError(ex, host, endpoint))
          {
            PamLayerB.TraceFallback(endpoint, resourceUid, ex);
          }
          catch (Exception ex)
          {
            PamLayerB.TraceNoFallback(endpoint, ex);
            throw;
          }
        }
      }

      resource.SetDataEdge("meta", JsonUtils.DumpJson(meta, indent: false), modified: true);
      await SaveAsync();
    }

    private async Task SetResourceConnectionAllowedDictionaryAsync(
      string resourceUid,
      GraphSyncProto.RefType resourceType,
      string connections,
      string sessionRecording,
      string typescriptRecording,
      bool? rotateOnTermination,
      string allowedSettingsName)
    {
      var resource = GetOrCreateVertex(resourceUid, resourceType);
      var meta = GetMetaDictionary(resource) ?? new Dictionary<string, object>();
      var settings = GetOrCreateSettingsDictionary(meta, allowedSettingsName);
      var dirty = ApplyTriStateSetting(settings, "connections", connections)
                  | ApplyTriStateSetting(settings, "sessionRecording", sessionRecording)
                  | ApplyTriStateSetting(settings, "typescriptRecording", typescriptRecording);

      if (rotateOnTermination != null)
      {
        var current = ReadBool(meta, "rotateOnTermination");
        if (current != rotateOnTermination.Value)
        {
          meta["version"] = 1;
          meta["rotateOnTermination"] = rotateOnTermination.Value;
          dirty = true;
        }
      }

      if (!dirty)
      {
        return;
      }

      meta[allowedSettingsName] = settings;
      resource.SetDataEdge("meta", JsonUtils.DumpJson(meta, indent: false), modified: true);
      await SaveAsync();
    }

    /// <summary>
    /// Applies on/off/default onto a typed nullable bool. Returns true when changed.
    /// </summary>
    private static bool ApplyTriStateToTyped(
      PamGraphAllowedSettings settings,
      string propertyName,
      string value,
      Action<bool?> assign)
    {
      if (value == null || settings == null)
      {
        return false;
      }

      var converted = ConvertAllowedSetting(value);
      bool? current = propertyName switch
      {
        nameof(PamGraphAllowedSettings.Connections) => settings.Connections,
        nameof(PamGraphAllowedSettings.SessionRecording) => settings.SessionRecording,
        nameof(PamGraphAllowedSettings.TypescriptRecording) => settings.TypescriptRecording,
        _ => null,
      };

      if (converted == null)
      {
        // "default" → clear
        if (current == null)
        {
          return false;
        }

        assign(null);
        return true;
      }

      if (current == converted.Value)
      {
        return false;
      }

      assign(converted.Value);
      return true;
    }

    /// <summary>
    /// Set or clear launch credential (and optionally admin) in one configure_resource call.
    /// </summary>
    public async Task SetLaunchCredentialsAsync(
      string resourceUid,
      string launchUid,
      string adminUid = null)
    {
      if (!ResourceBelongsToConfig(resourceUid))
      {
        throw new InvalidOperationException(
          $"Resource \"{resourceUid}\" does not belong to configuration \"{_configUid}\".");
      }

      // Version-only meta bump so vault reads ACL launch credentials without re-asserting flags.
      var upgradedMeta = new Dictionary<string, object>
      {
        ["version"] = 1,
        ["allowedSettings"] = new Dictionary<string, object>(),
      };

      var request = new PamProto.PAMResourceConfig
      {
        RecordUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode()),
        NetworkUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
        ConnectUsers = new PamProto.UidList(),
        Meta = ByteString.CopyFrom(JsonUtils.DumpJson(upgradedMeta, indent: false)),
      };

      if (!string.IsNullOrEmpty(launchUid))
      {
        request.ConnectUsers.Uids.Add(ByteString.CopyFrom(launchUid.Base64UrlDecode()));
      }

      if (!string.IsNullOrEmpty(adminUid))
      {
        request.AdminUid = ByteString.CopyFrom(adminUid.Base64UrlDecode());
      }

      const string endpoint = "configure_resource";
      var host = GetRouterHost();
      if (!PamLayerB.IsFeatureDisabled(host, endpoint))
      {
        try
        {
          await RouterUtils.ConfigureResourceAsync(_auth, request);
          if (!string.IsNullOrEmpty(launchUid))
          {
            ApplyUserAclLink(launchUid, resourceUid, isAdmin: null, belongsTo: true, isLaunchCredential: true);
            await SaveAsync();
          }

          return;
        }
        catch (Exception ex) when (PamLayerB.ShouldFallbackOnError(ex, host, endpoint))
        {
          PamLayerB.TraceFallback(endpoint, resourceUid, ex);
        }
        catch (Exception ex)
        {
          // configure_resource can 500 on some admin/launch combinations; fall back to DAG ACL writes.
          PamLayerB.TraceFallback(endpoint, resourceUid, ex);
        }
      }

      ClearLaunchCredentialFlags(resourceUid, excludeUserUid: launchUid);
      if (!string.IsNullOrEmpty(adminUid))
      {
        ApplyUserAclLink(adminUid, resourceUid, isAdmin: true, belongsTo: true, isLaunchCredential: null);
      }

      if (!string.IsNullOrEmpty(launchUid))
      {
        ApplyUserAclLink(launchUid, resourceUid, isAdmin: null, belongsTo: true, isLaunchCredential: true);
      }

      await SaveAsync();
    }

    /// <summary>
    /// Returns whether a resource allowedSettings flag is enabled.
    /// </summary>
    public bool CheckIfResourceAllowed(string resourceUid, string setting)
    {
      return GetResourceAllowedSetting(resourceUid, setting) == true;
    }

    /// <summary>
    /// Returns nullable allowedSettings flag for a resource (null = unset / default).
    /// </summary>
    public bool? GetResourceAllowedSetting(string resourceUid, string setting)
    {
      if (!_vertices.TryGetValue(resourceUid, out var resource))
      {
        return null;
      }

      var typed = resource.TryGetMetaContent()?.AllowedSettings;
      if (typed != null)
      {
        return setting switch
        {
          "connections" => typed.Connections,
          "sessionRecording" => typed.SessionRecording,
          "typescriptRecording" => typed.TypescriptRecording,
          "rotation" => typed.Rotation,
          "portForwards" => typed.PortForwards,
          "aiEnabled" => typed.AiEnabled,
          "aiSessionTerminate" => typed.AiSessionTerminate,
          "remoteBrowserIsolation" => typed.RemoteBrowserIsolation,
          _ => null,
        };
      }

      var meta = GetMetaDictionary(resource);
      var settings = CoerceStringObjectDictionary(
        meta != null && meta.TryGetValue("allowedSettings", out var raw) ? raw : null);
        
      if ((settings == null || !settings.ContainsKey(setting))
          && meta != null
          && meta.TryGetValue("pamRemoteBrowserSettings", out var rbiRaw))
      {
        settings = CoerceStringObjectDictionary(rbiRaw);
      }

      if (settings == null || !settings.ContainsKey(setting))
      {
        return null;
      }

      return ReadBool(settings, setting);
    }

    /// <summary>
    /// Returns whether a config-level allowedSettings flag is enabled.
    /// </summary>
    public bool CheckIfConfigAllowed(string setting)
    {
      return GetConfigAllowedSetting(setting) == true;
    }

    /// <summary>
    /// Returns nullable config allowedSettings flag (null = unset / default).
    /// </summary>
    public bool? GetConfigAllowedSetting(string setting)
    {
      if (!HasGraph || !_vertices.TryGetValue(_configUid, out var config))
      {
        return null;
      }

      var typed = config.TryGetMetaContent()?.AllowedSettings;
      if (typed != null)
      {
        return setting switch
        {
          "connections" => typed.Connections,
          "sessionRecording" => typed.SessionRecording,
          "typescriptRecording" => typed.TypescriptRecording,
          "rotation" => typed.Rotation,
          "portForwards" => typed.PortForwards,
          "aiEnabled" => typed.AiEnabled,
          "aiSessionTerminate" => typed.AiSessionTerminate,
          "remoteBrowserIsolation" => typed.RemoteBrowserIsolation,
          _ => null,
        };
      }

      var meta = GetMetaDictionary(config);
      var settings = CoerceStringObjectDictionary(
        meta != null && meta.TryGetValue("allowedSettings", out var raw) ? raw : null);
      if (settings == null || !settings.ContainsKey(setting))
      {
        return null;
      }

      return ReadBool(settings, setting);
    }

    /// <summary>
    /// rotation is Enabled unless explicitly false.
    /// </summary>
    public static string FormatRotationStatus(bool? rotation)
    {
      return rotation == false ? "Disabled" : "Enabled";
    }

    /// <summary>
    /// flag Enabled only when explicitly true.
    /// </summary>
    public static string FormatFlagStatus(bool? flag)
    {
      return flag == true ? "Enabled" : "Disabled";
    }

    /// <summary>
    /// Returns false when enabling a feature that the PAM configuration has not allowed.
    /// </summary>
    public bool CheckConfigAllows(
      bool? enableConnections = null,
      bool? enableSessionRecording = null,
      bool? enableTypescriptRecording = null)
    {
      if (enableConnections != true
          && enableSessionRecording != true
          && enableTypescriptRecording != true)
      {
        return true;
      }

      if (!HasGraph || !_vertices.TryGetValue(_configUid, out var config))
      {
        return false;
      }

      // Prefer typed meta (reliable with DataContractJsonSerializer nested objects).
      var typed = config.TryGetMetaContent()?.AllowedSettings;
      if (typed != null)
      {
        if (enableConnections == true && typed.Connections != true)
        {
          return false;
        }

        if (typed.Connections == true)
        {
          if (enableSessionRecording == true && typed.SessionRecording != true)
          {
            return false;
          }

          if (enableTypescriptRecording == true && typed.TypescriptRecording != true)
          {
            return false;
          }
        }

        return true;
      }

      var meta = GetMetaDictionary(config);
      var settings = CoerceStringObjectDictionary(
        meta != null && meta.TryGetValue("allowedSettings", out var raw) ? raw : null);
      if (settings == null || settings.Count == 0)
      {
        return false;
      }

      if (enableConnections == true && !ReadBool(settings, "connections"))
      {
        return false;
      }

      if (ReadBool(settings, "connections"))
      {
        if (enableSessionRecording == true && !ReadBool(settings, "sessionRecording"))
        {
          return false;
        }

        if (enableTypescriptRecording == true && !ReadBool(settings, "typescriptRecording"))
        {
          return false;
        }
      }

      return true;
    }

    private void ClearLaunchCredentialFlags(string resourceUid, string excludeUserUid)
    {
      foreach (var userUid in GetUsersLinkedToResource(resourceUid).ToList())
      {
        if (!string.IsNullOrEmpty(excludeUserUid)
            && string.Equals(userUid, excludeUserUid, StringComparison.Ordinal))
        {
          continue;
        }

        if (!_vertices.TryGetValue(userUid, out var user)
            || !user.TryGetAclContent(resourceUid, out var content)
            || !ReadBool(content, "is_launch_credential"))
        {
          continue;
        }

        content.Remove("is_launch_credential");
        user.SetEdge(resourceUid, PamGraphEdgeType.Acl, SerializeAclContent(content), path: null, modified: true);
      }
    }

    private static Dictionary<string, object> GetMetaDictionary(PamGraphVertex vertex)
    {
      return vertex?.TryGetMetaDictionary();
    }

    private static Dictionary<string, object> GetOrCreateSettingsDictionary(
      Dictionary<string, object> meta,
      string settingsName)
    {
      if (meta.TryGetValue(settingsName, out var raw))
      {
        var existing = CoerceStringObjectDictionary(raw);
        if (existing != null)
        {
          meta[settingsName] = existing;
          return existing;
        }
      }

      var created = new Dictionary<string, object>();
      meta[settingsName] = created;
      return created;
    }

    private static Dictionary<string, object> CoerceStringObjectDictionary(object raw)
    {
      if (raw == null)
      {
        return null;
      }

      if (raw is Dictionary<string, object> typed)
      {
        return typed;
      }

      if (raw is System.Collections.IDictionary map)
      {
        var result = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry entry in map)
        {
          if (entry.Key == null)
          {
            continue;
          }

          result[entry.Key.ToString()] = entry.Value;
        }

        return result;
      }

      if (raw is string json && !string.IsNullOrWhiteSpace(json))
      {
        try
        {
          return JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(json));
        }
        catch (Exception ex)
        {
          System.Diagnostics.Trace.TraceWarning("PAM: failed to coerce settings JSON: {0}", ex.Message);
        }
      }

      return null;
    }

    /// <summary>
    /// Applies on/off/default. Returns true when the dictionary changed.
    /// "default" removes the key. Null input skips.
    /// </summary>
    private static bool ApplyTriStateSetting(Dictionary<string, object> settings, string key, string value)
    {
      if (value == null)
      {
        return false;
      }

      var converted = ConvertAllowedSetting(value);
      settings.TryGetValue(key, out var currentRaw);
      bool? current = currentRaw switch
      {
        bool b => b,
        string s when bool.TryParse(s, out var parsed) => parsed,
        _ => null,
      };

      if (converted == null)
      {
        if (!settings.ContainsKey(key))
        {
          return false;
        }

        settings.Remove(key);
        return true;
      }

      if (current == converted.Value)
      {
        return false;
      }

      settings[key] = converted.Value;
      return true;
    }

    /// <summary>
    /// Converts on/off/default to true/false/null. Null input returns null (skip).
    /// </summary>
    public static bool? ConvertAllowedSetting(string value)
    {
      if (value == null)
      {
        return null;
      }

      if (bool.TryParse(value, out var asBool))
      {
        return asBool;
      }

      return value.Trim().ToLowerInvariant() switch
      {
        "on" => true,
        "off" => false,
        _ => null, // default / unknown -> remove key when applied
      };
    }

    private static bool IsDefaultReset(string value)
    {
      return value != null && ConvertAllowedSetting(value) == null;
    }

    private string GetRouterHost()
    {
      var routerUrl = Environment.GetEnvironmentVariable("ROUTER_URL");
      if (!string.IsNullOrEmpty(routerUrl))
      {
        return routerUrl;
      }

      if (_auth.Endpoint is KeeperEndpoint keeperEndpoint)
      {
        return keeperEndpoint.Server;
      }

      return string.Empty;
    }

    public static GraphSyncProto.RefType GetResourceRefType(string recordTypeName)
    {
      return recordTypeName switch
      {
        "pamDatabase" => GraphSyncProto.RefType.RftPamDatabase,
        "pamDirectory" => GraphSyncProto.RefType.RftPamDirectory,
        "pamRemoteBrowser" => GraphSyncProto.RefType.RftPamBrowser,
        _ => GraphSyncProto.RefType.RftPamMachine,
      };
    }

    private void ApplyUserAclLink(
      string userUid,
      string headUid,
      bool? isAdmin,
      bool? belongsTo,
      bool? isLaunchCredential)
    {
      var user = GetOrCreateVertex(userUid, GraphSyncProto.RefType.RftPamUser);
      var acl = GetUserAcl(user, headUid);

      if (isAdmin.HasValue)
      {
        acl.IsAdmin = isAdmin.Value;
      }

      if (belongsTo.HasValue)
      {
        acl.BelongsTo = belongsTo.Value;
      }

      if (isLaunchCredential.HasValue)
      {
        acl.IsLaunchCredential = isLaunchCredential.Value;
      }

      EnsureRotationSettings(acl);
      user.SetEdge(headUid, PamGraphEdgeType.Acl, SerializeUserAcl(acl), path: null, modified: true);
    }

    internal async Task RepairUserAclRotationSettingsAsync(string userUid, string resourceUid)
    {
      if (!_vertices.TryGetValue(userUid, out var user))
      {
        return;
      }

      var acl = GetUserAcl(user, resourceUid);
      if (!NeedsRotationSettingsRepair(acl))
      {
        return;
      }

      EnsureRotationSettings(acl);
      user.SetEdge(resourceUid, PamGraphEdgeType.Acl, SerializeUserAcl(acl), path: null, modified: true);
      await SaveAsync();
    }

    private static PamUserAclContent GetUserAcl(PamGraphVertex user, string headUid)
    {
      if (user.TryGetAclBytes(headUid, out var bytes))
      {
        return ParseUserAcl(bytes);
      }

      return new PamUserAclContent();
    }

    private static void EnsureRotationSettings(PamUserAclContent acl)
    {
      acl.RotationSettings ??= new PamUserAclRotationSettings();
      acl.RotationSettings.Schedule ??= "";
      acl.RotationSettings.PwdComplexity ??= "";
    }

    private static bool NeedsRotationSettingsRepair(PamUserAclContent acl)
    {
      if (acl.RotationSettings == null)
      {
        return true;
      }

      return acl.RotationSettings.Schedule == null || acl.RotationSettings.PwdComplexity == null;
    }

    private async Task SaveAsync()
    {
      _pendingSave.Clear();
      foreach (var vertex in _vertices.Values)
      {
        vertex.CollectPendingSave(this);
      }

      if (_pendingSave.Count == 0)
      {
        return;
      }

      var batch = _pendingSave.ToList();
      _pendingSave.Clear();
      await PamGraphSyncClient.AddDataAsync(_auth, _configUid, batch);
    }

    internal void QueueGraphSyncData(GraphSyncProto.GraphSyncData data)
    {
      _pendingSave.Add(data);
    }

    private PamGraphVertex GetOrCreateVertex(string uid, GraphSyncProto.RefType refType)
    {
      if (!_vertices.TryGetValue(uid, out var vertex))
      {
        vertex = new PamGraphVertex(uid, refType);
        _vertices[uid] = vertex;
      }

      return vertex;
    }

    private void RemoveEdge(string tailUid, string headUid, PamGraphEdgeType edgeType)
    {
      if (_vertices.TryGetValue(tailUid, out var tail))
      {
        tail.RemoveEdge(headUid, edgeType);
      }
    }

    [DataContract]
    private sealed class PamGraphAllowedSettings
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

      [DataMember(Name = "aiEnabled", EmitDefaultValue = false)]
      public bool? AiEnabled { get; set; }

      [DataMember(Name = "aiSessionTerminate", EmitDefaultValue = false)]
      public bool? AiSessionTerminate { get; set; }

      [DataMember(Name = "remoteBrowserIsolation", EmitDefaultValue = false)]
      public bool? RemoteBrowserIsolation { get; set; }
    }

    [DataContract]
    private sealed class PamGraphMetaContent
    {
      [DataMember(Name = "version", EmitDefaultValue = false)]
      public int? Version { get; set; }

      [DataMember(Name = "allowedSettings", EmitDefaultValue = false)]
      public PamGraphAllowedSettings AllowedSettings { get; set; }

      [DataMember(Name = "rotateOnTermination", EmitDefaultValue = false)]
      public bool? RotateOnTermination { get; set; }
    }

    private enum PamGraphEdgeType
    {
      Data,
      Key,
      Link,
      Acl,
    }

    private static PamGraphEdgeType MapEdgeType(GraphSyncProto.GraphSyncDataType type)
    {
      return type switch
      {
        GraphSyncProto.GraphSyncDataType.GseLink => PamGraphEdgeType.Link,
        GraphSyncProto.GraphSyncDataType.GseAcl => PamGraphEdgeType.Acl,
        GraphSyncProto.GraphSyncDataType.GseKey => PamGraphEdgeType.Key,
        _ => PamGraphEdgeType.Data,
      };
    }

    private static GraphSyncProto.GraphSyncDataType MapEdgeType(PamGraphEdgeType type)
    {
      return type switch
      {
        PamGraphEdgeType.Link => GraphSyncProto.GraphSyncDataType.GseLink,
        PamGraphEdgeType.Acl => GraphSyncProto.GraphSyncDataType.GseAcl,
        PamGraphEdgeType.Key => GraphSyncProto.GraphSyncDataType.GseKey,
        _ => GraphSyncProto.GraphSyncDataType.GseData,
      };
    }

    private static byte[] SerializeAclContent(Dictionary<string, object> content)
    {
      return JsonUtils.DumpJson(content);
    }

    private static Dictionary<string, object> ParseAclContent(byte[] content)
    {
      if (content == null || content.Length == 0)
      {
        return new Dictionary<string, object>();
      }

      try
      {
        return JsonUtils.ParseJson<Dictionary<string, object>>(content)
               ?? new Dictionary<string, object>();
      }
      catch (Exception ex)
      {
        System.Diagnostics.Trace.TraceWarning("PAM: failed to parse ACL content: {0}", ex.Message);
        return new Dictionary<string, object>();
      }
    }

    private static byte[] SerializeUserAcl(PamUserAclContent acl)
    {
      return JsonUtils.DumpJson(acl ?? new PamUserAclContent());
    }

    private static PamUserAclContent ParseUserAcl(byte[] content)
    {
      if (content == null || content.Length == 0)
      {
        return new PamUserAclContent();
      }

      try
      {
        return JsonUtils.ParseJson<PamUserAclContent>(content) ?? new PamUserAclContent();
      }
      catch (Exception ex)
      {
        System.Diagnostics.Trace.TraceWarning("PAM: failed to parse user ACL content: {0}", ex.Message);
        return new PamUserAclContent();
      }
    }

    [DataContract]
    private sealed class PamUserAclContent : IExtensibleDataObject
    {
      [DataMember(Name = "belongs_to", EmitDefaultValue = true)]
      public bool BelongsTo { get; set; }

      [DataMember(Name = "is_admin", EmitDefaultValue = true)]
      public bool IsAdmin { get; set; }

      [DataMember(Name = "is_iam_user", EmitDefaultValue = false)]
      public bool? IsIamUser { get; set; }

      [DataMember(Name = "is_launch_credential", EmitDefaultValue = true)]
      public bool IsLaunchCredential { get; set; }

      [DataMember(Name = "rotation_settings", EmitDefaultValue = true)]
      public PamUserAclRotationSettings RotationSettings { get; set; }

      public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    private sealed class PamUserAclRotationSettings : IExtensibleDataObject
    {
      [DataMember(Name = "schedule", EmitDefaultValue = true)]
      public string Schedule { get; set; }

      [DataMember(Name = "pwd_complexity", EmitDefaultValue = true)]
      public string PwdComplexity { get; set; }

      [DataMember(Name = "disabled", EmitDefaultValue = true)]
      public bool Disabled { get; set; }

      [DataMember(Name = "noop", EmitDefaultValue = true)]
      public bool Noop { get; set; }

      [DataMember(Name = "saas_record_uid_list", EmitDefaultValue = false)]
      public List<string> SaasRecordUidList { get; set; }

      public ExtensionDataObject ExtensionData { get; set; }
    }

    private sealed class PamGraphVertex
    {
      private readonly Dictionary<string, PamGraphEdge> _edges = new(StringComparer.Ordinal);
      private PamGraphEdge _dataEdge;

      internal PamGraphVertex(string uid, GraphSyncProto.RefType refType)
      {
        Uid = uid;
        RefType = refType;
      }

      internal string Uid { get; }

      internal GraphSyncProto.RefType RefType { get; }

      internal bool HasEdge(string headUid, PamGraphEdgeType edgeType)
      {
        return _edges.TryGetValue(EdgeKey(headUid, edgeType), out _);
      }

      internal bool TryGetAclContent(string headUid, out Dictionary<string, object> content)
      {
        content = null;
        if (!TryGetAclBytes(headUid, out var bytes))
        {
          return false;
        }

        content = ParseAclContent(bytes);
        return true;
      }

      internal bool TryGetAclBytes(string headUid, out byte[] content)
      {
        content = null;
        if (!_edges.TryGetValue(EdgeKey(headUid, PamGraphEdgeType.Acl), out var edge))
        {
          return false;
        }

        content = edge.Content;
        return true;
      }

      internal List<string> EdgeHeads(PamGraphEdgeType edgeType)
      {
        return _edges.Values
          .Where(x => x.EdgeType == edgeType)
          .Select(x => x.HeadUid)
          .ToList();
      }

      internal void SetEdge(
        string headUid,
        PamGraphEdgeType edgeType,
        byte[] content,
        string path,
        bool modified)
      {
        if (edgeType == PamGraphEdgeType.Data)
        {
          _dataEdge = new PamGraphEdge(Uid, headUid, edgeType, content, path, modified);
          return;
        }

        _edges[EdgeKey(headUid, edgeType)] = new PamGraphEdge(Uid, headUid, edgeType, content, path, modified);
      }

      internal void SetDataEdge(string path, byte[] content, bool modified)
      {
        _dataEdge = new PamGraphEdge(Uid, Uid, PamGraphEdgeType.Data, content, path, modified);
      }

      internal void ClearDataEdge()
      {
        _dataEdge = null;
      }

      internal PamGraphMetaContent TryGetMetaContent()
      {
        if (_dataEdge?.Content == null || _dataEdge.Content.Length == 0 || !IsMetaPath(_dataEdge.Path))
        {
          PamDebug($"TryGetMetaContent uid={Uid}: no data edge (path={_dataEdge?.Path ?? "null"}, bytes={_dataEdge?.Content?.Length ?? 0})");
          return null;
        }

        try
        {
          var parsed = JsonUtils.ParseJson<PamGraphMetaContent>(_dataEdge.Content);
          PamDebug(
            $"TryGetMetaContent uid={Uid} path={_dataEdge.Path} "
            + $"rotation={parsed?.AllowedSettings?.Rotation} "
            + $"connections={parsed?.AllowedSettings?.Connections} "
            + $"portForwards={parsed?.AllowedSettings?.PortForwards}");
          return parsed;
        }
        catch (Exception ex)
        {
          PamDebug($"TryGetMetaContent uid={Uid} PARSE FAIL: {ex.Message}");
          System.Diagnostics.Trace.TraceWarning("PAM: failed to parse graph meta content: {0}", ex.Message);
          return null;
        }
      }

      internal Dictionary<string, object> TryGetMetaDictionary()
      {
        if (_dataEdge?.Content == null || _dataEdge.Content.Length == 0 || !IsMetaPath(_dataEdge.Path))
        {
          return null;
        }

        try
        {
          return JsonUtils.ParseJson<Dictionary<string, object>>(_dataEdge.Content);
        }
        catch (Exception ex)
        {
          PamDebug($"TryGetMetaDictionary uid={Uid} PARSE FAIL: {ex.Message}");
          System.Diagnostics.Trace.TraceWarning("PAM: failed to parse graph meta dictionary: {0}", ex.Message);
          return null;
        }
      }

      internal void RemoveEdge(string headUid, PamGraphEdgeType edgeType)
      {
        _edges.Remove(EdgeKey(headUid, edgeType));
      }

      internal void CollectPendingSave(PamRotationGraph graph)
      {
        foreach (var edge in _edges.Values.Where(x => x.Modified))
        {
          graph.QueueGraphSyncData(BuildGraphSyncData(this, edge, graph._vertices));
          edge.Modified = false;
        }

        if (_dataEdge != null && _dataEdge.Modified)
        {
          graph.QueueGraphSyncData(BuildGraphSyncData(this, _dataEdge, graph._vertices));
          _dataEdge.Modified = false;
        }
      }

      private static string EdgeKey(string headUid, PamGraphEdgeType edgeType)
      {
        return $"{headUid}:{edgeType}";
      }
    }

    private sealed class PamGraphEdge
    {
      internal PamGraphEdge(
        string tailUid,
        string headUid,
        PamGraphEdgeType edgeType,
        byte[] content,
        string path,
        bool modified)
      {
        TailUid = tailUid;
        HeadUid = headUid;
        EdgeType = edgeType;
        Content = content;
        Path = path;
        Modified = modified;
      }

      internal string TailUid { get; }

      internal string HeadUid { get; }

      internal PamGraphEdgeType EdgeType { get; }

      internal byte[] Content { get; }

      internal string Path { get; }

      internal bool Modified { get; set; }
    }

    private static GraphSyncProto.GraphSyncData BuildGraphSyncData(
      PamGraphVertex tail,
      PamGraphEdge edge,
      Dictionary<string, PamGraphVertex> vertices)
    {
      var headUid = edge.HeadUid;
      var headType = GraphSyncProto.RefType.RftGeneral;
      if (vertices.TryGetValue(headUid, out var headVertex))
      {
        headType = headVertex.RefType;
      }
      else if (headUid == tail.Uid)
      {
        headType = tail.RefType;
      }

      return new GraphSyncProto.GraphSyncData
      {
        Type = MapEdgeType(edge.EdgeType),
        Ref = PamGraphSyncClient.CreateRef(tail.Uid, tail.RefType),
        ParentRef = PamGraphSyncClient.CreateRef(headUid, headType),
        Content = edge.Content != null ? ByteString.CopyFrom(edge.Content) : ByteString.Empty,
        Path = edge.Path ?? "",
      };
    }
  }

  /// <summary>
  /// High-level rotation edit graph operations
  /// </summary>
  public static class PamRotationGraphEdit
  {
    public static async Task ConfigureResourceAsync(
      IAuthentication auth,
      VaultOnline vault,
      TypedRecord resourceRecord,
      string configUid,
      string adminUserIdentifier,
      bool enable,
      bool disable)
    {
      if (string.IsNullOrEmpty(configUid))
      {
        throw new InvalidOperationException("Specify a configuration UID parameter [--config].");
      }

      var graph = new PamRotationGraph(auth, configUid);
      await graph.LoadAsync();

      if (!graph.HasGraph)
      {
        await graph.EnsureConfigGraphAsync(enableRotationOnConfig: true);
      }

      if (!graph.ResourceBelongsToConfig(resourceRecord.Uid))
      {
        var resourceType = PamRotationGraph.GetResourceRefType(resourceRecord.TypeName ?? "");
        await graph.LinkResourceToConfigAsync(resourceRecord.Uid, resourceType);
      }

      if (!string.IsNullOrWhiteSpace(adminUserIdentifier)
          && !string.Equals(resourceRecord.TypeName, "pamRemoteBrowser", StringComparison.Ordinal))
      {
        var adminUser = PamVaultHelpers.ResolveRecord(vault, adminUserIdentifier.Trim(), new[] { "pamUser" });
        if (adminUser == null)
        {
          throw new InvalidOperationException(
            $"Admin user '{adminUserIdentifier}' not found or is not a pamUser record.");
        }

        await graph.LinkUserToResourceAsync(adminUser.Uid, resourceRecord.Uid, isAdmin: true, belongsTo: true);
      }

      bool? rotationEnabled = RotationUtils.ResolveRotationEnabled(enable, disable);

      if (rotationEnabled != null)
      {
        var resourceType = PamRotationGraph.GetResourceRefType(resourceRecord.TypeName ?? "");
        await graph.SetResourceRotationAllowedAsync(resourceRecord.Uid, resourceType, rotationEnabled);
      }
    }

    public static async Task ConfigureUserAsync(
      IAuthentication auth,
      VaultOnline vault,
      TypedRecord userRecord,
      string resourceUid,
      string configUid,
      bool noopRotation,
      bool scheduleOnly)
    {
      if (scheduleOnly || noopRotation || string.IsNullOrEmpty(configUid))
      {
        System.Diagnostics.Trace.WriteLine(
          $"PAM: skipping user graph link for {userRecord.Uid} "
          + $"(scheduleOnly={scheduleOnly}, noopRotation={noopRotation}, configUid set={!string.IsNullOrEmpty(configUid)})");
        return;
      }

      if (string.IsNullOrEmpty(resourceUid))
      {
        System.Diagnostics.Trace.WriteLine(
          $"PAM: skipping user graph link for {userRecord.Uid} (resource UID not specified)");
        return;
      }

      var graph = new PamRotationGraph(auth, configUid);
      await graph.LoadAsync();

      if (!graph.ResourceBelongsToConfig(resourceUid))
      {
        var resource = PamVaultHelpers.ResolveRecord(vault, resourceUid, PamRecordTypes.Resource);
        if (resource != null)
        {
          await ConfigureResourceAsync(auth, vault, resource, configUid, adminUserIdentifier: null, enable: false, disable: false);
          await graph.LoadAsync();
        }
      }

      if (!graph.CheckIfResourceHasAdmin(resourceUid))
      {
        throw new InvalidOperationException(
          $"PAM Resource \"{resourceUid}\" does not have admin credentials. "
          + "Please link an admin credential to this resource "
          + $"(pam-rotation edit --record {resourceUid} --config {configUid} --admin-user ADMIN).");
      }

      if (!graph.UserBelongsToResource(userRecord.Uid, resourceUid))
      {
        var oldResourceUid = graph.GetBelongingResourceUid(userRecord.Uid);
        if (!string.IsNullOrEmpty(oldResourceUid) && !string.Equals(oldResourceUid, resourceUid, StringComparison.Ordinal))
        {
          await graph.LinkUserToResourceAsync(userRecord.Uid, oldResourceUid, belongsTo: false);
        }

        await graph.LinkUserToResourceAsync(userRecord.Uid, resourceUid, belongsTo: true);
      }
      else
      {
        // set_record_rotation can deserialize required fields.
        await graph.RepairUserAclRotationSettingsAsync(userRecord.Uid, resourceUid);
      }
    }
  }
}
