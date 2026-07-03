using System;
using System.Collections.Generic;
using System.Linq;
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
      foreach (var item in data)
      {
        var edge = item.Data;
        if (edge == null)
        {
          continue;
        }

        if (edge.Type == GraphSyncProto.GraphSyncDataType.GseData)
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
          RemoveEdge(tailUid, headUid, MapEdgeType(edge.Type));
          continue;
        }

        var tail = GetOrCreateVertex(tailUid, edge.Ref?.Type ?? GraphSyncProto.RefType.RftGeneral);
        GetOrCreateVertex(headUid, edge.ParentRef?.Type ?? GraphSyncProto.RefType.RftGeneral);
        tail.SetEdge(headUid, MapEdgeType(edge.Type), edge.Content?.ToByteArray(), edge.Path, modified: false);
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
             && content.TryGetValue("belongs_to", out var belongs)
             && belongs is bool flag
             && flag;
    }

    public bool CheckIfResourceHasAdmin(string resourceUid)
    {
      foreach (var userUid in GetUsersLinkedToResource(resourceUid))
      {
        if (_vertices.TryGetValue(userUid, out var user)
            && user.TryGetAclContent(resourceUid, out var content)
            && content.TryGetValue("is_admin", out var admin)
            && admin is bool flag
            && flag)
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
            && content.TryGetValue("is_launch_credential", out var launch)
            && launch is bool flag
            && flag)
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
          await EditTunnelingConfigAsync(rotation: true);
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

        try
        {
          await RouterUtils.ConfigureResourceAsync(_auth, request);
          return;
        }
        catch
        {
          // Fall back to legacy ACL write below.
        }
      }

      ApplyUserAclLink(userUid, resourceUid, isAdmin, belongsTo, isLaunchCredential: null);
      await SaveAsync();
    }

    public async Task EditTunnelingConfigAsync(bool? rotation = null)
    {
      if (rotation == null)
      {
        return;
      }

      var allowedSettings = new Dictionary<string, object> { ["rotation"] = rotation.Value };
      var request = new RouterProto.PAMNetworkConfigurationRequest
      {
        RecordUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
        NetworkSettings = new RouterProto.PAMNetworkSettings
        {
          AllowedSettings = ByteString.CopyFrom(JsonUtils.DumpJson(allowedSettings)),
        },
      };

      try
      {
        await RouterUtils.ConfigureNetworkGraphAsync(_auth, request);
        return;
      }
      catch
      {
        // Fall back to legacy meta write on config vertex.
      }

      var config = GetOrCreateVertex(_configUid, GraphSyncProto.RefType.RftPamNetwork);
      var content = new Dictionary<string, object>
      {
        ["allowedSettings"] = allowedSettings,
      };
      config.SetDataEdge("meta", JsonUtils.DumpJson(content), modified: true);
      await SaveAsync();
    }

    private static Dictionary<string, object> GetOrCreateAllowedSettings(Dictionary<string, object> metaContent)
    {
      metaContent ??= new Dictionary<string, object>();
      if (!metaContent.TryGetValue("allowedSettings", out var existing)
          || existing is not Dictionary<string, object> allowedSettings)
      {
        allowedSettings = new Dictionary<string, object>();
        metaContent["allowedSettings"] = allowedSettings;
      }

      return allowedSettings;
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
      var metaContent = resource.TryGetMetaContent() ?? new Dictionary<string, object>();
      var allowedSettings = GetOrCreateAllowedSettings(metaContent);
      allowedSettings["rotation"] = rotationEnabled.Value;

      var request = new PamProto.PAMResourceConfig
      {
        RecordUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode()),
        NetworkUid = ByteString.CopyFrom(_configUid.Base64UrlDecode()),
        Meta = ByteString.CopyFrom(JsonUtils.DumpJson(metaContent)),
      };

      try
      {
        await RouterUtils.ConfigureResourceAsync(_auth, request);
        return;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Trace.TraceWarning(
          "PAM: configure_resource failed for {0}, falling back to graph meta write: {1}",
          resourceUid,
          ex.Message);
      }

      resource.SetDataEdge("meta", JsonUtils.DumpJson(metaContent), modified: true);
      await SaveAsync();
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
      user.TryGetAclContent(headUid, out var existing);
      existing ??= new Dictionary<string, object>();

      MergeTriState(existing, "is_admin", isAdmin);
      MergeTriState(existing, "belongs_to", belongsTo);
      MergeTriState(existing, "is_launch_credential", isLaunchCredential);

      user.SetEdge(headUid, PamGraphEdgeType.Acl, SerializeAclContent(existing), path: null, modified: true);
    }

    private static void MergeTriState(IDictionary<string, object> content, string key, bool? value)
    {
      if (value == null)
      {
        return;
      }

      content[key] = value.Value;
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
      catch
      {
        return new Dictionary<string, object>();
      }
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
        if (!_edges.TryGetValue(EdgeKey(headUid, PamGraphEdgeType.Acl), out var edge))
        {
          return false;
        }

        content = ParseAclContent(edge.Content);
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

      internal Dictionary<string, object> TryGetMetaContent()
      {
        if (_dataEdge?.Content == null
            || _dataEdge.Content.Length == 0
            || !string.Equals(_dataEdge.Path, "meta", StringComparison.Ordinal))
        {
          return null;
        }

        try
        {
          return JsonUtils.ParseJson<Dictionary<string, object>>(_dataEdge.Content);
        }
        catch
        {
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
  /// High-level rotation edit graph operations (config_resource / config_user).
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
        await graph.LoadAsync();
      }

      if (!graph.ResourceBelongsToConfig(resourceRecord.Uid))
      {
        var resourceType = PamRotationGraph.GetResourceRefType(resourceRecord.TypeName ?? "");
        await graph.LinkResourceToConfigAsync(resourceRecord.Uid, resourceType);
        await graph.LoadAsync();
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

      bool? rotationEnabled = null;
      if (enable)
      {
        rotationEnabled = true;
      }
      else if (disable)
      {
        rotationEnabled = false;
      }

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
        return;
      }

      if (string.IsNullOrEmpty(resourceUid))
      {
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
    }
  }
}
