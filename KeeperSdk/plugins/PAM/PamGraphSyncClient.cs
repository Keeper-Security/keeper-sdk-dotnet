using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Google.Protobuf;
using GraphSyncProto = GraphSync;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Plugins.PAM
{
  /// <summary>
  /// HTTP client for PAM graph-sync endpoints (rotation linking graph).
  /// </summary>
  internal static class PamGraphSyncClient
  {
    internal const string PamGraphEndpoint = "graph-sync/pam";

    internal static async Task<List<GraphSyncProto.GraphSyncDataPlus>> MultiSyncAsync(
      IAuthentication auth,
      string configUid,
      long syncPoint = 0)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      if (string.IsNullOrEmpty(configUid))
      {
        throw new ArgumentNullException(nameof(configUid));
      }

      var originBytes = ByteString.CopyFrom(configUid.Base64UrlDecode());
      var allData = new List<GraphSyncProto.GraphSyncDataPlus>();
      var perStreamSyncPoint = new Dictionary<string, long>(StringComparer.Ordinal)
      {
        [configUid] = syncPoint,
      };

      while (perStreamSyncPoint.Count > 0)
      {
        var multiQuery = new GraphSyncProto.GraphSyncMultiQuery();
        foreach (var entry in perStreamSyncPoint)
        {
          multiQuery.Queries.Add(new GraphSyncProto.GraphSyncQuery
          {
            StreamId = ByteString.CopyFrom(entry.Key.Base64UrlDecode()),
            Origin = originBytes,
            SyncPoint = entry.Value,
          });
        }

        var responseBytes = await ExecuteGraphSyncAsync(auth, $"{PamGraphEndpoint}/multi_sync", multiQuery.ToByteArray());
        if (responseBytes == null || responseBytes.Length == 0)
        {
          break;
        }

        var multiResult = GraphSyncProto.GraphSyncMultiResult.Parser.ParseFrom(responseBytes);
        var nextStreams = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var result in multiResult.Results)
        {
          allData.AddRange(result.Data);
          if (result.HasMore && result.StreamId != null && !result.StreamId.IsEmpty)
          {
            var streamUid = result.StreamId.ToByteArray().Base64UrlEncode();
            nextStreams[streamUid] = result.SyncPoint;
          }
        }

        perStreamSyncPoint = nextStreams;
      }

      return allData;
    }

    internal static async Task AddDataAsync(
      IAuthentication auth,
      string configUid,
      IEnumerable<GraphSyncProto.GraphSyncData> data)
    {
      if (auth == null)
      {
        throw new ArgumentNullException(nameof(auth));
      }

      var request = new GraphSyncProto.GraphSyncAddDataRequest
      {
        Origin = CreateRef(configUid, GraphSyncProto.RefType.RftPamNetwork),
      };
      request.Data.AddRange(data);
      await ExecuteGraphSyncAsync(auth, $"{PamGraphEndpoint}/add_data", request.ToByteArray());
    }

    internal static GraphSyncProto.GraphSyncRef CreateRef(string uid, GraphSyncProto.RefType refType)
    {
      return new GraphSyncProto.GraphSyncRef
      {
        Type = refType,
        Value = ByteString.CopyFrom(uid.Base64UrlDecode()),
      };
    }

    private static async Task<byte[]> ExecuteGraphSyncAsync(IAuthentication auth, string endpoint, byte[] payload)
    {
      if (auth.Endpoint is not KeeperEndpoint keeperEndpoint)
      {
        throw new InvalidOperationException("Endpoint must be KeeperEndpoint to use PAM graph sync.");
      }

      return await keeperEndpoint.ExecuteRouterRest(endpoint, auth.AuthContext.SessionToken, payload);
    }
  }
}
