using KeeperSecurity.Utils;
using System.Security.Cryptography;
using System.Text;
using Authentication;
using Google.Protobuf;
using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using System.Linq;
using System.Collections.Generic;

namespace KeeperSecurity.Vault;

/// <summary>
/// Represents External / One-Time Share
/// </summary>
public class ExternalRecordShare { 
    /// <summary>
    /// Record UID
    /// </summary>
    public string RecordUid { get; internal set; }
    /// <exclude/>
    public string ClientId { get; internal set; }
    /// <summary>
    /// Share Name
    /// </summary>
    public string Name { get; internal set; }
    /// <summary>
    /// Share Created
    /// </summary>
    public DateTimeOffset CreatedOn { get; internal set; }
    /// <exclude/>
    public DateTimeOffset FirstAccessExpiresOn { get; internal set; }
    /// <summary>
    /// Share Expiration
    /// </summary>
    public DateTimeOffset AccessExpiresOn { get; internal set; }
    /// <summary>
    /// URL Opened
    /// </summary>
    public DateTimeOffset? FirstAccessed { get; internal set; }
    /// <summary>
    /// Last Accessed
    /// </summary>
    public DateTimeOffset? LastAccessed { get; internal set; }
}

/// <summary>
/// Miscellaneous External Share Methods
/// </summary>
public static class ExternalRecordShareExtensions
{
    /// <summary>
    /// Retrieve external shares for a record
    /// </summary>
    /// <param name="vault">Vault</param>
    /// <param name="recordUid">Record UID</param>
    /// <returns>List of external shares</returns>
    public static async Task<ExternalRecordShare[]> GetExernalRecordShares(this VaultOnline vault, string recordUid)
    {
        var rq = new GetAppInfoRequest
        {
            AppRecordUid = { ByteString.CopyFrom(recordUid.Base64UrlDecode()) },
        };

        var rs = await vault.Auth.ExecuteAuthRest<GetAppInfoRequest, GetAppInfoResponse>("vault/get_app_info", rq);

        return rs.AppInfo.Where(x => x.IsExternalShare).SelectMany(share => share.Clients, (share, client) => new { share, client })
            .Select(x => new ExternalRecordShare
            {
                RecordUid = x.share.AppRecordUid.ToArray().Base64UrlEncode(),
                ClientId = x.client.ClientId.ToArray().Base64UrlEncode(),
                Name = x.client.Id,
                CreatedOn = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.client.CreatedOn),
                FirstAccessExpiresOn = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.client.FirstAccessExpireOn),
                AccessExpiresOn = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.client.AccessExpireOn),
                FirstAccessed = x.client.FirstAccess > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.client.FirstAccess) : null,
                LastAccessed = x.client.LastAccess > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x.client.LastAccess) : null,
            }).ToArray();
    }

    /// <summary>
    /// Deletes external shares for a record
    /// </summary>
    /// <param name="vault">Vault</param>
    /// <param name="recordUid">Record UID</param>
    /// <param name="clientIds">List of external share names</param>
    /// <returns>Awaitable task</returns>
    public static async Task DeleteExernalRecordShares(this VaultOnline vault, string recordUid, IEnumerable<string> clientIds)
    {
        var rq = new RemoveAppClientsRequest
        {
            AppRecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
        };
        var allShares = await vault.GetExernalRecordShares(recordUid);
        foreach (var clientId in clientIds)
        {
            var share = allShares.FirstOrDefault(x => x.ClientId == clientId);
            if (share != null)
            {
                rq.Clients.Add(ByteString.CopyFrom(clientId.Base64UrlDecode()));
            }
        }
        if (rq.Clients.Count > 0)
        {
            await vault.Auth.ExecuteAuthRest("vault/external_share_remove", rq);
        }
    }

    /// <summary>
    /// Creates an external share for a record
    /// </summary>
    /// <param name="vault">Vault</param>
    /// <param name="recordUid">Record UID</param>
    /// <param name="expireIn">Share Expiration</param>
    /// <param name="shareName">Share Name</param>
    /// <returns>External Share URL</returns>
    /// <exception cref="VaultException"></exception>
    public static async Task<string> CreateExternalRecordShare(this VaultOnline vault, string recordUid, TimeSpan expireIn, string shareName = null) {
        var record = vault.GetRecord(recordUid);
        if (record == null)
        {
            throw new VaultException($"Record Uid \"{recordUid}\" not found");
        }
        if (record is not TypedRecord tr) {
            throw new VaultException($"Record Uid \"{record.Uid}\" / Title \"{record.Title}\" should be typed record.");
        }

        var clientKey = CryptoUtils.GenerateEncryptionKey();
        var hmac = new HMACSHA512(clientKey);
        var clientId = hmac.ComputeHash(Encoding.UTF8.GetBytes("KEEPER_SECRETS_MANAGER_CLIENT_ID"));
        var rq = new AddExternalShareRequest { 
            RecordUid = ByteString.CopyFrom(tr.Uid.Base64UrlDecode()),
            ClientId = ByteString.CopyFrom(clientId),
            EncryptedRecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(tr.RecordKey, clientKey)),
            AccessExpireOn = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (long)expireIn.TotalMilliseconds,
        };
        if (!string.IsNullOrEmpty(shareName)) 
        {
            rq.Id = shareName;
        }
        await vault.Auth.ExecuteAuthRest("vault/external_share_add", rq);
        var builder = new UriBuilder(vault.Auth.Endpoint.Server)
        {
            Path = "/vault/share",
            Scheme = "https",
            Port = 443,
            Fragment = clientKey.Base64UrlEncode(),
        };
        return builder.ToString();
    }
}