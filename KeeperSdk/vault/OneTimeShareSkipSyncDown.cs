using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Authentication;
using Records;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// One-Time Share operations without requiring a full vault sync.
    /// Uses direct API calls with record-level decryption keys.
    /// This Skip Sync method works ONLY for owned records.
    /// </summary>
    public static class OneTimeShareSkipSyncDown
    {
        /// <summary>
        /// Creates an external/one-time share for an owned record without requiring vault sync.
        /// Fetches only the specific record's details and encryption key via API.
        ///
        /// LIMITATION: This method only supports owned records. For records in shared folders
        /// use the standard New-KeeperOneTimeShare command.
        /// </summary>
        /// <param name="auth">Authenticated session (IAuthentication, not VaultOnline).</param>
        /// <param name="recordUid">The UID of the owned record to share.</param>
        /// <param name="expireIn">How long the share should remain active.</param>
        /// <param name="shareName">Optional label for the one-time share.</param>
        /// <param name="isEditable">Share recipient can edit the record.</param>
        /// <returns>The one-time share URL (includes embedded client key in fragment).</returns>
        /// <exception cref="VaultException">If record not found, not owned, or decryption fails.</exception>
        public static async Task<string> CreateExternalRecordShareAsync(
            IAuthentication auth,
            string recordUid,
            TimeSpan expireIn,
            string shareName = null,
            bool isEditable = false)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(recordUid))
                throw new ArgumentException("recordUid is required.", nameof(recordUid));

            var trimmedUid = recordUid.Trim();

            var recordDetails = await RecordSkipSyncDown.GetOwnedRecordsAsync(
                auth,
                new[] { trimmedUid })
                .ConfigureAwait(false);

            if (recordDetails.Records.Count > 0)
            {
                var record = recordDetails.Records[0];
                if (record is TypedRecord typedRecord)
                {
                    return await CreateExternalRecordShareInternalAsync(
                        auth,
                        typedRecord.Uid,
                        typedRecord.RecordKey,
                        expireIn,
                        shareName,
                        isEditable)
                        .ConfigureAwait(false);
                }
                throw new VaultException($"Record \"{recordUid}\" must be a typed record. Legacy records cannot be shared as one-time shares.");
            }

            if (recordDetails.NoPermissionRecordUids.Count > 0)
                throw new VaultException($"No permission to access record \"{recordUid}\". Ensure you own this record or have appropriate access.");
            if (recordDetails.InvalidRecordUids.Count > 0)
                throw new VaultException($"Invalid record UID format: \"{recordUid}\"");

            throw new VaultException(
                $"Record \"{recordUid}\" not found as owned record. Skip Sync one-time share creation supports only owned records. " +
                $"For records in shared folders, use New-KeeperOneTimeShare (requires full vault sync).");
        }

        /// <summary>
        /// Creates an external/one-time share using a pre-decrypted record key.
        /// </summary>
        private static async Task<string> CreateExternalRecordShareInternalAsync(
            IAuthentication auth,
            string recordUid,
            byte[] recordKey,
            TimeSpan expireIn,
            string shareName = null,
            bool isEditable = false)
        {
            if (recordKey == null || recordKey.Length == 0)
                throw new VaultException("Record key is required to create external share.");

            var clientKey = CryptoUtils.GenerateEncryptionKey();
            var hmac = new HMACSHA512(clientKey);
            var clientId = hmac.ComputeHash(Encoding.UTF8.GetBytes("KEEPER_SECRETS_MANAGER_CLIENT_ID"));

            var request = new AddExternalShareRequest
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                ClientId = ByteString.CopyFrom(clientId),
                EncryptedRecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(recordKey, clientKey)),
                AccessExpireOn = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (long)expireIn.TotalMilliseconds,
                IsEditable = isEditable,
            };

            if (!string.IsNullOrEmpty(shareName))
            {
                request.Id = shareName;
            }

            return await auth.AddExternalShareAndBuildUriAsync(request, clientKey)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Retrieves all external/one-time shares for a specific record without vault sync.
        /// Works for both owned records and records in shared folders (when accessible).
        /// </summary>
        /// <param name="auth">Authenticated session (IAuthentication, not VaultOnline).</param>
        /// <param name="recordUid">The UID of the record to fetch shares for.</param>
        /// <returns>Array of external/one-time shares for the record (empty array if none exist).</returns>
        /// <exception cref="VaultException">If the record UID is invalid or API call fails.</exception>
        public static async Task<ExternalRecordShare[]> GetExternalRecordSharesAsync(
            IAuthentication auth,
            string recordUid)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(recordUid))
                throw new ArgumentException("recordUid is required.", nameof(recordUid));

            try
            {
                var request = new GetAppInfoRequest
                {
                    AppRecordUid = { ByteString.CopyFrom(recordUid.Trim().Base64UrlDecode()) },
                };

                var response = await auth.ExecuteAuthRest<GetAppInfoRequest, GetAppInfoResponse>(
                    "vault/get_app_info", request)
                    .ConfigureAwait(false);

                if (response?.AppInfo == null)
                    return Array.Empty<ExternalRecordShare>();

                return response.AppInfo
                    .Where(x => x.IsExternalShare)
                    .SelectMany(share => share.Clients, (share, client) => new { share, client })
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
                    })
                    .ToArray();
            }
            catch (Exception ex)
            {
                throw new VaultException($"Failed to retrieve external shares for record {recordUid}: {ex.Message}");
            }
        }

        /// <summary>
        /// Deletes one or more external/one-time shares for a record without vault sync.
        /// Can delete shares for both owned records and shared folder records.
        /// </summary>
        /// <param name="auth">Authenticated session (IAuthentication, not VaultOnline).</param>
        /// <param name="recordUid">The UID of the record whose shares should be deleted.</param>
        /// <param name="clientIds">Client IDs of the shares to delete (obtain from GetExternalRecordSharesAsync).</param>
        /// <exception cref="VaultException">If record UID is invalid or deletion fails.</exception>
        public static async Task DeleteExternalRecordSharesAsync(
            IAuthentication auth,
            string recordUid,
            IEnumerable<string> clientIds)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(recordUid))
                throw new ArgumentException("recordUid is required.", nameof(recordUid));
            if (clientIds == null)
                throw new ArgumentNullException(nameof(clientIds));

            var clientIdList = clientIds.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
            if (clientIdList.Count == 0)
                return;

            try
            {
                var request = new RemoveAppClientsRequest
                {
                    AppRecordUid = ByteString.CopyFrom(recordUid.Trim().Base64UrlDecode()),
                };

                foreach (var clientId in clientIdList)
                {
                    try
                    {
                        request.Clients.Add(ByteString.CopyFrom(clientId.Trim().Base64UrlDecode()));
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Warning: Invalid client ID format: {clientId}. Error: {ex.Message}");
                    }
                }

                if (request.Clients.Count > 0)
                {
                    await auth.ExecuteAuthRest("vault/external_share_remove", request)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                throw new VaultException($"Failed to delete external shares for record {recordUid}: {ex.Message}");
            }
        }

        /// <summary>
        /// Deletes an external/one-time share by name without vault sync.
        /// Fetches all shares for the record, finds the matching share by name, then deletes it.
        /// </summary>
        /// <param name="auth">Authenticated session (IAuthentication, not VaultOnline).</param>
        /// <param name="recordUid">The UID of the record whose share should be deleted.</param>
        /// <param name="shareName">The name/label of the share to delete (must match exactly).</param>
        /// <exception cref="VaultException">If share not found, record UID invalid, or deletion fails.</exception>
        public static async Task DeleteExternalRecordShareByNameAsync(
            IAuthentication auth,
            string recordUid,
            string shareName)
        {
            if (string.IsNullOrWhiteSpace(shareName))
                throw new ArgumentException("shareName is required.", nameof(shareName));

            var shares = await GetExternalRecordSharesAsync(auth, recordUid)
                .ConfigureAwait(false);

            var shareToDelete = shares.FirstOrDefault(x => x.Name == shareName);
            if (shareToDelete == null)
                throw new VaultException($"External share '{shareName}' not found for record {recordUid}");

            await DeleteExternalRecordSharesAsync(auth, recordUid, new[] { shareToDelete.ClientId })
                .ConfigureAwait(false);
        }

    }
}
