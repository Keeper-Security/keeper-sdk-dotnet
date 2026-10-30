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
    /// <summary>Result of creating a one-time share.</summary>
    public sealed class ExternalRecordShareCreationResult
    {
        internal ExternalRecordShareCreationResult(string shareUrl, bool isEditable, bool? canEdit)
        {
            ShareUrl = shareUrl;
            IsEditable = isEditable;
            CanEdit = canEdit;
        }

        /// <summary>The share URL.</summary>
        public string ShareUrl { get; }

        /// <summary>Whether the recipient can edit the record.</summary>
        public bool IsEditable { get; }

        /// <summary>Current user's edit permission, or null if it was not checked or could not be checked.</summary>
        public bool? CanEdit { get; }
    }

    /// <summary>
    /// One-time share operations for classic records without a full vault sync.
    /// </summary>
    public static class OneTimeShareSkipSyncDown
    {
        /// <summary>
        /// Creates a one-time share for an accessible classic record.
        /// </summary>
        /// <param name="auth">Authenticated session (IAuthentication, not VaultOnline).</param>
        /// <param name="recordUid">The UID of the record to share.</param>
        /// <param name="expireIn">Share lifetime; must be at least one second and no longer than 180 days.</param>
        /// <param name="shareName">Optional label for the one-time share.</param>
        /// <param name="isEditable">Allow editing only if the current user has edit access.</param>
        /// <returns>The one-time share URL (includes embedded client key in fragment).</returns>
        /// <exception cref="VaultException">If the record is not accessible or its key cannot be decrypted.</exception>
        public static async Task<string> CreateExternalRecordShareAsync(
            IAuthentication auth,
            string recordUid,
            TimeSpan expireIn,
            string shareName = null,
            bool isEditable = false)
        {
            var result = await CreateExternalRecordShareWithStatusAsync(
                auth, recordUid, expireIn, shareName, isEditable).ConfigureAwait(false);
            return result.ShareUrl;
        }

        /// <summary>
        /// Creates a one-time share and reports whether edit access was confirmed.
        /// </summary>
        /// <param name="auth">Authenticated session.</param>
        /// <param name="recordUid">Classic record UID.</param>
        /// <param name="expireIn">Share lifetime; must be at least one second and no longer than 180 days.</param>
        /// <param name="shareName">Optional label for the one-time share.</param>
        /// <param name="isEditable">Allow editing only if the current user has edit access.</param>
        /// <returns>The URL and the effective edit settings.</returns>
        /// <exception cref="VaultException">If the record is not accessible or its key cannot be decrypted.</exception>
        public static async Task<ExternalRecordShareCreationResult> CreateExternalRecordShareWithStatusAsync(
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
            if (expireIn < TimeSpan.FromSeconds(1))
                throw new ArgumentOutOfRangeException(nameof(expireIn), "Share expiration must be at least one second.");
            if (expireIn > TimeSpan.FromDays(180))
                throw new ArgumentOutOfRangeException(nameof(expireIn), "Share expiration cannot exceed 180 days.");

            var trimmedUid = recordUid.Trim();

            RecordDetailsSkipSyncResult recordDetails;
            try
            {
                recordDetails = await RecordSkipSyncDown.GetOwnedRecordsAsync(
                        auth, new[] { trimmedUid })
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new VaultException($"Failed to retrieve record \"{recordUid}\": {ex.Message}");
            }

            if (recordDetails.Records.Count > 0)
            {
                var record = recordDetails.Records.FirstOrDefault(x =>
                    string.Equals(x?.Uid, trimmedUid, StringComparison.Ordinal));
                if (record == null)
                    throw new VaultException($"Record details did not contain the requested record \"{recordUid}\".");

                if (record is TypedRecord typedRecord)
                {
                    bool? canEdit = null;
                    if (isEditable)
                        canEdit = await RecordSkipSyncDown.CanEditRecordAsync(auth, typedRecord.Uid).ConfigureAwait(false);
                    var effectiveEditable = isEditable && canEdit == true;

                    var shareUrl = await CreateExternalRecordShareInternalAsync(
                        auth,
                        typedRecord.Uid,
                        typedRecord.RecordKey,
                        expireIn,
                        shareName,
                        effectiveEditable).ConfigureAwait(false);
                    return new ExternalRecordShareCreationResult(shareUrl, effectiveEditable, canEdit);
                }
                throw new VaultException($"Record \"{recordUid}\" must be a typed record. Legacy records cannot be shared as one-time shares.");
            }

            if (recordDetails.NoPermissionRecordUids.Count > 0)
                throw new VaultException(
                    $"No permission to access record \"{recordUid}\". Ensure it is owned by you or shared with you.");
            if (recordDetails.InvalidRecordUids.Count > 0)
                throw new VaultException($"Invalid record UID format: \"{recordUid}\"");

            if (recordDetails.FailedRecordUids.Count > 0)
            {
                throw new VaultException(
                    $"Could not load record \"{recordUid}\". Verify your access and that its record key is available.");
            }

            throw new VaultException($"Record \"{recordUid}\" was not found or could not be accessed.");
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
            if (recordKey == null || recordKey.Length != 32)
                throw new VaultException("A valid 256-bit record key is required to create an external share.");

            var clientKey = CryptoUtils.GenerateEncryptionKey();
            byte[] clientId;
            using (var hmac = new HMACSHA512(clientKey))
            {
                clientId = hmac.ComputeHash(Encoding.UTF8.GetBytes("KEEPER_SECRETS_MANAGER_CLIENT_ID"));
            }

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
                    byte[] decodedClientId;
                    try
                    {
                        decodedClientId = clientId.Trim().Base64UrlDecode();
                    }
                    catch (Exception ex)
                    {
                        throw new VaultException($"Invalid client ID format: \"{clientId}\". {ex.Message}");
                    }
                    request.Clients.Add(ByteString.CopyFrom(decodedClientId));
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
