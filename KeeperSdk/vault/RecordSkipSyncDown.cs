using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using Records;
using KeeperSecurity.Vault.Commands;

namespace KeeperSecurity.Vault
{
    /// <summary>Load records without vault sync.</summary>
    public static class RecordSkipSyncDown
    {
        /// <summary>
        /// Loads records with keys returned by <c>vault/get_records_details</c> or accessible shared folders.
        /// </summary>
        public static Task<RecordDetailsSkipSyncResult> GetOwnedRecordsAsync(IAuthentication auth,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include = RecordDetailsInclude.DataPlusShare)
            => GetRecordsDetailsAsync(auth, recordUids, include, sharedFolderRecordKeys: null);

        /// <summary>
        /// Checks whether the current user can edit the record. Returns null if the check fails.
        /// </summary>
        internal static async Task<bool?> CanEditRecordAsync(IAuthentication auth, string recordUid)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(recordUid))
                throw new ArgumentException("recordUid is required.", nameof(recordUid));

            var trimmedUid = recordUid.Trim();
            ByteString uidBytes;
            try
            {
                var decodedUid = trimmedUid.Base64UrlDecode();
                if (decodedUid == null || decodedUid.Length == 0)
                    return null;
                uidBytes = ByteString.CopyFrom(decodedUid);
            }
            catch
            {
                return null;
            }

            var request = new GetRecordDataWithAccessInfoRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                RecordDetailsInclude = RecordDetailsInclude.ShareOnly,
            };
            request.RecordUid.Add(uidBytes);

            try
            {
                var response = await auth.ExecuteAuthRest<GetRecordDataWithAccessInfoRequest, GetRecordDataWithAccessInfoResponse>(
                    "vault/get_records_details", request).ConfigureAwait(false);
                var recordUidBase64 = uidBytes.ToByteArray().Base64UrlEncode();
                var details = response?.RecordDataWithAccessInfo?.FirstOrDefault(x =>
                    x.RecordUid != null
                    && string.Equals(
                        x.RecordUid.ToByteArray().Base64UrlEncode(),
                        recordUidBase64,
                        StringComparison.Ordinal));
                if (details == null)
                    return null;

                var userPermission = string.IsNullOrWhiteSpace(auth.Username)
                    ? null
                    : details.UserPermission.FirstOrDefault(permission =>
                        string.Equals(permission.Username, auth.Username, StringComparison.OrdinalIgnoreCase));
                if (userPermission == null && details.SharedFolderPermission.Count == 0)
                    return null;

                return (userPermission != null && (userPermission.Owner || userPermission.Editable))
                    || details.SharedFolderPermission.Any(permission => permission.Editable);
            }
            catch
            {
                return null;
            }
        }

        ///<summary>
        /// Calls <c>get_record_history</c> and returns the last modifier and timestamp
        /// for a record without requiring a vault sync.
        /// Use <see cref="KeeperRecord.Uid"/> from
        /// <see cref="GetSharedFolderRecordsAsync(IAuthentication, string, RecordDetailsInclude)"/>
        /// or <see cref="GetOwnedRecordsAsync"/> as the <paramref name="recordUid"/>.
        /// </summary>
        public static async Task<RecordLastModifiedInfo> GetRecordLastModifiedAsync(IAuthentication auth,string recordUid)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(recordUid))
                throw new ArgumentException("recordUid is required.", nameof(recordUid));

            var rs = await VaultOnline.FetchRecordHistoryResponseAsync(auth, recordUid.Trim()).ConfigureAwait(false);
            var latest = rs.History?.LastOrDefault();
            return new RecordLastModifiedInfo(
            recordUid: recordUid.Trim(),
            lastModifiedBy: latest?.Username,
            lastModifiedTime: latest?.ClientModifiedTime ?? 0
            );
        }

        /// <summary>
        /// Calls <c>vault/get_records_details</c> with <see cref="GetRecordDataWithAccessInfoRequest"/> and decrypts each
        /// <see cref="RecordDataWithAccessInfo"/> (see API <c>recordDataWithAccessInfo</c> / <c>noPermissionRecordUid</c>).
        /// </summary>
        /// <remarks>Prefer <see cref="GetOwnedRecordsAsync"/> or <see cref="GetSharedFolderRecordsAsync"/>.</remarks>
        [Obsolete("Use GetOwnedRecordsAsync for arbitrary record UIDs, or GetSharedFolderRecordsAsync for shared-folder records.")]
        public static Task<RecordDetailsSkipSyncResult> GetRecordsAsync(IAuthentication auth,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include = RecordDetailsInclude.DataPlusShare)
            => GetOwnedRecordsAsync(auth, recordUids, include);

        /// <summary>
        /// Loads decrypted record keys via <see cref="SharedFolderSkipSyncDown.GetRecordKeysFromSharedFolderAsync"/>
        /// (<c>get_shared_folders</c> → <c>records</c>), then calls <c>vault/get_records_details</c> and decrypts using those keys.
        /// </summary>
        public static async Task<RecordDetailsSkipSyncResult> GetSharedFolderRecordsAsync(IAuthentication auth,
            string sharedFolderUid,
            RecordDetailsInclude include = RecordDetailsInclude.DataPlusShare)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(sharedFolderUid))
                throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));

            var keys = await SharedFolderSkipSyncDown.GetRecordKeysFromSharedFolderAsync(auth, sharedFolderUid.Trim())
                .ConfigureAwait(false);
            if (keys.Count == 0)
            {
                return new RecordDetailsSkipSyncResult(
                    Array.Empty<KeeperRecord>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>());
            }

            return await GetRecordsDetailsAsync(auth, keys.Keys, include, keys).ConfigureAwait(false);
        }

        /// <summary>
        /// Like <see cref="GetSharedFolderRecordsAsync(IAuthentication, string, RecordDetailsInclude)"/>, 
        /// but only requests the given record UIDs.
        /// </summary>
        public static async Task<RecordDetailsSkipSyncResult> GetSharedFolderRecordsAsync(IAuthentication auth,
            string sharedFolderUid,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include = RecordDetailsInclude.DataPlusShare)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");
            if (string.IsNullOrWhiteSpace(sharedFolderUid))
                throw new ArgumentException("Shared folder UID is required.", nameof(sharedFolderUid));

            var uidList = (recordUids ?? Enumerable.Empty<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (uidList.Count == 0)
            {
                return new RecordDetailsSkipSyncResult(
                    Array.Empty<KeeperRecord>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>());
            }

            // Try this folder first, then the folders returned with the record details.
            return await GetRecordsDetailsAsync(auth, uidList, include,
                    sharedFolderRecordKeys: null, sharedFolderUidFallback: sharedFolderUid.Trim())
                .ConfigureAwait(false);
        }

        private static async Task<RecordDetailsSkipSyncResult> GetRecordsDetailsAsync(IAuthentication auth,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include,
            IReadOnlyDictionary<string, byte[]> sharedFolderRecordKeys,
            string sharedFolderUidFallback = null)
        {
            if (auth == null || auth.AuthContext == null)
                throw new VaultException("An authenticated session is needed.");

            var uidList = (recordUids ?? Enumerable.Empty<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (uidList.Count == 0)
            {
                return new RecordDetailsSkipSyncResult(
                    Array.Empty<KeeperRecord>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>());
            }

            var invalid = new List<string>();
            var rq = new GetRecordDataWithAccessInfoRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                RecordDetailsInclude = include,
            };
            foreach (var uid in uidList)
            {
                try
                {
                    rq.RecordUid.Add(ByteString.CopyFrom(uid.Base64UrlDecode()));
                }
                catch
                {
                    invalid.Add(uid);
                }
            }

            if (rq.RecordUid.Count == 0)
            {
                return new RecordDetailsSkipSyncResult(
                    Array.Empty<KeeperRecord>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    invalid);
            }

            var rs = await auth
                .ExecuteAuthRest<GetRecordDataWithAccessInfoRequest, GetRecordDataWithAccessInfoResponse>(
                    "vault/get_records_details", rq)
                .ConfigureAwait(false);

            var noPermission = (rs.NoPermissionRecordUid ?? Enumerable.Empty<ByteString>())
                .Select(x => x.ToArray().Base64UrlEncode())
                .ToList();

            var records = new List<KeeperRecord>();
            var failed = new List<string>();
            var sharedFolderRecordKeyCache =
                new Dictionary<string, IReadOnlyDictionary<string, byte[]>>(StringComparer.OrdinalIgnoreCase);

            foreach (var item in rs.RecordDataWithAccessInfo ?? Enumerable.Empty<RecordDataWithAccessInfo>())
            {
                if (item.RecordUid == null || item.RecordUid.IsEmpty)
                    continue;

                var uid = item.RecordUid.ToArray().Base64UrlEncode();
                var rd = item.RecordData;
                if (rd == null || string.IsNullOrEmpty(rd.EncryptedRecordData))
                {
                    failed.Add(uid);
                    continue;
                }

                var hasRecordKey = TryResolveRecordKey(
                    auth.AuthContext, rd, uid, sharedFolderRecordKeys, out var recordKey);
                if (!hasRecordKey && sharedFolderRecordKeys == null)
                {
                    recordKey = await TryResolveRecordKeyFromSharedFoldersAsync(
                            auth,
                            item,
                            uid,
                            sharedFolderUidFallback,
                            sharedFolderRecordKeyCache)
                        .ConfigureAwait(false);
                    hasRecordKey = recordKey != null && recordKey.Length > 0;
                }

                if (!hasRecordKey || recordKey == null || recordKey.Length == 0)
                {
                    failed.Add(uid);
                    continue;
                }

                if (!TryLoadKeeperRecordFromDetails(item, recordKey, out var keeperRecord))
                {
                    failed.Add(uid);
                    continue;
                }

                keeperRecord.Revision = rd.Revision;
                records.Add(keeperRecord);
            }

            return new RecordDetailsSkipSyncResult(records, noPermission, failed, invalid);
        }

        private static bool TryResolveRecordKey(IAuthContext authContext, RecordData rd, string uid,
            IReadOnlyDictionary<string, byte[]> sharedFolderRecordKeys, out byte[] recordKey)
        {
            recordKey = null;
            // Try the key returned with the record before using shared-folder keys.
            var encryptedRecordKey = rd.RecordKey?.ToByteArray();
            if (encryptedRecordKey != null && encryptedRecordKey.Length > 0)
            {
                try
                {
                    recordKey = SharedFolderSkipSyncDown.DecryptKeeperKey(
                        authContext,
                        encryptedRecordKey,
                        rd.RecordKeyType);
                    if (recordKey != null && recordKey.Length > 0)
                        return true;
                }
                catch
                {
                    // Try the shared-folder key below.
                }
            }

            if (sharedFolderRecordKeys != null
                && sharedFolderRecordKeys.TryGetValue(uid, out var sharedFolderRecordKey)
                && sharedFolderRecordKey != null
                && sharedFolderRecordKey.Length > 0)
            {
                recordKey = sharedFolderRecordKey;
                return true;
            }

            return false;
        }

        private static async Task<byte[]> TryResolveRecordKeyFromSharedFoldersAsync(
            IAuthentication auth,
            RecordDataWithAccessInfo item,
            string recordUid,
            string preferredSharedFolderUid,
            IDictionary<string, IReadOnlyDictionary<string, byte[]>> sharedFolderRecordKeyCache)
        {
            var sharedFolderUids = new List<string>();
            if (!string.IsNullOrWhiteSpace(preferredSharedFolderUid))
                sharedFolderUids.Add(preferredSharedFolderUid.Trim());

            foreach (var permission in item.SharedFolderPermission)
            {
                if (permission?.SharedFolderUid == null || permission.SharedFolderUid.IsEmpty)
                    continue;
                var uid = permission.SharedFolderUid.ToArray().Base64UrlEncode();
                if (!sharedFolderUids.Contains(uid, StringComparer.OrdinalIgnoreCase))
                    sharedFolderUids.Add(uid);
            }

            foreach (var sharedFolderUid in sharedFolderUids)
            {
                if (!sharedFolderRecordKeyCache.TryGetValue(sharedFolderUid, out var keys))
                {
                    try
                    {
                        keys = await SharedFolderSkipSyncDown
                            .GetRecordKeysFromSharedFolderAsync(auth, sharedFolderUid)
                            .ConfigureAwait(false);
                    }
                    catch
                    {
                        keys = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                    }

                    sharedFolderRecordKeyCache[sharedFolderUid] = keys
                        ?? new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                }

                if (keys != null && keys.TryGetValue(recordUid, out var key) && key != null && key.Length > 0)
                {
                    return key;
                }
            }

            return null;
        }

        private static bool TryLoadKeeperRecordFromDetails(RecordDataWithAccessInfo item, byte[] recordKey,
            out KeeperRecord keeperRecord)
        {
            keeperRecord = null;
            var rd = item.RecordData;
            if (item.RecordUid == null || item.RecordUid.IsEmpty || rd == null)
                return false;

            var uid = item.RecordUid.ToArray().Base64UrlEncode();
            var ephemeral = new EphemeralStorageRecord
            {
                RecordUid = uid,
                Revision = rd.Revision,
                Version = rd.Version,
                Shared = rd.Shared,
                ClientModifiedTime = rd.ClientModifiedTime,
                Data = rd.EncryptedRecordData ?? "",
                Extra = rd.EncryptedExtraData ?? "",
                Udata = rd.NonSharedData ?? "",
            };

            try
            {
                keeperRecord = ephemeral.Load(recordKey);
            }
            catch
            {
                return false;
            }

            return keeperRecord != null;
        }

        private sealed class EphemeralStorageRecord : IStorageRecord, IUid
        {
            public string RecordUid { get; set; }
            public long Revision { get; set; }
            public int Version { get; set; }
            public long ClientModifiedTime { get; set; }
            public string Data { get; set; }
            public string Extra { get; set; }
            public string Udata { get; set; }
            public bool Shared { get; set; }
            string IUid.Uid => RecordUid;
        }
    }

    public sealed class RecordLastModifiedInfo
    {
        public string RecordUid { get; }
        public string LastModifiedBy { get; }
        public long LastModifiedTime { get; }

        public RecordLastModifiedInfo(
            string recordUid,
            string lastModifiedBy,
            long lastModifiedTime)
        {
            RecordUid = recordUid;
            LastModifiedBy = lastModifiedBy;
            LastModifiedTime = lastModifiedTime;
        }
    }
}
