using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using Records;

namespace KeeperSecurity.Vault
{
    /// <summary>Load records without vault sync.</summary>
    public static class RecordSkipSyncDown
    {
        /// <summary>
        /// Calls <c>vault/get_records_details</c> and decrypts payloads using the record key from each
        /// <see cref="RecordData"/> (<see cref="RecordData.RecordKey"/> / <see cref="RecordData.RecordKeyType"/>).
        /// </summary>
        public static Task<RecordDetailsSkipSyncResult> GetOwnedRecordsAsync(IAuthentication auth,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include = RecordDetailsInclude.DataPlusShare)
            => GetRecordsDetailsAsync(auth, recordUids, include, sharedFolderRecordKeys: null);

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

        private static async Task<RecordDetailsSkipSyncResult> GetRecordsDetailsAsync(IAuthentication auth,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include,
            IReadOnlyDictionary<string, byte[]> sharedFolderRecordKeys)
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

                if (!TryResolveRecordKey(auth.AuthContext, rd, uid, sharedFolderRecordKeys, out var recordKey) ||
                    recordKey == null || recordKey.Length == 0)
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
            if (sharedFolderRecordKeys != null)
            {
                if (sharedFolderRecordKeys.TryGetValue(uid, out var k) && k != null && k.Length > 0)
                {
                    recordKey = k;
                    return true;
                }

                return false;
            }

            try
            {
                recordKey = SharedFolderSkipSyncDown.DecryptKeeperKey(
                    authContext,
                    rd.RecordKey?.ToByteArray() ?? Array.Empty<byte>(),
                    rd.RecordKeyType);
            }
            catch
            {
                return false;
            }

            return recordKey != null && recordKey.Length > 0;
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
}
