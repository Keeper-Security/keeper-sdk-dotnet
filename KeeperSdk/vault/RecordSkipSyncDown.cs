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
        /// Calls <c>vault/get_records_details</c> with <see cref="GetRecordDataWithAccessInfoRequest"/> and decrypts each
        /// <see cref="RecordDataWithAccessInfo"/> (see API <c>recordDataWithAccessInfo</c> / <c>noPermissionRecordUid</c>).
        /// </summary>
        /// <param name="include">
        /// Maps to <c>recordDetailsInclude</c> on the request (API default <c>DATA_PLUS_SHARE</c> =
        /// <see cref="RecordDetailsInclude.DataPlusShare"/>).
        /// </param>
        public static async Task<RecordDetailsSkipSyncResult> GetRecordsAsync(IAuthentication auth,
            IEnumerable<string> recordUids,
            RecordDetailsInclude include = RecordDetailsInclude.DataPlusShare)
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

                byte[] recordKey;
                try
                {
                    recordKey = SharedFolderSkipSyncDown.DecryptKeeperKey(
                        auth.AuthContext,
                        rd.RecordKey?.ToByteArray() ?? Array.Empty<byte>(),
                        rd.RecordKeyType);
                }
                catch
                {
                    failed.Add(uid);
                    continue;
                }

                if (recordKey == null || recordKey.Length == 0)
                {
                    failed.Add(uid);
                    continue;
                }

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

                KeeperRecord keeperRecord;
                try
                {
                    keeperRecord = ephemeral.Load(recordKey);
                }
                catch
                {
                    failed.Add(uid);
                    continue;
                }

                if (keeperRecord == null)
                {
                    failed.Add(uid);
                    continue;
                }

                keeperRecord.Revision = rd.Revision;
                records.Add(keeperRecord);
            }

            return new RecordDetailsSkipSyncResult(records, noPermission, failed, invalid);
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
