using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using BreachWatchProto = BreachWatch;
using KeeperSecurity.Utils;
using Tokens;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Service class for handling BreachWatch operations.
    /// </summary>
    internal class BreachWatchService
    {
        private readonly IKeeperStorage _storage;
        private readonly ConcurrentDictionary<string, BreachWatchInfo> _breachWatchRecords;
        private readonly Func<IStorageRecordKey, byte[]> _decryptRecordKey;
        private readonly Func<string, KeeperRecord> _loadRecord;

        /// <summary>
        /// Initializes a new instance of the BreachWatchService class.
        /// </summary>
        /// <param name="storage">The storage interface.</param>
        /// <param name="decryptRecordKey">Function to decrypt record keys.</param>
        /// <param name="loadRecord">Function to load records.</param>
        public BreachWatchService(
            IKeeperStorage storage,
            Func<IStorageRecordKey, byte[]> decryptRecordKey,
            Func<string, KeeperRecord> loadRecord)
        {
            _storage = storage ?? throw new ArgumentNullException(nameof(storage));
            _decryptRecordKey = decryptRecordKey ?? throw new ArgumentNullException(nameof(decryptRecordKey));
            _loadRecord = loadRecord ?? throw new ArgumentNullException(nameof(loadRecord));
            _breachWatchRecords = new ConcurrentDictionary<string, BreachWatchInfo>();
        }

        /// <summary>
        /// Gets all BreachWatch records.
        /// </summary>
        /// <returns>Collection of BreachWatch information.</returns>
        public IEnumerable<BreachWatchInfo> GetBreachWatchRecords()
        {
            if (_breachWatchRecords.IsEmpty)
            {
                RefreshBreachWatchData();
            }
            return _breachWatchRecords.Values;
        }

        /// <summary>
        /// Refreshes BreachWatch data from storage.
        /// </summary>
        public void RefreshBreachWatchData()
        {
            try
            {
                _breachWatchRecords.Clear();
                BuildBreachWatchData();
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Error refreshing BreachWatch data: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets BreachWatch information for a specific record.
        /// </summary>
        /// <param name="recordUid">The record UID.</param>
        /// <returns>BreachWatch information if found, null otherwise.</returns>
        public BreachWatchInfo GetBreachWatchInfo(string recordUid)
        {
            if (string.IsNullOrEmpty(recordUid))
            {
                return null;
            }

            if (_breachWatchRecords.IsEmpty)
            {
                RefreshBreachWatchData();
            }

            return _breachWatchRecords.TryGetValue(recordUid, out var info) ? info : null;
        }

        /// <summary>
        /// Updates BreachWatch records for specific record UIDs.
        /// </summary>
        /// <param name="recordUids">The record UIDs to update.</param>
        public void UpdateBreachWatchRecords(IEnumerable<string> recordUids)
        {
            if (recordUids == null)
            {
                return;
            }

            var recordKeyLookup = BuildRecordKeyLookup();

            foreach (var recordUid in recordUids)
            {
                if (string.IsNullOrEmpty(recordUid))
                {
                    continue;
                }

                // Remove existing entry
                _breachWatchRecords.TryRemove(recordUid, out _);

                // Try to rebuild for this specific record
                var storageRecord = _storage.BreachWatchRecords.GetEntity(recordUid);
                if (storageRecord != null)
                {
                    var breachWatchInfo = ProcessBreachWatchRecord(storageRecord, recordKeyLookup);
                    if (breachWatchInfo != null)
                    {
                        _breachWatchRecords.TryAdd(breachWatchInfo.RecordUid, breachWatchInfo);
                    }
                }
            }
        }

        private void BuildBreachWatchData()
        {
            var storageBreachWatchRecords = _storage.BreachWatchRecords.GetAll();
            if (!storageBreachWatchRecords.Any())
            {
                return;
            }

            var recordKeyLookup = BuildRecordKeyLookup();

            foreach (var storageBWRecord in storageBreachWatchRecords)
            {
                if (!IsValidBreachWatchRecord(storageBWRecord))
                {
                    continue;
                }

                var breachWatchInfo = ProcessBreachWatchRecord(storageBWRecord, recordKeyLookup);
                if (breachWatchInfo != null)
                {
                    _breachWatchRecords.TryAdd(breachWatchInfo.RecordUid, breachWatchInfo);
                }
            }
        }

        private Dictionary<string, IStorageRecordKey> BuildRecordKeyLookup()
        {
            var recordKeyLookup = new Dictionary<string, IStorageRecordKey>();

            foreach (var record in _storage.RecordKeys.GetAllLinks())
            {
                if (!recordKeyLookup.ContainsKey(record.RecordUid))
                {
                    recordKeyLookup.Add(record.RecordUid, record);
                }
            }

            return recordKeyLookup;
        }

        private static bool IsValidBreachWatchRecord(IStorageBreachWatchRecord storageBWRecord)
        {
            return (BreachWatchProto.BreachWatchInfoType)storageBWRecord.Type ==
                   BreachWatchProto.BreachWatchInfoType.Record;
        }

        private BreachWatchInfo ProcessBreachWatchRecord(
            IStorageBreachWatchRecord storageBWRecord,
            Dictionary<string, IStorageRecordKey> recordKeyLookup)
        {
            var recordUid = storageBWRecord.RecordUid;

            if (!recordKeyLookup.TryGetValue(recordUid, out var storageRecord))
            {
                return null;
            }

            var recordKey = _decryptRecordKey(storageRecord);
            if (recordKey == null)
            {
                return null;
            }

            try
            {
                var breachWatchData = DecryptBreachWatchData(storageBWRecord.Data, recordKey);
                return CreateBreachWatchInfo(recordUid, breachWatchData);
            }
            catch (Exception err)
            {
                Trace.TraceError($"Decrypt BreachWatch data error for record {recordUid}: {err.Message}");
                return null;
            }
        }

        private static BreachWatchData DecryptBreachWatchData(string encryptedData, byte[] recordKey)
        {
            var decryptedData = CryptoUtils.DecryptAesV2(encryptedData.Base64UrlDecode(), recordKey);
            return BreachWatchData.Parser.ParseFrom(decryptedData);
        }

        private BreachWatchInfo CreateBreachWatchInfo(string recordUid, BreachWatchData dataObject)
        {
            var (status, resolved) = DetermineBreachWatchStatus(recordUid, dataObject);

            return new BreachWatchInfo
            {
                RecordUid = recordUid,
                Status = status,
                Resolved = resolved,
                Total = dataObject.Passwords.Count
            };
        }

        private (BWStatus Status, ulong Resolved) DetermineBreachWatchStatus(
            string recordUid,
            BreachWatchData dataObject)
        {
            var total = dataObject.Passwords.Count;
            if (total == 0)
            {
                return (BWStatus.Good, 0);
            }

            if (total > 1)
            {
                var keeperRecord = _loadRecord(recordUid);
                if (keeperRecord != null)
                {
                    var currentPassword = keeperRecord.ExtractPassword();
                    if (!string.IsNullOrEmpty(currentPassword))
                    {
                        var matchingPasswordInfo = dataObject.Passwords.FirstOrDefault(x => x.Value == currentPassword);
                        if (matchingPasswordInfo != null)
                        {
                            return (matchingPasswordInfo.Status, matchingPasswordInfo.Resolved);
                        }
                    }
                }
            }

            var firstPassword = dataObject.Passwords[0];
            return (firstPassword.Status, firstPassword.Resolved);
        }

        /// <summary>
        /// Clears all cached BreachWatch data.
        /// </summary>
        public void ClearCache()
        {
            _breachWatchRecords.Clear();
        }
    }
} 