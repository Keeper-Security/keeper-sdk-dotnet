using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using Google.Protobuf;
using Folder;
using Records;
using System;
using System.Diagnostics;
using System.Runtime.Serialization;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Vault
{
    public static class TrashManagement
    {
        private static readonly int AES_V2_KEY_LENGTH = 60;
        private static readonly int RECORD_VERSION_THRESHOLD = 3;
        private static readonly int BATCH_SIZE_LIMIT = 100;
        private static readonly int MIN_RECORDS_FOR_BATCH = 1;
        private static readonly string PASSWORD_FIELD_TYPE = "password";

        private static readonly ConcurrentDictionary<string, DeletedRecord> DeletedRecordCache = new();
        private static readonly ConcurrentDictionary<string, DeletedRecord> OrphanedRecordCache = new();
        public class DeletedSharedFolderCacheData
        {
            public Dictionary<string, DeletedSharedFolder> Folders { get; set; } = new();
            public Dictionary<string, DeletedRecord> Records { get; set; } = new();
        }

        private static DeletedSharedFolderCacheData DeletedSharedFolderCache = new();



        private static async Task<Folder.GetDeletedSharedFoldersAndRecordsResponse> FetchDeletedSharedFoldersAndRecords(VaultOnline vault)
        {
            return (Folder.GetDeletedSharedFoldersAndRecordsResponse) await vault.Auth.ExecuteAuthRest("vault/get_deleted_shared_folders_and_records", null, typeof(Folder.GetDeletedSharedFoldersAndRecordsResponse));
        }

        private static Dictionary<string, string> ExtractUsers(Folder.GetDeletedSharedFoldersAndRecordsResponse response)
        {
            return response.Usernames.ToDictionary(
                x => x.AccountUid.ToByteArray().Base64UrlEncode(),
                x => x.Username_
            );
        }

        private static Dictionary<string, (byte[], string)> BuildFolderKeys(VaultOnline vault)
        {
            if (vault?.SharedFolders == null)
            {
                return new Dictionary<string, (byte[], string)>();
            }

            var folderKeys = new Dictionary<string, (byte[], string)>();

            foreach (var sharedFolder in vault.SharedFolders)
            {
                if (sharedFolder?.SharedFolderKey != null && !string.IsNullOrEmpty(sharedFolder.Uid))
                {
                    folderKeys[sharedFolder.Uid] = (sharedFolder.SharedFolderKey, sharedFolder.Uid);
                }
            }

            return folderKeys;
        }

        private static Task<byte[]> DecryptFolderKey(Folder.DeletedSharedFolder sf, VaultOnline vault, Dictionary<string, (byte[], string)> folderKeys)
        {
            try
            {
                return DecryptFolderKeyByType(sf, vault, folderKeys);
            }
            catch (Exception e)
            {
                Trace.TraceError(e.Message);
                return Task.FromResult<byte[]>(null);
            }
        }

        private static Task<byte[]> DecryptFolderKeyByType(Folder.DeletedSharedFolder sf, VaultOnline vault, Dictionary<string, (byte[], string)> folderKeys)
        {
            var keyType = sf.FolderKeyType;
            var EncryptedKey = sf.SharedFolderKey.ToByteArray();
            var AuthContext = vault.Auth.AuthContext;

            return (RecordKeyType) keyType switch
            {
                RecordKeyType.EncryptedByDataKey => Task.FromResult(CryptoUtils.DecryptAesV1(EncryptedKey, AuthContext.DataKey)),
                RecordKeyType.EncryptedByPublicKey => Task.FromResult(CryptoUtils.DecryptRsa(EncryptedKey, AuthContext.PrivateRsaKey)),
                RecordKeyType.EncryptedByDataKeyGcm => Task.FromResult(CryptoUtils.DecryptAesV2(EncryptedKey, AuthContext.DataKey)),
                RecordKeyType.EncryptedByPublicKeyEcc => Task.FromResult(CryptoUtils.DecryptEc(EncryptedKey, AuthContext.PrivateEcKey)),
                RecordKeyType.EncryptedByRootKeyCbc or RecordKeyType.EncryptedByRootKeyGcm => DecryptWithRootKey(sf, folderKeys),
                _ => Task.FromResult<byte[]>(null)
            };
        }

        private static Task<byte[]> DecryptWithRootKey(Folder.DeletedSharedFolder sf, Dictionary<string, (byte[], string)> folderKeys)
        {
            if (sf?.SharedFolderUid == null || folderKeys == null)
            {
                return Task.FromResult<byte[]>(null);
            }

            var SharedFolderUid = sf.SharedFolderUid.ToByteArray().Base64UrlEncode();

            if (!folderKeys.TryGetValue(SharedFolderUid, out var folderKey))
            {
                return Task.FromResult<byte[]>(null);
            }

            var (sharedFolderKey, _) = folderKey;

            return (RecordKeyType) sf.FolderKeyType switch
            {
                RecordKeyType.EncryptedByRootKeyCbc => Task.FromResult(CryptoUtils.DecryptAesV1(sf.SharedFolderKey.ToByteArray(), sharedFolderKey)),
                RecordKeyType.EncryptedByRootKeyGcm => Task.FromResult(CryptoUtils.DecryptAesV2(sf.SharedFolderKey.ToByteArray(), sharedFolderKey)),
                _ => Task.FromResult<byte[]>(null)
            };
        }

        private static DeletedSharedFolder CreateSharedFolderNode(Folder.DeletedSharedFolder sf,
        string SharedFolderUid, string FolderUid, Byte[] folderKey, Byte[] DecryptedData)
        {
            if (sf == null)
            {
                return null;
            }

            var customSf = new DeletedSharedFolder
            {
                SharedFolderUid = sf.SharedFolderUid?.ToByteArray(),
                FolderUid = sf.FolderUid?.ToByteArray(),
                ParentUid = sf.ParentUid?.ToByteArray(),
                SharedFolderKey = sf.SharedFolderKey?.ToByteArray(),
                FolderKeyType = (int) sf.FolderKeyType,
                Data = sf.Data?.ToByteArray(),
                DateDeleted = sf.DateDeleted,
                Revision = sf.Revision,
                SharedFolderUidString = SharedFolderUid,
                FolderUidString = FolderUid,
                DataString = sf.Data?.ToByteArray().Base64UrlEncode(),
                DataUnEncrypted = DecryptedData,
                FolderKeyUnEncrypted = folderKey
            };

            if (sf.ParentUid != null && sf.ParentUid.Length > 0)
            {
                customSf.ParentUidString = sf.ParentUid.ToByteArray().Base64UrlEncode();
            }
            return customSf;
        }

        private static async Task<Dictionary<string, DeletedSharedFolder>> ProcessSharedFolders(
            Folder.GetDeletedSharedFoldersAndRecordsResponse folderResponse,
            VaultOnline vault,
            Dictionary<string, (byte[], string)> folderKeys)
        {
            var folders = new Dictionary<string, DeletedSharedFolder>();

            foreach (var sharedFolder in folderResponse.SharedFolders)
            {
                var folderData = await ProcessSingleSharedFolder(sharedFolder, vault, folderKeys);
                if (folderData != null)
                {
                    folders[folderData.FolderUidString] = folderData;
                }
            }

            return folders;
        }

        private static async Task<DeletedSharedFolder> ProcessSingleSharedFolder(Folder.DeletedSharedFolder sf, VaultOnline vault, Dictionary<string, (byte[], string)> folderKeys)
        {
            var sharedFolderUid = sf.SharedFolderUid.ToByteArray().Base64UrlEncode();
            var folderUid = sf.FolderUid.ToByteArray().Base64UrlEncode();

            var folderKey = await DecryptFolderKey(sf, vault, folderKeys);
            if (folderKey == null)
            {
                return null;
            }

            try
            {
                folderKeys[folderUid] = (folderKey, sharedFolderUid);
                var decryptedData = CryptoUtils.DecryptAesV1(sf.Data.ToByteArray(), folderKey);

                var folderDict = CreateSharedFolderNode(sf, sharedFolderUid, folderUid, folderKey, decryptedData);
                return folderDict;
            }
            catch (Exception e)
            {
                Trace.TraceError($"Shared folder data decryption failed: {e.Message}");
                return null;
            }
        }

        private static async Task<Dictionary<string, (byte[] RecordKey, string FolderUid, long DateDeleted)>> ProcessSharedFolderRecords(
            Folder.GetDeletedSharedFoldersAndRecordsResponse folderResponse,
            Dictionary<string, (byte[], string)> folderKeys)
        {
            var recordKeys = new Dictionary<string, (byte[], string, long)>();

            foreach (var recordKeyData in folderResponse.SharedFolderRecords)
            {
                var recordKeyInfo = await ProcessSingleSharedFolderRecord(recordKeyData, folderKeys);
                if (recordKeyInfo.HasValue)
                {
                    var (recordUid, keyData) = recordKeyInfo.Value;
                    recordKeys[recordUid] = keyData;
                }
            }

            return recordKeys;
        }

        private static async Task<(string RecordUid, (byte[] RecordKey, string FolderUid, long DateDeleted))?> ProcessSingleSharedFolderRecord(Folder.DeletedSharedFolderRecord rk, Dictionary<string, (byte[], string)> folderKeys)
        {
            var folderUid = rk.FolderUid.ToByteArray().Base64UrlEncode();
            if (!folderKeys.TryGetValue(folderUid, out var folderKeyData))
            {
                return null;
            }

            var (_, sharedFolderUid) = folderKeyData;
            if (!folderKeys.TryGetValue(sharedFolderUid, out var sharedFolderKeyData))
            {
                return null;
            }

            var (folderKey, _) = sharedFolderKeyData;
            var recordUid = rk.RecordUid.ToByteArray().Base64UrlEncode();

            try
            {
                var recordKey = await DecryptSharedRecordKey(rk.SharedRecordKey.ToByteArray(), folderKey);
                return (recordUid, (recordKey, folderUid, rk.DateDeleted));
            }
            catch (Exception e)
            {
                Trace.TraceError($"Record \"{recordUid}\" key decryption failed: {e.Message}");
                return null;
            }
        }

        private static Task<byte[]> DecryptSharedRecordKey(Byte[] SharedRecordKey, Byte[] FolderKey)
        {
            if (SharedRecordKey.Length == AES_V2_KEY_LENGTH)
            {
                return Task.FromResult(CryptoUtils.DecryptAesV2(SharedRecordKey, FolderKey));
            }
            else
            {
                return Task.FromResult(CryptoUtils.DecryptAesV1(SharedRecordKey, FolderKey));
            }
        }


        private static byte[] DecryptRecordDataByVersion(byte[] encryptedData, int version, byte[] recordKey)
        {
            if (version < RECORD_VERSION_THRESHOLD)
            {
                return CryptoUtils.DecryptAesV1(encryptedData, recordKey);
            }
            else
            {
                return CryptoUtils.DecryptAesV2(encryptedData, recordKey);
            }
        }

        private static Dictionary<string, DeletedRecord> ProcessDeletedRecordData(
            Folder.GetDeletedSharedFoldersAndRecordsResponse folderResponse,
            Dictionary<string, (byte[] RecordKey, string FolderUid, long DateDeleted)> recordKeys,
            Dictionary<string, string> users)
        {
            var records = new Dictionary<string, DeletedRecord>();

            foreach (var recordData in folderResponse.DeletedRecordData)
            {
                var recordInfo = ProcessSingleDeletedRecord(recordData, recordKeys, users);
                if (recordInfo.HasValue)
                {
                    var (recordUid, recordDict) = recordInfo.Value;
                    records[recordUid] = recordDict;
                }
            }

            return records;
        }

        private static (string RecordUid, DeletedRecord)? ProcessSingleDeletedRecord(
            Folder.DeletedRecordData r,
            Dictionary<string, (byte[] RecordKey, string FolderUid, long DateDeleted)> recordKeys,
            Dictionary<string, string> users)
        {
            var recordUid = r.RecordUid.ToByteArray().Base64UrlEncode();
            if (!recordKeys.TryGetValue(recordUid, out var recordData))
            {
                return null;
            }

            var (recordKey, folderUid, timeDeleted) = recordData;

            try
            {
                var decryptedData = DecryptRecordDataByVersion(r.Data.ToByteArray(), r.Version, recordKey);
                var recordDict = CreateRecordDict(r, recordUid, folderUid, timeDeleted, recordKey, decryptedData, users);
                return (recordUid, recordDict);
            }
            catch (Exception e)
            {
                Trace.TraceError($"Record \"{recordUid}\" data decryption failed: {e.Message}");
                return null;
            }
        }

        private static DeletedRecord CreateRecordDict(Folder.DeletedRecordData r, string recordUid, string folderUid, long timeDeleted, byte[] recordKey, byte[] decryptedData, Dictionary<string, string> users)
        {
            var ownerUid = r.OwnerUid.ToByteArray().Base64UrlEncode();

            return new DeletedRecord
            {
                RecordUid = recordUid,
                FolderUid = folderUid,
                Revision = r.Revision,
                Version = r.Version,
                Owner = users.ContainsKey(ownerUid) ? users[ownerUid] : null,
                ClientModifiedTime = r.ClientModifiedTime,
                DateDeleted = timeDeleted,
                Data = r.Data.ToByteArray().Base64UrlEncode(),
                DataUnencrypted = decryptedData,
                RecordKeyUnencrypted = recordKey,
            };
        }

        private static void UpdateSharedFolderCache(
            Dictionary<string, DeletedSharedFolder> folders,
            Dictionary<string, DeletedRecord> records)
        {
            DeletedSharedFolderCache.Folders.Clear();
            DeletedSharedFolderCache.Records.Clear();

            if (folders?.Count > 0)
            {
                DeletedSharedFolderCache.Folders = folders;
            }
            if (records?.Count > 0)
            {
                DeletedSharedFolderCache.Records = records;
            }
        }

        private static byte[] DecryptRecordKey(DeletedRecord record, VaultOnline vault)
        {
            try
            {
                var keyType = record.RecordKeyType;
                var recordKey = record.RecordKey.Base64UrlDecode();
                var authContext = vault.Auth.AuthContext;

                return keyType switch
                {
                    0 => authContext.DataKey,
                    1 => CryptoUtils.DecryptAesV1(recordKey, authContext.DataKey),
                    2 => CryptoUtils.DecryptRsa(recordKey, authContext.PrivateRsaKey),
                    3 => CryptoUtils.DecryptAesV2(recordKey, authContext.DataKey),
                    4 => CryptoUtils.DecryptEc(recordKey, authContext.PrivateEcKey),
                    _ => null
                };
            }
            catch (Exception e)
            {
                Trace.TraceError($"Record key decryption failed for {record.RecordUid}: {e.Message}");
                return null;
            }
        }

        private static Byte[] DecryptRecordData(Folder.DeletedRecordData r, byte[] recordKey)
        {
            try
            {
                var data = r.Data.ToByteArray();
                var version = r.Version;

                if (version >= RECORD_VERSION_THRESHOLD)
                {
                    return CryptoUtils.DecryptAesV2(data, recordKey);
                }
                else
                {
                    return CryptoUtils.DecryptAesV1(data, recordKey);
                }
            }
            catch (Exception e)
            {
                Trace.TraceError($"Record data decryption failed for {r.RecordUid.ToByteArray().Base64UrlEncode()}: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Process a single deleted record from command response.
        /// </summary>
        private static bool ProcessSingleDeletedRecordFromCommand(DeletedRecord record, VaultOnline vault)
        {
            var recordKey = DecryptRecordKey(record, vault);
            if (recordKey == null)
            {
                return false;
            }

            record.RecordKeyUnencrypted = recordKey;

            var tempRecordData = new DeletedRecordData
            {
                Data = ByteString.CopyFrom(record.Data.Base64UrlDecode()),
                Version = record.Version,
                RecordUid = ByteString.CopyFrom(record.RecordUid.Base64UrlDecode())
            };

            var decryptedData = DecryptRecordData(tempRecordData, recordKey);
            if (decryptedData == null)
            {
                return false;
            }

            record.DataUnencrypted = decryptedData;
            return true;
        }

        /// <summary>
        /// Process deleted records response for a specific record type.
        /// </summary>
        private static void ProcessDeletedRecordsResponse(GetDeletedRecordsResponse response, string recordType, ConcurrentDictionary<string, DeletedRecord> cache, VaultOnline vault)
        {
            DeletedRecord[] records = recordType switch
            {
                "records" => response.Records,
                "non_access_records" => response.NonAccessRecords,
                _ => null
            };

            if (records == null)
            {
                return;
            }

            var deletedUids = new HashSet<string>();

            foreach (var record in records)
            {
                var recordUid = record.RecordUid;
                deletedUids.Add(recordUid);

                if (cache.ContainsKey(recordUid))
                {
                    continue;
                }

                if (ProcessSingleDeletedRecordFromCommand(record, vault))
                {
                    cache[recordUid] = record;
                }
            }

            CleanupRemovedRecords(cache, deletedUids);
        }

        /// <summary>
        /// Remove records from cache that are no longer in the deleted list.
        /// </summary>
        private static void CleanupRemovedRecords(ConcurrentDictionary<string, DeletedRecord> cache, HashSet<string> currentUids)
        {
            var recordsToRemove = cache.Keys.Where(recordUid => !currentUids.Contains(recordUid)).ToList();
            foreach (var recordUid in recordsToRemove)
            {
                cache.TryRemove(recordUid, out _);
            }
        }

        /// <summary>
        /// Load deleted records using the get_deleted_records command.
        /// </summary>
        private static async Task LoadDeletedRecordsFromCommand(VaultOnline vault)
        {
            var request = new GetDeletedRecordsCommand();

            var response = (GetDeletedRecordsResponse) await vault.Auth.ExecuteAuthCommand(request, typeof(GetDeletedRecordsResponse), true);

            ProcessDeletedRecordsResponse(response, "records", DeletedRecordCache, vault);
            ProcessDeletedRecordsResponse(response, "non_access_records", OrphanedRecordCache, vault);
        }

        /// <summary>
        /// Load and cache all deleted records, orphaned records, and shared folders.
        /// 
        /// This method orchestrates the loading of all trash data from different sources:
        /// - Deleted shared folders and their records from REST API
        /// - Regular deleted records from command API
        /// - Orphaned records from command API
        /// </summary>
        /// <param name="vault">The vault instance to load deleted records from</param>
        public static async Task EnsureDeletedRecordsLoaded(VaultOnline vault)
        {
            if (vault?.Auth?.AuthContext == null)
            {
                return;
            }

            var folderResponse = await FetchDeletedSharedFoldersAndRecords(vault);
            if (folderResponse == null)
            {
                return;
            }

            var users = ExtractUsers(folderResponse);
            var folderKeys = BuildFolderKeys(vault);
            if (folderKeys == null)
            {
                return;
            }

            var folders = await ProcessSharedFolders(folderResponse, vault, folderKeys);
            var recordKeys = await ProcessSharedFolderRecords(folderResponse, folderKeys);
            var records = ProcessDeletedRecordData(folderResponse, recordKeys, users);

            UpdateSharedFolderCache(folders, records);

            await LoadDeletedRecordsFromCommand(vault);
        }

        /// <summary>
        /// Get all deleted records from cache.
        /// </summary>
        public static IReadOnlyDictionary<string, DeletedRecord> GetDeletedRecords()
        {
            return DeletedRecordCache;
        }

        /// <summary>
        /// Get all orphaned records from cache.
        /// </summary>
        public static IReadOnlyDictionary<string, DeletedRecord> GetOrphanedRecords()
        {
            return OrphanedRecordCache;
        }

        /// <summary>
        /// Get all deleted shared folders from cache.
        /// </summary>
        public static DeletedSharedFolderCacheData GetSharedFolders()
        {
            return DeletedSharedFolderCache;
        }

        /// <summary>
        /// Check if trash is empty.
        /// </summary>
        public static bool IsTrashEmpty()
        {
            return DeletedSharedFolderCache.Folders.Count == 0 && DeletedSharedFolderCache.Records.Count == 0 && DeletedRecordCache.Count == 0 && OrphanedRecordCache.Count == 0;
        }

        private static async Task<TrashData> LoadTrashData(VaultOnline vault)
        {
            await EnsureDeletedRecordsLoaded(vault);
            var sharedFolders = GetSharedFolders();

            return new TrashData
            {
                DeletedRecords = GetDeletedRecords(),
                OrphanedRecords = GetOrphanedRecords(),
                DeletedSharedRecords = sharedFolders.Records,
                DeletedSharedFolders = sharedFolders.Folders
            };
        }

        /// <summary>
        /// Restore deleted records from trash.
        /// </summary>
        /// <param name="vault">The vault instance</param>
        /// <param name="records">List of record UIDs or patterns to restore</param>
        public static async Task RestoreTrashRecords(VaultOnline vault, List<string> records)
        {
            var trashData = await LoadTrashData(vault);
            if (IsTrashEmpty())
            {
                Trace.TraceInformation("Trash is empty");
                return;
            }
            
            var restorePlan = CreateRestorePlan(records, trashData);
            if (IsRestorePlanEmpty(restorePlan))
            {
                Trace.TraceInformation("There are no records to restore");
                return;
            }

            await ExecuteRecordRestoration(vault, restorePlan, trashData);
            await ExecuteSharedFolderRestoration(vault, restorePlan);
            await PostRestoreProcessing(vault, restorePlan, trashData);
        }

        private static RestorePlan CreateRestorePlan(List<string> records, TrashData trashData)
        {
            var recordsToRestore = new HashSet<string>();
            var foldersToRestore = new HashSet<string>();
            var folderRecordsToRestore = new Dictionary<string, List<string>>();

            foreach (var recordId in records)
            {
                ProcessSingleRecordForRestore(recordId, trashData, recordsToRestore, foldersToRestore, folderRecordsToRestore);
            }

            foreach (var folderUid in foldersToRestore)
            {
                folderRecordsToRestore.Remove(folderUid);
            }

            return new RestorePlan
            {
                RecordsToRestore = recordsToRestore,
                FoldersToRestore = foldersToRestore,
                FolderRecordsToRestore = folderRecordsToRestore
            };
        }

        private static bool IsRestorePlanEmpty(RestorePlan restorePlan)
        {
            var recordCount = restorePlan.RecordsToRestore?.Count ?? 0;
            if (restorePlan.FolderRecordsToRestore != null)
            {
                foreach (var folderRecords in restorePlan.FolderRecordsToRestore.Values)
                {
                    recordCount += folderRecords?.Count ?? 0;
                }
            }
            var folderCount = restorePlan.FoldersToRestore?.Count ?? 0;

            return recordCount == 0 && folderCount == 0;
        }

        private static async Task ExecuteRecordRestoration(VaultOnline vault, RestorePlan restorePlan, TrashData trashData)
        {
            if (restorePlan.RecordsToRestore == null || restorePlan.RecordsToRestore.Count == 0)
            {
                return;
            }

            var deletedRecords = trashData.DeletedRecords;
            var orphanedRecords = trashData.OrphanedRecords;

            var RecordsBatchToRestore = new List<KeeperApiCommand>();
            foreach (var recordUid in restorePlan.RecordsToRestore)
            {
                var record = (deletedRecords?.ContainsKey(recordUid) == true ? deletedRecords[recordUid] : null) ??
                             (orphanedRecords?.ContainsKey(recordUid) == true ? orphanedRecords[recordUid] : null);
                if (record == null)
                {
                    continue;
                }

                var request = new UndeleteRecordCommand
                {
                    RecordUid = recordUid
                };

                if (record.Revision > 0)
                {
                    request.Revision = record.Revision;
                }

                RecordsBatchToRestore.Add(request);
            }

            if (RecordsBatchToRestore.Count > 0)
            {
                await vault.Auth.ExecuteBatch(RecordsBatchToRestore);
            }
        }

        private static async Task ProcessSharedFolderBatches(VaultOnline vault, List<Folder.RestoreSharedObject> sharedFolderRequests, List<Folder.RestoreSharedObject> sharedFolderRecordRequests)
        {
            while (sharedFolderRequests.Count > 0 || sharedFolderRecordRequests.Count > 0)
            {
                var request = new Folder.RestoreDeletedSharedFoldersAndRecordsRequest();
                var remainingSpace = BATCH_SIZE_LIMIT;

                if (sharedFolderRequests.Count > 0)
                {
                    var chunkSize = Math.Min(sharedFolderRequests.Count, remainingSpace);
                    var chunk = sharedFolderRequests.Take(chunkSize).ToList();
                    sharedFolderRequests.RemoveRange(0, chunkSize);
                    remainingSpace -= chunk.Count;
                    request.Folders.AddRange(chunk);
                }

                if (sharedFolderRecordRequests.Count > 0 && remainingSpace >= MIN_RECORDS_FOR_BATCH)
                {
                    var chunkSize = Math.Min(sharedFolderRecordRequests.Count, remainingSpace);
                    var chunk = sharedFolderRecordRequests.Take(chunkSize).ToList();
                    sharedFolderRecordRequests.RemoveRange(0, chunkSize);
                    request.Records.AddRange(chunk);
                }

                await vault.Auth.ExecuteAuthRest("vault/restore_deleted_shared_folders_and_records", request);
            }
        }

        private static List<Folder.RestoreSharedObject> CreateSharedFolderRequests(HashSet<string> foldersToRestore)
        {
            var requests = new List<Folder.RestoreSharedObject>();
            foreach (var folderUid in foldersToRestore)
            {
                var request = new Folder.RestoreSharedObject
                {
                    FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode())
                };
                requests.Add(request);
            }
            return requests;
        }

        private static List<Folder.RestoreSharedObject> CreateSharedFolderRecordRequests(Dictionary<string, List<string>> folderRecordsToRestore)
        {
            var requests = new List<Folder.RestoreSharedObject>();
            foreach (var kvp in folderRecordsToRestore)
            {
                var folderUid = kvp.Key;
                var recordUids = kvp.Value;

                var request = new Folder.RestoreSharedObject
                {
                    FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode())
                };

                foreach (var recordUid in recordUids)
                {
                    request.RecordUids.Add(ByteString.CopyFrom(recordUid.Base64UrlDecode()));
                }

                requests.Add(request);
            }
            return requests;
        }

        private static async Task ExecuteSharedFolderRestoration(VaultOnline vault, RestorePlan restorePlan)
        {
            if ((restorePlan.FoldersToRestore == null || restorePlan.FoldersToRestore.Count == 0) &&
                (restorePlan.FolderRecordsToRestore == null || restorePlan.FolderRecordsToRestore.Count == 0))
            {
                return;
            }

            var sharedFolderRequests = CreateSharedFolderRequests(restorePlan.FoldersToRestore);
            var sharedFolderRecordRequests = CreateSharedFolderRecordRequests(restorePlan.FolderRecordsToRestore);

            await ProcessSharedFolderBatches(vault, sharedFolderRequests, sharedFolderRecordRequests);
        }

        private static string ExtractPasswordFromRecord(DeletedRecord record)
        {
            try
            {
                if (record?.DataUnencrypted == null)
                {
                    return null;
                }

                try
                {
                    var recordTypeData = JsonUtils.ParseJson<RecordTypeData>(record.DataUnencrypted);
                    if (recordTypeData?.Fields != null)
                    {
                        foreach (var field in recordTypeData.Fields)
                        {
                            if (field?.Type == PASSWORD_FIELD_TYPE)
                            {
                                // Parse field as dictionary to get the value
                                var fieldDict = JsonUtils.ParseJson<Dictionary<string, object>>(JsonUtils.DumpJson(field));
                                if (fieldDict?.TryGetValue("value", out var valueObj) == true)
                                {
                                    if (valueObj is object[] valueArray && valueArray.Length > 0)
                                    {
                                        return valueArray[0]?.ToString();
                                    }
                                    else if (valueObj is List<object> valueList && valueList.Count > 0)
                                    {
                                        return valueList[0]?.ToString();
                                    }
                                    else if (valueObj != null)
                                    {
                                        return valueObj.ToString();
                                    }
                                }
                            }
                        }
                    }
                }
                catch
                {
                    // Fall back to RecordData parsing (V2 records)
                    try
                    {
                        var recordData = JsonUtils.ParseJson<KeeperSecurity.Commands.RecordData>(record.DataUnencrypted);
                        if (recordData?.Secret2 != null)
                        {
                            return recordData.Secret2;
                        }
                    }
                    catch
                    {
                        // If both fail, return null
                    }
                }

                return null;
            }
            catch (Exception e)
            {
                Trace.TraceError($"Password extraction failed for {record.RecordUid}: {e.Message}");
                return null;
            }
        }

        private static bool RecordTitleMatches(DeletedRecord record, System.Text.RegularExpressions.Regex pattern)
        {
            try
            {
                if (record?.DataUnencrypted == null)
                {
                    return false;
                }

                var recordData = JsonUtils.ParseJson<KeeperRecord>(record.DataUnencrypted);
                if (recordData?.Title == null)
                {
                    return false;
                }

                return pattern.IsMatch(recordData.Title);
            }
            catch (Exception e)
            {
                Trace.TraceError($"Record title matching failed for {record.RecordUid}: {e.Message}");
                return false;
            }
        }

        private static bool FolderNameMatches(DeletedSharedFolder folder, System.Text.RegularExpressions.Regex pattern, string folderUid)
        {
            try
            {
                if (folder?.DataUnEncrypted == null)
                {
                    return false;
                }

                var folderData = JsonUtils.ParseJson<FolderData>(folder.DataUnEncrypted);
                var folderName = folderData?.name ?? folderUid;

                return pattern.IsMatch(folderName);
            }
            catch (Exception e)
            {
                Trace.TraceError($"Folder name matching failed for {folderUid}: {e.Message}");
                return false;
            }
        }

        private static void MatchFoldersByTitle(Dictionary<string, DeletedSharedFolder> folders, System.Text.RegularExpressions.Regex pattern, HashSet<string> foldersToRestore)
        {
            foreach (var kvp in folders)
            {
                var folderUid = kvp.Key;
                var folder = kvp.Value;

                if (foldersToRestore.Contains(folderUid))
                {
                    continue;
                }

                if (FolderNameMatches(folder, pattern, folderUid))
                {
                    foldersToRestore.Add(folderUid);
                }
            }
        }

        private static void MatchSharedRecordsByTitle(Dictionary<string, DeletedRecord> sharedRecords, System.Text.RegularExpressions.Regex pattern, Dictionary<string, List<string>> folderRecordsToRestore)
        {
            foreach (var kvp in sharedRecords)
            {
                var recordUid = kvp.Key;
                var sharedRecord = kvp.Value;

                if (folderRecordsToRestore.ContainsKey(recordUid))
                {
                    continue;
                }

                if (RecordTitleMatches(sharedRecord, pattern))
                {
                    var folderUid = sharedRecord.FolderUid;
                    if (!string.IsNullOrEmpty(folderUid))
                    {
                        if (!folderRecordsToRestore.TryGetValue(folderUid, out var recordList))
                        {
                            recordList = new List<string>();
                            folderRecordsToRestore[folderUid] = recordList;
                        }
                        recordList.Add(recordUid);
                    }
                }
            }
        }

        private static void MatchRecordsByTitle(Dictionary<string, DeletedRecord> records, System.Text.RegularExpressions.Regex pattern, HashSet<string> recordsToRestore)
        {
            foreach (var kvp in records)
            {
                var recordUid = kvp.Key;
                var record = kvp.Value;

                if (recordsToRestore.Contains(recordUid))
                {
                    continue;
                }

                if (RecordTitleMatches(record, pattern))
                {
                    recordsToRestore.Add(recordUid);
                }
            }
        }

        private static void ProcessPatternMatching(string pattern, TrashData trashData, HashSet<string> recordsToRestore, HashSet<string> foldersToRestore, Dictionary<string, List<string>> folderRecordsToRestore)
        {
            var regexPattern = SanitizePattern(pattern);
            var titlePattern = new System.Text.RegularExpressions.Regex(regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            if (trashData.DeletedRecords != null)
            {
                MatchRecordsByTitle(trashData.DeletedRecords.ToDictionary(kvp => kvp.Key, kvp => kvp.Value), titlePattern, recordsToRestore);
            }
            
            if (trashData.OrphanedRecords != null)
            {
                MatchRecordsByTitle(trashData.OrphanedRecords.ToDictionary(kvp => kvp.Key, kvp => kvp.Value), titlePattern, recordsToRestore);
            }

            if (trashData.DeletedSharedRecords != null)
            {
                MatchSharedRecordsByTitle(trashData.DeletedSharedRecords, titlePattern, folderRecordsToRestore);
            }

            if (trashData.DeletedSharedFolders != null)
            {
                MatchFoldersByTitle(trashData.DeletedSharedFolders, titlePattern, foldersToRestore);
            }
        }

        private static string SanitizePattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return ".*";
            }

            var escaped = System.Text.RegularExpressions.Regex.Escape(pattern);
            
            escaped = escaped.Replace(@"\*", ".*");
            escaped = escaped.Replace(@"\?", ".");
            
            return "^" + escaped + "$";
        }

        private static void AddSharedRecordToRestore(string recordId, Dictionary<string, DeletedRecord> deletedSharedRecords, Dictionary<string, List<string>> folderRecordsToRestore)
        {
            if (!deletedSharedRecords.TryGetValue(recordId, out var sharedRecord))
            {
                return;
            }

            var folderUid = sharedRecord.FolderUid;
            var recordUid = sharedRecord.RecordUid;

            if (!string.IsNullOrEmpty(folderUid) && !string.IsNullOrEmpty(recordUid))
            {
                if (!folderRecordsToRestore.TryGetValue(folderUid, out var recordList))
                {
                    recordList = new List<string>();
                    folderRecordsToRestore[folderUid] = recordList;
                }
                recordList.Add(recordUid);
            }
        }

        private static void ProcessSingleRecordForRestore(string recordId, TrashData trashData, HashSet<string> recordsToRestore, HashSet<string> foldersToRestore, Dictionary<string, List<string>> folderRecordsToRestore)
        {
            var deletedRecords = trashData.DeletedRecords;
            var orphanedRecords = trashData.OrphanedRecords;
            var deletedSharedRecords = trashData.DeletedSharedRecords;
            var deletedSharedFolders = trashData.DeletedSharedFolders;

            if ((deletedRecords?.ContainsKey(recordId) == true) || (orphanedRecords?.ContainsKey(recordId) == true))
            {
                recordsToRestore.Add(recordId);
            }
            else if (deletedSharedRecords?.ContainsKey(recordId) == true)
            {
                AddSharedRecordToRestore(recordId, deletedSharedRecords, folderRecordsToRestore);
            }
            else if (deletedSharedFolders?.ContainsKey(recordId) == true)
            {
                foldersToRestore.Add(recordId);
            }
            else
            {
                ProcessPatternMatching(recordId, trashData, recordsToRestore, foldersToRestore, folderRecordsToRestore);
            }
        }

        private static async Task PostRestoreProcessing(VaultOnline vault, RestorePlan restorePlan, TrashData trashData)
        {
            await vault.SyncDown();

            if (restorePlan.RecordsToRestore == null || restorePlan.RecordsToRestore.Count == 0)
            {
                return;
            }

            var deletedRecords = trashData.DeletedRecords;
            var orphanedRecords = trashData.OrphanedRecords;

            foreach (var recordUid in restorePlan.RecordsToRestore)
            {
                var record = (deletedRecords?.ContainsKey(recordUid) == true ? deletedRecords[recordUid] : null) ?? 
                             (orphanedRecords?.ContainsKey(recordUid) == true ? orphanedRecords[recordUid] : null);
                if (record == null)
                {
                    continue;
                }
                var recordKey = record.RecordKeyUnencrypted;
                var password = ExtractPasswordFromRecord(record);

                vault.Auth.ScheduleAuditEventLogging("record_restored", new AuditEventInput { RecordUid = recordUid });

                if (!string.IsNullOrEmpty(password) && recordKey != null)
                {
                    await vault.ScanAndStoreRecordStatusAsync(recordUid, recordKey, password);
                }
            }
            await vault.SyncDown(true);
        }

        private class TrashData
        {
            internal IReadOnlyDictionary<string, DeletedRecord> DeletedRecords { get; set; }
            internal IReadOnlyDictionary<string, DeletedRecord> OrphanedRecords { get; set; }
            internal Dictionary<string, DeletedRecord> DeletedSharedRecords { get; set; }
            internal Dictionary<string, DeletedSharedFolder> DeletedSharedFolders { get; set; }
        }
    }


    public interface IDeletedItem { }

    [DataContract]
    public class DeletedRecord : IDeletedItem
    {
        [DataMember(Name = "record_uid")] 
        public string RecordUid;
        [DataMember(Name = "owner")] 
        public string Owner;
        [DataMember(Name = "revision")] 
        public long Revision;
        [DataMember(Name = "client_modified_time")] 
        public long ClientModifiedTime;
        [DataMember(Name = "data")] 
        public string Data;
        [DataMember(Name = "record_key")] 
        public string RecordKey;
        [DataMember(Name = "record_key_type")] 
        public int RecordKeyType;
        [DataMember(Name = "date_deleted")] 
        public long DateDeleted;
        [DataMember(Name = "breach_watch_data", EmitDefaultValue = false)] 
        public string BreachWatchData;        
        public string FolderUid { get; set; }
        [DataMember(Name = "version")]
        public int Version { get; set; }
        public byte[] DataUnencrypted { get; set; }
        public byte[] RecordKeyUnencrypted { get; set; }
    }

    [DataContract]
    public class DeletedSharedFolder
    {
        [DataMember(Name = "sharedFolderUid")]
        public byte[] SharedFolderUid;
        [DataMember(Name = "folderUid")]
        public byte[] FolderUid;
        [DataMember(Name = "parentUid")]
        public byte[] ParentUid;
        [DataMember(Name = "sharedFolderKey")]
        public byte[] SharedFolderKey;
        [DataMember(Name = "folderKeyType")]
        public int FolderKeyType;
        [DataMember(Name = "data")]
        public byte[] Data;
        [DataMember(Name = "dateDeleted")]
        public long DateDeleted;
        [DataMember(Name = "revision")]
        public long Revision;        
        public string SharedFolderUidString { get; set; }
        public string FolderUidString { get; set; }
        public string ParentUidString { get; set; }
        public string DataString { get; set; }
        public byte[] DataUnEncrypted { get; set; }
        public byte[] FolderKeyUnEncrypted { get; set; }
    }


    [DataContract]
    public class DeletedSharedFolderRecord
    {
        [DataMember(Name = "shared_folder_uid")]
        public string SharedFolderUid;
        [DataMember(Name = "shared_folder_key")] 
        public string SharedFolderKey;
        [DataMember(Name = "key_type")] 
        public int KeyType;
        [DataMember(Name = "data")] 
        public string Data;
        [DataMember(Name = "records")] 
        public DeletedRecord[] Records;
        [DataMember(Name = "who_delete_record")] 
        public string WhoDeleteRecord;
        [DataMember(Name = "revision")] 
        public long Revision;
    }

    /// <summary>
    /// Represents a plan for restoring items from trash.
    /// </summary>
    internal class RestorePlan
    {
        internal HashSet<string> RecordsToRestore { get; set; } = new HashSet<string>();
        internal HashSet<string> FoldersToRestore { get; set; } = new HashSet<string>();
        internal Dictionary<string, List<string>> FolderRecordsToRestore { get; set; } = new Dictionary<string, List<string>>();
    }

}