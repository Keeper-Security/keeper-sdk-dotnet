using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// A single record in the Drive (NSF) trashcan.
    /// </summary>
    internal class NsfTrashcanRecord
    {
        public string RecordUid;
        public string TrashcanUid;
        public string FolderUid;
        public long DateDeleted;
        public byte[] RecordKeyUnencrypted;
    }

    /// <summary>
    /// A single folder in the Drive (NSF) trashcan.
    /// </summary>
    internal class NsfTrashcanFolderEntry
    {
        public string FolderUid;
        public string TrashcanUid;
        public string ParentUid;
        public long DateDeleted;
        public byte[] FolderKeyUnencrypted;

        // The trashcan sync message itself carries no name - this is only set if we managed
        // to resolve it against the active folder tree before that tree dropped the entry.
        public string Name;
    }

    /// <summary>
    /// Keeps a local copy of the Drive (NSF) trashcan in sync with the server.
    /// This trashcan is tracked separately from the regular vault sync stream.
    internal static class NsfTrashcanSync
    {
        private const int MaxCountPerRequest = 999;

        private static long _syncPoint;
        private static readonly ConcurrentDictionary<string, NsfTrashcanRecord> RecordCache = new();
        private static readonly ConcurrentDictionary<string, NsfTrashcanFolderEntry> FolderCache = new();

        public static void Reset()
        {
            _syncPoint = 0;
            RecordCache.Clear();
            FolderCache.Clear();
        }

        public static IReadOnlyDictionary<string, NsfTrashcanRecord> GetRecords() => RecordCache;

        public static IReadOnlyDictionary<string, NsfTrashcanFolderEntry> GetFolders() => FolderCache;

        public static async Task EnsureSynced(VaultOnline vault, bool reload = false)
        {
            if (reload)
            {
                Reset();
            }

            var syncPoint = _syncPoint;
            var hasMore = true;

            while (hasMore)
            {
                var request = new global::Vault.TrashcanSyncRequest
                {
                    SyncPoint = syncPoint,
                    MaxCount = MaxCountPerRequest,
                };

                var response = await vault.Auth.ExecuteAuthRest<global::Vault.TrashcanSyncRequest, global::Vault.TrashcanSyncResponse>(
                    "vault/folders/v3/trashcan/sync", request).ConfigureAwait(false);

                ApplySyncData(response.TrashcanData, vault);

                syncPoint = response.SyncPoint;
                hasMore = response.HasMore;
            }

            _syncPoint = syncPoint;
        }

        private static void ApplySyncData(global::Vault.TrashcanSyncData data, VaultOnline vault)
        {
            if (data == null)
            {
                return;
            }

            foreach (var removedFolder in data.RemovedTrashcanFolders)
            {
                FolderCache.TryRemove(removedFolder.FolderUid.ToByteArray().Base64UrlEncode(), out _);
            }

            foreach (var removedRecord in data.RemovedTrashcanRecords)
            {
                RecordCache.TryRemove(removedRecord.RecordUid.ToByteArray().Base64UrlEncode(), out _);
            }

            foreach (var folder in data.TrashcanFolders)
            {
                var folderUid = folder.FolderUid.ToByteArray().Base64UrlEncode();
                byte[] folderKey = null;
                if (folder.FolderKey != null && !folder.FolderKey.IsEmpty)
                {
                    folderKey = DecryptByKeyType(folder.FolderKeyType, folder.FolderKey.ToByteArray(), vault);
                }

                string name = null;
                if (vault.TryResolveKeeperNSFFolder(folderUid, out var folderNode) && !string.IsNullOrEmpty(folderNode.Name))
                {
                    name = folderNode.Name;
                }
                else if (FolderCache.TryGetValue(folderUid, out var existing) && !string.IsNullOrEmpty(existing.Name))
                {
                    name = existing.Name;
                }

                FolderCache[folderUid] = new NsfTrashcanFolderEntry
                {
                    FolderUid = folderUid,
                    TrashcanUid = folder.TrashcanUid != null && !folder.TrashcanUid.IsEmpty
                        ? folder.TrashcanUid.ToByteArray().Base64UrlEncode()
                        : null,
                    ParentUid = folder.ParentUid != null && !folder.ParentUid.IsEmpty
                        ? folder.ParentUid.ToByteArray().Base64UrlEncode()
                        : null,
                    DateDeleted = folder.DateDeleted,
                    FolderKeyUnencrypted = folderKey,
                    Name = name,
                };
            }

            foreach (var record in data.TrashcanRecords)
            {
                var recordUid = record.RecordUid.ToByteArray().Base64UrlEncode();
                byte[] recordKey = null;
                string folderUid = null;

                var folderRecordKey = record.FolderRecordKey;
                if (folderRecordKey != null && folderRecordKey.RecordKey != null && !folderRecordKey.RecordKey.IsEmpty)
                {
                    if (folderRecordKey.FolderUid != null && !folderRecordKey.FolderUid.IsEmpty)
                    {
                        folderUid = folderRecordKey.FolderUid.ToByteArray().Base64UrlEncode();
                    }

                    byte[] wrappingKey = null;
                    if (!string.IsNullOrEmpty(folderUid))
                    {
                        if (vault.TryResolveKeeperNSFFolderOrRoot(folderUid, out var folderNode) &&
                            folderNode.FolderKey != null && folderNode.FolderKey.Length > 0)
                        {
                            wrappingKey = folderNode.FolderKey;
                        }
                        else if (FolderCache.TryGetValue(folderUid, out var trashedFolder) &&
                            trashedFolder.FolderKeyUnencrypted != null && trashedFolder.FolderKeyUnencrypted.Length > 0)
                        {
                            wrappingKey = trashedFolder.FolderKeyUnencrypted;
                        }
                    }

                    recordKey = DecryptByKeyType(folderRecordKey.RecordKeyType, folderRecordKey.RecordKey.ToByteArray(), vault, wrappingKey);
                }

                RecordCache[recordUid] = new NsfTrashcanRecord
                {
                    RecordUid = recordUid,
                    TrashcanUid = record.TrashcanUid != null && !record.TrashcanUid.IsEmpty
                        ? record.TrashcanUid.ToByteArray().Base64UrlEncode()
                        : null,
                    FolderUid = folderUid,
                    DateDeleted = record.DateDeleted,
                    RecordKeyUnencrypted = recordKey,
                };
            }
        }

        private static byte[] DecryptByKeyType(
            Records.RecordKeyType keyType, byte[] encryptedKey, VaultOnline vault, byte[] wrappingKey = null)
        {
            try
            {
                var authContext = vault.Auth.AuthContext;
                switch (keyType)
                {
                    case Records.RecordKeyType.EncryptedByDataKey:
                        return CryptoUtils.DecryptAesV1(encryptedKey, authContext.DataKey);
                    case Records.RecordKeyType.EncryptedByPublicKey:
                        return CryptoUtils.DecryptRsa(encryptedKey, authContext.PrivateRsaKey);
                    case Records.RecordKeyType.EncryptedByDataKeyGcm:
                        return CryptoUtils.DecryptAesV2(encryptedKey, authContext.DataKey);
                    case Records.RecordKeyType.EncryptedByPublicKeyEcc:
                        return CryptoUtils.DecryptEc(encryptedKey, authContext.PrivateEcKey);
                    case Records.RecordKeyType.EncryptedByRootKeyCbc:
                        return wrappingKey != null ? CryptoUtils.DecryptAesV1(encryptedKey, wrappingKey) : null;
                    case Records.RecordKeyType.EncryptedByRootKeyGcm:
                        return wrappingKey != null ? CryptoUtils.DecryptAesV2(encryptedKey, wrappingKey) : null;
                    default:
                        return null;
                }
            }
            catch (Exception e)
            {
                Trace.TraceError($"NSF trashcan key decryption failed: {e.Message}");
                return null;
            }
        }
    }
}
