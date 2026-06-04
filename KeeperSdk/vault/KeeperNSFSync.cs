using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using KeeperSecurity.Authentication;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using FolderProto = Folder;
using RecordSharingProto = Record.V3.Sharing;
using VaultProto = Vault;

namespace KeeperSecurity.Vault
{
    internal static class KeeperNSFSync
    {
        internal static void ProcessKeeperNSFData(
            VaultProto.KeeperDriveData kdData,
            IKeeperStorage storage)
        {
            if (kdData == null) return;

            ProcessRemovedFolders(kdData, storage);
            ProcessRemovedFolderRecords(kdData, storage);
            ProcessRemovedRecordLinks(kdData, storage);
            StoreFolders(kdData, storage);
            StoreFolderKeys(kdData, storage);
            StoreRecords(kdData, storage);
            StoreRecordData(kdData, storage);
            StoreFolderRecords(kdData, storage);
            ProcessRevokedFolderAccesses(kdData, storage);
            ProcessRevokedRecordAccesses(kdData, storage);
            StoreFolderAccesses(kdData, storage);
            StoreRecordAccesses(kdData, storage);
            StoreRecordLinks(kdData, storage);
            StoreFolderSharingStates(kdData, storage);
            StoreRecordSharingStates(kdData, storage);
        }

        private static void ProcessRemovedFolders(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RemovedFolders.Count == 0) return;

            var removedUids = kdData.RemovedFolders
                .Select(x => x.FolderUid.ToByteArray().Base64UrlEncode())
                .ToArray();

            storage.KdFolderKeys.DeleteLinksForSubjects(removedUids);
            storage.KdFolderRecords.DeleteLinksForSubjects(removedUids);
            storage.KdFolders.DeleteUids(removedUids);
        }

        private static void ProcessRemovedFolderRecords(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RemovedFolderRecords.Count == 0) return;

            var links = kdData.RemovedFolderRecords
                .Select(x => UidLink.Create(
                    x.FolderUid.ToByteArray().Base64UrlEncode(),
                    x.RecordUid.ToByteArray().Base64UrlEncode()))
                .ToArray();

            storage.KdFolderRecords.DeleteLinks(links);

            var recordKeyLinks = links
                .Select(x => UidLink.Create(x.ObjectUid, x.SubjectUid))
                .ToArray();
            storage.KdRecordKeys.DeleteLinks(recordKeyLinks);
        }

        private static void StoreFolders(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.Folders.Count == 0) return;

            var folders = kdData.Folders.Select(f =>
            {
                var ownerAccountUid = "";
                var ownerUsername = "";
                if (f.OwnerInfo != null)
                {
                    if (f.OwnerInfo.AccountUid.Length > 0)
                        ownerAccountUid = f.OwnerInfo.AccountUid.ToByteArray().Base64UrlEncode();
                    ownerUsername = f.OwnerInfo.Username ?? "";
                }

                return new StorageKdFolder
                {
                    FolderUid = f.FolderUid.ToByteArray().Base64UrlEncode(),
                    ParentUid = f.ParentUid.Length > 0 ? f.ParentUid.ToByteArray().Base64UrlEncode() : "",
                    Data = f.Data.Length > 0 ? f.Data.ToByteArray().Base64UrlEncode() : "",
                    FolderKey = f.FolderKey.Length > 0 ? f.FolderKey.ToByteArray().Base64UrlEncode() : "",
                    KeyType = (int)f.Type,
                    FolderType = (int)f.Type,
                    InheritPermissions = (int)f.InheritUserPermissions,
                    OwnerAccountUid = ownerAccountUid,
                    OwnerUsername = ownerUsername,
                    DateCreated = f.DateCreated,
                    LastModified = f.LastModified,
                };
            }).ToArray();

            storage.KdFolders.PutEntities(folders);
        }

        private static void StoreFolderKeys(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.FolderKeys.Count == 0) return;

            var keys = kdData.FolderKeys.Select(fk => new StorageKdFolderKey
            {
                FolderUid = fk.FolderUid.ToByteArray().Base64UrlEncode(),
                ParentUid = fk.ParentUid.Length > 0 ? fk.ParentUid.ToByteArray().Base64UrlEncode() : "",
                EncryptedKey = fk.FolderKey_.Length > 0 ? fk.FolderKey_.ToByteArray().Base64UrlEncode() : "",
                KeyType = (int)fk.EncryptedBy,
            }).ToArray();

            storage.KdFolderKeys.PutLinks(keys);
        }

        private static void StoreRecordData(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RecordData.Count == 0) return;

            foreach (var rd in kdData.RecordData)
            {
                var recordUid = rd.RecordUid.ToByteArray().Base64UrlEncode();
                var existing = storage.KdRecords.GetEntity(recordUid);
                if (existing != null)
                {
                    var updated = new StorageKdRecord();
                    ((IEntityCopy<IStorageKdRecord>)updated).CopyFields(existing);
                    updated.Data = rd.Data.Length > 0 ? rd.Data.ToByteArray().Base64UrlEncode() : "";
                    storage.KdRecords.PutEntities(new[] { updated });
                }
            }
        }

        private static void StoreFolderRecords(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.FolderRecords.Count == 0) return;

            var folderRecords = new List<StorageKdFolderRecord>();
            var recordKeys = new List<StorageKdRecordKey>();

            foreach (var fr in kdData.FolderRecords)
            {
                var folderUid = fr.FolderUid.ToByteArray().Base64UrlEncode();
                var metadata = fr.RecordMetadata;
                if (metadata == null) continue;

                var recordUid = metadata.RecordUid.ToByteArray().Base64UrlEncode();

                folderRecords.Add(new StorageKdFolderRecord
                {
                    FolderUid = folderUid,
                    RecordUid = recordUid,
                });

                if (metadata.EncryptedRecordKey.Length > 0)
                {
                    recordKeys.Add(new StorageKdRecordKey
                    {
                        RecordUid = recordUid,
                        FolderUid = folderUid,
                        RecordKey = metadata.EncryptedRecordKey.ToByteArray().Base64UrlEncode(),
                        RecordKeyType = (int)metadata.EncryptedRecordKeyType,
                        FolderKeyEncryptionType = (int)fr.FolderKeyEncryptionType,
                    });
                }
            }

            if (folderRecords.Count > 0)
                storage.KdFolderRecords.PutLinks(folderRecords);
            if (recordKeys.Count > 0)
                storage.KdRecordKeys.PutLinks(recordKeys);
        }

        private static void StoreRecords(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.Records.Count == 0) return;

            var records = kdData.Records.Select(dr =>
            {
                var recordUid = dr.RecordUid.ToByteArray().Base64UrlEncode();
                var existing = storage.KdRecords.GetEntity(recordUid);

                var record = new StorageKdRecord
                {
                    RecordUid = recordUid,
                    Revision = dr.Revision,
                    Version = dr.Version,
                    Shared = dr.Shared,
                    ClientModifiedTime = dr.ClientModifiedTime,
                    FileSize = dr.FileSize,
                    ThumbnailSize = dr.ThumbnailSize,
                    Data = existing?.Data ?? "",
                };
                return record;
            }).ToArray();

            storage.KdRecords.PutEntities(records);
        }

        private static void StoreFolderAccesses(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.FolderAccesses.Count == 0) return;

            var accesses = kdData.FolderAccesses.Select(fa =>
            {
                var encKey = "";
                var keyType = 0;
                if (fa.FolderKey != null && fa.FolderKey.EncryptedKey.Length > 0)
                {
                    encKey = fa.FolderKey.EncryptedKey.ToByteArray().Base64UrlEncode();
                    keyType = (int)fa.FolderKey.EncryptedKeyType;
                }

                return new StorageKdFolderAccess
                {
                    FolderUid = fa.FolderUid.ToByteArray().Base64UrlEncode(),
                    AccessTypeUid = fa.AccessTypeUid.ToByteArray().Base64UrlEncode(),
                    AccessType = (int)fa.AccessType,
                    AccessRoleType = (int)fa.AccessRoleType,
                    Inherited = fa.Inherited,
                    Hidden = fa.Hidden,
                    DeniedAccess = fa.DeniedAccess,
                    EncryptedFolderKey = encKey,
                    FolderKeyType = keyType,
                    DateCreated = fa.DateCreated,
                    LastModified = fa.LastModified,
                };
            }).ToArray();

            storage.KdFolderAccesses.PutLinks(accesses);
        }

        private static void ProcessRevokedFolderAccesses(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RevokedFolderAccesses.Count == 0) return;

            var links = kdData.RevokedFolderAccesses
                .Select(rfa => UidLink.Create(
                    rfa.FolderUid.ToByteArray().Base64UrlEncode(),
                    rfa.ActorUid.ToByteArray().Base64UrlEncode()))
                .ToArray();

            storage.KdFolderAccesses.DeleteLinks(links);
        }

        private static void StoreRecordAccesses(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RecordAccesses.Count == 0) return;

            var accesses = kdData.RecordAccesses.Select(ra => new StorageKdRecordAccess
            {
                RecordUid = ra.RecordUid.ToByteArray().Base64UrlEncode(),
                AccessTypeUid = ra.AccessTypeUid.ToByteArray().Base64UrlEncode(),
                AccessType = (int)ra.AccessType,
                AccessRoleType = (int)ra.AccessRoleType,
                Owner = ra.Owner,
                Inherited = ra.Inherited,
                Hidden = ra.Hidden,
                DeniedAccess = ra.DeniedAccess,
                CanViewTitle = ra.CanViewTitle,
                CanEdit = ra.CanEdit,
                CanView = ra.CanView,
                CanListAccess = ra.CanListAccess,
                CanUpdateAccess = ra.CanUpdateAccess,
                CanDelete = ra.CanDelete,
                CanChangeOwnership = ra.CanChangeOwnership,
                CanRequestAccess = ra.CanRequestAccess,
                CanApproveAccess = ra.CanApproveAccess,
                DateCreated = ra.DateCreated,
                LastModified = ra.LastModified,
            }).ToArray();

            storage.KdRecordAccesses.PutLinks(accesses);
        }

        private static void ProcessRevokedRecordAccesses(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RevokedRecordAccesses.Count == 0) return;

            var links = kdData.RevokedRecordAccesses
                .Select(rra => UidLink.Create(
                    rra.RecordUid.ToByteArray().Base64UrlEncode(),
                    rra.ActorUid.ToByteArray().Base64UrlEncode()))
                .ToArray();

            storage.KdRecordAccesses.DeleteLinks(links);
        }

        private static void StoreRecordLinks(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RecordLinks.Count == 0) return;

            var links = kdData.RecordLinks.Select(rl => new StorageKdRecordLink
            {
                ParentRecordUid = rl.ParentRecordUid.Length > 0 ? rl.ParentRecordUid.ToByteArray().Base64UrlEncode() : "",
                ChildRecordUid = rl.ChildRecordUid.ToByteArray().Base64UrlEncode(),
                RecordKey = rl.RecordKey.Length > 0 ? rl.RecordKey.ToByteArray().Base64UrlEncode() : "",
                Revision = rl.Revision,
            }).ToArray();

            storage.KdRecordLinks.PutLinks(links);
        }

        private static void ProcessRemovedRecordLinks(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RemovedRecordLinks.Count == 0) return;

            var links = kdData.RemovedRecordLinks
                .Select(rl => UidLink.Create(
                    rl.ParentRecordUid.ToByteArray().Base64UrlEncode(),
                    rl.ChildRecordUid.ToByteArray().Base64UrlEncode()))
                .ToArray();

            storage.KdRecordLinks.DeleteLinks(links);
        }

        private static void StoreFolderSharingStates(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.FolderSharingState.Count == 0) return;

            var states = kdData.FolderSharingState.Select(fss => new StorageKdFolderSharingState
            {
                FolderUid = fss.FolderUid.ToByteArray().Base64UrlEncode(),
                Shared = fss.Shared,
                Count = fss.Count,
            }).ToArray();

            storage.KdFolderSharingStates.PutEntities(states);
        }

        private static void StoreRecordSharingStates(VaultProto.KeeperDriveData kdData, IKeeperStorage storage)
        {
            if (kdData.RecordSharingStates.Count == 0) return;

            var states = kdData.RecordSharingStates.Select(rss => new StorageKdRecordSharingState
            {
                RecordUid = rss.RecordUid.ToByteArray().Base64UrlEncode(),
                IsDirectlyShared = rss.IsDirectlyShared,
                IsIndirectlyShared = rss.IsIndirectlyShared,
                IsShared = rss.IsShared,
            }).ToArray();

            storage.KdRecordSharingStates.PutEntities(states);
        }

        internal static void RebuildKeeperNSF(
            VaultData vault,
            IAuthContext context)
        {
            var storage = vault.Storage;

            var decryptedFolderKeys = DecryptFolderKeys(storage, context);

            var decryptedRecordKeys = DecryptRecordKeys(storage, decryptedFolderKeys, context);

            RebuildFolderTree(vault, storage, decryptedFolderKeys);
            RebuildRecords(vault, storage, decryptedRecordKeys, decryptedFolderKeys);
            PurgeOrphanedRecords(vault, storage);
        }

        private static void PurgeOrphanedRecords(VaultData vault, IKeeperStorage storage)
        {
            var allFolderRecordUids = new HashSet<string>();
            foreach (var fr in storage.KdFolderRecords.GetAllLinks())
            {
                allFolderRecordUids.Add(fr.RecordUid);
            }

            var orphanedUids = vault.KeeperNSFRecords.Keys
                .Where(uid => !allFolderRecordUids.Contains(uid))
                .ToList();

            foreach (var uid in orphanedUids)
            {
                vault.KeeperNSFRecords.TryRemove(uid, out _);
                Trace.TraceWarning($"Orphaned record removed: {uid}");
            }
        }

        private static Dictionary<string, byte[]> DecryptFolderKeys(
            IKeeperStorage storage,
            IAuthContext context)
        {
            var decryptedKeys = new Dictionary<string, byte[]>();
            var allKeys = storage.KdFolderKeys.GetAllLinks().ToList();

            var keysByFolder = new Dictionary<string, List<IStorageKdFolderKey>>();
            foreach (var fk in allKeys)
            {
                if (!keysByFolder.TryGetValue(fk.FolderUid, out var list))
                {
                    list = new List<IStorageKdFolderKey>();
                    keysByFolder[fk.FolderUid] = list;
                }
                list.Add(fk);
            }

            bool progress;
            do
            {
                progress = false;
                foreach (var kvp in keysByFolder)
                {
                    if (decryptedKeys.ContainsKey(kvp.Key)) continue;

                    foreach (var fk in kvp.Value)
                    {
                        if (TryDecryptFolderKey(fk, context, decryptedKeys, out var decryptedKey))
                        {
                            decryptedKeys[kvp.Key] = decryptedKey;
                            progress = true;
                            break;
                        }
                    }
                }
            } while (progress);

            if (decryptedKeys.Count < keysByFolder.Count)
            {
                var undecrypted = keysByFolder.Keys.Where(k => !decryptedKeys.ContainsKey(k)).ToList();
                foreach (var folderUid in undecrypted)
                {
                    var folderKey = TryDecryptFromFolderAccess(folderUid, storage, context);
                    if (folderKey != null)
                    {
                        decryptedKeys[folderUid] = folderKey;
                    }
                    else
                    {
                        Trace.TraceWarning($"Failed to decrypt folder key: {folderUid}");
                    }
                }
            }

            foreach (var kdFolder in storage.KdFolders.GetAll())
            {
                if (decryptedKeys.ContainsKey(kdFolder.FolderUid)) continue;
                var folderKey = TryDecryptFromFolderAccess(kdFolder.FolderUid, storage, context);
                if (folderKey != null)
                {
                    decryptedKeys[kdFolder.FolderUid] = folderKey;
                }
            }

            return decryptedKeys;
        }

        private static byte[] TryDecryptFromFolderAccess(
            string folderUid,
            IKeeperStorage storage,
            IAuthContext context)
        {
            foreach (var fa in storage.KdFolderAccesses.GetLinksForSubject(folderUid))
            {
                if (string.IsNullOrEmpty(fa.EncryptedFolderKey)) continue;

                try
                {
                    var encKey = fa.EncryptedFolderKey.Base64UrlDecode();
                    var keyType = (FolderProto.EncryptedKeyType)fa.FolderKeyType;

                    switch (keyType)
                    {
                        case FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm:
                            return CryptoUtils.DecryptAesV2(encKey, context.DataKey);
                        case FolderProto.EncryptedKeyType.EncryptedByDataKey:
                            return CryptoUtils.DecryptAesV1(encKey, context.DataKey);
                        case FolderProto.EncryptedKeyType.EncryptedByPublicKey:
                            if (context.PrivateRsaKey != null)
                                return CryptoUtils.DecryptRsa(encKey, context.PrivateRsaKey);
                            break;
                        case FolderProto.EncryptedKeyType.EncryptedByPublicKeyEcc:
                            if (context.PrivateEcKey != null)
                                return CryptoUtils.DecryptEc(encKey, context.PrivateEcKey);
                            break;
                        default:
                            var result = TryDecryptWithUserKeys(encKey, context);
                            if (result != null) return result;
                            break;
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceError($"KeeperNSF: Error decrypting folder access key for {folderUid}: {e.Message}");
                }
            }

            return null;
        }

        private static byte[] TryDecryptSymmetric(byte[] encryptedKey, byte[] symmetricKey)
        {
            try { return CryptoUtils.DecryptAesV2(encryptedKey, symmetricKey); }
            catch (Exception ex)
            {
                Trace.TraceWarning($"AES-V2 decryption failed: {ex.Message}");
            }
            try { return CryptoUtils.DecryptAesV1(encryptedKey, symmetricKey); }
            catch (Exception ex)
            {
                Trace.TraceWarning($"AES-V1 decryption failed: {ex.Message}");
            }
            return null;
        }

        private static byte[] TryDecryptWithUserKeys(byte[] encryptedKey, IAuthContext context)
        {
            var result = TryDecryptSymmetric(encryptedKey, context.DataKey);
            if (result != null) return result;

            if (context.PrivateRsaKey != null)
            {
                try { return CryptoUtils.DecryptRsa(encryptedKey, context.PrivateRsaKey); }
                catch (Exception ex)
                {
                    Trace.TraceWarning($"RSA decryption failed: {ex.Message}");
                }
            }
            if (context.PrivateEcKey != null)
            {
                try { return CryptoUtils.DecryptEc(encryptedKey, context.PrivateEcKey); }
                catch (Exception ex)
                {
                    Trace.TraceWarning($"EC decryption failed: {ex.Message}");
                }
            }
            return null;
        }

        private static bool TryDecryptFolderKey(
            IStorageKdFolderKey fk,
            IAuthContext context,
            Dictionary<string, byte[]> decryptedKeys,
            out byte[] decryptedKey)
        {
            decryptedKey = null;
            try
            {
                var encKeyType = (FolderProto.FolderKeyEncryptionType)fk.KeyType;
                var encryptedKey = fk.EncryptedKey.Base64UrlDecode();

                switch (encKeyType)
                {
                    case FolderProto.FolderKeyEncryptionType.EncryptedByUserKey:
                        decryptedKey = TryDecryptWithUserKeys(encryptedKey, context);
                        return decryptedKey != null;

                    case FolderProto.FolderKeyEncryptionType.EncryptedByParentKey:
                        if (string.IsNullOrEmpty(fk.ParentUid)) return false;
                        if (!decryptedKeys.TryGetValue(fk.ParentUid, out var parentKey)) return false;
                        decryptedKey = TryDecryptSymmetric(encryptedKey, parentKey);
                        return decryptedKey != null;

                    case FolderProto.FolderKeyEncryptionType.EncryptedByTeamKey:
                        return false;

                    default:
                        Trace.TraceWarning($"KeeperNSF: Unknown folder key type {fk.KeyType}");
                        return false;
                }
            }
            catch (Exception e)
            {
                Trace.TraceError($"Failed to decrypt folder key: {fk.FolderUid}. {e.Message}");
                return false;
            }
        }

        private static Dictionary<string, byte[]> DecryptRecordKeys(
            IKeeperStorage storage,
            Dictionary<string, byte[]> decryptedFolderKeys,
            IAuthContext context)
        {
            var decryptedKeys = new Dictionary<string, byte[]>();

            foreach (var rk in storage.KdRecordKeys.GetAllLinks())
            {
                if (decryptedKeys.ContainsKey(rk.RecordUid)) continue;

                try
                {
                    var encryptedKey = rk.RecordKey.Base64UrlDecode();
                    var encKeyType = (FolderProto.EncryptedKeyType)rk.RecordKeyType;
                    var folderEncType = (FolderProto.FolderKeyEncryptionType)rk.FolderKeyEncryptionType;

                    byte[] recordKey = null;

                    switch (encKeyType)
                    {
                        case FolderProto.EncryptedKeyType.EncryptedByPublicKey:
                            if (context.PrivateRsaKey != null)
                                recordKey = CryptoUtils.DecryptRsa(encryptedKey, context.PrivateRsaKey);
                            break;
                        case FolderProto.EncryptedKeyType.EncryptedByPublicKeyEcc:
                            if (context.PrivateEcKey != null)
                                recordKey = CryptoUtils.DecryptEc(encryptedKey, context.PrivateEcKey);
                            break;
                        case FolderProto.EncryptedKeyType.EncryptedByDataKey:
                        case FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm:
                        default:
                            byte[] folderKey = null;
                            if (!string.IsNullOrEmpty(rk.FolderUid))
                                decryptedFolderKeys.TryGetValue(rk.FolderUid, out folderKey);

                            var keysToTry =
                                folderEncType == FolderProto.FolderKeyEncryptionType.EncryptedByUserKey
                                || string.IsNullOrEmpty(rk.FolderUid)
                                    ? new[] { context.DataKey, folderKey }
                                    : new[] { folderKey, context.DataKey };

                            foreach (var key in keysToTry)
                            {
                                if (key == null) continue;

                                recordKey = TryDecryptSymmetric(encryptedKey, key);
                                if (recordKey != null)
                                    break;
                            }

                            recordKey ??= TryDecryptWithUserKeys(encryptedKey, context);
                            break;
                    }

                    if (recordKey != null)
                    {
                        decryptedKeys[rk.RecordUid] = recordKey;
                    }
                    else
                    {
                        Trace.TraceWarning($"Failed to decrypt record key: {rk.RecordUid}");
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceError($"Failed to decrypt record key: {rk.RecordUid}. {e.Message}");
                }
            }

            return decryptedKeys;
        }

        private static void RebuildFolderTree(
            VaultData vault,
            IKeeperStorage storage,
            Dictionary<string, byte[]> decryptedFolderKeys)
        {
            foreach (var kdFolder in storage.KdFolders.GetAll())
            {
                try
                {
                    string folderName = null;
                    if (decryptedFolderKeys.TryGetValue(kdFolder.FolderUid, out var folderKey))
                    {
                        if (!string.IsNullOrEmpty(kdFolder.Data))
                        {
                            try
                            {
                                var dataBytes = CryptoUtils.DecryptAesV2(kdFolder.Data.Base64UrlDecode(), folderKey);
                                var dataJson = JsonUtils.ParseJson<FolderDataJson>(dataBytes);
                                folderName = dataJson?.name;
                            }
                            catch (Exception ex)
                            {
                                Trace.TraceError($"Failed to decrypt folder data: {kdFolder.FolderUid}. {ex.Message}");
                            }
                        }
                    }

                    var node = new FolderNode
                    {
                        FolderUid = kdFolder.FolderUid,
                        ParentUid = string.IsNullOrEmpty(kdFolder.ParentUid) ? null : kdFolder.ParentUid,
                        FolderType = FolderType.UserFolder,
                        Name = string.IsNullOrEmpty(folderName) ? KeeperNSFConstants.FolderPlaceholderName : folderName,
                        FolderKey = folderKey,
                    };

                    vault.KeeperNSFFolders[node.FolderUid] = node;
                }
                catch (Exception e)
                {
                    Trace.TraceError($"KeeperNSF: Error rebuilding folder {kdFolder.FolderUid}: {e.Message}");
                }
            }

            foreach (var node in vault.KeeperNSFFolders.Values)
            {
                if (!string.IsNullOrEmpty(node.ParentUid) &&
                    vault.KeeperNSFFolders.TryGetValue(node.ParentUid, out var parent))
                {
                    parent.Subfolders.Add(node.FolderUid);
                }
            }

            foreach (var fr in storage.KdFolderRecords.GetAllLinks())
            {
                if (vault.KeeperNSFFolders.TryGetValue(fr.FolderUid, out var folder))
                {
                    folder.Records.Add(fr.RecordUid);
                }
            }
        }

        private static (string FolderUid, string FolderName) ResolvePrimaryFolder(
            VaultData vault,
            IKeeperStorage storage,
            string recordUid)
        {
            var link = storage.KdFolderRecords.GetLinksForObject(recordUid).FirstOrDefault();
            if (link == null)
            {
                return (null, null);
            }

            var folderUid = link.FolderUid;
            string folderName = null;
            if (vault.KeeperNSFFolders.TryGetValue(folderUid, out var folder))
            {
                folderName = folder.Name;
            }

            return (folderUid, folderName);
        }

        private static void RebuildRecords(
            VaultData vault,
            IKeeperStorage storage,
            Dictionary<string, byte[]> decryptedRecordKeys,
            Dictionary<string, byte[]> decryptedFolderKeys)
        {
            foreach (var kdRecord in storage.KdRecords.GetAll())
            {
                try
                {
                    if (!decryptedRecordKeys.TryGetValue(kdRecord.RecordUid, out var recordKey))
                    {
                        Trace.TraceWarning($"KeeperNSF: No decrypted key for record {kdRecord.RecordUid}");
                        continue;
                    }

                    NsfRecordData data = null;
                    if (!string.IsNullOrEmpty(kdRecord.Data))
                    {
                        try
                        {
                            var dataBytes = CryptoUtils.DecryptAesV2(kdRecord.Data.Base64UrlDecode(), recordKey);
                            data = JsonUtils.ParseJson<NsfRecordData>(dataBytes);
                        }
                        catch (Exception ex)
                        {
                            Trace.TraceError($"Failed to decrypt record data: {kdRecord.RecordUid}.{ex.Message}");
                        }
                    }
                    else
                    {
                        Trace.TraceWarning($"KeeperNSF: Record {kdRecord.RecordUid} has no encrypted data payload");
                    }

                    var resolvedTitle = !string.IsNullOrEmpty(data?.Title) ? data.Title : data?.Name;
                    if (data != null && string.IsNullOrEmpty(resolvedTitle) && string.IsNullOrEmpty(data.Type))
                    {
                        Trace.TraceWarning($"KeeperNSF: Record {kdRecord.RecordUid} data parsed but has no title/name/type fields");
                    }

                    var (folderUid, folderName) = ResolvePrimaryFolder(vault, storage, kdRecord.RecordUid);

                    var entry = new KeeperNSFRecord
                    {
                        RecordUid = kdRecord.RecordUid,
                        Title = resolvedTitle,
                        Type = data?.Type,
                        Notes = data?.Notes,
                        Fields = data?.Fields?
                            .Select(f => new KeeperNSFField
                            {
                                Type = f.Type,
                                Value = f.Value?.Select(CoerceFieldValueToString).ToList(),
                            })
                            .ToList(),
                        FolderUid = folderUid,
                        FolderName = folderName,
                        Revision = kdRecord.Revision,
                        Version = kdRecord.Version,
                        Shared = kdRecord.Shared,
                        ClientModifiedTime = kdRecord.ClientModifiedTime,
                        FileSize = kdRecord.FileSize,
                        ThumbnailSize = kdRecord.ThumbnailSize,
                        RecordKey = recordKey,
                        Data = data,
                    };

                    vault.KeeperNSFRecords[entry.RecordUid] = entry;
                }
                catch (Exception e)
                {
                    Trace.TraceError($"KeeperNSF: Error rebuilding record {kdRecord.RecordUid}: {e.Message}");
                }
            }
        }

        private static string CoerceFieldValueToString(object value)
        {
            if (value == null) return null;
            if (value is string s) return s;
            try
            {
                return Encoding.UTF8.GetString(JsonUtils.DumpJson(value, indent: false));
            }
            catch
            {
                return value.ToString();
            }
        }
    }

    [DataContract]
    internal class NsfRecordFieldData : IExtensibleDataObject
    {
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        [DataMember(Name = "value", EmitDefaultValue = false)]
        public object[] Value { get; set; }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    [DataContract]
    internal class NsfRecordData : IExtensibleDataObject
    {
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string Type { get; set; }

        [DataMember(Name = "title", EmitDefaultValue = false)]
        public string Title { get; set; }

        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        [DataMember(Name = "notes", EmitDefaultValue = false)]
        public string Notes { get; set; }

        [DataMember(Name = "fields", EmitDefaultValue = false)]
        public List<NsfRecordFieldData> Fields { get; set; }

        public ExtensionDataObject ExtensionData { get; set; }
    }

    /// <summary>
    /// A typed view of a single field on a Keeper NSF record.
    /// </summary>
    public class KeeperNSFField
    {
        public string Type { get; internal set; }
        public IReadOnlyList<string> Value { get; internal set; }
    }

    public class KeeperNSFRecord
    {
        public string RecordUid { get; internal set; }

        /// <summary>The resolved display title (data.title, falling back to data.name).</summary>
        public string Title { get; internal set; }

        /// <summary>The NSF record type (data.type), or null when not specified.</summary>
        public string Type { get; internal set; }

        /// <summary>Notes attached to the record (data.notes), or null.</summary>
        public string Notes { get; internal set; }

        /// <summary>Typed projection of the record's fields.</summary>
        public IReadOnlyList<KeeperNSFField> Fields { get; internal set; }

        /// <summary>
        /// UID of the first folder this record is linked to (from sync-down folder-record links),
        /// or null when the record is not in a folder or only at drive root.
        /// </summary>
        public string FolderUid { get; internal set; }

        /// <summary>Display name of <see cref="FolderUid"/>, when known from the cached folder tree.</summary>
        public string FolderName { get; internal set; }

        public long Revision { get; internal set; }
        public int Version { get; internal set; }
        public bool Shared { get; internal set; }
        public long ClientModifiedTime { get; internal set; }
        public long FileSize { get; internal set; }
        public long ThumbnailSize { get; internal set; }
        public byte[] RecordKey { get; internal set; }

        /// <summary>Parsed record data POCO; preserves unknown JSON fields across round-trips.</summary>
        internal NsfRecordData Data { get; set; }
    }

    public class KeeperNSFAccessEntry
    {
        public string RecordUid { get; internal set; }
        public string AccessorName { get; internal set; }
        public string AccessTypeUid { get; internal set; }
        public bool Owner { get; internal set; }
        public bool Inherited { get; internal set; }
        public int AccessRoleType { get; internal set; }
        public bool CanEdit { get; internal set; }
        public bool CanView { get; internal set; }
        public bool CanUpdateAccess { get; internal set; }
        public bool CanDelete { get; internal set; }
    }

    public class KeeperNSFPermissionChange
    {
        public string RecordUid { get; internal set; }
        public string Email { get; internal set; }
        public string CurrentRole { get; internal set; }
        public string NewRole { get; internal set; }
        public string ChangeType { get; internal set; }
        public bool Success { get; internal set; }
        public string Message { get; internal set; }
    }

    public class KeeperNSFPermissionResult
    {
        public List<KeeperNSFPermissionChange> Grants { get; } = new List<KeeperNSFPermissionChange>();
        public List<KeeperNSFPermissionChange> Revokes { get; } = new List<KeeperNSFPermissionChange>();
        public List<KeeperNSFPermissionChange> Skipped { get; } = new List<KeeperNSFPermissionChange>();
    }

    /// <summary>
    /// Represents a record that appears in multiple Keeper NSF folders (a "shortcut").
    /// </summary>
    public class KeeperNSFShortcutEntry
    {
        public string RecordUid { get; internal set; }
        public string Title { get; internal set; }
        public List<KeeperNSFShortcutFolder> Folders { get; } = new List<KeeperNSFShortcutFolder>();
    }

    /// <summary>
    /// A folder reference within a shortcut entry.
    /// </summary>
    public class KeeperNSFShortcutFolder
    {
        public string FolderUid { get; internal set; }
        public string Name { get; internal set; }
    }

    /// <summary>
    /// Result of a shortcut-keep operation (keeping a record in one folder, removing from others).
    /// </summary>
    public class KeeperNSFShortcutKeepResult
    {
        public string RecordUid { get; internal set; }
        public string KeptFolderUid { get; internal set; }
        public string KeptFolderName { get; internal set; }
        public List<KeeperNSFShortcutRemoval> Removals { get; } = new List<KeeperNSFShortcutRemoval>();
    }

    /// <summary>
    /// Result of removing a record from a single folder during a shortcut-keep operation.
    /// </summary>
    public class KeeperNSFShortcutRemoval
    {
        public string FolderUid { get; internal set; }
        public string FolderName { get; internal set; }
        public bool Success { get; internal set; }
        public string Message { get; internal set; }
    }
}
