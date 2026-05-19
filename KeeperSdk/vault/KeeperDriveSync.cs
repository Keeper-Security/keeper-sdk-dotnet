using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using KeeperSecurity.Authentication;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using FolderProto = Folder;
using RecordSharingProto = Record.V3.Sharing;
using VaultProto = Vault;

namespace KeeperSecurity.Vault
{
    internal static class KeeperDriveSync
    {
        internal static void ProcessKeeperDriveData(
            VaultProto.KeeperDriveData kdData,
            IKeeperStorage storage,
            RebuildTask result)
        {
            if (kdData == null) return;

            Debug.WriteLine($"KeeperDrive SyncDown: folders={kdData.Folders.Count}, folderKeys={kdData.FolderKeys.Count}, " +
                $"records={kdData.Records.Count}, recordData={kdData.RecordData.Count}, " +
                $"folderRecords={kdData.FolderRecords.Count}, removedFolders={kdData.RemovedFolders.Count}");

            ProcessRemovedFolders(kdData, storage);
            ProcessRemovedFolderRecords(kdData, storage);
            ProcessRemovedRecordLinks(kdData, storage);
            StoreFolders(kdData, storage);
            StoreFolderKeys(kdData, storage);
            StoreRecordData(kdData, storage);
            StoreFolderRecords(kdData, storage);
            StoreRecords(kdData, storage);
            StoreFolderAccesses(kdData, storage);
            ProcessRevokedFolderAccesses(kdData, storage);
            StoreRecordAccesses(kdData, storage);
            ProcessRevokedRecordAccesses(kdData, storage);
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

        internal static void RebuildKeeperDrive(
            VaultData vault,
            IAuthContext context,
            byte[] clientKey,
            bool fullRebuild)
        {
            var storage = vault.Storage;

            var decryptedFolderKeys = DecryptFolderKeys(storage, context, clientKey);

            var decryptedRecordKeys = DecryptRecordKeys(storage, decryptedFolderKeys, context, clientKey);

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

            var orphanedUids = vault.KeeperDriveRecords.Keys
                .Where(uid => !allFolderRecordUids.Contains(uid))
                .ToList();

            foreach (var uid in orphanedUids)
            {
                vault.KeeperDriveRecords.TryRemove(uid, out _);
                Trace.TraceWarning($"KeeperDrive: Purged orphaned record {uid}");
            }
        }

        private static Dictionary<string, byte[]> DecryptFolderKeys(
            IKeeperStorage storage,
            IAuthContext context,
            byte[] clientKey)
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
                        if (TryDecryptFolderKey(fk, context, clientKey, decryptedKeys, out var decryptedKey))
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
                        Trace.TraceWarning($"KeeperDrive: Could not decrypt folder key for {folderUid}");
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
                    Trace.TraceError($"KeeperDrive: Error decrypting folder access key for {folderUid}: {e.Message}");
                }
            }

            return null;
        }

        private static byte[] TryDecryptSymmetric(byte[] encryptedKey, byte[] symmetricKey)
        {
            try { return CryptoUtils.DecryptAesV2(encryptedKey, symmetricKey); } catch { }
            try { return CryptoUtils.DecryptAesV1(encryptedKey, symmetricKey); } catch { }
            return null;
        }

        private static byte[] TryDecryptWithUserKeys(byte[] encryptedKey, IAuthContext context)
        {
            var result = TryDecryptSymmetric(encryptedKey, context.DataKey);
            if (result != null) return result;
            if (context.PrivateRsaKey != null)
                try { return CryptoUtils.DecryptRsa(encryptedKey, context.PrivateRsaKey); } catch { }
            if (context.PrivateEcKey != null)
                try { return CryptoUtils.DecryptEc(encryptedKey, context.PrivateEcKey); } catch { }
            return null;
        }

        private static bool TryDecryptFolderKey(
            IStorageKdFolderKey fk,
            IAuthContext context,
            byte[] clientKey,
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
                        Trace.TraceWarning($"KeeperDrive: Unknown folder key type {fk.KeyType}");
                        return false;
                }
            }
            catch (Exception e)
            {
                Trace.TraceError($"KeeperDrive: Error decrypting folder key for {fk.FolderUid}: {e.Message}");
                return false;
            }
        }

        private static Dictionary<string, byte[]> DecryptRecordKeys(
            IKeeperStorage storage,
            Dictionary<string, byte[]> decryptedFolderKeys,
            IAuthContext context,
            byte[] clientKey)
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

                            if (folderEncType == FolderProto.FolderKeyEncryptionType.EncryptedByUserKey
                                || string.IsNullOrEmpty(rk.FolderUid))
                            {
                                recordKey = TryDecryptSymmetric(encryptedKey, context.DataKey);
                                if (recordKey == null && folderKey != null)
                                    recordKey = TryDecryptSymmetric(encryptedKey, folderKey);
                            }
                            else
                            {
                                if (folderKey != null)
                                    recordKey = TryDecryptSymmetric(encryptedKey, folderKey);
                                if (recordKey == null)
                                    recordKey = TryDecryptSymmetric(encryptedKey, context.DataKey);
                            }

                            if (recordKey == null && context.PrivateRsaKey != null)
                                try { recordKey = CryptoUtils.DecryptRsa(encryptedKey, context.PrivateRsaKey); } catch { }
                            if (recordKey == null && context.PrivateEcKey != null)
                                try { recordKey = CryptoUtils.DecryptEc(encryptedKey, context.PrivateEcKey); } catch { }
                            break;
                    }

                    if (recordKey != null)
                    {
                        decryptedKeys[rk.RecordUid] = recordKey;
                    }
                    else
                    {
                        Trace.TraceWarning($"KeeperDrive: Could not decrypt record key for {rk.RecordUid}");
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceError($"KeeperDrive: Error decrypting record key for {rk.RecordUid}: {e.Message}");
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
                                Trace.TraceError($"KeeperDrive: Error decrypting folder data for {kdFolder.FolderUid}: {ex.Message}");
                            }
                        }
                    }

                    var node = new FolderNode
                    {
                        FolderUid = kdFolder.FolderUid,
                        ParentUid = string.IsNullOrEmpty(kdFolder.ParentUid) ? null : kdFolder.ParentUid,
                        FolderType = FolderType.UserFolder,
                        Name = folderName ?? "(Keeper Drive Folder)",
                        FolderKey = folderKey,
                    };

                    vault.KeeperDriveFolders[node.FolderUid] = node;
                }
                catch (Exception e)
                {
                    Trace.TraceError($"KeeperDrive: Error rebuilding folder {kdFolder.FolderUid}: {e.Message}");
                }
            }

            foreach (var node in vault.KeeperDriveFolders.Values)
            {
                if (!string.IsNullOrEmpty(node.ParentUid) &&
                    vault.KeeperDriveFolders.TryGetValue(node.ParentUid, out var parent))
                {
                    parent.Subfolders.Add(node.FolderUid);
                }
            }

            foreach (var fr in storage.KdFolderRecords.GetAllLinks())
            {
                if (vault.KeeperDriveFolders.TryGetValue(fr.FolderUid, out var folder))
                {
                    folder.Records.Add(fr.RecordUid);
                }
            }
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
                        Trace.TraceWarning($"KeeperDrive: No decrypted key for record {kdRecord.RecordUid}");
                        continue;
                    }

                    string recordData = null;
                    if (!string.IsNullOrEmpty(kdRecord.Data))
                    {
                        try
                        {
                            var dataBytes = CryptoUtils.DecryptAesV2(kdRecord.Data.Base64UrlDecode(), recordKey);
                            recordData = System.Text.Encoding.UTF8.GetString(dataBytes);
                        }
                        catch (Exception ex)
                        {
                            Trace.TraceError($"KeeperDrive: Error decrypting record data for {kdRecord.RecordUid}: {ex.Message}");
                        }
                    }

                    var entry = new KeeperDriveRecord
                    {
                        RecordUid = kdRecord.RecordUid,
                        Revision = kdRecord.Revision,
                        Version = kdRecord.Version,
                        Shared = kdRecord.Shared,
                        ClientModifiedTime = kdRecord.ClientModifiedTime,
                        FileSize = kdRecord.FileSize,
                        ThumbnailSize = kdRecord.ThumbnailSize,
                        RecordKey = recordKey,
                        DecryptedData = recordData,
                    };

                    vault.KeeperDriveRecords[entry.RecordUid] = entry;
                }
                catch (Exception e)
                {
                    Trace.TraceError($"KeeperDrive: Error rebuilding record {kdRecord.RecordUid}: {e.Message}");
                }
            }
        }
    }

    [DataContract]
    internal class FolderDataJson
    {
        [DataMember(Name = "name")]
        public string name { get; set; }
    }

    public class KeeperDriveRecord
    {
        public string RecordUid { get; set; }
        public long Revision { get; set; }
        public int Version { get; set; }
        public bool Shared { get; set; }
        public long ClientModifiedTime { get; set; }
        public long FileSize { get; set; }
        public long ThumbnailSize { get; set; }
        public byte[] RecordKey { get; set; }
        public string DecryptedData { get; set; }
    }
}
