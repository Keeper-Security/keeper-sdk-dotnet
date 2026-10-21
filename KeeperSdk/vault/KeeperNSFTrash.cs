using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Folder.V3.Remove;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline
    {
        private const int MinUidLength = 16;
        private const int MaxUidLength = 64;
        private const string UidValidationPattern = "^[A-Za-z0-9_-]+$";
        private const int MaxTrashRestoreUidsPerRequest = 990;

        private static bool IsValidTrashUid(string uid)
        {
            if (string.IsNullOrWhiteSpace(uid))
            {
                return false;
            }

            if (uid.Length < MinUidLength || uid.Length > MaxUidLength)
            {
                return false;
            }

            return Regex.IsMatch(uid, UidValidationPattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
        }

        /// <inheritdoc/>
        public async Task<KeeperNSFTrashGetResult> GetKeeperNSFTrashItem(string uid)
        {
            if (string.IsNullOrEmpty(uid))
            {
                throw new KeeperInvalidParameter(
                    nameof(GetKeeperNSFTrashItem), "uid", "", "a record or folder UID is required");
            }

            if (!IsValidTrashUid(uid))
            {
                throw new KeeperInvalidParameter(
                    nameof(GetKeeperNSFTrashItem), "uid", uid,
                    $"UID must be {MinUidLength}-{MaxUidLength} characters and contain only letters, digits, '_' or '-'");
            }

            await NsfTrashcanSync.EnsureSynced(this).ConfigureAwait(false);

            if (NsfTrashcanSync.GetRecords().TryGetValue(uid, out var driveRecord))
            {
                return await BuildDriveTrashRecordResult(driveRecord).ConfigureAwait(false);
            }

            if (NsfTrashcanSync.GetFolders().TryGetValue(uid, out var driveFolder))
            {
                return BuildDriveTrashFolderResult(driveFolder);
            }

            return null;
        }

        /// <inheritdoc/>
        public async Task<KeeperNSFTrashListResult> GetKeeperNSFTrash(bool reload = false)
        {
            await NsfTrashcanSync.EnsureSynced(this, reload).ConfigureAwait(false);

            var driveRecords = NsfTrashcanSync.GetRecords().Values.ToList();
            var driveFolders = NsfTrashcanSync.GetFolders().Values.ToList();

            var recordUids = driveRecords.Select(r => r.RecordUid).ToList();
            var recordDetails = recordUids.Count > 0
                ? (await GetKeeperNSFRecordDetails(recordUids).ConfigureAwait(false)).Data
                : new List<KeeperNSFRecordDetailEntry>();

            var records = driveRecords
                .Select(r =>
                {
                    var details = recordDetails.FirstOrDefault(d => d.RecordUid == r.RecordUid);
                    return new KeeperNSFTrashItem
                    {
                        Uid = r.RecordUid,
                        IsFolder = false,
                        Title = details?.Title,
                        RecordType = details?.Type,
                        DateDeleted = r.DateDeleted,
                    };
                })
                .ToList();

            var folders = driveFolders
                .Select(f => new KeeperNSFTrashItem
                {
                    Uid = f.FolderUid,
                    IsFolder = true,
                    Title = f.Name ?? f.FolderUid,
                    DateDeleted = f.DateDeleted,
                })
                .ToList();

            return new KeeperNSFTrashListResult
            {
                Records = records,
                Folders = folders,
            };
        }

        /// <inheritdoc/>
        public async Task<KeeperNSFTrashRestoreResult> RestoreKeeperNSFTrash(
            IReadOnlyList<string> uids, string targetFolderUid = null, bool dryRun = false)
        {
            if (uids == null || uids.Count == 0)
            {
                throw new KeeperInvalidParameter(
                    nameof(RestoreKeeperNSFTrash), "uids", "", "at least one record or folder UID is required");
            }

            var distinctUids = uids.Distinct().ToList();
            if (distinctUids.Count > MaxTrashRestoreUidsPerRequest)
            {
                throw new KeeperInvalidParameter(
                    nameof(RestoreKeeperNSFTrash), "uids", distinctUids.Count.ToString(),
                    $"too many UIDs specified (max: {MaxTrashRestoreUidsPerRequest})");
            }

            targetFolderUid = NormalizeKeeperNSFRootAlias(targetFolderUid);

            await NsfTrashcanSync.EnsureSynced(this).ConfigureAwait(false);

            var driveRecords = NsfTrashcanSync.GetRecords();
            var driveFolders = NsfTrashcanSync.GetFolders();

            var errors = new List<string>();
            var recordsToRestore = new Dictionary<string, NsfTrashcanRecord>();
            var foldersToRestore = new Dictionary<string, NsfTrashcanFolderEntry>();

            // Record titles, fetched once and only if we actually need to match by pattern.
            List<KeeperNSFRecordDetailEntry> recordDetailsForMatching = null;

            foreach (var uid in distinctUids)
            {
                if (driveRecords.TryGetValue(uid, out var exactRecord))
                {
                    recordsToRestore[uid] = exactRecord;
                    continue;
                }

                if (driveFolders.TryGetValue(uid, out var exactFolder))
                {
                    foldersToRestore[uid] = exactFolder;
                    continue;
                }

                // Not an exact UID match - try it as a title pattern (plain text or wildcard),
                var titlePattern = BuildTrashTitlePattern(uid);
                var matchedAny = false;

                foreach (var kvp in driveFolders)
                {
                    if (foldersToRestore.ContainsKey(kvp.Key))
                    {
                        continue;
                    }

                    if (!string.IsNullOrEmpty(kvp.Value.Name) && titlePattern.IsMatch(kvp.Value.Name))
                    {
                        foldersToRestore[kvp.Key] = kvp.Value;
                        matchedAny = true;
                    }
                }

                if (recordDetailsForMatching == null)
                {
                    var allRecordUids = driveRecords.Keys.ToList();
                    recordDetailsForMatching = allRecordUids.Count > 0
                        ? (await GetKeeperNSFRecordDetails(allRecordUids).ConfigureAwait(false)).Data
                        : new List<KeeperNSFRecordDetailEntry>();
                }

                foreach (var detail in recordDetailsForMatching)
                {
                    if (recordsToRestore.ContainsKey(detail.RecordUid) || !driveRecords.TryGetValue(detail.RecordUid, out var candidate))
                    {
                        continue;
                    }

                    if (!string.IsNullOrEmpty(detail.Title) && titlePattern.IsMatch(detail.Title))
                    {
                        recordsToRestore[detail.RecordUid] = candidate;
                        matchedAny = true;
                    }
                }

                if (!matchedAny)
                {
                    errors.Add($"UID \"{uid}\" was not found in the Drive trashcan");
                }
            }

            if (recordsToRestore.Count == 0 && foldersToRestore.Count == 0)
            {
                return new KeeperNSFTrashRestoreResult
                {
                    Success = false,
                    Errors = errors,
                };
            }

            if (dryRun)
            {
                return new KeeperNSFTrashRestoreResult
                {
                    Success = errors.Count == 0,
                    RestoredRecordUids = recordsToRestore.Keys.ToList(),
                    RestoredFolderUids = foldersToRestore.Keys.ToList(),
                    Errors = errors,
                };
            }

            byte[] explicitTargetKey = null;
            if (!string.IsNullOrEmpty(targetFolderUid))
            {
                if (!TryResolveKeeperNSFFolderOrRoot(targetFolderUid, out var targetFolder) || targetFolder.FolderKey == null || targetFolder.FolderKey.Length == 0)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RestoreKeeperNSFTrash), "targetFolderUid", targetFolderUid, "target folder was not found or its key is unavailable");
                }

                explicitTargetKey = targetFolder.FolderKey;
            }

            var groups = new Dictionary<string, (List<(string Uid, byte[] Key, string SourceFolderUid)> Records, List<(string Uid, byte[] Key)> Folders)>();

            foreach (var kvp in recordsToRestore)
            {
                if (kvp.Value.RecordKeyUnencrypted == null || kvp.Value.RecordKeyUnencrypted.Length == 0)
                {
                    errors.Add($"UID \"{kvp.Key}\": Cannot decrypt record key - the record's folder key is unavailable (folder may have been deleted from the active drive)");
                    continue;
                }

                var sourceFolderUid = kvp.Value.FolderUid;

                if (string.IsNullOrEmpty(sourceFolderUid))
                {
                    sourceFolderUid = kvp.Value.TrashcanUid;
                }

                if (string.IsNullOrEmpty(sourceFolderUid))
                {
                    if (string.IsNullOrEmpty(targetFolderUid))
                    {
                        errors.Add($"UID \"{kvp.Key}\": Record has no source folder or trashcan UID and no target folder specified");
                        continue;
                    }
                }

                var destUid = targetFolderUid ?? sourceFolderUid ?? "";

                if (!groups.TryGetValue(destUid, out var group))
                {
                    group = (new List<(string, byte[], string)>(), new List<(string, byte[])>());
                    groups[destUid] = group;
                }

                group.Records.Add((kvp.Key, kvp.Value.RecordKeyUnencrypted, sourceFolderUid));
            }

            foreach (var kvp in foldersToRestore)
            {
                if (kvp.Value.FolderKeyUnencrypted == null || kvp.Value.FolderKeyUnencrypted.Length == 0)
                {
                    errors.Add($"UID \"{kvp.Key}\": Cannot decrypt folder key - the folder's parent key is unavailable (parent folder may have been deleted from the active drive)");
                    continue;
                }

                var destUid = targetFolderUid ?? kvp.Value.ParentUid ?? "";
                if (!groups.TryGetValue(destUid, out var group))
                {
                    group = (new List<(string, byte[], string)>(), new List<(string, byte[])>());
                    groups[destUid] = group;
                }

                group.Folders.Add((kvp.Key, kvp.Value.FolderKeyUnencrypted));
            }

            var restoredRecords = new List<string>();
            var restoredFolders = new List<string>();
            var restoredRecordKeys = new Dictionary<string, byte[]>();

            foreach (var groupEntry in groups)
            {
                var destUid = groupEntry.Key;
                var group = groupEntry.Value;

                byte[] targetKey;
                if (explicitTargetKey != null)
                {
                    targetKey = explicitTargetKey;
                }
                else if (!TryGetNsfRestoreDestinationKey(destUid, out targetKey, out var keyError))
                {
                    errors.Add($"Restore into \"{destUid}\" failed: {keyError}");
                    continue;
                }

                var request = new TrashcanRestoreRequest();
                if (string.IsNullOrEmpty(destUid))
                {
                    errors.Add($"Restore into \"{destUid}\" failed: target folder UID is required");
                    continue;
                }

                request.TargetFolderUid = ByteString.CopyFrom(destUid.Base64UrlDecode());

                foreach (var (recordUid, recordKey, recordSourceFolderUid) in group.Records)
                {
                    request.Records.Add(BuildRestoreRecord(recordUid, recordKey, recordSourceFolderUid, targetKey));
                    restoredRecordKeys[recordUid] = recordKey;
                }

                foreach (var (folderUid, folderKey) in group.Folders)
                {
                    request.Folders.Add(BuildRestoreFolder(folderUid, folderKey, targetKey));
                }

                TrashcanRestoreResponse response;
                try
                {
                    response = await Auth.ExecuteAuthRest<TrashcanRestoreRequest, TrashcanRestoreResponse>(
                        "vault/folders/v3/trashcan/restore", request).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    errors.Add($"Restore into \"{destUid}\" failed: {ex.Message}");
                    continue;
                }

                if (!string.IsNullOrEmpty(response.ErrorMessage))
                {
                    errors.Add(response.ErrorMessage);
                    continue;
                }

                foreach (var result in response.Results)
                {
                    var itemUid = result.ItemUid.ToByteArray().Base64UrlEncode();
                    if (result.Status == RestoreStatus.RsSuccess)
                    {
                        if (result.ItemType == RestoreItemType.RestoreItemFolder)
                        {
                            restoredFolders.Add(itemUid);
                        }
                        else
                        {
                            restoredRecords.Add(itemUid);
                        }
                    }
                    else
                    {
                        errors.Add($"UID \"{itemUid}\": {result.Status}" +
                            (string.IsNullOrEmpty(result.ErrorMessage) ? "" : $" ({result.ErrorMessage})"));
                    }
                }
            }

            if (restoredRecords.Count > 0 || restoredFolders.Count > 0)
            {
                NsfTrashcanSync.Reset();

                await SyncDown().ConfigureAwait(false);

                foreach (var recordUid in restoredRecords)
                {
                    Auth.ScheduleAuditEventLogging("record_restored", new AuditEventInput { RecordUid = recordUid });

                    if (restoredRecordKeys.TryGetValue(recordUid, out var recordKey) && recordKey != null
                        && TryGetKeeperNSFRecord(recordUid, out var nsfRecord))
                    {
                        var password = nsfRecord.Fields?.FirstOrDefault(f => f.Type == "password")?.Value?.FirstOrDefault();
                        if (!string.IsNullOrEmpty(password))
                        {
                            await this.ScanAndStoreRecordStatusAsync(recordUid, recordKey, password).ConfigureAwait(false);
                        }
                    }
                }
            }

            return new KeeperNSFTrashRestoreResult
            {
                Success = errors.Count == 0 && (restoredRecords.Count > 0 || restoredFolders.Count > 0),
                RestoredRecordUids = restoredRecords,
                RestoredFolderUids = restoredFolders,
                Errors = errors,
            };
        }

        private bool TryGetNsfRestoreDestinationKey(string folderUid, out byte[] key, out string error)
        {
            if (string.IsNullOrEmpty(folderUid))
            {
                key = Auth.AuthContext.DataKey;
                error = null;
                return true;
            }

            if (TryResolveKeeperNSFFolderOrRoot(folderUid, out var folder) && folder.FolderKey != null && folder.FolderKey.Length > 0)
            {
                key = folder.FolderKey;
                error = null;
                return true;
            }

            key = null;
            error = $"destination folder \"{folderUid}\" was not found or its key is unavailable";
            return false;
        }

        private static string NormalizeKeeperNSFRootAlias(string folderUid)
        {
            if (folderUid == null)
            {
                return null;
            }

            var trimmed = folderUid.Trim();
            return trimmed.Length == 0
                || string.Equals(trimmed, "/", StringComparison.Ordinal)
                || string.Equals(trimmed, "root", StringComparison.OrdinalIgnoreCase)
                ? KeeperNSFConstants.KeeperDriveRootFolderUid
                : trimmed;
        }

        private static Regex BuildTrashTitlePattern(string pattern)
        {
            var escaped = Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".");
            return new Regex("^" + escaped + "$", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
        }

        // Drive trashcan records don't carry a title in the sync stream, so we fetch it separately.
        private async Task<KeeperNSFTrashGetResult> BuildDriveTrashRecordResult(NsfTrashcanRecord record)
        {
            string title = null;
            string recordType = null;

            try
            {
                var details = await GetKeeperNSFRecordDetails(new[] { record.RecordUid }).ConfigureAwait(false);
                var entry = details.Data.FirstOrDefault(d => d.RecordUid == record.RecordUid);
                title = entry?.Title;
                recordType = entry?.Type;
            }
            catch (Exception)
            {
            }

            return new KeeperNSFTrashGetResult
            {
                Uid = record.RecordUid,
                IsFolder = false,
                Title = title,
                RecordType = recordType,
                Status = "Drive",
                DateDeleted = record.DateDeleted,
            };
        }

        // The folder's name, if any, was already captured when we first synced it (see
        // NsfTrashcanSync) - the trashcan sync message itself carries no name field.
        private static KeeperNSFTrashGetResult BuildDriveTrashFolderResult(NsfTrashcanFolderEntry folder)
        {
            return new KeeperNSFTrashGetResult
            {
                Uid = folder.FolderUid,
                IsFolder = true,
                Title = folder.Name ?? folder.FolderUid,
                Status = "Drive Folder",
                DateDeleted = folder.DateDeleted,
            };
        }

        // Builds one restore entry for a record. If we're moving it to a new folder, we also
        // wrap a copy of its key under that folder's key so the server can store it there.
        private static RestoreRecord BuildRestoreRecord(
            string recordUid, byte[] recordKey, string sourceFolderUid, byte[] targetFolderKey)
        {
            if (targetFolderKey == null || targetFolderKey.Length == 0)
            {
                throw new KeeperInvalidParameter(nameof(BuildRestoreRecord), "targetFolderKey", "", "target folder key is required to build restore request");
            }

            if (recordKey == null || recordKey.Length == 0)
            {
                throw new KeeperInvalidParameter(nameof(BuildRestoreRecord), "recordKey", "", "record key is required to build restore request");
            }

            Trace.TraceInformation($"BuildRestoreRecord: recordUid={recordUid}, sourceFolderUid={sourceFolderUid ?? "(null)"}");

            var restoreRecord = new RestoreRecord
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                EncryptedRecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(recordKey, targetFolderKey)),
            };

            if (!string.IsNullOrEmpty(sourceFolderUid))
            {
                restoreRecord.SourceFolderUid = ByteString.CopyFrom(sourceFolderUid.Base64UrlDecode());
            }

            return restoreRecord;
        }

        // Same idea as BuildRestoreRecord, but for a folder - folders don't need a source Uid
        // since each one only ever has a single parent.
        private static RestoreFolder BuildRestoreFolder(string folderUid, byte[] folderKey, byte[] targetFolderKey)
        {
            if (targetFolderKey == null || targetFolderKey.Length == 0)
            {
                throw new KeeperInvalidParameter(nameof(BuildRestoreFolder), "targetFolderKey", "", "target folder key is required to build restore request");
            }

            if (folderKey == null || folderKey.Length == 0)
            {
                throw new KeeperInvalidParameter(nameof(BuildRestoreFolder), "folderKey", "", "folder key is required to build restore request");
            }

            var restoreFolder = new RestoreFolder
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                EncryptedFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(folderKey, targetFolderKey)),
            };

            return restoreFolder;
        }
    }
}
