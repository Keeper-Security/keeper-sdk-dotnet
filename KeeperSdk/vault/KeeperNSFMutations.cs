using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using Folder.V3.Remove;
using FolderProto = Folder;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using Records;
using AuthProto = Authentication;

namespace KeeperSecurity.Vault
{
    public partial class VaultOnline
    {
        /// <inheritdoc/>
        public async Task<KeeperNSFRemoveResult> RemoveKeeperNSFRecords(
            IReadOnlyList<KeeperNSFRecordRemoval> removals, bool dryRun = false)
        {
            var result = await ExecuteKeeperNSFRecordRemovalAsync(removals, dryRun).ConfigureAwait(false);
            if (!dryRun && result.Confirmed)
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return result;
        }

        /// <inheritdoc/>
        public async Task<KeeperNSFRemoveResult> RemoveKeeperNSFFolders(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, bool dryRun = false)
        {
            var result = await ExecuteKeeperNSFFolderRemovalAsync(removals, dryRun).ConfigureAwait(false);
            if (!dryRun && result.Confirmed)
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return result;
        }

        /// <inheritdoc/>
        public async Task<FolderProto.FolderModifyResult> UpdateKeeperNSFFolder(
            string folderUidOrName, string newName = null, string color = null, bool? inheritPermissions = null)
        {
            return await UpdateKeeperNSFFolderCore(
                folderUidOrName, newName, color, inheritPermissions, requestSync: true).ConfigureAwait(false);
        }

        /// <summary>
        /// Update multiple Keeper NSF folders in batches. The server supports up to 100 folders per update request.
        /// Returns the list of per-folder modify results in the same order as the provided updates.
        /// </summary>
        public async Task<IReadOnlyList<FolderProto.FolderModifyResult>> UpdateKeeperNSFFolders(
            IEnumerable<(string FolderUidOrName, string NewName, string Color, bool? InheritPermissions)> updates)
        {
            if (updates == null) throw new KeeperInvalidParameter(nameof(UpdateKeeperNSFFolders), "updates", "", "at least one update required");
            var list = updates.Where(u => !string.IsNullOrWhiteSpace(u.FolderUidOrName)).ToList();
            if (list.Count == 0) throw new KeeperInvalidParameter(nameof(UpdateKeeperNSFFolders), "updates", "", "at least one update required");

            const int MaxPerRequest = 100;
            var allResults = new List<FolderProto.FolderModifyResult>(list.Count);
            var anySuccess = false;

            for (int i = 0; i < list.Count; i += MaxPerRequest)
            {
                var batch = list.Skip(i).Take(MaxPerRequest).ToList();

                var request = new FolderProto.FolderUpdateRequest();
                var batchFolderNodes = new List<FolderNode>(batch.Count);
                var batchFolderUids = new List<string>(batch.Count);

                foreach (var item in batch)
                {
                    if (!TryResolveKeeperNSFFolder(item.FolderUidOrName, out var folder))
                    {
                        throw new VaultException($"Keeper NSF folder \"{item.FolderUidOrName}\" was not found.");
                    }

                    if (folder.FolderKey == null || folder.FolderKey.Length == 0)
                    {
                        throw new VaultException($"Folder key is not available for \"{folder.FolderUid}\".");
                    }

                    if (item.InheritPermissions.HasValue)
                    {
                        await KeeperNSFAccessHelpers.RequireKeeperNSFFolderSharePermissionAsync(this, folder.FolderUid)
                            .ConfigureAwait(false);
                    }

                    var folderJson = BuildKeeperNSFFolderUpdateData(folder, item.NewName, item.Color);
                    var encryptedData = CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(folderJson), folder.FolderKey);

                    var folderData = new FolderProto.FolderData
                    {
                        FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                        Data = ByteString.CopyFrom(encryptedData),
                    };
                    if (item.InheritPermissions.HasValue)
                    {
                        folderData.InheritUserPermissions = item.InheritPermissions.Value
                            ? FolderProto.SetBooleanValue.BooleanTrue
                            : FolderProto.SetBooleanValue.BooleanFalse;
                    }

                    request.FolderData.Add(folderData);
                    batchFolderNodes.Add(folder);
                    batchFolderUids.Add(folder.FolderUid);
                }

                var response = await Auth.ExecuteAuthRest<FolderProto.FolderUpdateRequest, FolderProto.FolderUpdateResponse>(
                    "vault/folders/v3/update", request).ConfigureAwait(false);

                var results = response?.FolderUpdateResults ?? new Google.Protobuf.Collections.RepeatedField<FolderProto.FolderModifyResult>();

                for (int j = 0; j < Math.Max(results.Count, batchFolderNodes.Count); j++)
                {
                    var modifyResult = j < results.Count ? results[j] : null;
                    allResults.Add(modifyResult);

                    if (modifyResult != null && modifyResult.Status == FolderProto.FolderModifyStatus.Success)
                    {
                        anySuccess = true;
                        if (j < batchFolderNodes.Count)
                        {
                            var folderNode = batchFolderNodes[j];
                            var displayName = BuildKeeperNSFFolderUpdateData(folderNode, batch[j].NewName, batch[j].Color).name;
                            PersistKdFolderData(folderNode.FolderUid, folderNode.FolderKey, CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(BuildKeeperNSFFolderUpdateData(folderNode, batch[j].NewName, batch[j].Color)), folderNode.FolderKey));
                            if (batch[j].InheritPermissions.HasValue)
                            {
                                PersistKdFolderInheritPermissions(folderNode.FolderUid, batch[j].InheritPermissions.Value);
                            }

                            if (KeeperNSFFolders.TryGetValue(folderNode.FolderUid, out var cachedFolder))
                            {
                                var nameToUse = displayName;
                                cachedFolder.Name = string.IsNullOrEmpty(nameToUse)
                                    ? KeeperNSFConstants.FolderPlaceholderName
                                    : nameToUse;
                            }
                        }
                    }
                }
            }

            if (anySuccess)
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return allResults;
        }

        /// <summary>
        /// Accepts a simple DTO that can be used from PowerShell.
        /// </summary>
        public async Task<IReadOnlyList<FolderProto.FolderModifyResult>> UpdateKeeperNSFFolders(
            IEnumerable<KeeperNSFFolderUpdate> updates)
        {
            if (updates == null) throw new KeeperInvalidParameter(nameof(UpdateKeeperNSFFolders), "updates", "", "at least one update required");
            var list = updates.Select(u => (u.FolderUidOrName, u.NewName, u.Color, u.InheritPermissions)).ToList();
            return await UpdateKeeperNSFFolders(list).ConfigureAwait(false);
        }

        internal async Task<FolderProto.FolderModifyResult> UpdateKeeperNSFFolderCore(
            string folderUidOrName, string newName, string color, bool? inheritPermissions, bool requestSync)
        {
            if (string.IsNullOrWhiteSpace(folderUidOrName))
            {
                throw new KeeperInvalidParameter(nameof(UpdateKeeperNSFFolder), nameof(folderUidOrName), folderUidOrName, "required");
            }

            if (newName == null && color == null && !inheritPermissions.HasValue)
            {
                throw new KeeperInvalidParameter(nameof(UpdateKeeperNSFFolder), "newName/color/inheritPermissions", "", "at least one field required");
            }

            if (!TryResolveKeeperNSFFolder(folderUidOrName, out var folder))
            {
                throw new VaultException($"Keeper NSF folder \"{folderUidOrName}\" was not found.");
            }

            if (folder.FolderKey == null || folder.FolderKey.Length == 0)
            {
                throw new VaultException($"Folder key is not available for \"{folder.FolderUid}\".");
            }

            if (inheritPermissions.HasValue)
            {
                await KeeperNSFAccessHelpers.RequireKeeperNSFFolderSharePermissionAsync(this, folder.FolderUid)
                    .ConfigureAwait(false);
            }

            var folderJson = BuildKeeperNSFFolderUpdateData(folder, newName, color);
            var encryptedData = CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(folderJson), folder.FolderKey);

            var folderData = new FolderProto.FolderData
            {
                FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                Data = ByteString.CopyFrom(encryptedData),
            };
            if (inheritPermissions.HasValue)
            {
                folderData.InheritUserPermissions = inheritPermissions.Value
                    ? FolderProto.SetBooleanValue.BooleanTrue
                    : FolderProto.SetBooleanValue.BooleanFalse;
            }

            var request = new FolderProto.FolderUpdateRequest();
            request.FolderData.Add(folderData);

            var response = await Auth.ExecuteAuthRest<FolderProto.FolderUpdateRequest, FolderProto.FolderUpdateResponse>(
                "vault/folders/v3/update", request).ConfigureAwait(false);

            var modifyResult = response?.FolderUpdateResults?.FirstOrDefault()
                ?? throw new VaultException("No results from folder update.");

            if (modifyResult.Status == FolderProto.FolderModifyStatus.Success)
            {
                PersistKdFolderData(folder.FolderUid, folder.FolderKey, encryptedData);
                if (inheritPermissions.HasValue)
                {
                    PersistKdFolderInheritPermissions(folder.FolderUid, inheritPermissions.Value);
                }

                if (KeeperNSFFolders.TryGetValue(folder.FolderUid, out var cachedFolder))
                {
                    var displayName = folderJson.name;
                    cachedFolder.Name = string.IsNullOrEmpty(displayName)
                        ? KeeperNSFConstants.FolderPlaceholderName
                        : displayName;
                }

                if (requestSync)
                {
                    await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
                }
            }

            return modifyResult;
        }

        private void PersistKdFolderInheritPermissions(string folderUid, bool inheritPermissions)
        {
            var row = Storage.KdFolders.GetEntity(folderUid) as StorageKdFolder;
            if (row == null)
            {
                return;
            }

            row.InheritPermissions = inheritPermissions
                ? (int)FolderProto.SetBooleanValue.BooleanTrue
                : (int)FolderProto.SetBooleanValue.BooleanFalse;
            Storage.KdFolders.PutEntities(new IStorageKdFolder[] { row });
        }

        /// <inheritdoc/>
        public async Task<FolderProto.FolderRecordUpdateResult> LinkKeeperNSFRecordToFolder(
            string recordUidOrTitle, string folderUidOrName)
        {
            if (string.IsNullOrWhiteSpace(recordUidOrTitle))
            {
                throw new KeeperInvalidParameter(nameof(LinkKeeperNSFRecordToFolder), nameof(recordUidOrTitle), recordUidOrTitle, "required");
            }

            if (string.IsNullOrWhiteSpace(folderUidOrName))
            {
                throw new KeeperInvalidParameter(nameof(LinkKeeperNSFRecordToFolder), nameof(folderUidOrName), folderUidOrName, "required");
            }

            if (!TryResolveKeeperNSFRecord(recordUidOrTitle, out var record))
            {
                throw new VaultException($"Keeper NSF record \"{recordUidOrTitle}\" was not found.");
            }

            if (!TryResolveKeeperNSFFolder(folderUidOrName, out var folder))
            {
                throw new VaultException($"Keeper NSF folder \"{folderUidOrName}\" was not found.");
            }

            await KeeperNSFAccessHelpers.RequireKeeperNSFFolderAddPermissionAsync(this, folder.FolderUid)
                .ConfigureAwait(false);

            if (folder.FolderKey == null || folder.FolderKey.Length == 0)
            {
                throw new VaultException($"Folder key is not available for \"{folder.FolderUid}\".");
            }

            if (!TryGetKeeperNSFRecordKey(record.RecordUid, out var recordKey))
            {
                throw new VaultException(
                    $"Record key is not available for \"{record.RecordUid}\". Try running Sync-Keeper first.");
            }

            var apiFolderUid = GetKeeperNSFApiFolderUid(folder);
            if (IsRecordLinkedToKeeperNSFFolder(record.RecordUid, apiFolderUid))
            {
                throw new VaultException($"Record \"{record.RecordUid}\" is already linked to this folder.");
            }

            if (!TryGetKeeperNSFRecordKeyType(record.RecordUid, out var recordKeyType))
            {
                throw new VaultException(
                    $"Record key type is not available for \"{record.RecordUid}\". Try running Sync-Keeper first.");
            }

            var metadata = BuildKeeperNSFRecordMetadata(record.RecordUid, recordKey, recordKeyType, folder.FolderKey);

            var request = new FolderProto.FolderRecordUpdateRequest
            {
                FolderUid = string.IsNullOrEmpty(apiFolderUid)
                    ? ByteString.Empty
                    : ByteString.CopyFrom(apiFolderUid.Base64UrlDecode()),
            };
            request.AddRecords.Add(metadata);

            var response = await Auth.ExecuteAuthRest<FolderProto.FolderRecordUpdateRequest, FolderProto.FolderRecordUpdateResponse>(
                "vault/folders/v3/record_update", request).ConfigureAwait(false);

            var linkResult = response?.FolderRecordUpdateResult?.FirstOrDefault()
                ?? throw new VaultException("No results from record link.");

            await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            return linkResult;
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<KeeperNSFRecordTransferResult>> TransferKeeperNSFRecordOwnership(
            IReadOnlyList<string> recordUidOrTitles, string newOwnerEmail)
        {
            if (recordUidOrTitles == null || recordUidOrTitles.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(TransferKeeperNSFRecordOwnership), "recordUidOrTitles", "", "at least one record required");
            }

            if (string.IsNullOrWhiteSpace(newOwnerEmail))
            {
                throw new KeeperInvalidParameter(nameof(TransferKeeperNSFRecordOwnership), nameof(newOwnerEmail), newOwnerEmail, "required");
            }

            var ownerEmail = newOwnerEmail.Trim();
            var recipientKey = await GetRecipientPublicKeyAsync(ownerEmail).ConfigureAwait(false);

            var transferPayload = new List<(string RecordUid, byte[] RecordKey)>();
            foreach (var identifier in recordUidOrTitles)
            {
                if (!TryResolveKeeperNSFRecord(identifier, out var record))
                {
                    throw new VaultException($"Keeper NSF record \"{identifier}\" was not found.");
                }

                await KeeperNSFAccessHelpers.RequireKeeperNSFRecordOwnershipPermissionAsync(this, record.RecordUid)
                    .ConfigureAwait(false);

                if (!TryGetKeeperNSFRecordKey(record.RecordUid, out var recordKey))
                {
                    throw new VaultException(
                        $"Record key is not available for \"{record.RecordUid}\". Try running Sync-Keeper first.");
                }

                transferPayload.Add((record.RecordUid, recordKey));
            }

            var results = await TransferKeeperNSFRecordOwnershipBatchAsync(
                transferPayload, ownerEmail, recipientKey).ConfigureAwait(false);

            if (results.Any(r => r.Success))
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return results;
        }

        private async Task<IReadOnlyList<KeeperNSFRecordTransferResult>> TransferKeeperNSFRecordOwnershipBatchAsync(
            IReadOnlyList<(string RecordUid, byte[] RecordKey)> transfers,
            string ownerEmail,
            RecipientPublicKeyInfo recipientKey)
        {
            var request = new RecordsOnwershipTransferRequest();
            foreach (var transfer in transfers)
            {
                request.TransferRecords.Add(
                    BuildKeeperNSFTransferRecord(transfer.RecordUid, transfer.RecordKey, ownerEmail, recipientKey));
            }

            var response = await Auth.ExecuteAuthRest<RecordsOnwershipTransferRequest, RecordsOnwershipTransferResponse>(
                KeeperNSFTransferEndpoint, request).ConfigureAwait(false);

            var statusByRecordUid = ParseKeeperNSFTransferResults(response, ownerEmail)
                .ToDictionary(r => r.RecordUid, StringComparer.Ordinal);

            var results = new List<KeeperNSFRecordTransferResult>(transfers.Count);
            foreach (var transfer in transfers)
            {
                if (!statusByRecordUid.TryGetValue(transfer.RecordUid, out var result))
                {
                    throw new VaultException($"Transfer returned no result for record {transfer.RecordUid}.");
                }

                if (result.Success)
                {
                    results.Add(result);
                    continue;
                }

                if (string.Equals(result.Status, AlreadySharedTransferStatus, StringComparison.OrdinalIgnoreCase))
                {
                    await this.TransferKeeperNSFRecordOwnershipViaShareInternal(transfer.RecordUid, ownerEmail)
                        .ConfigureAwait(false);
                    results.Add(new KeeperNSFRecordTransferResult
                    {
                        RecordUid = transfer.RecordUid,
                        Username = ownerEmail,
                        Status = AlreadySharedTransferStatus,
                        Message = "Ownership transferred via record share.",
                        Success = true,
                    });
                    continue;
                }

                results.Add(result);
            }

            return results;
        }

        /// <inheritdoc/>
        public bool TryResolveKeeperNSFRecord(string uidOrTitle, out KeeperNSFRecord record)
        {
            record = null;
            if (string.IsNullOrWhiteSpace(uidOrTitle))
            {
                return false;
            }

            if (TryGetKeeperNSFRecord(uidOrTitle, out var kdRecord) && kdRecord != null)
            {
                record = kdRecord;
                return true;
            }

            var lower = uidOrTitle.Trim();
            foreach (var entry in KeeperNSFRecordEntries)
            {
                if (entry == null)
                {
                    continue;
                }

                if (string.Equals(entry.RecordUid, lower, StringComparison.OrdinalIgnoreCase))
                {
                    record = entry;
                    return true;
                }

                if (!string.IsNullOrEmpty(entry.Title)
                    && string.Equals(entry.Title, lower, StringComparison.OrdinalIgnoreCase))
                {
                    record = entry;
                    return true;
                }
            }

            return false;
        }

        /// <inheritdoc/>
        public bool TryResolveKeeperNSFFolder(string uidOrName, out FolderNode folder)
        {
            folder = null;
            if (string.IsNullOrWhiteSpace(uidOrName))
            {
                return false;
            }

            var trimmed = uidOrName.Trim();
            if (IsKeeperDriveRootFolderIdentifier(trimmed))
            {
                folder = TryCreateKeeperDriveRootFolderNode();
                return folder != null;
            }

            if (TryGetKeeperNSFFolder(uidOrName, out folder))
            {
                return true;
            }

            folder = KeeperNSFFolderNodes
                .Where(node => node != null)
                .FirstOrDefault(node =>
                    string.Equals(node.FolderUid, trimmed, StringComparison.OrdinalIgnoreCase)
                    || (!string.IsNullOrEmpty(node.Name)
                        && string.Equals(node.Name, trimmed, StringComparison.OrdinalIgnoreCase)));

            return folder != null;
        }

        /// <inheritdoc/>
        public IEnumerable<string> GetKeeperNSFFoldersForRecord(string recordUid)
        {
            if (string.IsNullOrWhiteSpace(recordUid))
            {
                return Enumerable.Empty<string>();
            }

            return Storage.KdFolderRecords.GetAllLinks()
                .Where(link => string.Equals(link.RecordUid, recordUid, StringComparison.Ordinal))
                .Select(link => link.FolderUid)
                .Distinct(StringComparer.Ordinal);
        }

        /// <inheritdoc/>
        public bool TryResolveKeeperNSFRecordRemovalFolder(
            string recordUid,
            string folderUidOrName,
            KeeperNSFRecordRemoveOperation operation,
            out string folderUid)
        {
            folderUid = null;
            if (operation == KeeperNSFRecordRemoveOperation.OwnerTrash)
            {
                if (!string.IsNullOrWhiteSpace(folderUidOrName))
                {
                    if (!TryResolveKeeperNSFFolder(folderUidOrName, out var ownerTrashFolder))
                    {
                        return false;
                    }

                    folderUid = GetKeeperNSFApiFolderUid(ownerTrashFolder);
                }
                else
                {
                    folderUid = GetKeeperNSFFoldersForRecord(recordUid).FirstOrDefault();
                }

                return true;
            }

            if (!string.IsNullOrWhiteSpace(folderUidOrName))
            {
                if (!TryResolveKeeperNSFFolder(folderUidOrName, out var folder))
                {
                    return false;
                }

                folderUid = GetKeeperNSFApiFolderUid(folder);
                return true;
            }

            folderUid = GetKeeperNSFFoldersForRecord(recordUid).FirstOrDefault();
            return !string.IsNullOrEmpty(folderUid);
        }

        /// <summary>
        /// Validates a Keeper NSF remove API response and throws <see cref="VaultException"/> on failure.
        /// </summary>
        public static void ValidateRemoveResponse(RemoveResponse response, bool isConfirm)
        {
            if (response == null)
            {
                throw new VaultException("Remove response was empty.");
            }

            if (!string.IsNullOrEmpty(response.ErrorMessage))
            {
                throw new VaultException(response.ErrorMessage);
            }

            foreach (var result in response.Results)
            {
                if (result.Error != null && !string.IsNullOrEmpty(result.Error.Message))
                {
                    throw new VaultException(result.Error.Message);
                }

                if (isConfirm && result.Status != RemoveStatus.Success)
                {
                    throw new VaultException($"Remove failed with status {result.Status}.");
                }
            }
        }

        /// <summary>
        /// Validates a folder modify result and throws <see cref="VaultException"/> on failure.
        /// </summary>
        public static void ValidateFolderModifyResult(FolderProto.FolderModifyResult result)
        {
            if (result == null)
            {
                throw new VaultException("Folder update returned no result.");
            }

            if (result.Status != FolderProto.FolderModifyStatus.Success)
            {
                throw new VaultException(string.IsNullOrEmpty(result.Message)
                    ? $"Folder update failed with status {result.Status}."
                    : result.Message);
            }
        }

        /// <summary>
        /// Validates a folder record update result and throws <see cref="VaultException"/> on failure.
        /// </summary>
        public static void ValidateFolderRecordUpdateResult(FolderProto.FolderRecordUpdateResult result)
        {
            if (result == null)
            {
                throw new VaultException("Record link returned no result.");
            }

            if (result.Status != FolderProto.FolderModifyStatus.Success)
            {
                throw new VaultException(string.IsNullOrEmpty(result.Message)
                    ? $"Record link failed with status {result.Status}."
                    : result.Message);
            }
        }

        /// <summary>
        /// Validates transfer results and throws <see cref="VaultException"/> when any transfer failed.
        /// </summary>
        public static void ValidateKeeperNSFTransferResults(IReadOnlyList<KeeperNSFRecordTransferResult> results)
        {
            if (results == null || results.Count == 0)
            {
                throw new VaultException("Transfer returned no results.");
            }

            var failure = results.FirstOrDefault(r => !r.Success);
            if (failure != null)
            {
                var detail = string.IsNullOrEmpty(failure.Status)
                    ? failure.Message
                    : $"[{failure.Status}] {failure.Message}".Trim();
                throw new VaultException(string.IsNullOrEmpty(detail)
                    ? $"Transfer failed for record {failure.RecordUid}."
                    : $"Transfer failed for record {failure.RecordUid}: {detail}");
            }
        }

        private static bool IsKeeperDriveRootFolderIdentifier(string identifier)
        {
            return string.Equals(identifier, "/", StringComparison.Ordinal)
                || string.Equals(identifier, "root", StringComparison.OrdinalIgnoreCase)
                || string.Equals(identifier, KeeperNSFConstants.KeeperDriveRootFolderUid, StringComparison.Ordinal);
        }

        private FolderNode TryCreateKeeperDriveRootFolderNode()
        {
            var dataKey = Auth?.AuthContext?.DataKey;
            if (dataKey == null || dataKey.Length == 0)
            {
                return null;
            }

            return new FolderNode
            {
                FolderUid = string.Empty,
                Name = "root",
                FolderKey = dataKey,
            };
        }

        private static string GetKeeperNSFApiFolderUid(FolderNode folder)
        {
            return string.IsNullOrEmpty(folder?.FolderUid) ? string.Empty : folder.FolderUid;
        }

        private bool IsRecordLinkedToKeeperNSFFolder(string recordUid, string apiFolderUid)
        {
            return GetKeeperNSFFoldersForRecord(recordUid).Any(folderUid =>
                string.Equals(folderUid, apiFolderUid, StringComparison.Ordinal)
                || (string.IsNullOrEmpty(apiFolderUid) && IsKeeperDriveRootFolderIdentifier(folderUid))
                || (string.IsNullOrEmpty(folderUid) && IsKeeperDriveRootFolderIdentifier(apiFolderUid)));
        }

        private bool TryGetKeeperNSFRecordKey(string recordUid, out byte[] recordKey)
        {
            recordKey = null;
            if (!TryGetKeeperNSFRecord(recordUid, out var kdRecord)
                || kdRecord.RecordKey == null
                || kdRecord.RecordKey.Length == 0)
            {
                return false;
            }

            recordKey = kdRecord.RecordKey;
            return true;
        }

        private bool TryGetKeeperNSFRecordKeyType(
            string recordUid, out FolderProto.EncryptedKeyType recordKeyType)
        {
            recordKeyType = default;

            var link = Storage.KdRecordKeys.GetAllLinks()
                .FirstOrDefault(item => string.Equals(item.RecordUid, recordUid, StringComparison.Ordinal));

            if (link == null)
            {
                return false;
            }

            recordKeyType = (FolderProto.EncryptedKeyType)link.RecordKeyType;
            return true;
        }

        private static FolderProto.RecordMetadata BuildKeeperNSFRecordMetadata(
            string recordUid,
            byte[] recordKey,
            FolderProto.EncryptedKeyType recordKeyType,
            byte[] folderKey)
        {
            var (encryptedKey, encryptedKeyType) = EncryptKeeperNSFRecordKeyForFolder(recordKey, folderKey, recordKeyType);
            return new FolderProto.RecordMetadata
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                EncryptedRecordKey = ByteString.CopyFrom(encryptedKey),
                EncryptedRecordKeyType = encryptedKeyType,
            };
        }

        private static (byte[] EncryptedKey, FolderProto.EncryptedKeyType KeyType) EncryptKeeperNSFRecordKeyForFolder(
            byte[] recordKey,
            byte[] folderKey,
            FolderProto.EncryptedKeyType recordKeyType)
        {
            if (recordKeyType == FolderProto.EncryptedKeyType.EncryptedByDataKey)
            {
                return (CryptoUtils.EncryptAesV1(recordKey, folderKey), FolderProto.EncryptedKeyType.EncryptedByDataKey);
            }

            return (CryptoUtils.EncryptAesV2(recordKey, folderKey), FolderProto.EncryptedKeyType.EncryptedByDataKeyGcm);
        }

        private async Task<RecipientPublicKeyInfo> GetRecipientPublicKeyAsync(string username)
        {
            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(username);

            var pkRss = await Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq).ConfigureAwait(false);

            if (pkRss?.KeyResponses == null || pkRss.KeyResponses.Count == 0)
            {
                throw new KeeperApiException("public_key_error", $"Public key not found for user '{username}'.");
            }

            var pkRs = pkRss.KeyResponses[0];
            if (pkRs == null)
            {
                throw new KeeperApiException("public_key_error", $"Empty public key response for user '{username}'.");
            }

            if (!string.IsNullOrEmpty(pkRs.ErrorCode)
                && !string.Equals(pkRs.ErrorCode, "success", StringComparison.OrdinalIgnoreCase))
            {
                throw new KeeperApiException(pkRs.ErrorCode,
                    string.IsNullOrEmpty(pkRs.Message)
                        ? $"Public key lookup failed for user '{username}'."
                        : pkRs.Message);
            }

            var hasEcc = pkRs.PublicEccKey != null && !pkRs.PublicEccKey.IsEmpty;
            var hasRsa = pkRs.PublicKey != null && !pkRs.PublicKey.IsEmpty;

            if (!hasEcc && !hasRsa)
            {
                throw new KeeperApiException("public_key_error",
                    string.IsNullOrEmpty(pkRs.Message)
                        ? $"User '{username}' has no public key."
                        : pkRs.Message);
            }

            var forbidKeyType2 = Auth.AuthContext.ForbidKeyType2;

            return (forbidKeyType2, hasEcc, hasRsa) switch
            {
                (true, true, _) => CreateEccInfo(pkRs.PublicEccKey),
                (false, _, true) => CreateRsaInfo(pkRs.PublicKey),
                (_, true, _) => CreateEccInfo(pkRs.PublicEccKey),
                (_, _, true) => CreateRsaInfo(pkRs.PublicKey),
                _ => throw new KeeperApiException("public_key_error", $"No usable public key for user '{username}'."),
            };

            static RecipientPublicKeyInfo CreateEccInfo(ByteString eccKey) => new RecipientPublicKeyInfo
            {
                UseEccKey = true,
                EcPublicKey = CryptoUtils.LoadEcPublicKey(eccKey.ToByteArray()),
            };

            static RecipientPublicKeyInfo CreateRsaInfo(ByteString rsaKey) => new RecipientPublicKeyInfo
            {
                UseEccKey = false,
                RsaPublicKey = CryptoUtils.LoadRsaPublicKey(rsaKey.ToByteArray()),
            };
        }

        private static TransferRecord BuildKeeperNSFTransferRecord(
            string recordUid,
            byte[] recordKey,
            string username,
            RecipientPublicKeyInfo recipientKey)
        {
            var transfer = new TransferRecord
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                Username = username,
            };

            if (recipientKey.UseEccKey)
            {
                transfer.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(recordKey, recipientKey.EcPublicKey));
                transfer.UseEccKey = true;
            }
            else
            {
                transfer.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptRsa(recordKey, recipientKey.RsaPublicKey));
            }

            return transfer;
        }

        private const string TransferRecordSuccessStatus = "transfer_record_success";
        private const string AlreadySharedTransferStatus = "already_shared";
        private const string KeeperNSFTransferEndpoint = "vault/records/v3/transfer";

        private static bool IsKeeperNSFTransferSuccessStatus(string status)
        {
            return string.Equals(status, TransferRecordSuccessStatus, StringComparison.Ordinal);
        }

        private static IReadOnlyList<KeeperNSFRecordTransferResult> ParseKeeperNSFTransferResults(
            RecordsOnwershipTransferResponse response,
            string username)
        {
            if (response?.TransferRecordStatus == null || response.TransferRecordStatus.Count == 0)
            {
                throw new VaultException("Transfer returned no results.");
            }

            return response.TransferRecordStatus
                .Select(status => new KeeperNSFRecordTransferResult
                {
                    RecordUid = status.RecordUid.Length > 0
                        ? status.RecordUid.ToByteArray().Base64UrlEncode()
                        : string.Empty,
                    Username = string.IsNullOrEmpty(status.Username) ? username : status.Username,
                    Status = status.Status,
                    Message = status.Message,
                    Success = IsKeeperNSFTransferSuccessStatus(status.Status),
                })
                .ToList();
        }

        private async Task<KeeperNSFRemoveResult> ExecuteKeeperNSFRecordRemovalAsync(
            IReadOnlyList<KeeperNSFRecordRemoval> removals, bool dryRun)
        {
            if (removals == null || removals.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFRecords), "removals", "", "at least one record required");
            }

            if (removals.Count > 500)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFRecords), "removals", removals.Count.ToString(), "maximum 500 records per request");
            }

            var previewRequest = BuildRemoveRecordRequest(removals, RemoveAction.Preview);
            var previewResponse = await Auth.ExecuteAuthRest<RemoveRecordRequest, RemoveResponse>(
                "vault/folders/v3/remove_record", previewRequest).ConfigureAwait(false);

            var result = new KeeperNSFRemoveResult
            {
                PreviewResponse = previewResponse,
                TokenExpiresAt = previewResponse.TokenExpiresAt > 0 ? previewResponse.TokenExpiresAt : (long?)null,
            };

            if (dryRun || previewResponse.ConfirmationToken.IsEmpty)
            {
                return result;
            }

            var confirmRequest = new RemoveRecordRequest
            {
                Action = RemoveAction.Confirm,
                ConfirmationToken = previewResponse.ConfirmationToken,
            };
            confirmRequest.Records.Add(previewRequest.Records);

            var confirmResponse = await Auth.ExecuteAuthRest<RemoveRecordRequest, RemoveResponse>(
                "vault/folders/v3/remove_record", confirmRequest).ConfigureAwait(false);

            ValidateRemoveResponse(confirmResponse, true);
            result.Confirmed = true;
            return result;
        }

        private async Task<KeeperNSFRemoveResult> ExecuteKeeperNSFFolderRemovalAsync(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, bool dryRun)
        {
            if (removals == null || removals.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFFolders), "removals", "", "at least one folder required");
            }

            if (removals.Count > 100)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFFolders), "removals", removals.Count.ToString(), "maximum 100 folders per request");
            }

            var previewRequest = BuildRemoveFolderRequest(removals, RemoveAction.Preview);
            var previewResponse = await Auth.ExecuteAuthRest<RemoveFolderRequest, RemoveResponse>(
                "vault/folders/v3/remove_folder", previewRequest).ConfigureAwait(false);

            var result = new KeeperNSFRemoveResult
            {
                PreviewResponse = previewResponse,
                TokenExpiresAt = previewResponse.TokenExpiresAt > 0 ? previewResponse.TokenExpiresAt : (long?)null,
            };

            if (dryRun || previewResponse.ConfirmationToken.IsEmpty)
            {
                return result;
            }

            var confirmRequest = new RemoveFolderRequest
            {
                Action = RemoveAction.Confirm,
                ConfirmationToken = previewResponse.ConfirmationToken,
            };
            confirmRequest.Folders.Add(previewRequest.Folders);

            var confirmResponse = await Auth.ExecuteAuthRest<RemoveFolderRequest, RemoveResponse>(
                "vault/folders/v3/remove_folder", confirmRequest).ConfigureAwait(false);

            ValidateRemoveResponse(confirmResponse, true);
            result.Confirmed = true;
            return result;
        }

        private static RemoveRecordRequest BuildRemoveRecordRequest(
            IReadOnlyList<KeeperNSFRecordRemoval> removals, RemoveAction action)
        {
            var request = new RemoveRecordRequest { Action = action };
            foreach (var removal in removals.Where(r => r != null && !string.IsNullOrEmpty(r.RecordUid)))
            {
                var recordUidBytes = removal.RecordUid.Base64UrlDecode();
                if (recordUidBytes == null || recordUidBytes.Length == 0)
                {
                    Trace.TraceWarning($"KeeperNSF: Skipping record removal with malformed RecordUid '{removal.RecordUid}'");
                    continue;
                }

                var recordRemoval = new RecordRemoval
                {
                    RecordUid = ByteString.CopyFrom(recordUidBytes),
                    OperationType = MapRecordOperation(removal.Operation),
                };

                if (!string.IsNullOrEmpty(removal.FolderUid))
                {
                    var folderUidBytes = removal.FolderUid.Base64UrlDecode();
                    if (folderUidBytes == null || folderUidBytes.Length == 0)
                    {
                        Trace.TraceWarning($"KeeperNSF: Skipping record removal for '{removal.RecordUid}'; FolderUid '{removal.FolderUid}' is malformed");
                        continue;
                    }
                    recordRemoval.FolderUid = ByteString.CopyFrom(folderUidBytes);
                }

                request.Records.Add(recordRemoval);
            }

            return request;
        }

        private static RemoveFolderRequest BuildRemoveFolderRequest(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, RemoveAction action)
        {
            var request = new RemoveFolderRequest { Action = action };
            foreach (var removal in removals.Where(r => r != null && !string.IsNullOrEmpty(r.FolderUid)))
            {
                var folderUidBytes = removal.FolderUid.Base64UrlDecode();
                if (folderUidBytes == null || folderUidBytes.Length == 0)
                {
                    Trace.TraceWarning($"KeeperNSF: Skipping folder removal with malformed FolderUid '{removal.FolderUid}'");
                    continue;
                }

                request.Folders.Add(new FolderRemoval
                {
                    FolderUid = ByteString.CopyFrom(folderUidBytes),
                    OperationType = MapFolderOperation(removal.Operation),
                });
            }

            return request;
        }

        private static RecordOperationType MapRecordOperation(KeeperNSFRecordRemoveOperation operation)
        {
            return operation switch
            {
                KeeperNSFRecordRemoveOperation.Unlink => RecordOperationType.UnlinkFromFolder,
                KeeperNSFRecordRemoveOperation.FolderTrash => RecordOperationType.MoveToFolderTrash,
                _ => RecordOperationType.MoveToOwnerTrash,
            };
        }

        private static FolderOperationType MapFolderOperation(KeeperNSFFolderRemoveOperation operation)
        {
            return operation switch
            {
                KeeperNSFFolderRemoveOperation.DeletePermanent => FolderOperationType.FolderDeletePermanent,
                _ => FolderOperationType.FolderMoveToFolderTrash,
            };
        }

        private FolderDataJson BuildKeeperNSFFolderUpdateData(FolderNode folder, string newName, string color)
        {
            var existing = ReadKdFolderData(folder.FolderUid, folder.FolderKey);
            var result = new FolderDataJson();

            if (newName != null)
            {
                result.name = newName;
            }
            else if (TryGetKeeperNSFFolderDisplayName(folder, out var displayName))
            {
                result.name = displayName;
            }
            else if (!string.IsNullOrEmpty(existing?.name))
            {
                result.name = existing.name;
            }
            else if (!string.IsNullOrEmpty(folder?.Name))
            {
                result.name = folder.Name;
            }
            else
            {
                result.name = KeeperNSFConstants.FolderPlaceholderName;
            }

            if (color != null)
            {
                if (string.Equals(color, "none", StringComparison.OrdinalIgnoreCase)
                    || color.Length == 0)
                {
                    result.color = null;
                }
                else
                {
                    result.color = string.Equals(color, "grey", StringComparison.OrdinalIgnoreCase)
                        ? "gray"
                        : color;
                }
            }
            else if (!string.IsNullOrEmpty(existing?.color)
                     && !string.Equals(existing.color, "none", StringComparison.OrdinalIgnoreCase))
            {
                result.color = existing.color;
            }

            return result;
        }

        private FolderDataJson ReadKdFolderData(string folderUid, byte[] folderKey)
        {
            var storageFolder = Storage.KdFolders.GetEntity(folderUid);
            if (storageFolder == null || string.IsNullOrEmpty(storageFolder.Data) || folderKey == null)
            {
                return null;
            }

            try
            {
                var dataBytes = CryptoUtils.DecryptAesV2(storageFolder.Data.Base64UrlDecode(), folderKey);
                return JsonUtils.ParseJson<FolderDataJson>(dataBytes);
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"KeeperNSF: Could not read existing folder data for '{folderUid}'; subsequent update will start from empty data: {ex.Message}");
                return null;
            }
        }

        private void PersistKdFolderData(string folderUid, byte[] folderKey, byte[] encryptedData)
        {
            var existing = Storage.KdFolders.GetEntity(folderUid);
            if (existing == null)
            {
                return;
            }

            var updated = new StorageKdFolder();
            ((IEntityCopy<IStorageKdFolder>)updated).CopyFields(existing);
            updated.Data = encryptedData.Base64UrlEncode();
            Storage.KdFolders.PutEntities(new[] { updated });
        }

        private static bool TryGetKeeperNSFFolderDisplayName(FolderNode folder, out string displayName)
        {
            displayName = null;
            if (folder == null
                || string.IsNullOrEmpty(folder.Name)
                || string.Equals(folder.Name, KeeperNSFConstants.FolderPlaceholderName, StringComparison.Ordinal))
            {
                return false;
            }

            displayName = folder.Name;
            return true;
        }

        private sealed class RecipientPublicKeyInfo
        {
            public bool UseEccKey { get; set; }
            public EcPublicKey EcPublicKey { get; set; }
            public RsaPublicKey RsaPublicKey { get; set; }
        }
    }

    [DataContract]
    internal class FolderDataJson
    {
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string name { get; set; }

        [DataMember(Name = "color", EmitDefaultValue = false)]
        public string color { get; set; }
    }

    /// <summary>
    /// DTO for PowerShell or other callers to describe a folder update.
    /// </summary>
    public class KeeperNSFFolderUpdate
    {
        public string FolderUidOrName { get; set; }
        public string NewName { get; set; }
        public string Color { get; set; }
        public bool? InheritPermissions { get; set; }
    }

    internal static class KeeperNSFConstants
    {
        public const string FolderPlaceholderName = "(Keeper NSF Folder)";
        public const string KeeperDriveRootFolderUid = "AAAAAAAAAAAAAAAAAPmtNA";
    }
}
