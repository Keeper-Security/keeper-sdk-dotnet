using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
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
            if (!dryRun && (result.Confirmed || result.PartialSuccess))
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return result;
        }

        /// <inheritdoc/>
        public Task<KeeperNSFRemoveResult> RemoveKeeperNSFRecord(
            KeeperNSFRecordRemoval removal, bool dryRun = false)
        {
            if (removal == null)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFRecord), "removal", "", "removal required");
            }

            return RemoveKeeperNSFRecords(new[] { removal }, dryRun);
        }

        /// <inheritdoc/>
        public async Task<KeeperNSFRemoveResult> RemoveKeeperNSFFolders(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, bool dryRun = false)
        {
            var result = await ExecuteKeeperNSFFolderRemovalAsync(removals, dryRun).ConfigureAwait(false);
            if (!dryRun && (result.Confirmed || result.PartialSuccess))
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return result;
        }

        /// <inheritdoc/>
        public async Task<KeeperNSFRemoveResult> ConfirmKeeperNSFFolders(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, KeeperNSFRemoveResult previewResult)
        {
            var result = await ConfirmKeeperNSFFolderRemovalAsync(removals, previewResult).ConfigureAwait(false);
            if (result.Confirmed || result.PartialSuccess)
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return result;
        }

        /// <inheritdoc/>
        public Task<KeeperNSFRemoveResult> RemoveKeeperNSFFolder(
            KeeperNSFFolderRemoval removal, bool dryRun = false)
        {
            if (removal == null)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFFolder), "removal", "", "removal required");
            }

            return RemoveKeeperNSFFolders(new[] { removal }, dryRun);
        }

        /// <inheritdoc/>
        public async Task<FolderProto.FolderModifyResult> UpdateKeeperNSFFolder(
            string folderUidOrName, string newName = null, string color = null, bool? inheritPermissions = null)
        {
            return await UpdateKeeperNSFFolderCore(
                folderUidOrName, newName, color, inheritPermissions, requestSync: true).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<KeeperNSFFolderUpdateResult>> UpdateKeeperNSFFolders(
            IReadOnlyList<KeeperNSFFolderUpdateRequest> folders)
        {
            if (folders == null || folders.Count == 0)
            {
                throw new ArgumentException("At least one folder update is required.", nameof(folders));
            }

            for (var i = 0; i < folders.Count; i++)
            {
                if (folders[i] == null)
                {
                    throw new ArgumentException($"Folder update at index {i} is null.", nameof(folders));
                }

                if (string.IsNullOrWhiteSpace(folders[i].FolderUid))
                {
                    throw new ArgumentException($"Folder UID cannot be empty (index {i}).", nameof(folders));
                }

                if (folders[i].Name == null
                    && folders[i].Color == null
                    && !folders[i].InheritPermissions.HasValue)
                {
                    throw new ArgumentException(
                        $"At least one of name, color, or inherit_permissions is required (index {i}).",
                        nameof(folders));
                }

                // Updates can only disable inheritance (same as single UpdateKeeperNSFFolder / nsf-rndir).
                if (folders[i].InheritPermissions == true)
                {
                    throw new ArgumentException(
                        $"inherit_permissions can only be set to false on update (index {i}); enabling inheritance is not supported.",
                        nameof(folders));
                }
            }

            const int MaxPerRequest = 100;
            var results = new KeeperNSFFolderUpdateResult[folders.Count];
            var prepared = new List<(int Index, KeeperNSFFolderUpdateRequest Request, FolderNode Folder, string DisplayName, FolderProto.FolderData FolderData)>();

            for (var i = 0; i < folders.Count; i++)
            {
                var request = folders[i];
                var folderRef = request.FolderUid.Trim();

                results[i] = new KeeperNSFFolderUpdateResult
                {
                    FolderUid = folderRef,
                    Name = request.Name,
                    Success = false,
                };

                if (!TryResolveKeeperNSFFolder(folderRef, out var folder))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF folder '{folderRef}' was not found.";
                    continue;
                }

                results[i].FolderUid = folder.FolderUid;

                if (folder.FolderKey == null || folder.FolderKey.Length == 0)
                {
                    results[i].Status = "missing_key";
                    results[i].Message = $"Folder key is not available for '{folder.FolderUid}'.";
                    continue;
                }

                if (!IsValidAesV2Key(folder.FolderKey))
                {
                    results[i].Status = "invalid_key";
                    results[i].Message =
                        $"Folder key for '{folder.FolderUid}' has invalid length {folder.FolderKey.Length}; expected 32 bytes.";
                    continue;
                }

                if (request.InheritPermissions.HasValue)
                {
                    try
                    {
                        await KeeperNSFAccessHelpers.RequireKeeperNSFFolderSharePermissionAsync(this, folder.FolderUid)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        results[i].Status = "access_denied";
                        results[i].Message = ex.Message;
                        continue;
                    }
                }

                try
                {
                    var folderJson = BuildKeeperNSFFolderUpdateData(folder, request.Name, request.Color);
                    // AES-GCM: folder name/color live in encrypted FolderData.Data
                    var encryptedData = CryptoUtils.EncryptAesV2(JsonUtils.DumpJson(folderJson), folder.FolderKey);
                    var folderData = new FolderProto.FolderData
                    {
                        FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                        Data = ByteString.CopyFrom(encryptedData),
                    };
                    if (request.InheritPermissions.HasValue)
                    {
                        folderData.InheritUserPermissions = request.InheritPermissions.Value
                            ? FolderProto.SetBooleanValue.BooleanTrue
                            : FolderProto.SetBooleanValue.BooleanFalse;
                    }

                    prepared.Add((i, request, folder, folderJson.name, folderData));
                    results[i].Name = folderJson.name;
                }
                catch (Exception ex)
                {
                    results[i].Status = "prepare_failed";
                    results[i].Message = ex.Message;
                }
            }

            var anySuccess = false;
            for (var offset = 0; offset < prepared.Count; offset += MaxPerRequest)
            {
                var chunk = prepared.Skip(offset).Take(MaxPerRequest).ToList();
                var request = new FolderProto.FolderUpdateRequest();
                foreach (var item in chunk)
                {
                    request.FolderData.Add(item.FolderData);
                }

                var response = await Auth.ExecuteAuthRest<FolderProto.FolderUpdateRequest, FolderProto.FolderUpdateResponse>(
                    "vault/folders/v3/update", request).ConfigureAwait(false);

                var statusByUid = new Dictionary<string, FolderProto.FolderModifyResult>(StringComparer.Ordinal);
                var serverResults = response?.FolderUpdateResults;
                var missingServerUidCount = 0;
                if (serverResults != null)
                {
                    foreach (var status in serverResults)
                    {
                        if (status?.FolderUid == null || status.FolderUid.IsEmpty)
                        {
                            missingServerUidCount++;
                            continue;
                        }

                        statusByUid[CryptoUtils.Base64UrlEncode(status.FolderUid.ToByteArray())] = status;
                    }

                    if (missingServerUidCount > 0)
                    {
                        Trace.TraceWarning(
                            $"KeeperNSF folder update: server returned {missingServerUidCount} result(s) without FolderUid; those cannot be attributed by UID.");
                    }
                }

                for (var j = 0; j < chunk.Count; j++)
                {
                    var item = chunk[j];
                    FolderProto.FolderModifyResult modifyResult = null;
                    if (!statusByUid.TryGetValue(item.Folder.FolderUid, out modifyResult))
                    {
                        // Positional fallback only when server omitted FolderUid on some results.
                        if (serverResults != null && j < serverResults.Count
                            && (serverResults[j]?.FolderUid == null || serverResults[j].FolderUid.IsEmpty))
                        {
                            Trace.TraceWarning(
                                $"KeeperNSF folder update: attributing server result at index {j} to folder '{item.Folder.FolderUid}' by position (missing FolderUid).");
                            modifyResult = serverResults[j];
                        }
                    }

                    if (modifyResult == null)
                    {
                        results[item.Index].Status = "missing";
                        results[item.Index].Message = "Server returned no status for this folder.";
                        continue;
                    }

                    results[item.Index].Status = Enum.GetName(typeof(FolderProto.FolderModifyStatus), modifyResult.Status)
                        ?? modifyResult.Status.ToString();
                    results[item.Index].Message = modifyResult.Message;
                    results[item.Index].Success = modifyResult.Status == FolderProto.FolderModifyStatus.Success;

                    if (!results[item.Index].Success)
                    {
                        continue;
                    }

                    anySuccess = true;
                    PersistKdFolderData(
                        item.Folder.FolderUid,
                        item.Folder.FolderKey,
                        item.FolderData.Data.ToByteArray());
                    if (item.Request.InheritPermissions.HasValue)
                    {
                        PersistKdFolderInheritPermissions(item.Folder.FolderUid, item.Request.InheritPermissions.Value);
                    }

                    if (KeeperNSFFolders.TryGetValue(item.Folder.FolderUid, out var cachedFolder))
                    {
                        cachedFolder.Name = string.IsNullOrEmpty(item.DisplayName)
                            ? KeeperNSFConstants.FolderPlaceholderName
                            : item.DisplayName;
                    }
                }
            }

            if (anySuccess)
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return results;
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

            if (!IsValidAesV2Key(folder.FolderKey))
            {
                throw new VaultException(
                    $"Folder key for \"{folder.FolderUid}\" has invalid length {folder.FolderKey.Length}; expected 32 bytes.");
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

            if (!IsValidAesV2Key(folder.FolderKey))
            {
                throw new VaultException(
                    $"Folder key for \"{folder.FolderUid}\" has invalid length {folder.FolderKey.Length}; expected 32 bytes.");
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

        // Max records per record_update call
        private const int MaxKeeperNSFFolderRecordBatchSize = 500;

        // Shared link/unlink path for batch folder-record APIs.
        private enum KeeperNSFFolderRecordBatchOperation
        {
            Link,
            Unlink,
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<KeeperNSFFolderRecordResult>> LinkKeeperNSFRecordsToFolders(
            IReadOnlyList<KeeperNSFFolderRecordLinkRequest> links)
        {
            if (links == null || links.Count == 0)
            {
                throw new ArgumentException("At least one folder-record link is required.", nameof(links));
            }

            for (var i = 0; i < links.Count; i++)
            {
                if (links[i] == null)
                {
                    throw new ArgumentException($"Link at index {i} is null.", nameof(links));
                }
            }

            var items = links
                .Select(l => (FolderUid: l.FolderUid, RecordUid: l.RecordUid))
                .ToList();
            var results = await ExecuteKeeperNSFFolderRecordBatchAsync(
                items, KeeperNSFFolderRecordBatchOperation.Link).ConfigureAwait(false);
            if (results.Any(r => r.Success))
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return results;
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<KeeperNSFFolderRecordResult>> UnlinkKeeperNSFRecordsFromFolders(
            IReadOnlyList<KeeperNSFFolderRecordUnlinkRequest> unlinks)
        {
            if (unlinks == null || unlinks.Count == 0)
            {
                throw new ArgumentException("At least one folder-record unlink is required.", nameof(unlinks));
            }

            for (var i = 0; i < unlinks.Count; i++)
            {
                if (unlinks[i] == null)
                {
                    throw new ArgumentException($"Unlink at index {i} is null.", nameof(unlinks));
                }
            }

            var items = unlinks
                .Select(u => (FolderUid: u.FolderUid, RecordUid: u.RecordUid))
                .ToList();
            var results = await ExecuteKeeperNSFFolderRecordBatchAsync(
                items, KeeperNSFFolderRecordBatchOperation.Unlink).ConfigureAwait(false);
            if (results.Any(r => r.Success))
            {
                await ScheduleSyncDown(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
            }

            return results;
        }

        // Resolves folders/records, checks add/remove permission, then posts record_update in 500-record chunks per folder.
        private async Task<IReadOnlyList<KeeperNSFFolderRecordResult>> ExecuteKeeperNSFFolderRecordBatchAsync(
            IReadOnlyList<(string FolderUid, string RecordUid)> items,
            KeeperNSFFolderRecordBatchOperation operation)
        {
            var results = new KeeperNSFFolderRecordResult[items.Count];
            var folderRefs = items
                .Select(i => i.FolderUid?.Trim() ?? string.Empty)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var resolvedFolders = new Dictionary<string, FolderNode>(StringComparer.Ordinal);
            var folderResolveErrors = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var folderRef in folderRefs)
            {
                var resolveKey = string.IsNullOrEmpty(folderRef) ? "/" : folderRef;
                if (!TryResolveKeeperNSFFolder(resolveKey, out var folder))
                {
                    folderResolveErrors[folderRef] = $"Keeper NSF folder \"{resolveKey}\" was not found.";
                    continue;
                }

                resolvedFolders[folderRef] = folder;
            }

            var permissionDenied = operation == KeeperNSFFolderRecordBatchOperation.Unlink
                ? await KeeperNSFAccessHelpers.EvaluateKeeperNSFFolderRemovePermissionsAsync(
                    this,
                    resolvedFolders.Values.Select(f => f.FolderUid ?? string.Empty)).ConfigureAwait(false)
                : await KeeperNSFAccessHelpers.EvaluateKeeperNSFFolderAddPermissionsAsync(
                    this,
                    resolvedFolders.Values.Select(f => f.FolderUid ?? string.Empty)).ConfigureAwait(false);

            var preparedByFolder =
                new Dictionary<string, List<(int Index, string RecordUid, FolderProto.RecordMetadata Metadata)>>(
                    StringComparer.Ordinal);
            var seen = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < items.Count; i++)
            {
                var folderRef = items[i].FolderUid?.Trim() ?? string.Empty;
                var recordRef = items[i].RecordUid?.Trim();

                results[i] = new KeeperNSFFolderRecordResult
                {
                    FolderUid = folderRef,
                    RecordUid = recordRef,
                    Success = false,
                };

                if (string.IsNullOrEmpty(recordRef))
                {
                    results[i].Status = "invalid";
                    results[i].Message = "Record UID cannot be empty.";
                    continue;
                }

                if (folderResolveErrors.TryGetValue(folderRef, out var folderError))
                {
                    results[i].Status = "not_found";
                    results[i].Message = folderError;
                    continue;
                }

                if (!resolvedFolders.TryGetValue(folderRef, out var folder))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF folder \"{(string.IsNullOrEmpty(folderRef) ? "/" : folderRef)}\" was not found.";
                    continue;
                }

                results[i].FolderUid = folder.FolderUid ?? string.Empty;
                var folderPermKey = folder.FolderUid ?? string.Empty;
                if (permissionDenied.TryGetValue(folderPermKey, out var denyMessage))
                {
                    results[i].Status = "access_denied";
                    results[i].Message = denyMessage;
                    continue;
                }

                if (!TryResolveKeeperNSFRecord(recordRef, out var record))
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Keeper NSF record \"{recordRef}\" was not found.";
                    continue;
                }

                results[i].RecordUid = record.RecordUid;
                var apiFolderUid = GetKeeperNSFApiFolderUid(folder);
                var dupKey = $"{apiFolderUid}|{record.RecordUid}|{operation}";
                if (!seen.Add(dupKey))
                {
                    results[i].Status = "duplicate";
                    results[i].Message =
                        $"Duplicate {operation.ToString().ToLowerInvariant()} for record '{record.RecordUid}' and folder '{apiFolderUid}'.";
                    continue;
                }

                var alreadyLinked = IsRecordLinkedToKeeperNSFFolder(record.RecordUid, apiFolderUid);
                if (operation == KeeperNSFFolderRecordBatchOperation.Link && alreadyLinked)
                {
                    results[i].Status = "already_exists";
                    results[i].Message = $"Record \"{record.RecordUid}\" is already linked to this folder.";
                    continue;
                }

                if (operation == KeeperNSFFolderRecordBatchOperation.Unlink && !alreadyLinked)
                {
                    results[i].Status = "not_found";
                    results[i].Message = $"Record \"{record.RecordUid}\" is not linked to this folder.";
                    continue;
                }

                FolderProto.RecordMetadata metadata;
                if (operation == KeeperNSFFolderRecordBatchOperation.Unlink)
                {
                    metadata = new FolderProto.RecordMetadata
                    {
                        RecordUid = ByteString.CopyFrom(record.RecordUid.Base64UrlDecode()),
                        EncryptedRecordKey = ByteString.Empty,
                        EncryptedRecordKeyType = FolderProto.EncryptedKeyType.NoKey,
                    };
                }
                else
                {
                    if (folder.FolderKey == null || folder.FolderKey.Length == 0)
                    {
                        results[i].Status = "missing_key";
                        results[i].Message = $"Folder key is not available for \"{folder.FolderUid}\".";
                        continue;
                    }

                    if (!IsValidAesV2Key(folder.FolderKey))
                    {
                        results[i].Status = "invalid_key";
                        results[i].Message =
                            $"Folder key for \"{folder.FolderUid}\" has invalid length {folder.FolderKey.Length}; expected 32 bytes.";
                        continue;
                    }

                    if (!TryGetKeeperNSFRecordKey(record.RecordUid, out var recordKey))
                    {
                        results[i].Status = "missing_key";
                        results[i].Message =
                            $"Record key is not available for \"{record.RecordUid}\". Try running Sync-Keeper first.";
                        continue;
                    }

                    if (!TryGetKeeperNSFRecordKeyType(record.RecordUid, out var recordKeyType))
                    {
                        results[i].Status = "missing_key";
                        results[i].Message =
                            $"Record key type is not available for \"{record.RecordUid}\". Try running Sync-Keeper first.";
                        continue;
                    }

                    try
                    {
                        metadata = BuildKeeperNSFRecordMetadata(
                            record.RecordUid, recordKey, recordKeyType, folder.FolderKey);
                    }
                    catch (Exception ex)
                    {
                        results[i].Status = "prepare_failed";
                        results[i].Message = ex.Message;
                        continue;
                    }
                }

                var groupKey = apiFolderUid ?? string.Empty;
                if (!preparedByFolder.TryGetValue(groupKey, out var list))
                {
                    list = new List<(int Index, string RecordUid, FolderProto.RecordMetadata Metadata)>();
                    preparedByFolder[groupKey] = list;
                }

                list.Add((i, record.RecordUid, metadata));
            }

            foreach (var pair in preparedByFolder)
            {
                var apiFolderUid = pair.Key;
                var prepared = pair.Value;
                for (var offset = 0; offset < prepared.Count; offset += MaxKeeperNSFFolderRecordBatchSize)
                {
                    var chunk = prepared.Skip(offset).Take(MaxKeeperNSFFolderRecordBatchSize).ToList();
                    var request = new FolderProto.FolderRecordUpdateRequest
                    {
                        FolderUid = string.IsNullOrEmpty(apiFolderUid)
                            ? ByteString.Empty
                            : ByteString.CopyFrom(apiFolderUid.Base64UrlDecode()),
                    };

                    foreach (var item in chunk)
                    {
                        if (operation == KeeperNSFFolderRecordBatchOperation.Link)
                        {
                            request.AddRecords.Add(item.Metadata);
                        }
                        else
                        {
                            request.RemoveRecords.Add(item.Metadata);
                        }
                    }

                    FolderProto.FolderRecordUpdateResponse response;
                    try
                    {
                        response = await Auth
                            .ExecuteAuthRest<FolderProto.FolderRecordUpdateRequest, FolderProto.FolderRecordUpdateResponse>(
                                "vault/folders/v3/record_update", request)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        foreach (var item in chunk)
                        {
                            results[item.Index].Status = "request_failed";
                            results[item.Index].Message = ex.Message;
                        }

                        continue;
                    }

                    var statusByRecordUid = new Dictionary<string, FolderProto.FolderRecordUpdateResult>(StringComparer.Ordinal);
                    var serverResults = response?.FolderRecordUpdateResult;
                    if (serverResults != null)
                    {
                        foreach (var status in serverResults)
                        {
                            if (status?.RecordUid == null || status.RecordUid.IsEmpty)
                            {
                                continue;
                            }

                            statusByRecordUid[CryptoUtils.Base64UrlEncode(status.RecordUid.ToByteArray())] = status;
                        }
                    }

                    for (var j = 0; j < chunk.Count; j++)
                    {
                        var item = chunk[j];
                        if (!statusByRecordUid.TryGetValue(item.RecordUid, out var modifyResult))
                        {
                            // Positional fallback only when every server result lacks a usable UID
                            // and counts align — otherwise risk attributing another record's status.
                            if (serverResults != null
                                && serverResults.Count == chunk.Count
                                && statusByRecordUid.Count == 0
                                && j < serverResults.Count
                                && (serverResults[j]?.RecordUid == null || serverResults[j].RecordUid.IsEmpty))
                            {
                                modifyResult = serverResults[j];
                            }
                        }

                        if (modifyResult == null)
                        {
                            results[item.Index].Status = "missing";
                            results[item.Index].Message = "Server returned no status for this folder-record entry.";
                            continue;
                        }

                        results[item.Index].Status = Enum.GetName(typeof(FolderProto.FolderModifyStatus), modifyResult.Status)
                            ?? modifyResult.Status.ToString();
                        results[item.Index].Message = modifyResult.Message;
                        results[item.Index].Success = modifyResult.Status == FolderProto.FolderModifyStatus.Success;
                    }
                }
            }

            return results;
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

        // One transfer call for all prepared records; falls back to share when already_shared.
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

        // Max records per remove_record preview/confirm pair.
        private const int MaxKeeperNSFRecordRemovalBatchSize = 500;

        // Splits large remove lists into chunks; merges preview responses and aggregates chunk outcomes.
        private async Task<KeeperNSFRemoveResult> ExecuteKeeperNSFRecordRemovalAsync(
            IReadOnlyList<KeeperNSFRecordRemoval> removals, bool dryRun)
        {
            if (removals == null || removals.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFRecords), "removals", "", "at least one record required");
            }

            var validRemovals = removals
                .Where(r => r != null && !string.IsNullOrEmpty(r.RecordUid))
                .ToList();
            if (validRemovals.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFRecords), "removals", "", "at least one record required");
            }

            var mergedPreview = new RemoveResponse();
            var confirmedChunkCount = 0;
            var failedChunkCount = 0;
            var chunkErrors = new List<string>();
            long? earliestExpiry = null;

            for (var offset = 0; offset < validRemovals.Count; offset += MaxKeeperNSFRecordRemovalBatchSize)
            {
                var chunk = validRemovals.Skip(offset).Take(MaxKeeperNSFRecordRemovalBatchSize).ToList();
                try
                {
                    var chunkResult = await ExecuteKeeperNSFRecordRemovalChunkAsync(chunk, dryRun).ConfigureAwait(false);
                    MergeRemovePreviewResponse(mergedPreview, chunkResult.PreviewResponse);

                    if (chunkResult.TokenExpiresAt.HasValue)
                    {
                        earliestExpiry = earliestExpiry.HasValue
                            ? Math.Min(earliestExpiry.Value, chunkResult.TokenExpiresAt.Value)
                            : chunkResult.TokenExpiresAt;
                    }

                    if (dryRun)
                    {
                        continue;
                    }

                    if (chunkResult.Confirmed)
                    {
                        confirmedChunkCount++;
                    }
                    else
                    {
                        failedChunkCount++;
                        chunkErrors.Add(
                            $"Chunk at offset {offset} ({chunk.Count} records): confirmation did not complete.");
                    }
                }
                catch (Exception ex)
                {
                    failedChunkCount++;
                    chunkErrors.Add($"Chunk at offset {offset} ({chunk.Count} records): {ex.Message}");
                }
            }

            return new KeeperNSFRemoveResult
            {
                PreviewResponse = mergedPreview,
                Confirmed = !dryRun && failedChunkCount == 0 && confirmedChunkCount > 0,
                ConfirmedChunkCount = confirmedChunkCount,
                FailedChunkCount = failedChunkCount,
                ChunkErrors = chunkErrors,
                TokenExpiresAt = earliestExpiry,
            };
        }

        // Single-chunk preview; auto-confirms when dryRun is false and the server returns a token.
        private async Task<KeeperNSFRemoveResult> ExecuteKeeperNSFRecordRemovalChunkAsync(
            IReadOnlyList<KeeperNSFRecordRemoval> removals, bool dryRun)
        {
            var previewRequest = BuildRemoveRecordRequest(removals, RemoveAction.Preview);
            if (previewRequest.Records.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFRecords), "removals", "", "no valid record UIDs");
            }

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

        // Max folders per remove_folder preview/confirm pair.
        private const int MaxKeeperNSFFolderRemovalBatchSize = 100;

        // Chunks folder removals; stores per-chunk tokens + a fingerprint for ConfirmKeeperNSFFolders.
        private async Task<KeeperNSFRemoveResult> ExecuteKeeperNSFFolderRemovalAsync(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, bool dryRun)
        {
            var validated = ValidateKeeperNSFFolderRemovals(removals);
            var fingerprint = BuildFolderRemovalPreviewFingerprint(
                validated, MaxKeeperNSFFolderRemovalBatchSize);

            var mergedPreview = new RemoveResponse();
            var confirmedChunkCount = 0;
            var failedChunkCount = 0;
            var chunkErrors = new List<string>();
            var chunkTokens = new List<byte[]>();
            long? earliestExpiry = null;

            for (var offset = 0; offset < validated.Count; offset += MaxKeeperNSFFolderRemovalBatchSize)
            {
                var chunk = validated.Skip(offset).Take(MaxKeeperNSFFolderRemovalBatchSize).ToList();
                try
                {
                    var chunkResult = await ExecuteKeeperNSFFolderRemovalChunkAsync(chunk, dryRun)
                        .ConfigureAwait(false);
                    MergeRemovePreviewResponse(mergedPreview, chunkResult.PreviewResponse);
                    chunkTokens.Add(ExtractConfirmationTokenBytes(chunkResult.PreviewResponse));

                    if (chunkResult.TokenExpiresAt.HasValue)
                    {
                        earliestExpiry = earliestExpiry.HasValue
                            ? Math.Min(earliestExpiry.Value, chunkResult.TokenExpiresAt.Value)
                            : chunkResult.TokenExpiresAt;
                    }

                    if (dryRun)
                    {
                        continue;
                    }

                    if (chunkResult.Confirmed)
                    {
                        confirmedChunkCount++;
                    }
                    else
                    {
                        failedChunkCount++;
                        chunkErrors.Add(
                            $"Chunk at offset {offset} ({chunk.Count} folders): confirmation did not complete.");
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failedChunkCount++;
                    chunkErrors.Add($"Chunk at offset {offset} ({chunk.Count} folders): {ex.Message}");
                    if (dryRun)
                    {
                        chunkTokens.Add(Array.Empty<byte>());
                    }
                }
            }

            if (dryRun && failedChunkCount > 0)
            {
                throw new VaultException(
                    $"Folder remove preview failed for {failedChunkCount} chunk(s): {string.Join("; ", chunkErrors)}");
            }

            return new KeeperNSFRemoveResult
            {
                PreviewResponse = mergedPreview,
                Confirmed = !dryRun && failedChunkCount == 0 && confirmedChunkCount > 0,
                ConfirmedChunkCount = confirmedChunkCount,
                FailedChunkCount = failedChunkCount,
                ChunkErrors = chunkErrors,
                TokenExpiresAt = earliestExpiry,
                ChunkConfirmationTokens = chunkTokens,
                PreviewRemovalsFingerprint = fingerprint,
                PreviewItemCount = validated.Count,
                PreviewChunkSize = MaxKeeperNSFFolderRemovalBatchSize,
            };
        }

        // Confirms each preview chunk. Removals must match the dry-run preview (order included).
        private async Task<KeeperNSFRemoveResult> ConfirmKeeperNSFFolderRemovalAsync(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, KeeperNSFRemoveResult previewResult)
        {
            var validated = ValidateKeeperNSFFolderRemovals(removals);
            if (previewResult == null)
            {
                throw new KeeperInvalidParameter(
                    nameof(ConfirmKeeperNSFFolders),
                    "previewResult",
                    "",
                    "preview result is required; run RemoveKeeperNSFFolders with dryRun: true first");
            }

            var chunkSize = previewResult.PreviewChunkSize > 0
                ? previewResult.PreviewChunkSize
                : MaxKeeperNSFFolderRemovalBatchSize;
            var expectedFingerprint = BuildFolderRemovalPreviewFingerprint(validated, chunkSize);
            if (string.IsNullOrEmpty(previewResult.PreviewRemovalsFingerprint))
            {
                throw new KeeperInvalidParameter(
                    nameof(ConfirmKeeperNSFFolders),
                    "previewResult",
                    "",
                    "preview result is missing the removals fingerprint; re-run RemoveKeeperNSFFolders with dryRun: true");
            }

            if (!string.Equals(previewResult.PreviewRemovalsFingerprint, expectedFingerprint, StringComparison.Ordinal))
            {
                throw new KeeperInvalidParameter(
                    nameof(ConfirmKeeperNSFFolders),
                    "removals",
                    "",
                    "removals list does not match the dry-run preview (UID, operation, or order changed). "
                    + "Pass the same list used for preview, or re-run preview.");
            }

            if (previewResult.PreviewItemCount > 0 && previewResult.PreviewItemCount != validated.Count)
            {
                throw new KeeperInvalidParameter(
                    nameof(ConfirmKeeperNSFFolders),
                    "removals",
                    "",
                    $"removals count ({validated.Count}) does not match preview count ({previewResult.PreviewItemCount}); re-run preview");
            }

            var tokens = previewResult.ChunkConfirmationTokens;
            if (tokens == null || tokens.Count == 0)
            {
                throw new KeeperInvalidParameter(
                    nameof(ConfirmKeeperNSFFolders),
                    "previewResult",
                    "",
                    "preview result has no confirmation tokens; run RemoveKeeperNSFFolders with dryRun: true first");
            }

            var expectedChunks = (validated.Count + chunkSize - 1) / chunkSize;
            if (tokens.Count != expectedChunks)
            {
                throw new KeeperInvalidParameter(
                    nameof(ConfirmKeeperNSFFolders),
                    "previewResult",
                    "",
                    $"preview token count ({tokens.Count}) does not match folder chunk count ({expectedChunks}); re-run preview with the same removals list");
            }

            var mergedPreview = previewResult.PreviewResponse ?? new RemoveResponse();
            var confirmedChunkCount = 0;
            var failedChunkCount = 0;
            var chunkErrors = new List<string>();
            var chunkIndex = 0;

            for (var offset = 0; offset < validated.Count; offset += chunkSize)
            {
                var chunk = validated.Skip(offset).Take(chunkSize).ToList();
                var tokenBytes = tokens[chunkIndex++];
                try
                {
                    if (tokenBytes == null || tokenBytes.Length == 0)
                    {
                        throw new VaultException(
                            $"Chunk at offset {offset} has an empty confirmation token; re-run preview.");
                    }

                    await ConfirmKeeperNSFFolderRemovalChunkAsync(chunk, ByteString.CopyFrom(tokenBytes))
                        .ConfigureAwait(false);
                    confirmedChunkCount++;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failedChunkCount++;
                    chunkErrors.Add($"Chunk at offset {offset} ({chunk.Count} folders): {ex.Message}");
                }
            }

            return new KeeperNSFRemoveResult
            {
                PreviewResponse = mergedPreview,
                Confirmed = failedChunkCount == 0 && confirmedChunkCount > 0,
                ConfirmedChunkCount = confirmedChunkCount,
                FailedChunkCount = failedChunkCount,
                ChunkErrors = chunkErrors,
                TokenExpiresAt = previewResult.TokenExpiresAt,
                ChunkConfirmationTokens = tokens.ToList(),
                PreviewRemovalsFingerprint = previewResult.PreviewRemovalsFingerprint,
                PreviewItemCount = previewResult.PreviewItemCount,
                PreviewChunkSize = chunkSize,
            };
        }

        // Posts one remove_folder confirm for a single chunk and its preview token.
        private async Task ConfirmKeeperNSFFolderRemovalChunkAsync(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, ByteString confirmationToken)
        {
            var foldersRequest = BuildRemoveFolderRequest(removals, RemoveAction.Confirm);
            var confirmRequest = new RemoveFolderRequest
            {
                Action = RemoveAction.Confirm,
                ConfirmationToken = confirmationToken,
            };
            confirmRequest.Folders.Add(foldersRequest.Folders);

            var confirmResponse = await Auth.ExecuteAuthRest<RemoveFolderRequest, RemoveResponse>(
                "vault/folders/v3/remove_folder", confirmRequest).ConfigureAwait(false);

            ValidateRemoveResponse(confirmResponse, true);
        }

        // Single-chunk folder preview; auto-confirms when dryRun is false and the server returns a token.
        private async Task<KeeperNSFRemoveResult> ExecuteKeeperNSFFolderRemovalChunkAsync(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, bool dryRun)
        {
            var previewRequest = BuildRemoveFolderRequest(removals, RemoveAction.Preview);
            if (previewRequest.Folders.Count == 0)
            {
                throw new KeeperInvalidParameter(nameof(RemoveKeeperNSFFolders), "removals", "", "no valid folder UIDs");
            }

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

        // Pulls the preview token bytes for ChunkConfirmationTokens (empty when preview had no token).
        private static byte[] ExtractConfirmationTokenBytes(RemoveResponse previewResponse)
        {
            if (previewResponse?.ConfirmationToken == null || previewResponse.ConfirmationToken.IsEmpty)
            {
                return Array.Empty<byte>();
            }

            return previewResponse.ConfirmationToken.ToByteArray();
        }

        // Hash of chunk size + ordered uid|operation lines so confirm can reject reordered/changed lists.
        private static string BuildFolderRemovalPreviewFingerprint(
            IReadOnlyList<KeeperNSFFolderRemoval> validated, int chunkSize)
        {
            var sb = new StringBuilder(32 + (validated?.Count ?? 0) * 48);
            sb.Append("chunk=").Append(chunkSize).Append('\n');
            if (validated != null)
            {
                for (var i = 0; i < validated.Count; i++)
                {
                    var removal = validated[i];
                    sb.Append(removal?.FolderUid ?? string.Empty)
                        .Append('|')
                        .Append((int)(removal?.Operation ?? 0))
                        .Append('\n');
                }
            }

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                return Convert.ToBase64String(hash);
            }
        }

        // Normalizes folder UIDs and rejects duplicates before batch remove/confirm.
        private static IReadOnlyList<KeeperNSFFolderRemoval> ValidateKeeperNSFFolderRemovals(
            IReadOnlyList<KeeperNSFFolderRemoval> removals)
        {
            if (removals == null || removals.Count == 0)
            {
                throw new KeeperInvalidParameter(
                    nameof(RemoveKeeperNSFFolders), "removals", "", "folders must not be empty");
            }

            var validated = new List<KeeperNSFFolderRemoval>(removals.Count);
            var seenUids = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < removals.Count; i++)
            {
                var removal = removals[i];
                if (removal == null)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "removals", i.ToString(),
                        $"folder removal at index {i} is null");
                }

                var folderUid = removal.FolderUid?.Trim();
                if (string.IsNullOrEmpty(folderUid))
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "folder_uid", i.ToString(),
                        $"folder removal at index {i} requires a valid folder_uid");
                }

                byte[] folderUidBytes;
                try
                {
                    folderUidBytes = folderUid.Base64UrlDecode();
                }
                catch (Exception)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "folder_uid", folderUid,
                        $"folder removal at index {i} has an invalid folder_uid");
                }

                if (folderUidBytes == null || folderUidBytes.Length == 0)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "folder_uid", folderUid,
                        $"folder removal at index {i} has an invalid folder_uid");
                }

                if (!seenUids.Add(folderUid))
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "folder_uid", folderUid,
                        $"duplicate folder_uid '{folderUid}' in the same request");
                }

                if (!Enum.IsDefined(typeof(KeeperNSFFolderRemoveOperation), removal.Operation))
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "operation_type", removal.Operation.ToString(),
                        $"folder removal at index {i} has an unsupported operation_type");
                }

                validated.Add(new KeeperNSFFolderRemoval
                {
                    FolderUid = folderUid,
                    Operation = removal.Operation,
                });
            }

            return validated;
        }

        // Combines chunk preview results into one response for callers (results, errors, earliest expiry).
        private static void MergeRemovePreviewResponse(RemoveResponse target, RemoveResponse source)
        {
            if (target == null || source == null)
            {
                return;
            }

            target.Results.AddRange(source.Results);

            if (!string.IsNullOrEmpty(source.ErrorMessage))
            {
                target.ErrorMessage = string.IsNullOrEmpty(target.ErrorMessage)
                    ? source.ErrorMessage
                    : $"{target.ErrorMessage}; {source.ErrorMessage}";
            }

            if ((target.ConfirmationToken == null || target.ConfirmationToken.IsEmpty)
                && source.ConfirmationToken != null
                && !source.ConfirmationToken.IsEmpty)
            {
                target.ConfirmationToken = source.ConfirmationToken;
                target.TokenExpiresAt = source.TokenExpiresAt;
            }
            else if (target.TokenExpiresAt == 0 && source.TokenExpiresAt > 0)
            {
                target.TokenExpiresAt = source.TokenExpiresAt;
            }
            else if (target.TokenExpiresAt > 0 && source.TokenExpiresAt > 0)
            {
                target.TokenExpiresAt = Math.Min(target.TokenExpiresAt, source.TokenExpiresAt);
            }
        }

        // Builds remove_record protobuf for one chunk; skips malformed UIDs with a trace warning.
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

        // Builds remove_folder protobuf for one chunk (preview or confirm).
        private static RemoveFolderRequest BuildRemoveFolderRequest(
            IReadOnlyList<KeeperNSFFolderRemoval> removals, RemoveAction action)
        {
            if (action != RemoveAction.Preview && action != RemoveAction.Confirm)
            {
                throw new KeeperInvalidParameter(
                    nameof(RemoveKeeperNSFFolders), "action", action.ToString(),
                    "action must be PREVIEW or CONFIRM");
            }

            var request = new RemoveFolderRequest { Action = action };
            foreach (var removal in removals)
            {
                var folderUidBytes = removal.FolderUid.Base64UrlDecode();
                if (folderUidBytes == null || folderUidBytes.Length == 0)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "folder_uid", removal.FolderUid ?? "",
                        "folder_uid is missing or not valid base64url");
                }

                var operationType = MapFolderOperation(removal.Operation);
                if (operationType == FolderOperationType.FolderOperationUnknown)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "operation_type", removal.Operation.ToString(),
                        "operation_type must not be FOLDER_OPERATION_UNKNOWN");
                }

                if (operationType == FolderOperationType.FolderMoveToOwnerTrash)
                {
                    throw new KeeperInvalidParameter(
                        nameof(RemoveKeeperNSFFolders), "operation_type", "FOLDER_MOVE_TO_OWNER_TRASH",
                        "FOLDER_MOVE_TO_OWNER_TRASH is not supported yet");
                }

                request.Folders.Add(new FolderRemoval
                {
                    FolderUid = ByteString.CopyFrom(folderUidBytes),
                    OperationType = operationType,
                });
            }

            return request;
        }

        private static bool IsValidAesV2Key(byte[] key)
        {
            // Keeper folder keys are AES-256 (32 bytes), matching CryptoUtils.GenerateEncryptionKey().
            return key != null && key.Length == 32;
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

    internal static class KeeperNSFConstants
    {
        public const string FolderPlaceholderName = "(Keeper NSF Folder)";
        public const string KeeperDriveRootFolderUid = "AAAAAAAAAAAAAAAAAPmtNA";
    }
}
