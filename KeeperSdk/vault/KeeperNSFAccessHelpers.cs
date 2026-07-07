using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using FolderProto = Folder;
using RecordDetailsProto = Record.V3.Details;

namespace KeeperSecurity.Vault
{
    internal sealed class KeeperNSFAccessorInfo
    {
        public string AccessTypeUid { get; set; }
        public int AccessType { get; set; }
        public bool Owner { get; set; }
        public bool Inherited { get; set; }
        public bool DeniedAccess { get; set; }
        public string Username { get; set; }
        public Dictionary<string, bool> Permissions { get; set; }
        public bool CanUpdateAccess { get; set; }
        public bool CanChangeOwnership { get; set; }
    }

    /// <summary>
    /// Shared NSF folder/record access loading, permission blobs, and client-side permission gates.
    /// </summary>
    internal static class KeeperNSFAccessHelpers
    {
        private static readonly IReadOnlyDictionary<string, string> PermissionKeyAliases = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["can_update_access"] = "canUpdateAccess",
            ["can_update_setting"] = "canUpdateSetting",
            ["can_delete"] = "canDelete",
            ["can_change_ownership"] = "canChangeOwnership",
            ["can_edit"] = "canEdit",
            ["can_view"] = "canView",
            ["can_list_access"] = "canListAccess",
            ["can_add"] = "canAdd",
            ["can_remove"] = "canRemove",
            ["can_edit_records"] = "canEditRecords",
            ["can_view_records"] = "canViewRecords",
            ["can_approve_access"] = "canApproveAccess",
            ["can_request_access"] = "canRequestAccess",
            ["can_list_records"] = "canListRecords",
            ["can_list_folders"] = "canListFolders",
        };

        internal static string SerializeFolderPermissions(FolderProto.FolderPermissions permissions)
        {
            if (permissions == null)
            {
                return string.Empty;
            }

            var payload = FolderPermissionsToCamelCaseDictionary(permissions);
            return Encoding.UTF8.GetString(JsonUtils.DumpJson(payload, indent: false));
        }

        /// <summary>
        /// Fetch folder accessors for a single folder UID. This calls the batch overload.
        /// </summary>
        internal static Task<IReadOnlyList<FolderProto.FolderAccessData>> FetchFolderAccessDataAsync(
            VaultOnline vault,
            string folderUid)
        {
            return FetchFolderAccessDataAsync(vault, new[] { folderUid }, pageSize: 100);
        }

        /// <summary>
        /// Fetch folder accessors for one or more folder UIDs.
        /// Supports batching up to 100 folder UIDs per request.
        /// </summary>
        internal static async Task<IReadOnlyList<FolderProto.FolderAccessData>> FetchFolderAccessDataAsync(
            VaultOnline vault,
            IEnumerable<string> folderUids,
            int pageSize = 100)
        {
            if (vault == null) throw new ArgumentNullException(nameof(vault));
            if (folderUids == null) throw new ArgumentNullException(nameof(folderUids));

            var allAccessors = new List<FolderProto.FolderAccessData>();

            if (pageSize <= 0) pageSize = 100;
            if (pageSize > 1000) pageSize = 1000;

            var foldersList = folderUids.Where(f => !string.IsNullOrEmpty(f)).ToList();
            const int MaxFoldersPerRequest = 100;
            for (int i = 0; i < foldersList.Count; i += MaxFoldersPerRequest)
            {
                var batch = foldersList.Skip(i).Take(MaxFoldersPerRequest).ToList();
                FolderProto.V3.ContinuationToken continuationToken = null;

                do
                {
                    var rq = new FolderProto.V3.GetFolderAccessRequest();
                    foreach (var f in batch)
                    {
                        rq.FolderUid.Add(ByteString.CopyFrom(f.Base64UrlDecode()));
                    }

                    if (continuationToken != null)
                    {
                        rq.ContinuationToken = continuationToken;
                    }

                    rq.PageSize = pageSize;

                    var rs = await vault.Auth.ExecuteAuthRest<FolderProto.V3.GetFolderAccessRequest, FolderProto.V3.GetFolderAccessResponse>(
                        "vault/folders/v3/access", rq).ConfigureAwait(false);

                    if (rs == null)
                    {
                        throw new VaultException("GetFolderAccessResponse was null from server.");
                    }

                    if (rs.HasMore && rs.ContinuationToken == null)
                    {
                        throw new VaultException("Server indicated more results but did not provide a continuation token.");
                    }

                    if (rs.FolderAccessResults != null)
                    {
                        foreach (var result in rs.FolderAccessResults)
                        {
                            if (result == null)
                            {
                                continue;
                            }

                            if (result.Error != null)
                            {
                                System.Diagnostics.Trace.TraceWarning($"GetFolderAccessResult error: {result.Error}");
                                continue;
                            }

                            if (result.Accessors != null && result.Accessors.Count > 0)
                            {
                                allAccessors.AddRange(result.Accessors);
                            }
                        }
                    }

                    continuationToken = rs.HasMore ? rs.ContinuationToken : null;
                }
                while (continuationToken != null);
            }

            return allAccessors;
        }

        internal static async Task<RecordDetailsProto.RecordAccessResponse> FetchRecordAccessDetailsAsync(
            VaultOnline vault,
            IEnumerable<string> recordUids)
        {
            var rq = new RecordDetailsProto.RecordAccessRequest();
            foreach (var recordUid in recordUids)
            {
                rq.RecordUids.Add(ByteString.CopyFrom(recordUid.Base64UrlDecode()));
            }

            return await vault.Auth.ExecuteAuthRest<RecordDetailsProto.RecordAccessRequest, RecordDetailsProto.RecordAccessResponse>(
                "vault/records/v3/details/access", rq).ConfigureAwait(false);
        }

        internal static async Task RequireKeeperNSFFolderSharePermissionAsync(VaultOnline vault, string folderUid)
        {
            await RequireKeeperNSFFolderPermissionAsync(
                vault,
                folderUid,
                "can_update_access",
                "You do not have permission to share this folder.").ConfigureAwait(false);
        }

        internal static async Task RequireKeeperNSFFolderAddPermissionAsync(VaultOnline vault, string folderUid)
        {
            await RequireKeeperNSFFolderPermissionAsync(
                vault,
                folderUid,
                "can_add",
                "You do not have permission to add content to this folder.").ConfigureAwait(false);
        }

        internal static async Task RequireKeeperNSFRecordSharePermissionAsync(VaultOnline vault, string recordUid)
        {
            await RequireKeeperNSFRecordPermissionAsync(
                vault,
                recordUid,
                "can_update_access",
                "You do not have permission to share this record.").ConfigureAwait(false);
        }

        internal static async Task RequireKeeperNSFRecordOwnershipPermissionAsync(VaultOnline vault, string recordUid)
        {
            await RequireKeeperNSFRecordPermissionAsync(
                vault,
                recordUid,
                "can_change_ownership",
                "You do not have permission to transfer ownership of this record.").ConfigureAwait(false);
        }

        internal static async Task RequireKeeperNSFFolderPermissionAsync(
            VaultOnline vault,
            string folderUid,
            string permissionKey,
            string errorMessage)
        {
            if (IsKeeperNSFFolderOwnerUser(vault, folderUid))
            {
                return;
            }

            var accessors = await CollectKeeperNSFFolderAccessorsAsync(vault, folderUid).ConfigureAwait(false);
            if (accessors.Count == 0)
            {
                throw new VaultException($"No accessors data found for folder {folderUid}.");
            }

            var accountUidB64 = GetCurrentUserAccountUidB64(vault);
            var (ownerUsername, ownerAccountUid) = GetFolderOwnerInfo(vault, folderUid);
            var foundCurrentUser = false;

            foreach (var accessor in accessors)
            {
                if (!IsCurrentUserNsfAccessor(accessor, vault, accountUidB64))
                {
                    continue;
                }

                foundCurrentUser = true;

                if (accessor.DeniedAccess)
                {
                    continue;
                }

                if (accessor.Owner
                    || IsAccessTypeOwner(accessor.AccessType)
                    || IsKeeperNSFFolderAccessorOwner(accessor.AccessTypeUid, accessor.Username, ownerAccountUid, ownerUsername))
                {
                    return;
                }

                if (GetPermissionValue(accessor.Permissions, permissionKey))
                {
                    return;
                }
            }

            if (!foundCurrentUser)
            {
                throw new VaultException($"No accessors data found for folder {folderUid}.");
            }

            throw new VaultException(errorMessage);
        }

        internal static async Task RequireKeeperNSFRecordPermissionAsync(
            VaultOnline vault,
            string recordUid,
            string permissionKey,
            string errorMessage)
        {
            var accessors = await CollectKeeperNSFRecordAccessorsAsync(vault, recordUid).ConfigureAwait(false);
            if (accessors.Count == 0)
            {
                throw new VaultException($"No accessors data found for record {recordUid}.");
            }

            var accountUidB64 = GetCurrentUserAccountUidB64(vault);
            var foundCurrentUser = false;

            foreach (var accessor in accessors)
            {
                if (!IsCurrentUserNsfAccessor(accessor, vault, accountUidB64))
                {
                    continue;
                }

                foundCurrentUser = true;

                if (accessor.DeniedAccess)
                {
                    continue;
                }

                if (accessor.Owner)
                {
                    return;
                }

                if (GetRecordPermissionValue(accessor, permissionKey))
                {
                    return;
                }
            }

            if (!foundCurrentUser)
            {
                throw new VaultException($"No accessors data found for record {recordUid}.");
            }

            throw new VaultException(errorMessage);
        }

        internal static async Task<IReadOnlyList<KeeperNSFAccessorInfo>> CollectKeeperNSFFolderAccessorsAsync(
            VaultOnline vault,
            string folderUid)
        {
            var accessors = vault.Storage.KdFolderAccesses
                .GetLinksForSubject(folderUid)
                .Select(FromStoredFolderAccess)
                .ToList();

            if (accessors.Count > 0)
            {
                var accountUidB64 = GetCurrentUserAccountUidB64(vault);
                var hasCurrentUserAccessor = accessors.Any(a => IsCurrentUserNsfAccessor(a, vault, accountUidB64));
                if (!hasCurrentUserAccessor || StoredFolderAccessNeedsPermissionRefresh(vault, folderUid, accountUidB64))
                {
                    var fromApi = await FetchFolderAccessorsFromApiAsync(vault, folderUid).ConfigureAwait(false);
                    if (fromApi.Count > 0)
                    {
                        return fromApi;
                    }
                }

                return accessors;
            }

            return await FetchFolderAccessorsFromApiAsync(vault, folderUid).ConfigureAwait(false);
        }

        internal static async Task<IReadOnlyList<KeeperNSFAccessorInfo>> CollectKeeperNSFRecordAccessorsAsync(
            VaultOnline vault,
            string recordUid)
        {
            var accessors = vault.Storage.KdRecordAccesses
                .GetLinksForSubject(recordUid)
                .Select(FromStoredRecordAccess)
                .ToList();

            if (accessors.Count > 0)
            {
                var accountUidB64 = GetCurrentUserAccountUidB64(vault);
                var hasCurrentUserAccessor = accessors.Any(a => IsCurrentUserNsfAccessor(a, vault, accountUidB64));
                if (!hasCurrentUserAccessor)
                {
                    var fromApi = await FetchRecordAccessorsFromApiAsync(vault, recordUid).ConfigureAwait(false);
                    if (fromApi.Count > 0)
                    {
                        return fromApi;
                    }
                }

                return accessors;
            }

            return await FetchRecordAccessorsFromApiAsync(vault, recordUid).ConfigureAwait(false);
        }

        internal static bool IsKeeperNSFFolderOwnerUser(VaultOnline vault, string folderUid)
        {
            var accountUidB64 = GetCurrentUserAccountUidB64(vault);
            var username = vault.Auth?.Username;
            var (ownerUsername, ownerAccountUid) = GetFolderOwnerInfo(vault, folderUid);

            return IsKeeperNSFFolderAccessorOwner(accountUidB64, username, ownerAccountUid, ownerUsername);
        }

        internal static bool IsKeeperNSFFolderAccessorOwner(
            string accessTypeUid,
            string username,
            string ownerAccountUid,
            string ownerUsername)
        {
            if (!string.IsNullOrEmpty(ownerAccountUid)
                && string.Equals(accessTypeUid, ownerAccountUid, StringComparison.Ordinal))
            {
                return true;
            }

            return !string.IsNullOrEmpty(ownerUsername)
                && !string.IsNullOrEmpty(username)
                && string.Equals(username, ownerUsername, StringComparison.OrdinalIgnoreCase);
        }

        private static KeeperNSFAccessorInfo FromStoredFolderAccess(IStorageKdFolderAccess access)
        {
            return new KeeperNSFAccessorInfo
            {
                AccessTypeUid = access.AccessTypeUid,
                AccessType = access.AccessType,
                Inherited = access.Inherited,
                DeniedAccess = access.DeniedAccess,
                Permissions = ParsePermissionsJson(access.PermissionsJson),
            };
        }

        private static KeeperNSFAccessorInfo FromStoredRecordAccess(IStorageKdRecordAccess access)
        {
            return new KeeperNSFAccessorInfo
            {
                AccessTypeUid = access.AccessTypeUid,
                AccessType = access.AccessType,
                Owner = access.Owner,
                Inherited = access.Inherited,
                DeniedAccess = access.DeniedAccess,
                CanUpdateAccess = access.CanUpdateAccess,
                CanChangeOwnership = access.CanChangeOwnership,
            };
        }

        private static async Task<IReadOnlyList<KeeperNSFAccessorInfo>> FetchFolderAccessorsFromApiAsync(
            VaultOnline vault,
            string folderUid)
        {
            var accessors = new List<KeeperNSFAccessorInfo>();
            try
            {
                foreach (var accessor in await FetchFolderAccessDataAsync(vault, folderUid).ConfigureAwait(false))
                {
                    accessors.Add(new KeeperNSFAccessorInfo
                    {
                        AccessTypeUid = accessor.AccessTypeUid.ToByteArray().Base64UrlEncode(),
                        AccessType = (int)accessor.AccessType,
                        Owner = accessor.AccessType == FolderProto.AccessType.AtOwner,
                        Inherited = accessor.Inherited,
                        DeniedAccess = accessor.DeniedAccess,
                        Permissions = FolderPermissionsToLookupDictionary(accessor.Permissions),
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning(
                    $"KeeperNSF: Could not fetch folder access for '{folderUid}': {ex.Message}");
            }

            return accessors;
        }

        private static async Task<IReadOnlyList<KeeperNSFAccessorInfo>> FetchRecordAccessorsFromApiAsync(
            VaultOnline vault,
            string recordUid)
        {
            var accessors = new List<KeeperNSFAccessorInfo>();
            try
            {
                var rs = await FetchRecordAccessDetailsAsync(vault, new[] { recordUid }).ConfigureAwait(false);
                foreach (var row in rs.RecordAccesses)
                {
                    var data = row?.Data;
                    if (data == null)
                    {
                        continue;
                    }

                    accessors.Add(new KeeperNSFAccessorInfo
                    {
                        AccessTypeUid = data.AccessTypeUid.ToByteArray().Base64UrlEncode(),
                        AccessType = (int)data.AccessType,
                        Owner = data.Owner,
                        Inherited = data.Inherited,
                        DeniedAccess = data.DeniedAccess,
                        Username = row.AccessorInfo?.Name,
                        CanUpdateAccess = data.CanUpdateAccess,
                        CanChangeOwnership = data.CanChangeOwnership,
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceWarning(
                    $"KeeperNSF: Could not fetch record access for '{recordUid}': {ex.Message}");
            }

            return accessors;
        }

        private static Dictionary<string, bool> FolderPermissionsToCamelCaseDictionary(
            FolderProto.FolderPermissions permissions)
        {
            return new Dictionary<string, bool>(StringComparer.Ordinal)
            {
                ["canAdd"] = permissions.CanAdd,
                ["canRemove"] = permissions.CanRemove,
                ["canDelete"] = permissions.CanDelete,
                ["canListAccess"] = permissions.CanListAccess,
                ["canUpdateAccess"] = permissions.CanUpdateAccess,
                ["canChangeOwnership"] = permissions.CanChangeOwnership,
                ["canEditRecords"] = permissions.CanEditRecords,
                ["canViewRecords"] = permissions.CanViewRecords,
                ["canApproveAccess"] = permissions.CanApproveAccess,
                ["canRequestAccess"] = permissions.CanRequestAccess,
                ["canUpdateSetting"] = permissions.CanUpdateSetting,
                ["canListRecords"] = permissions.CanListRecords,
                ["canListFolders"] = permissions.CanListFolders,
            };
        }

        private static Dictionary<string, bool> FolderPermissionsToLookupDictionary(
            FolderProto.FolderPermissions permissions)
        {
            if (permissions == null)
            {
                return new Dictionary<string, bool>(StringComparer.Ordinal);
            }

            var lookup = FolderPermissionsToCamelCaseDictionary(permissions);
            lookup["can_add"] = permissions.CanAdd;
            lookup["can_remove"] = permissions.CanRemove;
            lookup["can_delete"] = permissions.CanDelete;
            lookup["can_list_access"] = permissions.CanListAccess;
            lookup["can_update_access"] = permissions.CanUpdateAccess;
            lookup["can_change_ownership"] = permissions.CanChangeOwnership;
            lookup["can_edit_records"] = permissions.CanEditRecords;
            lookup["can_view_records"] = permissions.CanViewRecords;
            lookup["can_approve_access"] = permissions.CanApproveAccess;
            lookup["can_request_access"] = permissions.CanRequestAccess;
            lookup["can_update_setting"] = permissions.CanUpdateSetting;
            lookup["can_list_records"] = permissions.CanListRecords;
            lookup["can_list_folders"] = permissions.CanListFolders;
            return lookup;
        }

        private static Dictionary<string, bool> ParsePermissionsJson(string permissionsJson)
        {
            if (string.IsNullOrEmpty(permissionsJson))
            {
                return new Dictionary<string, bool>(StringComparer.Ordinal);
            }

            try
            {
                var parsed = JsonUtils.ParseJson<Dictionary<string, bool>>(Encoding.UTF8.GetBytes(permissionsJson));
                return parsed ?? new Dictionary<string, bool>(StringComparer.Ordinal);
            }
            catch
            {
                return new Dictionary<string, bool>(StringComparer.Ordinal);
            }
        }

        private static bool GetPermissionValue(Dictionary<string, bool> permissions, string key)
        {
            if (permissions == null || permissions.Count == 0)
            {
                return false;
            }

            if (permissions.TryGetValue(key, out var direct))
            {
                return direct;
            }

            if (PermissionKeyAliases.TryGetValue(key, out var aliasKey) && permissions.TryGetValue(aliasKey, out var aliasValue))
            {
                return aliasValue;
            }

            return false;
        }

        private static bool GetRecordPermissionValue(KeeperNSFAccessorInfo accessor, string key)
        {
            return key switch
            {
                "can_update_access" => accessor.CanUpdateAccess,
                "can_change_ownership" => accessor.CanChangeOwnership,
                _ => GetPermissionValue(accessor.Permissions, key),
            };
        }

        private static bool IsCurrentUserNsfAccessor(
            KeeperNSFAccessorInfo accessor,
            VaultOnline vault,
            string accountUidB64)
        {
            var username = vault.Auth?.Username;
            if (!string.IsNullOrEmpty(accessor.Username)
                && !string.IsNullOrEmpty(username)
                && string.Equals(accessor.Username, username, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return !string.IsNullOrEmpty(accessor.AccessTypeUid)
                && !string.IsNullOrEmpty(accountUidB64)
                && string.Equals(accessor.AccessTypeUid, accountUidB64, StringComparison.Ordinal);
        }

        private static bool IsAccessTypeOwner(int accessType)
        {
            return accessType == (int)FolderProto.AccessType.AtOwner;
        }

        private static bool StoredFolderAccessNeedsPermissionRefresh(
            VaultOnline vault,
            string folderUid,
            string accountUidB64)
        {
            if (string.IsNullOrEmpty(accountUidB64))
            {
                return true;
            }

            foreach (var link in vault.Storage.KdFolderAccesses.GetLinksForSubject(folderUid))
            {
                if (!string.Equals(link.AccessTypeUid, accountUidB64, StringComparison.Ordinal))
                {
                    continue;
                }

                return string.IsNullOrEmpty(link.PermissionsJson);
            }

            return true;
        }

        private static (string OwnerUsername, string OwnerAccountUid) GetFolderOwnerInfo(VaultOnline vault, string folderUid)
        {
            var row = vault.Storage.KdFolders.GetEntity(folderUid);
            if (row == null)
            {
                return (null, null);
            }

            return (row.OwnerUsername, row.OwnerAccountUid);
        }

        private static string GetCurrentUserAccountUidB64(VaultOnline vault)
        {
            var accountUid = vault.Auth?.AuthContext?.AccountUid;
            return accountUid != null && accountUid.Length > 0
                ? accountUid.Base64UrlEncode()
                : string.Empty;
        }
    }
}
