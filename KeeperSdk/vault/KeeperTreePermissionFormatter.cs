using System;
using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Shared permission formatting used by Commander and PowerCommander tree output.
    /// </summary>
    public static class KeeperTreePermissionFormatter
    {
        private const int NsfAccessTypeOwner = 1;
        private const int NsfAccessTypeTeam = 3;
        private const int NsfAccessTypeApplication = 6;
        private const int NsfRoleOwner = 1;
        private const int NsfRoleViewer = 2;
        private const int NsfRoleShareManager = 3;
        private const int NsfRoleContentManager = 4;
        private const int NsfRoleContentShareManager = 5;
        private const int NsfRoleFullManager = 6;

        public static Dictionary<string, object> GetNsfPermissions(VaultOnline vault,
            KeeperNSFSharePermissions shares, string uid, bool record)
        {
            var permissions = record ? shares?.RecordPermissions : shares?.FolderPermissions;
            return GetNsfPermissions(vault, permissions != null && permissions.TryGetValue(uid, out var entries)
                ? entries : Array.Empty<KeeperNSFAccessEntry>());
        }

        public static string FormatNsfPermissionText(VaultOnline vault,
            KeeperNSFSharePermissions shares, string uid, bool record)
        {
            var permissions = record ? shares?.RecordPermissions : shares?.FolderPermissions;
            if (permissions == null || !permissions.TryGetValue(uid, out var entries) || entries == null)
                return string.Empty;

            var users = new List<string>();
            var teams = new List<string>();
            var applications = new List<string>();
            foreach (var entry in entries)
            {
                if (entry == null) continue;
                var accessor = ResolveNsfAccessor(vault, entry);
                if (entry.AccessType != NsfAccessTypeTeam && entry.AccessType != NsfAccessTypeApplication &&
                    string.Equals(accessor, entry.AccessTypeUid, StringComparison.Ordinal)) continue;

                var value = $"[{accessor}:{GetNsfRoleAbbreviation(entry)}]";
                if (entry.AccessType == NsfAccessTypeTeam) teams.Add(value);
                else if (entry.AccessType == NsfAccessTypeApplication) applications.Add(value);
                else users.Add(value);
            }

            var parts = new List<string>();
            if (users.Count > 0) parts.Add("users:" + string.Join(",", users));
            if (teams.Count > 0) parts.Add("teams:" + string.Join(",", teams));
            if (applications.Count > 0) parts.Add("applications:" + string.Join(",", applications));
            return parts.Count == 0 ? string.Empty : " (" + string.Join("; ", parts) + ")";
        }

        public static Dictionary<string, object> GetClassicFolderPermissions(VaultOnline vault, SharedFolder folder)
        {
            if (folder == null) return new Dictionary<string, object>();
            var users = folder.UsersPermissions.Where(x => x.UserType == UserType.User)
                .Select(x => new Dictionary<string, object>
                {
                    ["accessor"] = ResolveClassicMemberName(vault, x), ["access_type"] = "AT_USER",
                    ["manage_records"] = x.ManageRecords, ["manage_users"] = x.ManageUsers,
                    ["expiration"] = x.Expiration?.ToUnixTimeMilliseconds()
                }).ToList();
            var teams = folder.UsersPermissions.Where(x => x.UserType == UserType.Team)
                .Select(x => new Dictionary<string, object>
                {
                    ["accessor"] = ResolveClassicMemberName(vault, x), ["access_type"] = "AT_TEAM",
                    ["manage_records"] = x.ManageRecords, ["manage_users"] = x.ManageUsers
                }).ToList();
            return new Dictionary<string, object> { ["user_permissions"] = users, ["team_permissions"] = teams };
        }

        public static string FormatClassicFolderPermissionText(VaultOnline vault, SharedFolder folder)
        {
            if (folder == null) return string.Empty;
            var defaults = new List<string>();
            if (folder.DefaultManageUsers) defaults.Add("MU");
            if (folder.DefaultManageRecords) defaults.Add("MR");
            if (folder.DefaultCanEdit) defaults.Add("CE");
            if (folder.DefaultCanShare) defaults.Add("CS");
            if (defaults.Count == 0) defaults.Add("RO");

            var users = new List<string>();
            var teams = new List<string>();
            foreach (var permission in folder.UsersPermissions)
            {
                var rights = new List<string>();
                if (permission.ManageUsers) rights.Add("MU");
                if (permission.ManageRecords) rights.Add("MR");
                if (rights.Count == 0) rights.Add("RO");
                var value = $"[{ResolveClassicMemberName(vault, permission)}:{string.Join(",", rights)}]";
                if (permission.UserType == UserType.Team) teams.Add(value);
                else if (permission.UserType == UserType.User) users.Add(value);
            }

            var parts = new List<string> { "default:" + string.Join(",", defaults) };
            if (teams.Count > 0) parts.Add("teams:" + string.Join(",", teams));
            if (users.Count > 0) parts.Add("users:" + string.Join(",", users));
            return " (" + string.Join("; ", parts) + ")";
        }

        public static Dictionary<string, object> GetClassicRecordPermissions(RecordSharePermissions share)
        {
            if (share == null) return new Dictionary<string, object>();
            return new Dictionary<string, object>
            {
                ["user_permissions"] = (share.UserPermissions ?? Array.Empty<UserRecordPermissions>()).Select(x => new Dictionary<string, object>
                {
                    ["username"] = x.Username, ["owner"] = x.Owner, ["shareable"] = x.CanShare,
                    ["editable"] = x.CanEdit, ["expiration"] = x.Expiration?.ToUnixTimeMilliseconds()
                }).ToList(),
                ["shared_folder_permissions"] = (share.SharedFolderPermissions ?? Array.Empty<SharedFolderRecordPermissions>()).Select(x => new Dictionary<string, object>
                {
                    ["shared_folder_uid"] = x.SharedFolderUid, ["reshareable"] = x.CanShare,
                    ["editable"] = x.CanEdit, ["expiration"] = x.Expiration?.ToUnixTimeMilliseconds()
                }).ToList()
            };
        }

        public static string FormatClassicRecordPermissionText(RecordSharePermissions share)
        {
            if (share?.UserPermissions == null) return string.Empty;
            var users = share.UserPermissions.Select(x =>
            {
                var rights = x.Owner ? new[] { "OW" } : new[] { x.CanEdit ? "CE" : null, x.CanShare ? "CS" : null }
                    .Where(y => !string.IsNullOrEmpty(y)).DefaultIfEmpty("RO");
                return $"[{x.Username}:{string.Join(",", rights)}]";
            }).ToList();
            return users.Count == 0 ? string.Empty : " (users:" + string.Join(",", users) + ")";
        }

        private static string GetNsfRoleName(KeeperNSFAccessEntry entry)
        {
            if (entry == null) return "unresolved";
            if (entry.Owner || entry.AccessRoleType == NsfRoleOwner) return "owner";
            switch (entry.AccessRoleType)
            {
                case NsfRoleViewer: return "viewer";
                case NsfRoleShareManager: return "share-manager";
                case NsfRoleContentManager: return "content-manager";
                case NsfRoleContentShareManager: return "content-share-manager";
                case NsfRoleFullManager: return "full-manager";
                default: return "unresolved";
            }
        }

        private static string GetNsfRoleAbbreviation(KeeperNSFAccessEntry entry)
        {
            switch (GetNsfRoleName(entry))
            {
                case "owner": return "OW";
                case "viewer": return "VW";
                case "share-manager": return "SM";
                case "content-manager": return "CM";
                case "content-share-manager": return "CSM";
                case "full-manager": return "FM";
                default: return "UN";
            }
        }

        private static Dictionary<string, object> GetNsfPermissions(VaultOnline vault, IEnumerable<KeeperNSFAccessEntry> entries)
        {
            var users = new List<object>();
            var teams = new List<object>();
            var applications = new List<object>();
            foreach (var entry in entries ?? Enumerable.Empty<KeeperNSFAccessEntry>())
            {
                if (entry == null) continue;
                var row = new Dictionary<string, object>
                {
                    ["accessor"] = ResolveNsfAccessor(vault, entry),
                    ["access_type"] = GetNsfAccessTypeLabel(entry.AccessType),
                    ["role"] = GetNsfRoleName(entry), ["inherited"] = entry.Inherited
                };
                if (entry.AccessType == NsfAccessTypeTeam) teams.Add(row);
                else if (entry.AccessType == NsfAccessTypeApplication) applications.Add(row);
                else users.Add(row);
            }
            return new Dictionary<string, object>
            {
                ["user_permissions"] = users, ["team_permissions"] = teams,
                ["application_permissions"] = applications
            };
        }

        private static string ResolveNsfAccessor(VaultOnline vault, KeeperNSFAccessEntry entry)
        {
            if (!string.IsNullOrEmpty(entry.AccessorName)) return entry.AccessorName;
            if (entry.AccessType == NsfAccessTypeTeam && vault.TryGetTeam(entry.AccessTypeUid, out var team)) return team.Name;
            if (entry.AccessType == NsfAccessTypeApplication && vault.TryGetKeeperRecord(entry.AccessTypeUid, out var application)) return application.Title;
            if (vault.TryGetUsername(entry.AccessTypeUid, out var username)) return username;
            return entry.AccessTypeUid;
        }

        private static string ResolveClassicMemberName(VaultOnline vault, SharedFolderPermission permission)
        {
            if (!string.IsNullOrEmpty(permission.Name)) return permission.Name;
            if (permission.UserType == UserType.User && vault.TryGetUsername(permission.Uid, out var username)) return username;
            if (permission.UserType == UserType.Team && vault.TryGetTeam(permission.Uid, out var team)) return team.Name;
            return permission.Uid;
        }

        private static string GetNsfAccessTypeLabel(int accessType)
        {
            switch (accessType)
            {
                case NsfAccessTypeOwner: return "AT_OWNER";
                case NsfAccessTypeTeam: return "AT_TEAM";
                case NsfAccessTypeApplication: return "AT_APPLICATION";
                default: return "AT_USER";
            }
        }
    }
}
