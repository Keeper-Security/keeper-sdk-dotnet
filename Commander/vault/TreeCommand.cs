using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using ZeroDep;

namespace Commander
{
    internal partial class VaultContext
    {
        private const int NsfAccessTypeTeam = 3;
        private const int NsfAccessTypeApplication = 6;
        private const int NsfRoleOwner = 1;
        private const int NsfRoleViewer = 2;
        private const int NsfRoleShareManager = 3;
        private const int NsfRoleContentManager = 4;
        private const int NsfRoleContentShareManager = 5;
        private const int NsfRoleFullManager = 6;
        private const int NsfRoleUnknown = 7;

        internal async Task<bool> EnhancedTreeCommand(TreeCommandOptions options)
        {
            var format = (options.Format ?? "table").Trim();
            if (!string.Equals(format, "table", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"Invalid format: {options.Format}. Expected table or json.");
                return false;
            }

            var folder = Vault.RootFolder;
            if (!string.IsNullOrEmpty(options.Folder) &&
                !Vault.TryGetKeeperNSFFolder(options.Folder, out folder) &&
                !Vault.TryGetFolder(options.Folder, out folder) &&
                !TryResolvePath(options.Folder, out folder))
            {
                Console.WriteLine($"Invalid folder: {options.Folder}");
                return false;
            }

            var classicRecordUids = new HashSet<string>(StringComparer.Ordinal);
            var nsfRecordUids = new HashSet<string>(StringComparer.Ordinal);
            var nsfFolderUids = new HashSet<string>(StringComparer.Ordinal);
            var visited = new HashSet<string>(StringComparer.Ordinal);
            CollectTreeTargets(folder, classicRecordUids, nsfRecordUids, nsfFolderUids, visited);

            if (string.IsNullOrEmpty(folder.FolderUid))
            {
                foreach (var nsfFolder in Vault.KeeperNSFFolderNodes)
                {
                    nsfFolderUids.Add(nsfFolder.FolderUid);
                }
                if (options.Record)
                {
                    foreach (var nsfRecord in Vault.KeeperNSFRecordEntries)
                        nsfRecordUids.Add(nsfRecord.RecordUid);
                }
            }

            var classicShares = options.Shares && options.Record
                ? (await Vault.GetSharesForRecords(classicRecordUids)).ToDictionary(x => x.RecordUid, StringComparer.Ordinal)
                : new Dictionary<string, RecordSharePermissions>(StringComparer.Ordinal);
            var nsfShares = (options.NsfShares && (options.Record || nsfFolderUids.Count > 0))
                ? await Vault.GetKeeperNSFSharePermissionsAsync(nsfFolderUids, nsfRecordUids)
                : null;

            if (string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            {
                var json = BuildTreeJson(folder, options, classicShares, nsfShares, new HashSet<string>(StringComparer.Ordinal), "/");
                var payload = new Dictionary<string, object> { ["tree"] = json };
                if (!string.IsNullOrEmpty(options.Title)) payload["title"] = options.Title;
                if ((options.Shares || options.NsfShares) && !options.HideSharedKeys)
                    payload["share_permissions_key"] = SharePermissionsKey(options);
                var text = Json.WriteFormatted(payload);
                if (!string.IsNullOrEmpty(options.Output)) File.WriteAllText(options.Output, text);
                else Console.WriteLine(text);
                return true;
            }

            if ((options.Shares || options.NsfShares) && !options.HideSharedKeys)
            {
                Console.WriteLine("Share Permissions Key:");
                Console.WriteLine("======================");
                if (options.Shares)
                {
                    Console.WriteLine("RO = Read-Only");
                    Console.WriteLine("MU = Can Manage Users");
                    Console.WriteLine("MR = Can Manage Records");
                    Console.WriteLine("CE = Can Edit");
                    Console.WriteLine("CS = Can Share");
                    Console.WriteLine("OW = Owner");
                }
                if (options.NsfShares)
                {
                    Console.WriteLine("OW = NSF Owner");
                    Console.WriteLine("VW = NSF Viewer");
                    Console.WriteLine("SM = NSF Share Manager");
                    Console.WriteLine("CM = NSF Content Manager");
                    Console.WriteLine("CSM = NSF Content + Share Manager");
                    Console.WriteLine("FM = NSF Full Manager");
                }
                Console.WriteLine("======================");
                Console.WriteLine();
            }

            if (!string.IsNullOrEmpty(options.Title)) Console.WriteLine(options.Title);

            PrintEnhancedTree(folder, options, classicShares, nsfShares,
                new HashSet<string>(StringComparer.Ordinal), "", true);
            return true;
        }

        private void CollectTreeTargets(FolderNode folder, HashSet<string> classicRecords,
            HashSet<string> nsfRecords, HashSet<string> nsfFolders, HashSet<string> visited)
        {
            var key = string.IsNullOrEmpty(folder.FolderUid) ? "__root__" : folder.FolderUid;
            if (!visited.Add(key)) return;
            if (Vault.TryGetKeeperNSFFolder(folder.FolderUid, out _)) nsfFolders.Add(folder.FolderUid);

            if (folder.Records != null)
            {
                foreach (var uid in folder.Records)
                {
                    if (Vault.TryGetKeeperNSFRecord(uid, out _)) nsfRecords.Add(uid);
                    else if (Vault.TryGetKeeperRecord(uid, out var record) && (record.Version == 2 || record.Version == 3))
                        classicRecords.Add(uid);
                }
            }

            foreach (var uid in folder.Subfolders ?? Array.Empty<string>())
            {
                if (TryGetTreeFolder(uid, out var child))
                    CollectTreeTargets(child, classicRecords, nsfRecords, nsfFolders, visited);
            }
        }

        private Dictionary<string, object> BuildTreeJson(FolderNode folder, TreeCommandOptions options,
            IReadOnlyDictionary<string, RecordSharePermissions> classicShares,
            KeeperNSFSharePermissions nsfShares, HashSet<string> visited, string parentPath)
        {
            var key = string.IsNullOrEmpty(folder.FolderUid) ? "__root__" : folder.FolderUid;
            if (!visited.Add(key)) return null;
            var isNsf = Vault.TryGetKeeperNSFFolder(folder.FolderUid, out _);
            var name = string.IsNullOrEmpty(folder.Name) ? "My Vault" : folder.Name;
            var path = string.IsNullOrEmpty(folder.FolderUid) ? "/" : JoinPath(parentPath, name);
            var result = new Dictionary<string, object>
            {
                ["name"] = name,
                ["path"] = path,
                ["kind"] = isNsf ? "nested_share_folder" : "folder"
            };
            if (options.Verbose && !string.IsNullOrEmpty(folder.FolderUid)) result["uid"] = folder.FolderUid;
            if (isNsf && options.NsfShares) result["share_permissions"] = NsfFolderPermissions(folder.FolderUid, nsfShares);
            else if (!isNsf && options.Shares) result["share_permissions"] = ClassicFolderPermissions(folder);

            var children = new List<Dictionary<string, object>>();
            foreach (var uid in folder.Subfolders ?? Array.Empty<string>())
            {
                if (TryGetTreeFolder(uid, out var child))
                {
                    var childJson = BuildTreeJson(child, options, classicShares, nsfShares, visited, path);
                    if (childJson != null) children.Add(childJson);
                }
            }
            if (string.IsNullOrEmpty(folder.FolderUid))
            {
                foreach (var child in Vault.KeeperNSFFolderNodes.Where(x => string.IsNullOrEmpty(x.ParentUid) || !Vault.TryGetKeeperNSFFolder(x.ParentUid, out _)))
                {
                    var childJson = BuildTreeJson(child, options, classicShares, nsfShares, visited, path);
                    if (childJson != null) children.Add(childJson);
                }
            }
            if (options.Record)
            {
                foreach (var uid in folder.Records ?? Array.Empty<string>())
                {
                    if (Vault.TryGetKeeperNSFRecord(uid, out var nsfRecord))
                    {
                        var item = RecordJson(nsfRecord.Title, nsfRecord.Type, uid, true, options, nsfShares, null, path);
                        children.Add(item);
                    }
                    else if (Vault.TryGetKeeperRecord(uid, out var record) && (record.Version == 2 || record.Version == 3))
                    {
                        classicShares.TryGetValue(uid, out var share);
                        children.Add(RecordJson(record.Title, record is TypedRecord tr ? tr.TypeName : "", uid, false, options, null, share, path));
                    }
                }
            }
            if (children.Count > 0) result["children"] = children.OrderBy(x => x["name"]?.ToString(), StringComparer.CurrentCultureIgnoreCase).ToList();
            return result;
        }

        private void PrintEnhancedTree(FolderNode folder, TreeCommandOptions options,
            IReadOnlyDictionary<string, RecordSharePermissions> classicShares, KeeperNSFSharePermissions nsfShares,
            HashSet<string> visited, string indent, bool last)
        {
            var key = string.IsNullOrEmpty(folder.FolderUid) ? "__root__" : folder.FolderUid;
            if (!visited.Add(key)) return;
            var isNsf = Vault.TryGetKeeperNSFFolder(folder.FolderUid, out _);
            var label = string.IsNullOrEmpty(folder.Name) ? "My Vault" : folder.Name;
            if (options.Verbose && !string.IsNullOrEmpty(folder.FolderUid)) label += $" (ID: {folder.FolderUid})";
            if (isNsf) label += " [Nested Share Folder]";
            else if (Vault.SharedFolders.Any(x => x.Uid == folder.FolderUid))
            {
                label += " [SHARED]";
                if (options.Shares) label += ClassicFolderPermissionText(folder);
            }
            if (isNsf && options.NsfShares) label += NsfPermissionText(folder.FolderUid, nsfShares);
            Console.WriteLine(indent + (string.IsNullOrEmpty(indent) ? "" : (last ? "└── " : "├── ")) + label);
            var childIndent = indent + (string.IsNullOrEmpty(indent) ? " " : (last ? "    " : "│   "));
            var childFolders = (folder.Subfolders ?? Array.Empty<string>()).Select(x => TryGetTreeFolder(x, out var f) ? f : null).Where(x => x != null).ToList();
            if (string.IsNullOrEmpty(folder.FolderUid))
            {
                var roots = Vault.KeeperNSFFolderNodes.Where(x => string.IsNullOrEmpty(x.ParentUid) || !Vault.TryGetKeeperNSFFolder(x.ParentUid, out _)).ToList();
                childFolders.AddRange(roots.Where(x => childFolders.All(y => y.FolderUid != x.FolderUid)));
            }
            childFolders = childFolders.OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
            for (var i = 0; i < childFolders.Count; i++) PrintEnhancedTree(childFolders[i], options, classicShares, nsfShares, visited, childIndent, i == childFolders.Count - 1);
            if (options.Record)
            {
                foreach (var uid in folder.Records ?? Array.Empty<string>())
                {
                    string labelRecord = null;
                    if (Vault.TryGetKeeperNSFRecord(uid, out var nr))
                    {
                        labelRecord = $"{nr.Title ?? uid} [Nested Record]";
                        if (options.NsfShares) labelRecord += NsfPermissionText(uid, nsfShares, true);
                    }
                    else if (Vault.TryGetKeeperRecord(uid, out var r) && (r.Version == 2 || r.Version == 3))
                    {
                        labelRecord = $"{r.Title ?? uid} [Record]";
                        if (options.Shares && classicShares.TryGetValue(uid, out var share))
                            labelRecord += ClassicRecordPermissionText(share);
                    }
                    if (labelRecord != null) Console.WriteLine(childIndent + "├── " + labelRecord);
                }
            }
        }

        private static string JoinPath(string parent, string name)
        {
            if (string.IsNullOrEmpty(name)) return string.IsNullOrEmpty(parent) ? "/" : parent;
            var childName = name.Trim('/');
            if (childName.Length == 0) return string.IsNullOrEmpty(parent) ? "/" : parent;
            if (string.IsNullOrEmpty(parent) || parent == "/") return "/" + childName;
            return parent.TrimEnd('/') + "/" + childName;
        }

        private bool TryGetTreeFolder(string uid, out FolderNode folder)
        {
            return Vault.TryGetFolder(uid, out folder) || Vault.TryGetKeeperNSFFolder(uid, out folder);
        }

        private static Dictionary<string, object> SharePermissionsKey(TreeCommandOptions options)
        {
            var key = new Dictionary<string, object>();
            if (options.Shares) key["classic"] = new Dictionary<string, string>
            {
                ["RO"] = "Read-Only", ["MU"] = "Can Manage Users", ["MR"] = "Can Manage Records",
                ["CE"] = "Can Edit", ["CS"] = "Can Share", ["OW"] = "Owner"
            };
            if (options.NsfShares) key["nsf"] = new Dictionary<string, string>
            {
                ["OW"] = "NSF Owner", ["VW"] = "NSF Viewer", ["SM"] = "NSF Share Manager",
                ["CM"] = "NSF Content Manager", ["CSM"] = "NSF Content + Share Manager", ["FM"] = "NSF Full Manager"
            };
            return key;
        }

        private Dictionary<string, object> RecordJson(string title, string type, string uid, bool nsf,
            TreeCommandOptions options, KeeperNSFSharePermissions nsfShares, RecordSharePermissions classicShare, string path)
        {
            var result = new Dictionary<string, object>
            {
                ["name"] = title ?? uid, ["path"] = path, ["kind"] = nsf ? "nested_record" : "record", ["record_type"] = type ?? ""
            };
            if (options.Verbose) result["uid"] = uid;
            if (nsf && options.NsfShares) result["share_permissions"] = NsfRecordPermissions(uid, nsfShares);
            else if (!nsf && classicShare != null && options.Shares) result["share_permissions"] = ClassicRecordPermissions(classicShare);
            return result;
        }

        private Dictionary<string, object> ClassicFolderPermissions(FolderNode folder)
        {
            if (!Vault.TryGetSharedFolder(folder.FolderUid, out var sf)) return new Dictionary<string, object>();
            var users = sf.UsersPermissions.Where(x => x.UserType == UserType.User).Select(x => new Dictionary<string, object> { ["accessor"] = ResolveClassicMemberName(x), ["access_type"] = "AT_USER", ["manage_records"] = x.ManageRecords, ["manage_users"] = x.ManageUsers }).ToList();
            var teams = sf.UsersPermissions.Where(x => x.UserType == UserType.Team).Select(x => new Dictionary<string, object> { ["accessor"] = ResolveClassicMemberName(x), ["access_type"] = "AT_TEAM", ["manage_records"] = x.ManageRecords, ["manage_users"] = x.ManageUsers }).ToList();
            return new Dictionary<string, object> { ["user_permissions"] = users, ["team_permissions"] = teams };
        }

        private string ResolveClassicMemberName(SharedFolderPermission permission)
        {
            if (!string.IsNullOrEmpty(permission.Name)) return permission.Name;
            if (permission.UserType == UserType.User && Vault.TryGetUsername(permission.Uid, out var username)) return username;
            if (permission.UserType == UserType.Team && Vault.TryGetTeam(permission.Uid, out var team)) return team.Name;
            return permission.Uid;
        }

        private string ClassicFolderPermissionText(FolderNode folder)
        {
            if (!Vault.TryGetSharedFolder(folder.FolderUid, out var sharedFolder)) return string.Empty;

            var defaults = new List<string>();
            if (sharedFolder.DefaultManageUsers) defaults.Add("MU");
            if (sharedFolder.DefaultManageRecords) defaults.Add("MR");
            if (sharedFolder.DefaultCanEdit) defaults.Add("CE");
            if (sharedFolder.DefaultCanShare) defaults.Add("CS");
            if (defaults.Count == 0) defaults.Add("RO");

            var users = new List<string>();
            var teams = new List<string>();
            foreach (var permission in sharedFolder.UsersPermissions)
            {
                var rights = new List<string>();
                if (permission.ManageUsers) rights.Add("MU");
                if (permission.ManageRecords) rights.Add("MR");
                if (rights.Count == 0) rights.Add("RO");
                var entry = $"[{ResolveClassicMemberName(permission)}:{string.Join(",", rights)}]";
                if (permission.UserType == UserType.Team) teams.Add(entry);
                else if (permission.UserType == UserType.User) users.Add(entry);
            }

            var parts = new List<string> { "default:" + string.Join(",", defaults) };
            if (teams.Count > 0) parts.Add("teams:" + string.Join(",", teams));
            if (users.Count > 0) parts.Add("users:" + string.Join(",", users));
            return " (" + string.Join("; ", parts) + ")";
        }

        private static string ClassicRecordPermissionText(RecordSharePermissions share)
        {
            var users = new List<string>();
            foreach (var permission in share.UserPermissions ?? Enumerable.Empty<UserRecordPermissions>())
            {
                var rights = permission.Owner
                    ? new[] { "OW" }
                    : new[] { permission.CanEdit ? "CE" : null, permission.CanShare ? "CS" : null }
                        .Where(x => !string.IsNullOrEmpty(x)).DefaultIfEmpty("RO");
                users.Add($"[{permission.Username}:{string.Join(",", rights)}]");
            }
            return users.Count == 0 ? string.Empty : " (users:" + string.Join(",", users) + ")";
        }

        private static Dictionary<string, object> ClassicRecordPermissions(RecordSharePermissions share) => new Dictionary<string, object>
        {
            ["user_permissions"] = share.UserPermissions.Select(x => new Dictionary<string, object> { ["username"] = x.Username, ["owner"] = x.Owner, ["shareable"] = x.CanShare, ["editable"] = x.CanEdit, ["expiration"] = x.Expiration?.ToUnixTimeMilliseconds() }).ToList(),
            ["shared_folder_permissions"] = share.SharedFolderPermissions.Select(x => new Dictionary<string, object> { ["shared_folder_uid"] = x.SharedFolderUid, ["reshareable"] = x.CanShare, ["editable"] = x.CanEdit, ["expiration"] = x.Expiration?.ToUnixTimeMilliseconds() }).ToList()
        };

        private Dictionary<string, object> NsfFolderPermissions(string uid, KeeperNSFSharePermissions shares) => NsfPermissions(shares?.FolderPermissions.TryGetValue(uid, out var entries) == true ? entries : Array.Empty<KeeperNSFAccessEntry>());
        private Dictionary<string, object> NsfRecordPermissions(string uid, KeeperNSFSharePermissions shares) => NsfPermissions(shares?.RecordPermissions.TryGetValue(uid, out var entries) == true ? entries : Array.Empty<KeeperNSFAccessEntry>());

        private string ResolveNsfAccessor(KeeperNSFAccessEntry entry)
        {
            if (!string.IsNullOrEmpty(entry.AccessorName)) return entry.AccessorName;
            if (entry.AccessType == NsfAccessTypeTeam && Vault.TryGetTeam(entry.AccessTypeUid, out var team)) return team.Name;
            if (entry.AccessType == NsfAccessTypeApplication && Vault.TryGetKeeperRecord(entry.AccessTypeUid, out var app)) return app.Title;
            if (Vault.TryGetUsername(entry.AccessTypeUid, out var username)) return username;
            return entry.AccessTypeUid;
        }

        private static string NsfRoleName(KeeperNSFAccessEntry entry)
        {
            if (entry.Owner || entry.AccessRoleType == NsfRoleOwner) return "owner";
            switch (entry.AccessRoleType)
            {
                case NsfRoleViewer: return "viewer";
                case NsfRoleShareManager: return "share-manager";
                case NsfRoleContentManager: return "content-manager";
                case NsfRoleContentShareManager: return "content-share-manager";
                case NsfRoleFullManager: return "full-manager";
                case NsfRoleUnknown: return "unresolved";
                default: return "unresolved";
            }
        }

        private Dictionary<string, object> NsfPermissions(IEnumerable<KeeperNSFAccessEntry> entries)
        {
            var users = new List<object>(); var teams = new List<object>(); var apps = new List<object>();
            foreach (var entry in entries ?? Enumerable.Empty<KeeperNSFAccessEntry>())
            {
                if (entry == null) continue;
                var row = new Dictionary<string, object> { ["accessor"] = ResolveNsfAccessor(entry), ["access_type"] = NsfHelpers.GetAccessTypeLabel(entry.AccessType), ["role"] = NsfRoleName(entry), ["inherited"] = entry.Inherited };
                if (entry.AccessType == NsfAccessTypeTeam) teams.Add(row);
                else if (entry.AccessType == NsfAccessTypeApplication) apps.Add(row);
                else users.Add(row);
            }
            return new Dictionary<string, object> { ["user_permissions"] = users, ["team_permissions"] = teams, ["application_permissions"] = apps };
        }

        private string NsfPermissionText(string uid, KeeperNSFSharePermissions shares, bool record = false)
        {
            var permissions = record ? shares?.RecordPermissions : shares?.FolderPermissions;
            if (permissions?.TryGetValue(uid, out var entries) != true || entries == null || entries.Count == 0) return "";
            var users = new List<string>(); var teams = new List<string>(); var apps = new List<string>();
            foreach (var entry in entries)
            {
                if (entry == null) continue;
                var name = ResolveNsfAccessor(entry);
                // Do not present an unresolved account UID as a user email in table output.
                if (entry.AccessType != NsfAccessTypeTeam && entry.AccessType != NsfAccessTypeApplication &&
                    string.Equals(name, entry.AccessTypeUid, StringComparison.Ordinal)) continue;
                var role = entry.Owner ? "OW" : NsfRoleAbbreviation(entry.AccessRoleType);
                var value = $"[{name}:{role}]";
                if (entry.AccessType == NsfAccessTypeTeam) teams.Add(value);
                else if (entry.AccessType == NsfAccessTypeApplication) apps.Add(value);
                else users.Add(value);
            }
            var parts = new List<string>();
            if (users.Count > 0) parts.Add("users:" + string.Join(",", users));
            if (teams.Count > 0) parts.Add("teams:" + string.Join(",", teams));
            if (apps.Count > 0) parts.Add("applications:" + string.Join(",", apps));
            return parts.Count == 0 ? "" : " (" + string.Join("; ", parts) + ")";
        }

        private static string NsfRoleAbbreviation(int role)
        {
            switch (role)
            {
                case NsfRoleOwner: return "OW";
                case NsfRoleViewer: return "VW";
                case NsfRoleShareManager: return "SM";
                case NsfRoleContentManager: return "CM";
                case NsfRoleContentShareManager: return "CSM";
                case NsfRoleFullManager: return "FM";
                case NsfRoleUnknown:
                default:
                    // Keep a stable abbreviation for future or malformed server values.
                    return "UN";
            }
        }
    }
}
