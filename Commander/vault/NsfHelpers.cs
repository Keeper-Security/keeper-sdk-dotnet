using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using Enterprise;
using Folder.V3.Remove;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Record.V3.Details;
using ZeroDep;
using GetShareObjectsRequest = Records.GetShareObjectsRequest;
using GetShareObjectsResponse = Records.GetShareObjectsResponse;

namespace Commander
{
    internal static class NsfHelpers
    {
        internal const int LabelWidth = 21;
        internal const int FolderLabelWidth = 25;
        internal const string KdRootFolderUid = "AAAAAAAAAAAAAAAAAPmtNA";

        private static readonly string[] SecretFieldTypes = { "password", "secret", "privateKey", "passkey", "otp" };

        private static readonly Dictionary<int, string> AccessRoleLabels = new Dictionary<int, string>
        {
            { 0, "contributor" },
            { 1, "contributor" },
            { 2, "viewer" },
            { 3, "share-manager" },
            { 4, "content-manager" },
            { 5, "content-share-manager" },
            { 6, "full-manager" },
            { 7, "unresolved" },
        };

        private static readonly Dictionary<int, string> AccessTypeLabels = new Dictionary<int, string>
        {
            { 0, "AT_UNKNOWN" },
            { 1, "AT_OWNER" },
            { 2, "AT_USER" },
            { 3, "AT_TEAM" },
            { 4, "AT_ENTERPRISE" },
            { 5, "AT_FOLDER" },
            { 6, "AT_APPLICATION" },
        };

        private static readonly Dictionary<string, string> FieldLabels = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "name", "File Name" },
            { "url", "URL" },
            { "otp", "OTP" },
            { "login", "Login" },
            { "password", "Password" },
            { "host", "Host" },
            { "notes", "Notes" },
            { "phone", "Phone" },
            { "address", "Address" },
        };

        private static Dictionary<string, string> _shareObjectsCache;
        private static string _shareObjectsCacheAccountUid;

        internal static bool PasswordVisible { get; set; }

        internal static string GetAccessRoleLabel(int roleType)
        {
            return AccessRoleLabels.TryGetValue(roleType, out var label) ? label : "unknown";
        }

        internal static (string Type, string Title) GetRecordTypeAndTitle(KeeperNSFRecord record)
        {
            string recordType;
            if (!string.IsNullOrEmpty(record?.Type))
            {
                recordType = record.Type;
            }
            else if (record?.Version == 4)
            {
                recordType = "file";
            }
            else if (record?.Version == 5)
            {
                recordType = "application";
            }
            else
            {
                recordType = "Unknown";
            }

            var title = record?.Title ?? "";
            return (recordType, title);
        }

        internal static (KeeperNSFRecord Record, FolderNode Folder) ResolveNsfObject(VaultOnline vault, string uid, string name)
        {
            if (!string.IsNullOrEmpty(uid))
            {
                if (vault.TryGetKeeperNSFFolder(uid, out var folder))
                {
                    return (null, folder);
                }

                if (vault.TryGetKeeperNSFRecord(uid, out var record))
                {
                    return (record, null);
                }

                return (null, null);
            }

            if (!string.IsNullOrEmpty(name))
            {
                foreach (var f in vault.KeeperNSFFolderNodes)
                {
                    if (f.Name != null && string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        return (null, f);
                    }
                }

                foreach (var r in vault.KeeperNSFRecordEntries)
                {
                    if (r.Title != null && string.Equals(r.Title, name, StringComparison.OrdinalIgnoreCase))
                    {
                        return (r, null);
                    }
                }

                foreach (var f in vault.KeeperNSFFolderNodes)
                {
                    if (f.Name != null && f.Name.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return (null, f);
                    }
                }

                foreach (var r in vault.KeeperNSFRecordEntries)
                {
                    if (r.Title != null && r.Title.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return (r, null);
                    }
                }
            }

            return (null, null);
        }

        internal static KeeperNSFRecord ResolveNsfRecord(VaultOnline vault, string identifier)
        {
            if (vault.TryGetKeeperNSFRecord(identifier, out var record))
            {
                return record;
            }

            foreach (var r in vault.KeeperNSFRecordEntries)
            {
                if (r.Title != null && string.Equals(r.Title, identifier, StringComparison.OrdinalIgnoreCase))
                {
                    return r;
                }
            }

            foreach (var r in vault.KeeperNSFRecordEntries)
            {
                if (r.Title != null && r.Title.IndexOf(identifier, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return r;
                }
            }

            return null;
        }

        internal static Dictionary<string, FolderNode> GetFolderNodeMap(VaultOnline vault)
        {
            return vault.KeeperNSFFolderNodes
                .Where(n => n?.FolderUid != null)
                .ToDictionary(n => n.FolderUid, n => n, StringComparer.Ordinal);
        }

        internal static string GetFolderPath(VaultOnline vault, string folderUid, Dictionary<string, FolderNode> folderMap = null)
        {
            folderMap ??= GetFolderNodeMap(vault);
            if (string.IsNullOrEmpty(folderUid))
            {
                return "/";
            }

            if (!folderMap.TryGetValue(folderUid, out var node))
            {
                return null;
            }

            var components = new List<string>();
            var current = node;
            while (current != null)
            {
                if (!string.IsNullOrEmpty(current.Name))
                {
                    components.Add(current.Name);
                }

                if (string.IsNullOrEmpty(current.ParentUid))
                {
                    break;
                }

                if (folderMap.TryGetValue(current.ParentUid, out var parent))
                {
                    current = parent;
                }
                else
                {
                    break;
                }
            }

            if (components.Count == 0)
            {
                return "/";
            }

            components.Reverse();
            return "/" + string.Join("/", components);
        }

        internal static string ResolveFolderParentUid(string rawParent, Dictionary<string, FolderNode> folderMap)
        {
            if (string.IsNullOrEmpty(rawParent)
                || rawParent == KdRootFolderUid
                || folderMap == null
                || !folderMap.ContainsKey(rawParent))
            {
                return null;
            }

            return rawParent;
        }

        internal static string FormatNsfFolderPath(string path)
        {
            if (string.IsNullOrEmpty(path) || path == "/")
            {
                return "/";
            }

            return path.TrimStart('/');
        }

        internal static string GetAccessTypeLabel(int accessType)
        {
            return AccessTypeLabels.TryGetValue(accessType, out var label) ? label : "AT_UNKNOWN";
        }

        internal static bool IsFolderOwner(string accessTypeUid, string username, string ownerAccountUid, string ownerUsername)
        {
            if (!string.IsNullOrEmpty(ownerAccountUid) && accessTypeUid == ownerAccountUid)
            {
                return true;
            }

            return !string.IsNullOrEmpty(ownerUsername)
                   && !string.IsNullOrEmpty(username)
                   && string.Equals(username, ownerUsername, StringComparison.OrdinalIgnoreCase);
        }

        internal static string GetFieldLabel(string fieldType)
        {
            if (FieldLabels.TryGetValue(fieldType, out var label))
            {
                return label;
            }

            return string.IsNullOrWhiteSpace(fieldType)
                ? fieldType
                : CultureInfo.CurrentCulture.TextInfo.ToTitleCase(fieldType.ToLower());
        }

        internal static bool IsSecretField(string fieldType)
        {
            return SecretFieldTypes.Contains(fieldType);
        }

        internal static Dictionary<string, object> ParseFieldSpecs(IEnumerable<string> fieldSpecs, bool generatePassword, out int parsedCount)
        {
            var fieldDict = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            parsedCount = 0;

            if (fieldSpecs != null)
            {
                foreach (var spec in fieldSpecs)
                {
                    if (string.IsNullOrWhiteSpace(spec))
                    {
                        continue;
                    }

                    var eqIdx = spec.IndexOf('=');
                    if (eqIdx <= 0)
                    {
                        Console.WriteLine($"Warning: Skipping invalid field '{spec}'. Expected format: key=value");
                        continue;
                    }

                    var key = spec.Substring(0, eqIdx).Trim();
                    var val = spec.Substring(eqIdx + 1).Trim();
                    if (string.IsNullOrEmpty(key))
                    {
                        continue;
                    }

                    fieldDict[key] = ResolveFieldValue(val);
                    parsedCount++;
                }
            }

            if (generatePassword)
            {
                fieldDict["password"] = CryptoUtils.GeneratePassword(null);
            }

            return fieldDict.Count > 0 ? fieldDict : null;
        }

        private static object ResolveFieldValue(string rawValue)
        {
            if (string.IsNullOrEmpty(rawValue))
            {
                return rawValue;
            }

            if (rawValue.StartsWith("$JSON:", StringComparison.Ordinal))
            {
                var jsonStr = rawValue.Substring(6);
                if (string.IsNullOrEmpty(jsonStr))
                {
                    Console.WriteLine("Warning: JSON value cannot be empty. Format: $JSON:<json_object>");
                    return rawValue;
                }

                try
                {
                    return Json.Deserialize(jsonStr);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Invalid JSON value: {ex.Message}");
                    return rawValue;
                }
            }

            return rawValue;
        }

        internal static void WriteRemoveImpact(RemoveResponse response, string itemLabel = "Record")
        {
            if (!string.IsNullOrEmpty(response?.ErrorMessage))
            {
                Console.WriteLine($"Error: {response.ErrorMessage}");
            }

            if (response?.Results == null)
            {
                return;
            }

            foreach (var result in response.Results)
            {
                var recordUid = result.ItemUid.Length > 0
                    ? result.ItemUid.ToByteArray().Base64UrlEncode()
                    : "(unknown)";
                var folderUid = result.FolderUid.Length > 0
                    ? result.FolderUid.ToByteArray().Base64UrlEncode()
                    : "";

                Console.WriteLine();
                Console.WriteLine($"{itemLabel}: {recordUid}");
                if (!string.IsNullOrEmpty(folderUid))
                {
                    Console.WriteLine($"  Folder context: {folderUid}");
                }

                Console.WriteLine($"  Status: {result.Status}");
                if (result.Error != null && !string.IsNullOrEmpty(result.Error.Message))
                {
                    Console.WriteLine($"  Error: {result.Error.Message}");
                }

                if (result.Impact != null)
                {
                    var impact = result.Impact;
                    Console.WriteLine("  Impact:");
                    Console.WriteLine($"    Folders:          {impact.FoldersCount}");
                    Console.WriteLine($"    Records:          {impact.RecordsCount}");
                    Console.WriteLine($"    Affected users:   {impact.AffectedUsersCount}");
                    Console.WriteLine($"    Affected teams:   {impact.AffectedTeamsCount}");
                    if (impact.RecordInfo != null && impact.RecordInfo.Count > 0)
                    {
                        Console.WriteLine($"    Other locations:  {impact.RecordInfo[0].LocationsCount}");
                    }

                    foreach (var warning in impact.Warnings)
                    {
                        Console.WriteLine($"    Warning: {warning}");
                    }
                }
            }
        }

        internal static async Task<bool> ConfirmAsync(string prompt, bool defaultYes = false)
        {
            Console.Write(prompt);
            var answer = (await Program.GetInputManager().ReadLine())?.Trim().ToLowerInvariant() ?? "";
            if (string.IsNullOrEmpty(answer))
            {
                return defaultYes;
            }

            return answer.StartsWith("y", StringComparison.Ordinal);
        }

        internal static void WriteCsv(string path, IEnumerable<string[]> rows)
        {
            var sb = new StringBuilder();
            foreach (var row in rows)
            {
                sb.AppendLine(string.Join(",", row.Select(EscapeCsv)));
            }

            System.IO.File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private static string EscapeCsv(string value)
        {
            if (value == null)
            {
                return "";
            }

            if (value.Contains('"') || value.Contains(',') || value.Contains('\n'))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }

            return value;
        }

        internal static void ResetShareObjectsCache()
        {
            _shareObjectsCache = null;
            _shareObjectsCacheAccountUid = null;
        }

        internal static async Task<string> ResolveUsernameAsync(VaultOnline vault, string accessTypeUid, string emailHint = null)
        {
            if (!string.IsNullOrEmpty(emailHint))
            {
                return emailHint;
            }

            var currentAccountUid = vault.Auth.AuthContext.AccountUid.Base64UrlEncode();
            if (accessTypeUid == currentAccountUid)
            {
                return vault.Auth.Username;
            }

            if (vault.TryGetUsername(accessTypeUid, out var username))
            {
                return username;
            }

            if (_shareObjectsCacheAccountUid != null && _shareObjectsCacheAccountUid != currentAccountUid)
            {
                ResetShareObjectsCache();
            }

            if (_shareObjectsCache == null)
            {
                try
                {
                    var rs = await vault.Auth.ExecuteAuthRest<GetShareObjectsRequest, GetShareObjectsResponse>(
                        "vault/get_share_objects", new GetShareObjectsRequest());
                    _shareObjectsCache = new Dictionary<string, string>(StringComparer.Ordinal);
                    foreach (var userList in new[]
                             {
                                 rs.ShareRelationships, rs.ShareFamilyUsers, rs.ShareEnterpriseUsers,
                                 rs.ShareMCEnterpriseUsers
                             })
                    {
                        foreach (var su in userList)
                        {
                            if (su.UserAccountUid != null && !su.UserAccountUid.IsEmpty)
                            {
                                var suUid = su.UserAccountUid.ToByteArray().Base64UrlEncode();
                                if (!string.IsNullOrEmpty(su.Username) && !_shareObjectsCache.ContainsKey(suUid))
                                {
                                    _shareObjectsCache[suUid] = su.Username;
                                }
                            }
                        }
                    }

                    _shareObjectsCacheAccountUid = currentAccountUid;
                }
                catch
                {
                    return accessTypeUid;
                }
            }

            return _shareObjectsCache.TryGetValue(accessTypeUid, out var cached) ? cached : accessTypeUid;
        }

        internal static void DisplayPermissionChanges(KeeperNSFPermissionResult result, bool isDryRun)
        {
            if (result.Skipped.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine($"  SKIPPED ({result.Skipped.Count}):");
                foreach (var s in result.Skipped)
                {
                    var email = s.Email ?? "-";
                    var curRole = s.CurrentRole ?? "-";
                    Console.WriteLine($"    {s.RecordUid}  {email}  [{curRole}]  {s.Message}");
                }
            }

            if (result.Grants.Count > 0)
            {
                var header = isDryRun ? "PLANNED GRANTS" : "GRANT";
                Console.WriteLine();
                Console.WriteLine($"  {header} ({result.Grants.Count}):");
                foreach (var g in result.Grants)
                {
                    var statusIcon = isDryRun ? "" : (g.Success ? "[OK] " : "[FAIL] ");
                    var inherited = g.ChangeType == "create" ? " (inherited override)" : "";
                    Console.WriteLine($"    {statusIcon}{g.RecordUid}  {g.Email}  {g.CurrentRole} -> {g.NewRole}{inherited}");
                    if (!isDryRun && !g.Success && !string.IsNullOrEmpty(g.Message))
                    {
                        Console.WriteLine($"         Error: {g.Message}");
                    }
                }
            }

            if (result.Revokes.Count > 0)
            {
                var header = isDryRun ? "PLANNED REVOKES" : "REVOKE";
                Console.WriteLine();
                Console.WriteLine($"  {header} ({result.Revokes.Count}):");
                foreach (var r in result.Revokes)
                {
                    var statusIcon = isDryRun ? "" : (r.Success ? "[OK] " : "[FAIL] ");
                    Console.WriteLine($"    {statusIcon}{r.RecordUid}  {r.Email}  [{r.CurrentRole}]");
                    if (!isDryRun && !r.Success && !string.IsNullOrEmpty(r.Message))
                    {
                        Console.WriteLine($"         Error: {r.Message}");
                    }
                }
            }

            if (result.Denies.Count > 0)
            {
                var header = isDryRun ? "PLANNED DENIES" : "DENY";
                Console.WriteLine();
                Console.WriteLine($"  {header} ({result.Denies.Count}):");
                foreach (var d in result.Denies)
                {
                    var statusIcon = isDryRun ? "" : (d.Success ? "[OK] " : "[FAIL] ");
                    var inherited = d.ChangeType == "deny" ? " (inherited override)" : "";
                    Console.WriteLine($"    {statusIcon}{d.RecordUid}  {d.Email}  [{d.CurrentRole}]{inherited}");
                    if (!isDryRun && !d.Success && !string.IsNullOrEmpty(d.Message))
                    {
                        Console.WriteLine($"         Error: {d.Message}");
                    }
                }
            }
        }
    }
}
