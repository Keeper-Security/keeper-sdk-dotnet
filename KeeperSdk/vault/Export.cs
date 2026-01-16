using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace KeeperSecurity
{
    namespace Commands
    {
        [DataContract]
        public class ExportRecordFolder
        {
            [DataMember(Name = "folder", EmitDefaultValue = false)]
            public string FolderPath { get; set; }

            [DataMember(Name = "shared_folder", EmitDefaultValue = false)]
            public string SharedFolderPath { get; set; }

            [DataMember(Name = "can_edit", EmitDefaultValue = false)]
            public bool? CanEdit { get; set; }

            [DataMember(Name = "can_share", EmitDefaultValue = false)]
            public bool? CanShare { get; set; }
        }

        [DataContract]
        public class ExportRecord
        {
            [DataMember(Name = "uid", EmitDefaultValue = false)]
            public string Uid { get; set; }

            [DataMember(Name = "title", EmitDefaultValue = false)]
            public string Title { get; set; }

            [DataMember(Name = "$type", EmitDefaultValue = false)]
            public string RecordType { get; set; }

            [DataMember(Name = "login", EmitDefaultValue = false)]
            public string Login { get; set; }

            [DataMember(Name = "password", EmitDefaultValue = false)]
            public string Password { get; set; }

            [DataMember(Name = "login_url", EmitDefaultValue = false)]
            public string LoginUrl { get; set; }

            [DataMember(Name = "notes", EmitDefaultValue = false)]
            public string Notes { get; set; }

            [DataMember(Name = "custom_fields", EmitDefaultValue = false)]
            public IDictionary<string, object> CustomFields { get; set; }

            [DataMember(Name = "folders", EmitDefaultValue = false)]
            public ExportRecordFolder[] Folders { get; set; }

            [DataMember(Name = "last_modified", EmitDefaultValue = false)]
            public long? LastModified { get; set; }
        }

        [DataContract]
        public class ExportSharedFolderPermissions
        {
            [DataMember(Name = "uid", EmitDefaultValue = false)]
            public string Uid { get; set; }

            [DataMember(Name = "name")]
            public string Name { get; set; }

            [DataMember(Name = "manage_users", EmitDefaultValue = false)]
            public bool? ManageUsers { get; set; }

            [DataMember(Name = "manage_records", EmitDefaultValue = false)]
            public bool? ManageRecords { get; set; }
        }

        [DataContract]
        public class ExportSharedFolder
        {
            [DataMember(Name = "uid", EmitDefaultValue = false)]
            public string Uid { get; set; }

            [DataMember(Name = "path", EmitDefaultValue = false)]
            public string Path { get; set; }

            [DataMember(Name = "can_edit")]
            public bool CanEdit { get; set; }

            [DataMember(Name = "can_share")]
            public bool CanShare { get; set; }

            [DataMember(Name = "manage_users")]
            public bool ManageUsers { get; set; }

            [DataMember(Name = "manage_records")]
            public bool ManageRecords { get; set; }

            [DataMember(Name = "permissions", EmitDefaultValue = false)]
            public ExportSharedFolderPermissions[] Permissions { get; set; }
        }

        [DataContract]
        public class ExportTeam
        {
            [DataMember(Name = "uid", EmitDefaultValue = false)]
            public string Uid { get; set; }

            [DataMember(Name = "name")]
            public string Name { get; set; }

            [DataMember(Name = "members", EmitDefaultValue = false)]
            public string[] Members { get; set; }
        }

        [DataContract]
        public class ExportFile
        {
            [DataMember(Name = "records", EmitDefaultValue = false)]
            public ExportRecord[] Records { get; set; }

            [DataMember(Name = "shared_folders", EmitDefaultValue = false)]
            public ExportSharedFolder[] SharedFolders { get; set; }

            [DataMember(Name = "teams", EmitDefaultValue = false)]
            public ExportTeam[] Teams { get; set; }
        }
    }

    namespace Vault
    {
        /// <summary>
        /// Keeper Export methods
        /// </summary>
        public static class KeeperExport
        {
            private const string TwoFactorCode = "TFC:Keeper";

            /// <summary>
            /// Converts a PasswordRecord to ExportRecord
            /// </summary>
            public static ExportRecord ToExportRecord(this PasswordRecord password)
            {
                var record = new ExportRecord
                {
                    Uid = password.Uid,
                    Title = password.Title,
                    Login = password.Login,
                    Password = password.Password,
                    LoginUrl = password.Link,
                    Notes = password.Notes
                };

                if (password.Custom != null && password.Custom.Count > 0)
                {
                    record.CustomFields = new Dictionary<string, object>();
                    foreach (var custom in password.Custom)
                    {
                        if (!string.IsNullOrEmpty(custom.Name) && !string.IsNullOrEmpty(custom.Value))
                        {
                            record.CustomFields[custom.Name] = custom.Value;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(password.Totp))
                {
                    if (record.CustomFields == null)
                    {
                        record.CustomFields = new Dictionary<string, object>();
                    }
                    record.CustomFields[TwoFactorCode] = password.Totp;
                }

                return record;
            }

            /// <summary>
            /// Converts a TypedRecord to ExportRecord
            /// </summary>
            public static ExportRecord ToExportRecord(this TypedRecord typed)
            {
                var record = new ExportRecord
                {
                    Uid = typed.Uid,
                    Title = typed.Title,
                    RecordType = typed.TypeName,
                    Notes = typed.Notes
                };

                var customFields = new Dictionary<string, object>();

                if (typed.Fields != null)
                {
                    foreach (var field in typed.Fields)
                    {
                        var fieldName = field.FieldName;
                        var fieldLabel = field.FieldLabel;

                        if (fieldName == "login" && IsValidFieldValue(field.ObjectValue))
                        {
                            record.Login = field.ObjectValue.ToString();
                        }
                        else if (fieldName == "password" && IsValidFieldValue(field.ObjectValue))
                        {
                            record.Password = field.ObjectValue.ToString();
                        }
                        else if (fieldName == "url" && IsValidFieldValue(field.ObjectValue))
                        {
                            record.LoginUrl = field.ObjectValue.ToString();
                        }
                        else if (fieldName == "oneTimeCode" && IsValidFieldValue(field.ObjectValue))
                        {
                            customFields[TwoFactorCode] = field.ObjectValue;
                        }
                        else
                        {
                            var key = string.IsNullOrEmpty(fieldLabel) 
                                ? $"${fieldName}" 
                                : $"${fieldName}:{fieldLabel}";
                            
                            if (IsValidFieldValue(field.ObjectValue))
                            {
                                customFields[key] = field.ObjectValue;
                            }
                        }
                    }
                }

                if (typed.Custom != null)
                {
                    foreach (var field in typed.Custom)
                    {
                        var fieldName = field.FieldName;
                        var fieldLabel = field.FieldLabel;
                        var key = string.IsNullOrEmpty(fieldLabel) 
                            ? $"${fieldName}" 
                            : $"${fieldName}:{fieldLabel}";
                        
                        if (IsValidFieldValue(field.ObjectValue))
                        {
                            customFields[key] = field.ObjectValue;
                        }
                    }
                }

                if (customFields.Count > 0)
                {
                    record.CustomFields = customFields;
                }

                return record;
            }

            /// <summary>
            /// Checks if field value has actual data (not empty string or empty passkey)
            /// </summary>
            private static bool IsValidFieldValue(object value)
            {
                if (value == null) return false;
                if (value is string s) return !string.IsNullOrEmpty(s);
                if (value is FieldTypePasskey p) return !string.IsNullOrEmpty(p.CredentialId) || p.PrivateKey != null;
                return true;
            }

            /// <summary>
            /// Converts a KeeperRecord (base class) to ExportRecord
            /// </summary>
            public static ExportRecord ToExportRecord(this KeeperRecord keeperRecord)
            {
                if (keeperRecord is PasswordRecord password)
                {
                    return password.ToExportRecord();
                }
                else if (keeperRecord is TypedRecord typed)
                {
                    return typed.ToExportRecord();
                }
                return null;
            }

            private static string GetFolderPath(IVaultData vault, string folderUid)
            {
                if (string.IsNullOrEmpty(folderUid))
                {
                    return "";
                }

                var path = new List<string>();
                var folder = folderUid;
                var visited = new HashSet<string>();

                while (!string.IsNullOrEmpty(folder) && visited.Add(folder))
                {
                    if (vault.TryGetFolder(folder, out var folderNode))
                    {
                        path.Add(folderNode.Name);
                        folder = folderNode.ParentUid;
                    }
                    else
                    {
                        break;
                    }
                }

                path.Reverse();
                return string.Join(BatchVaultOperations.PathDelimiter.ToString(), path);
            }

            /// <summary>
            /// Exports vault records to ExportFile format
            /// </summary>
            public static ExportFile ExportVault(
                this VaultOnline vault,
                IEnumerable<string> recordUids = null,
                bool includeSharedFolders = true)
            {
                var exportFile = new ExportFile();
                var recordsList = new List<ExportRecord>();
                var sharedFoldersList = new List<ExportSharedFolder>();

                var folderPaths = new Dictionary<string, string>();
                foreach (var folder in vault.Folders)
                {
                    try
                    {
                        var path = GetFolderPath(vault, folder.FolderUid);
                        if (!string.IsNullOrEmpty(path))
                        {
                            folderPaths[folder.FolderUid] = path;
                        }
                    }
                    catch
                    {
                        // Ignore folders we can't access
                    }
                }

                if (includeSharedFolders)
                {
                    foreach (var sf in vault.SharedFolders)
                    {
                        var path = folderPaths.ContainsKey(sf.Uid) ? folderPaths[sf.Uid] : sf.Name;
                        var exportSf = new ExportSharedFolder
                        {
                            Uid = sf.Uid,
                            Path = path,
                            CanEdit = sf.DefaultCanEdit,
                            CanShare = sf.DefaultCanShare,
                            ManageUsers = sf.DefaultManageUsers,
                            ManageRecords = sf.DefaultManageRecords
                        };

                        if (sf.UsersPermissions != null && sf.UsersPermissions.Count > 0)
                        {
                            var permissions = new List<ExportSharedFolderPermissions>();
                            foreach (var perm in sf.UsersPermissions)
                            {
                                permissions.Add(new ExportSharedFolderPermissions
                                {
                                    Uid = perm.Uid,
                                    Name = perm.Name,
                                    ManageUsers = perm.ManageUsers,
                                    ManageRecords = perm.ManageRecords
                                });
                            }
                            exportSf.Permissions = permissions.ToArray();
                        }

                        sharedFoldersList.Add(exportSf);
                    }
                }

                var recordFoldersMap = new Dictionary<string, List<string>>();
                foreach (var folder in vault.Folders)
                {
                    foreach (var recordUid in folder.Records)
                    {
                        if (!recordFoldersMap.ContainsKey(recordUid))
                        {
                            recordFoldersMap[recordUid] = new List<string>();
                        }
                        recordFoldersMap[recordUid].Add(folder.FolderUid);
                    }
                }

                var recordsToExport = recordUids != null 
                    ? vault.KeeperRecords.Where(r => recordUids.Contains(r.Uid))
                    : vault.KeeperRecords;

                foreach (var record in recordsToExport)
                {
                    try
                    {
                        var exportRecord = record.ToExportRecord();
                        if (exportRecord != null)
                        {
                            if (recordFoldersMap.TryGetValue(record.Uid, out var recordFolderUids) && recordFolderUids.Any())
                            {
                                var exportFolders = new List<ExportRecordFolder>();
                                foreach (var folderUid in recordFolderUids)
                                {
                                    if (!vault.TryGetFolder(folderUid, out var folder))
                                    {
                                        continue;
                                    }

                                    var exportFolder = new ExportRecordFolder();
                                    
                                    if (!string.IsNullOrEmpty(folder.SharedFolderUid))
                                    {
                                        if (vault.TryGetSharedFolder(folder.SharedFolderUid, out var sharedFolder))
                                        {
                                            var sharedFolderPath = folderPaths.ContainsKey(sharedFolder.Uid) 
                                                ? folderPaths[sharedFolder.Uid] 
                                                : sharedFolder.Name;
                                            exportFolder.SharedFolderPath = sharedFolderPath;
                                            
                                            if (folderPaths.ContainsKey(folderUid))
                                            {
                                                var fullPath = folderPaths[folderUid];
                                                if (fullPath.StartsWith(sharedFolderPath))
                                                {
                                                    var relativePath = fullPath.Substring(sharedFolderPath.Length);
                                                    if (relativePath.StartsWith(BatchVaultOperations.PathDelimiter.ToString()))
                                                    {
                                                        relativePath = relativePath.Substring(1);
                                                    }
                                                    if (!string.IsNullOrEmpty(relativePath))
                                                    {
                                                        exportFolder.FolderPath = relativePath;
                                                    }
                                                }
                                            }
                                            
                                            var recordPermission = sharedFolder.RecordPermissions?
                                                .FirstOrDefault(rp => rp.RecordUid == record.Uid);
                                            if (recordPermission != null)
                                            {
                                                exportFolder.CanEdit = recordPermission.CanEdit;
                                                exportFolder.CanShare = recordPermission.CanShare;
                                            }
                                        }
                                    }
                                    else if (folder.FolderType == FolderType.SharedFolder)
                                    {
                                        if (vault.TryGetSharedFolder(folder.FolderUid, out var sharedFolder))
                                        {
                                            var sharedFolderPath = folderPaths.ContainsKey(sharedFolder.Uid) 
                                                ? folderPaths[sharedFolder.Uid] 
                                                : sharedFolder.Name;
                                            exportFolder.SharedFolderPath = sharedFolderPath;
                                            
                                            var recordPermission = sharedFolder.RecordPermissions?
                                                .FirstOrDefault(rp => rp.RecordUid == record.Uid);
                                            if (recordPermission != null)
                                            {
                                                exportFolder.CanEdit = recordPermission.CanEdit;
                                                exportFolder.CanShare = recordPermission.CanShare;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        if (folderPaths.ContainsKey(folderUid))
                                        {
                                            exportFolder.FolderPath = folderPaths[folderUid];
                                        }
                                    }
                                    
                                    exportFolders.Add(exportFolder);
                                }
                                
                                if (exportFolders.Count > 0)
                                {
                                    exportRecord.Folders = exportFolders.ToArray();
                                }
                            }

                            var clientModifiedMs = record.ClientModified.ToUnixTimeMilliseconds();
                            if (clientModifiedMs > 0)
                            {
                                exportRecord.LastModified = clientModifiedMs / 1000;
                            }

                            recordsList.Add(exportRecord);
                        }
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceWarning($"Failed to export record {record.Uid}: {ex.Message}");
                    }
                }

                if (recordsList.Count > 0)
                {
                    exportFile.Records = recordsList.ToArray();
                }

                if (sharedFoldersList.Count > 0)
                {
                    exportFile.SharedFolders = sharedFoldersList.ToArray();
                }

                return exportFile;
            }

            /// <summary>
            /// Exports vault to JSON string
            /// </summary>
            public static string ExportVaultToJson(
                this VaultOnline vault,
                IEnumerable<string> recordUids = null,
                bool includeSharedFolders = true)
            {
                var exportFile = vault.ExportVault(recordUids, includeSharedFolders);
                var jsonBytes = JsonUtils.DumpJson(exportFile, indent: true);
                return System.Text.Encoding.UTF8.GetString(jsonBytes).Replace("\\/", "/");
            }

            /// <summary>
            /// Exports vault to JSON file
            /// </summary>
            public static Task ExportVaultToFile(
                this VaultOnline vault,
                string filename,
                IEnumerable<string> recordUids = null,
                bool includeSharedFolders = true)
            {
                var json = vault.ExportVaultToJson(recordUids, includeSharedFolders);
                System.IO.File.WriteAllText(filename, json);
                Trace.TraceInformation($"Exported to {filename}");
                return Task.CompletedTask;
            }
        }
    }
}

