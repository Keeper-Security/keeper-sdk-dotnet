﻿using KeeperSecurity.Commands;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading.Tasks;

namespace KeeperSecurity
{
    namespace Commands
    {
        [DataContract]
        public class ImportRecordFolder
        {
            [DataMember(Name = "folder", EmitDefaultValue = false)]
            public string FolderName { get; set; }

            [DataMember(Name = "shared_folder", EmitDefaultValue = false)]
            public string SharedFolderName { get; set; }

            [DataMember(Name = "can_edit", EmitDefaultValue = false)]
            public bool? CanEdit { get; set; }

            [DataMember(Name = "can_share", EmitDefaultValue = false)]
            public bool? CanShare { get; set; }
        }


        [DataContract]
        public class ImportRecord
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
            public ImportRecordFolder[] Folders { get; set; }
        }

        [DataContract]
        public class ImportSharedFolderPermissions
        {
            [DataMember(Name = "uid", EmitDefaultValue = false)]
            public string Uid { get; set; }

            [DataMember(Name = "name")] public string Name { get; set; }

            [DataMember(Name = "manage_users", EmitDefaultValue = false)]
            public bool? ManageUsers { get; set; }

            [DataMember(Name = "manage_records", EmitDefaultValue = false)]
            public bool? ManageRecords { get; set; }
        }

        [DataContract]
        public class ImportSharedFolder
        {
            [DataMember(Name = "path", EmitDefaultValue = false)]
            public string Path { get; set; }

            [DataMember(Name = "can_edit")] public bool CanEdit { get; set; }
            [DataMember(Name = "can_share")] public bool CanShare { get; set; }
            [DataMember(Name = "manage_users")] public bool ManageUsers { get; set; }
            [DataMember(Name = "manage_records")] public bool ManageRecords { get; set; }

            [DataMember(Name = "permissions")] public ImportSharedFolderPermissions[] Permissions { get; set; }
        }

        [DataContract]
        public class ImportFile
        {
            [DataMember(Name = "records")] public ImportRecord[] Records { get; set; }
            [DataMember(Name = "shared_folders")] public ImportSharedFolder[] SharedFolders { get; set; }
        }
    }

    namespace Vault
    {
        /// <summary>
        /// Keeper Import methods
        /// </summary>
        public static class KeeperImport
        {
            private const string TwoFactorCode = "TFC:Keeper";

            private static void PopulatePasswordRecord(this ImportRecord import, PasswordRecord password)
            {
                password.Uid = import.Uid;
                password.Title = import.Title;
                password.Login = import.Login;
                password.Password = import.Password;
                password.Link = import.LoginUrl;
                password.Notes = import.Notes;
                if (import.CustomFields != null)
                {
                    foreach (var pair in import.CustomFields)
                    {
                        var name = pair.Key;
                        var value = pair.Value;
                        if (value == null) continue;

                        if (value is string strValue && !string.IsNullOrEmpty(strValue))
                        {
                            if (name == TwoFactorCode)
                            {
                                password.Totp = strValue.StartsWith("otpauth://")
                                    ? strValue
                                    : $"otpauth://totp/?secret={strValue}";
                            }
                            else
                            {
                                password.SetCustomField(name, strValue);
                            }
                        }
                    }
                }
            }

            private static Tuple<string, string> SplitFieldKey(string fieldKey)
            {
                string fieldType;
                var fieldLabel = "";
                const char separator = ':';
                if (fieldKey.StartsWith("$"))
                {
                    var pos = fieldKey.IndexOf(separator);
                    if (pos > 0)
                    {
                        fieldType = fieldKey.Substring(1, pos - 1);
                        fieldLabel = fieldKey.Substring(pos + 1);
                    }
                    else
                    {
                        fieldType = fieldKey.Substring(1);
                    }
                }
                else
                {
                    fieldType = "text";
                    fieldLabel = fieldKey;
                }

                if (!string.IsNullOrEmpty(fieldLabel))
                {
                    var indexPos = fieldLabel.LastIndexOf(separator);
                    if (indexPos == fieldLabel.Length - 2)
                    {
                        var lastCh = fieldLabel[fieldLabel.Length - 1];
                        if (char.IsDigit(lastCh))
                        {
                            fieldLabel = fieldLabel.Substring(0, indexPos);
                        }
                    }
                }

                if (!string.IsNullOrEmpty(fieldType))
                {
                    if (!RecordTypesConstants.TryGetRecordField(fieldType, out _))
                    {
                        if (string.IsNullOrEmpty(fieldLabel))
                        {
                            fieldLabel = fieldType;
                        }

                        fieldType = "text";
                    }
                }

                return Tuple.Create(fieldType, fieldLabel);
            }

            static void AssignValueToField(this ITypedField field, object value, Action<Severity, string> logger)
            {
                if (value is string str && field is ISerializeTypedField sf)
                {
                    sf.ImportTypedField(str);
                }
                else
                {
                    IEnumerable<object> Values()
                    {
                        if (value != null)
                        {
                            if (value is Array arr)
                            {
                                for (var i = 0; i < arr.Length; i++)
                                {
                                    var v = arr.GetValue(i);
                                    if (v != null)
                                    {
                                        yield return v;
                                    }
                                }
                            }
                            else
                            {
                                yield return value;
                            }
                        }
                    }

                    foreach (var v in Values())
                    {
                        switch (v)
                        {
                            case string sv when field is TypedField<string> ls:
                            {
                                if (!string.IsNullOrEmpty(sv))
                                {
                                    ls.Values.Add(sv);
                                }

                                break;
                            }
                            case bool bv when field is TypedField<bool> lb:
                                lb.Values.Add(bv);
                                break;
                            case IConvertible conv when field is TypedField<long> lf:
                            {
                                var lv = conv.ToInt64(CultureInfo.InvariantCulture);
                                if (lv > 0)
                                {
                                    lf.Values.Add(lv);
                                }

                                break;
                            }
                            case IDictionary dict:
                            {
                                var obj = field.AppendValue();
                                if (obj is IFieldTypeSerialize fts)
                                {
                                    foreach (var key in dict.Keys)
                                    {
                                        var val = dict[key];
                                        if (key is string element && val is string elementValue)
                                        {
                                            if (!fts.SetElementValue(element, elementValue))
                                            {
                                                if (!string.IsNullOrEmpty(elementValue))
                                                {
                                                    logger?.Invoke(Severity.Warning,
                                                        $"Field \"${field.FieldName}.{field.FieldLabel}\": Unsupported element \"{element}\"");
                                                }
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    logger?.Invoke(Severity.Warning,
                                        $"Field \"${field.FieldName}.{field.FieldLabel}\": IFieldTypeSerialize interface is not supported");
                                }

                                break;
                            }
                            default:
                                logger?.Invoke(Severity.Warning,
                                    $"Field \"${field.FieldName}.{field.FieldLabel}\": Provided value is not supported");
                                break;
                        }
                    }
                }
            }

            static void PopulateTypedRecord(this ImportRecord import, TypedRecord typed, RecordTypeField[] schemaFields,
                Action<Severity, string> logger)
            {
                typed.Uid = import.Uid;
                typed.Title = import.Title;
                typed.Notes = import.Notes;

                Dictionary<string, object> customFields = null;
                if (import.CustomFields != null)
                {
                    customFields = import.CustomFields.ToDictionary(entry => entry.Key, entry => entry.Value);
                    if (customFields.TryGetValue(TwoFactorCode, out var tfa))
                    {
                        customFields["$oneTimeCode"] = tfa;
                        customFields.Remove(TwoFactorCode);
                    }
                }

                foreach (var schemaField in schemaFields)
                {
                    var field = schemaField.CreateTypedField();
                    typed.Fields.Add(field);

                    if (schemaField.FieldName == "login" && !string.IsNullOrEmpty(import.Login))
                    {
                        field.ObjectValue = import.Login;
                        import.Login = null;
                    }
                    else if (schemaField.FieldName == "password" && !string.IsNullOrEmpty(import.Password))
                    {
                        field.ObjectValue = import.Password;
                        import.Password = null;
                    }
                    else if (schemaField.FieldName == "url" && !string.IsNullOrEmpty(import.LoginUrl))
                    {
                        field.ObjectValue = import.LoginUrl;
                        import.LoginUrl = null;
                    }
                    else if (schemaField.FieldName.EndsWith("Ref"))
                    {
                        // TODO
                    }
                    else if (customFields != null)
                    {
                        var key = "";
                        var ignoreLabel = schemaField.RecordField != null &&
                                          schemaField.RecordField.Multiple != RecordFieldMultiple.Optional;
                        foreach (var fk in customFields.Keys)
                        {
                            var t = SplitFieldKey(fk);
                            if (t.Item1 == schemaField.FieldName ||
                                (string.IsNullOrEmpty(t.Item1) && schemaField.FieldName == "text"))
                            {
                                if (ignoreLabel || string.Equals(t.Item2, schemaField.FieldLabel,
                                        StringComparison.CurrentCultureIgnoreCase))
                                {
                                    key = fk;
                                    break;
                                }
                            }
                        }

                        if (string.IsNullOrEmpty(key)) continue;
                        if (!customFields.TryGetValue(key, out var value)) continue;
                        if (value != null)
                        {
                            field.AssignValueToField(value, logger);
                        }

                        customFields.Remove(key);
                    }
                }

                // custom fields
                if (!string.IsNullOrEmpty(import.Login))
                {
                    var tf = new RecordTypeField("login").CreateTypedField();
                    tf.ObjectValue = import.Login;
                    typed.Custom.Add(tf);
                }

                if (!string.IsNullOrEmpty(import.Password))
                {
                    var tf = new RecordTypeField("password").CreateTypedField();
                    tf.ObjectValue = import.Password;
                    typed.Custom.Add(tf);
                }

                if (!string.IsNullOrEmpty(import.LoginUrl))
                {
                    var tf = new RecordTypeField("url").CreateTypedField();
                    tf.ObjectValue = import.LoginUrl;
                    typed.Custom.Add(tf);
                }

                if (customFields != null)
                {
                    foreach (var pair in customFields)
                    {
                        var fk = pair.Key;
                        var value = pair.Value;
                        if (value == null)
                        {
                            continue;
                        }

                        var t = SplitFieldKey(fk);
                        var fieldType = t.Item1;
                        var fieldLabel = t.Item2;

                        try
                        {
                            var field = new RecordTypeField(fieldType, fieldLabel).CreateTypedField();
                            field.AssignValueToField(value, logger);
                            typed.Custom.Add(field);
                        }
                        catch (Exception e)
                        {
                            logger?.Invoke(Severity.Warning, $"Create field \"{fk}\" error: {e.Message}");
                        }
                    }
                }
            }

            private static FolderNode CreateFolderPath(this BatchVaultOperations bvo, string folderPath,
                SharedFolderOptions options = null)
            {
                FolderNode lastFolder = null;
                var path = BatchVaultOperations.ParseFolderPath(folderPath).ToArray();
                for (var i = 0; i < path.Length; i++)
                {
                    var currentPath = BatchVaultOperations.CreateFolderPath(path.Take(i + 1));
                    var folder = bvo.GetFolderByPath(currentPath) ??
                                 bvo.AddFolder(path[i], lastFolder?.FolderUid, i == path.Length - 1 ? options : null);
                    lastFolder = folder;
                }

                return lastFolder;
            }

            /// <summary>
            /// Parses JSON object to import type
            /// </summary>
            /// <param name="importFile">parsed JSON import file</param>
            /// <returns>parsed import object</returns>
            public static ImportFile LoadJsonDictionary(IDictionary<string, object> importFile)
            {
                var import = new ImportFile();
                if (importFile.TryGetValue("records", out var r))
                {
                    var recordList = new List<ImportRecord>();
                    if (r is Array records)
                    {
                        foreach (var ro in records)
                        {
                            if (ro is IDictionary<string, object> record)
                            {
                                var rec = new ImportRecord();
                                foreach (var pair in record)
                                {
                                    switch (pair.Key)
                                    {
                                        case "title":
                                            rec.Title = pair.Value as string;
                                            break;
                                        case "uid":
                                            rec.Uid = pair.Value as string;
                                            break;
                                        case "$type":
                                            rec.RecordType = pair.Value as string;
                                            break;
                                        case "login":
                                            rec.Login = pair.Value as string;
                                            break;
                                        case "password":
                                            rec.Password = pair.Value as string;
                                            break;
                                        case "login_url":
                                            rec.LoginUrl = pair.Value as string;
                                            break;
                                        case "notes":
                                            rec.Notes = pair.Value as string;
                                            break;
                                        case "folders":
                                        {
                                            if (pair.Value is Array folderArray)
                                            {
                                                var fl = new List<ImportRecordFolder>();
                                                foreach (var fo in folderArray)
                                                {
                                                    if (fo is IDictionary<string, object> folder)
                                                    {
                                                        var irf = new ImportRecordFolder();
                                                        foreach (var fp in folder)
                                                        {
                                                            switch (fp.Key)
                                                            {
                                                                case "folder":
                                                                    irf.FolderName = fp.Value as string;
                                                                    break;
                                                                case "shared_folder":
                                                                    irf.SharedFolderName = fp.Value as string;
                                                                    break;
                                                                case "can_edit":
                                                                    irf.CanEdit = fp.Value as bool?;
                                                                    break;
                                                                case "can_share":
                                                                    irf.CanShare = fp.Value as bool?;
                                                                    break;
                                                            }
                                                        }

                                                        fl.Add(irf);
                                                    }
                                                }

                                                rec.Folders = fl.ToArray();
                                            }
                                        }
                                            break;
                                        case "custom_fields":
                                            rec.CustomFields = pair.Value as IDictionary<string, object>;
                                            break;
                                    }
                                }

                                recordList.Add(rec);
                            }
                        }
                    }

                    import.Records = recordList.ToArray();
                }

                if (importFile.TryGetValue("shared_folders", out var sfs))
                {
                    var sharedFolderList = new List<ImportSharedFolder>();
                    if (sfs is Array sfArray)
                    {
                        foreach (var sfo in sfArray)
                        {
                            if (sfo is IDictionary<string, object> sharedFolder)
                            {
                                var sf = new ImportSharedFolder();
                                foreach (var pair in sharedFolder)
                                {

                                    switch (pair.Key)
                                    {
                                        case "path":
                                        {
                                            sf.Path = pair.Value as string;
                                        }
                                            break;
                                        case "can_edit":
                                        {
                                            sf.CanEdit = pair.Value is true;
                                        }
                                            break;
                                        case "can_share":
                                        {
                                            sf.CanShare = pair.Value is true;
                                        }
                                            break;
                                        case "manage_records":
                                        {
                                            sf.ManageRecords = pair.Value is true;
                                        }
                                            break;
                                        case "manage_users":
                                        {
                                            sf.ManageUsers = pair.Value is true;
                                        }
                                            break;
                                        case "permissions":
                                        {
                                            var permissions = new List<ImportSharedFolderPermissions>();
                                            if (pair.Value is Array ar)
                                            {
                                                foreach (var sfp in ar)
                                                {
                                                    if (sfp is not IDictionary<string, object> permission) continue;

                                                    var perm = new ImportSharedFolderPermissions();
                                                    foreach (var ppair in permission)
                                                    {
                                                        switch (ppair.Key)
                                                        {
                                                            case "uid":
                                                            {
                                                                perm.Uid = (ppair.Value ?? "").ToString();
                                                            }
                                                                break;
                                                            case "name":
                                                            {
                                                                perm.Name = (ppair.Value ?? "").ToString();
                                                            }
                                                                break;
                                                            case "manage_records":
                                                            {
                                                                perm.ManageRecords = ppair.Value is true;
                                                            }
                                                                break;
                                                            case "manage_users":
                                                            {
                                                                perm.ManageUsers = ppair.Value is true;
                                                            }
                                                                break;
                                                        }
                                                    }

                                                    permissions.Add(perm);
                                                }

                                                sf.Permissions = permissions.ToArray();
                                            }
                                        }
                                            break;
                                    }
                                }

                                sharedFolderList.Add(sf);
                            }
                        }

                        import.SharedFolders = sharedFolderList.ToArray();
                    }
                }

                return import;
            }

            /// <summary>
            /// Import Keeper JSON file
            /// </summary>
            /// <param name="vault">Vault instance</param>
            /// <param name="import">Import object</param>
            /// <param name="logger">Logger</param>
            /// <returns></returns>
            public static async Task<BatchResult> ImportJson(this VaultOnline vault, ImportFile import,
                Action<Severity, string> logger)
            {
                var bo = new BatchVaultOperations(vault)
                {
                    BatchLogger = logger
                };

                if (import.SharedFolders?.Length > 0)
                {
                    var teamLookup = new Dictionary<string, string>();
                    foreach (var team in await vault.GetTeamsForShare())
                    {
                        teamLookup[team.TeamUid] = team.TeamUid;
                        teamLookup[team.Name.ToLower()] = team.TeamUid;
                    }

                    foreach (var sharedFolder in import.SharedFolders)
                    {
                        if (!string.IsNullOrEmpty(sharedFolder.Path))
                        {
                            var folderNode = bo.GetFolderByPath(sharedFolder.Path);
                            if (folderNode == null)
                            {
                                SharedFolderOptions options = new SharedFolderOptions
                                {
                                    ManageRecords = sharedFolder.ManageRecords,
                                    ManageUsers = sharedFolder.ManageUsers,
                                    CanEdit = sharedFolder.CanEdit,
                                    CanShare = sharedFolder.CanShare,
                                };
                                folderNode = bo.CreateFolderPath(sharedFolder.Path, options);
                            }

                            if (folderNode != null && sharedFolder.Permissions != null)
                            {
                                foreach (var permission in sharedFolder.Permissions)
                                {
                                    string userId = null;
                                    UserType userType = UserType.Team;

                                    if (!string.IsNullOrEmpty(permission.Uid) && teamLookup.TryGetValue(permission.Uid, out var value1))
                                    {
                                        userId = value1;
                                    }
                                    else if (!string.IsNullOrEmpty(permission.Name))
                                    {
                                        var name = permission.Name.ToLower();
                                        if (teamLookup.TryGetValue(name, out var value))
                                        {
                                            userId = value;
                                        }
                                        else
                                        {
                                            try
                                            {
                                                _ = new System.Net.Mail.MailAddress(name);
                                                userId = name;
                                                userType = UserType.User;
                                            }
                                            catch
                                            {
                                                /*ignored*/
                                            }
                                        }
                                    }

                                    if (!string.IsNullOrEmpty(userId))
                                    {
                                        bo.PutUserToSharedFolder(folderNode.FolderUid, userId, userType,
                                            new SharedFolderUserOptions
                                            {
                                                ManageRecords = permission.ManageRecords,
                                                ManageUsers = permission.ManageUsers,
                                            });
                                    }
                                }
                            }
                        }
                    }
                }

                if (import.Records?.Length > 0)
                {
                    foreach (var record in import.Records)
                    {
                        if (!(record.Folders?.Length > 0)) continue;
                        foreach (var f in record.Folders)
                        {
                            if (string.IsNullOrEmpty(f.SharedFolderName)) continue;
                            var folderNode = bo.GetFolderByPath(f.SharedFolderName);
                            if (folderNode == null)
                            {
                                var options = new SharedFolderOptions
                                {
                                    ManageRecords = false,
                                    ManageUsers = false,
                                    CanEdit = false,
                                    CanShare = false,
                                };
                                bo.CreateFolderPath(f.SharedFolderName, options);
                            }
                        }
                    }
                }

                if (import.Records?.Length > 0)
                {
                    foreach (var record in import.Records)
                    {
                        KeeperRecord keeperRecord;
                        if (string.IsNullOrEmpty(record.RecordType))
                        {
                            var password = new PasswordRecord();
                            record.PopulatePasswordRecord(password);
                            keeperRecord = password;
                        }
                        else
                        {
                            if (!vault.TryGetRecordTypeByName(record.RecordType, out var recordType))
                            {
                                record.RecordType = "login";
                                vault.TryGetRecordTypeByName(record.RecordType, out recordType);
                            }

                            var typedRecord = new TypedRecord(record.RecordType);
                            record.PopulateTypedRecord(typedRecord, recordType.Fields, logger);
                            keeperRecord = typedRecord;
                        }

                        FolderNode folder = null;
                        if (record.Folders?.Length > 0)
                        {
                            var f = record.Folders[0];
                            if (!string.IsNullOrEmpty(f.FolderName) || !string.IsNullOrEmpty(f.SharedFolderName))
                            {
                                var path = string.IsNullOrEmpty(f.FolderName) ? "" : f.FolderName;
                                if (!string.IsNullOrEmpty(f.SharedFolderName))
                                {
                                    if (!string.IsNullOrEmpty(path))
                                    {
                                        if (f.SharedFolderName.EndsWith(BatchVaultOperations.PathDelimiter.ToString()))
                                        {
                                            f.SharedFolderName =
                                                f.SharedFolderName.Substring(0, f.SharedFolderName.Length - 1);
                                        }

                                        path = f.SharedFolderName + BatchVaultOperations.PathDelimiter + path;
                                    }
                                }

                                folder = bo.GetFolderByPath(path) ?? bo.CreateFolderPath(path);
                            }
                        }

                        bo.AddRecord(keeperRecord, folder);
                    }
                }

                return await bo.ApplyChanges();
            }
        }
    }
}
