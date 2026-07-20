using KeeperSecurity.Commands;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
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
            [DataMember(Name = "uid", EmitDefaultValue = false)]
            public string Uid { get; set; }

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

            internal static void PopulatePasswordRecord(this ImportRecord import, PasswordRecord password)
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

            internal static Tuple<string, string> SplitFieldKey(string fieldKey)
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

            static void AssignValueToField(this ITypedField field, object value)
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
                                // Prefer ObjectValue path (same coercion style NSF uses for nested objects).
                                field.ObjectValue = dict;
                                break;
                            }
                        default:
                            Trace.TraceWarning(
                                $"Field \"${field.FieldName}.{field.FieldLabel}\": Provided value is not supported");
                            break;
                        }
                    }
                }
            }

            internal static void PopulateTypedRecord(this ImportRecord import, TypedRecord typed, RecordTypeField[] schemaFields)
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
                            field.AssignValueToField(value);
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
                            field.AssignValueToField(value);
                            typed.Custom.Add(field);
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError($"Create field \"{fk}\" error: {e.Message}");
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

            private static object UnwrapInteropValue(object value)
            {
                while (value != null)
                {
                    var type = value.GetType();
                    if (!string.Equals(type.FullName, "System.Management.Automation.PSObject", StringComparison.Ordinal))
                    {
                        return value;
                    }

                    var baseObject = type.GetProperty("BaseObject")?.GetValue(value);
                    if (baseObject == null || ReferenceEquals(baseObject, value))
                    {
                        return value;
                    }

                    value = baseObject;
                }

                return null;
            }

            private static IDictionary<string, object> AsStringObjectDictionary(object value)
            {
                value = UnwrapInteropValue(value);
                if (value is IDictionary<string, object> typed)
                {
                    var normalized = new Dictionary<string, object>(typed.Count);
                    foreach (var pair in typed)
                    {
                        normalized[pair.Key] = NormalizeImportValue(pair.Value);
                    }

                    return normalized;
                }

                if (value is not IDictionary dictionary)
                {
                    return null;
                }

                var result = new Dictionary<string, object>();
                foreach (DictionaryEntry entry in dictionary)
                {
                    if (entry.Key is not string key)
                    {
                        continue;
                    }

                    result[key] = NormalizeImportValue(entry.Value);
                }

                return result;
            }

            private static object NormalizeImportValue(object value)
            {
                value = UnwrapInteropValue(value);
                if (value is IDictionary<string, object> typed)
                {
                    var nested = new Dictionary<string, object>(typed.Count);
                    foreach (var pair in typed)
                    {
                        nested[pair.Key] = NormalizeImportValue(pair.Value);
                    }

                    return nested;
                }

                if (value is IDictionary dictionary)
                {
                    return AsStringObjectDictionary(dictionary);
                }

                if (value is Array array)
                {
                    var items = new object[array.Length];
                    for (var i = 0; i < array.Length; i++)
                    {
                        items[i] = NormalizeImportValue(array.GetValue(i));
                    }

                    return items;
                }

                return value;
            }

            /// <summary>
            /// Parses JSON object to import type
            /// </summary>
            /// <param name="importFile">parsed JSON import file</param>
            /// <returns>parsed import object</returns>
            private static IEnumerable<object> EnumerateImportItems(object value)
            {
                value = UnwrapInteropValue(value);
                if (value == null)
                {
                    yield break;
                }

                if (value is string || value is ValueType)
                {
                    yield break;
                }

                if (value is Array array)
                {
                    for (var i = 0; i < array.Length; i++)
                    {
                        yield return array.GetValue(i);
                    }

                    yield break;
                }

                // PowerShell unwraps single-element arrays to the element itself.
                if (value is IDictionary || value is IDictionary<string, object>)
                {
                    yield return value;
                    yield break;
                }

                if (value is IEnumerable enumerable)
                {
                    foreach (var item in enumerable)
                    {
                        yield return item;
                    }
                }
            }

            private static ImportRecord ParseImportRecord(IDictionary<string, object> record)
            {
                var rec = new ImportRecord();
                foreach (var pair in record)
                {
                    switch (pair.Key)
                    {
                        case "title":
                            rec.Title = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "uid":
                            rec.Uid = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "$type":
                            rec.RecordType = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "login":
                            rec.Login = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "password":
                            rec.Password = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "login_url":
                            rec.LoginUrl = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "notes":
                            rec.Notes = pair.Value as string ?? pair.Value?.ToString();
                            break;
                        case "folders":
                        {
                            var fl = new List<ImportRecordFolder>();
                            foreach (var fo in EnumerateImportItems(pair.Value))
                            {
                                var folder = AsStringObjectDictionary(fo);
                                if (folder == null)
                                {
                                    continue;
                                }

                                var irf = new ImportRecordFolder();
                                foreach (var fp in folder)
                                {
                                    switch (fp.Key)
                                    {
                                        case "folder":
                                            irf.FolderName = fp.Value as string ?? fp.Value?.ToString();
                                            break;
                                        case "shared_folder":
                                            irf.SharedFolderName = fp.Value as string ?? fp.Value?.ToString();
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

                            if (fl.Count > 0)
                            {
                                rec.Folders = fl.ToArray();
                            }
                        }
                            break;
                        case "custom_fields":
                            rec.CustomFields = AsStringObjectDictionary(pair.Value);
                            break;
                    }
                }

                return rec;
            }

            public static ImportFile LoadJsonDictionary(IDictionary<string, object> importFile)
            {
                var import = new ImportFile();
                if (importFile.TryGetValue("records", out var r))
                {
                    var recordList = new List<ImportRecord>();
                    foreach (var ro in EnumerateImportItems(r))
                    {
                        var record = AsStringObjectDictionary(ro);
                        if (record == null)
                        {
                            continue;
                        }

                        recordList.Add(ParseImportRecord(record));
                    }

                    import.Records = recordList.ToArray();
                }

                if (importFile.TryGetValue("shared_folders", out var sfs))
                {
                    var sharedFolderList = new List<ImportSharedFolder>();
                    foreach (var sfo in EnumerateImportItems(sfs))
                    {
                        var sharedFolder = AsStringObjectDictionary(sfo);
                        if (sharedFolder == null)
                        {
                            continue;
                        }

                        var sf = new ImportSharedFolder();
                        foreach (var pair in sharedFolder)
                        {
                            switch (pair.Key)
                            {
                                case "path":
                                    sf.Path = pair.Value as string ?? pair.Value?.ToString();
                                    break;
                                case "can_edit":
                                    sf.CanEdit = pair.Value is true;
                                    break;
                                case "can_share":
                                    sf.CanShare = pair.Value is true;
                                    break;
                                case "manage_records":
                                    sf.ManageRecords = pair.Value is true;
                                    break;
                                case "manage_users":
                                    sf.ManageUsers = pair.Value is true;
                                    break;
                                case "permissions":
                                {
                                    var permissions = new List<ImportSharedFolderPermissions>();
                                    foreach (var sfp in EnumerateImportItems(pair.Value))
                                    {
                                        var permission = AsStringObjectDictionary(sfp);
                                        if (permission == null)
                                        {
                                            continue;
                                        }

                                        var perm = new ImportSharedFolderPermissions();
                                        foreach (var ppair in permission)
                                        {
                                            switch (ppair.Key)
                                            {
                                                case "uid":
                                                    perm.Uid = (ppair.Value ?? String.Empty).ToString();
                                                    break;
                                                case "name":
                                                    perm.Name = (ppair.Value ?? String.Empty).ToString();
                                                    break;
                                                case "manage_records":
                                                    perm.ManageRecords = ppair.Value is true;
                                                    break;
                                                case "manage_users":
                                                    perm.ManageUsers = ppair.Value is true;
                                                    break;
                                            }
                                        }

                                        permissions.Add(perm);
                                    }

                                    if (permissions.Count > 0)
                                    {
                                        sf.Permissions = permissions.ToArray();
                                    }
                                }
                                    break;
                            }
                        }

                        sharedFolderList.Add(sf);
                    }

                    import.SharedFolders = sharedFolderList.ToArray();
                }

                return import;
            }

            /// <summary>
            /// Import Keeper JSON file
            /// </summary>
            /// <param name="vault">Vault instance</param>
            /// <param name="import">Import object</param>
            /// <returns></returns>
            public static async Task<BatchResult> ImportJson(this VaultOnline vault, ImportFile import)
            {
                var bo = new BatchVaultOperations(vault);

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

                            // Snapshot custom_fields before PopulateTypedRecord mutates/removes keys.
                            var customSnapshot = record.CustomFields != null
                                ? new Dictionary<string, object>(record.CustomFields)
                                : null;

                            var typedRecord = new TypedRecord(record.RecordType);
                            record.PopulateTypedRecord(typedRecord, recordType.Fields);

                            // Re-apply nested custom_fields dictionaries onto any schema/custom fields
                            // that did not receive values (classic vault import parity with NSF).
                            ApplyImportCustomFieldDictionaries(typedRecord, customSnapshot);

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
                                    if (f.SharedFolderName.EndsWith(BatchVaultOperations.PathDelimiter.ToString()))
                                    {
                                        f.SharedFolderName =
                                            f.SharedFolderName.Substring(0, f.SharedFolderName.Length - 1);
                                    }

                                    path = string.IsNullOrEmpty(path)
                                        ? f.SharedFolderName
                                        : f.SharedFolderName + BatchVaultOperations.PathDelimiter + path;
                                }

                                folder = bo.GetFolderByPath(path) ?? bo.CreateFolderPath(path);
                            }
                        }

                        bo.AddRecord(keeperRecord, folder);
                    }
                }

                return await bo.ApplyChanges();
            }

            /// <summary>
            /// Converts import records to Keeper NSF batch create requests.
            /// Uses the same record JSON shape as <see cref="ImportJson"/> / Export-KeeperVault.
            /// Folder placement uses <c>folders[].folder</c> as an NSF folder name or UID;
            /// <c>can_edit</c>, <c>can_share</c>, and <c>shared_folder</c> are ignored.
            /// </summary>
            public static IReadOnlyList<KeeperNSFRecordCreateRequest> ToKeeperNSFCreateRequests(
                VaultOnline vault,
                ImportFile import,
                string defaultFolderUid = null)
            {
                if (vault == null)
                {
                    throw new ArgumentNullException(nameof(vault));
                }

                if (import?.Records == null || import.Records.Length == 0)
                {
                    throw new ArgumentException("Import file contains no records.", nameof(import));
                }

                var requests = new List<KeeperNSFRecordCreateRequest>(import.Records.Length);
                for (var i = 0; i < import.Records.Length; i++)
                {
                    var record = import.Records[i];
                    if (record == null)
                    {
                        throw new VaultException($"Import record at index {i} is null.");
                    }

                    if (string.IsNullOrWhiteSpace(record.Title))
                    {
                        throw new VaultException($"Each import record must include a title (index {i}).");
                    }

                    requests.Add(new KeeperNSFRecordCreateRequest
                    {
                        Title = record.Title.Trim(),
                        RecordType = string.IsNullOrEmpty(record.RecordType) ? "login" : record.RecordType,
                        Notes = record.Notes,
                        FolderUid = ResolveKeeperNSFFolderUid(vault, record, defaultFolderUid),
                        Fields = BuildNsfFieldsFromImportRecord(vault, record),
                    });
                }

                return requests;
            }

            /// <summary>
            /// Converts import records to Keeper NSF batch update requests.
            /// Uses the same record JSON shape as <see cref="ImportJson"/> / Export-KeeperVault.
            /// Each record must include <c>uid</c>. <c>folders</c> and <c>shared_folders</c> are ignored.
            /// Null properties leave existing values unchanged; empty strings clear title/notes/login/password/url
            /// when those keys were present in the import JSON.
            /// </summary>
            public static IReadOnlyList<KeeperNSFRecordUpdateRequest> ToKeeperNSFUpdateRequests(
                VaultOnline vault,
                ImportFile import)
            {
                if (vault == null)
                {
                    throw new ArgumentNullException(nameof(vault));
                }

                if (import?.Records == null || import.Records.Length == 0)
                {
                    throw new ArgumentException("Import file contains no records.", nameof(import));
                }

                var requests = new List<KeeperNSFRecordUpdateRequest>(import.Records.Length);
                for (var i = 0; i < import.Records.Length; i++)
                {
                    var record = import.Records[i];
                    if (record == null)
                    {
                        throw new VaultException($"Import record at index {i} is null.");
                    }

                    if (string.IsNullOrWhiteSpace(record.Uid))
                    {
                        throw new VaultException($"Each update record must include a uid (index {i}).");
                    }

                    requests.Add(new KeeperNSFRecordUpdateRequest
                    {
                        RecordUid = record.Uid.Trim(),
                        // null = omit (leave unchanged); empty/whitespace = clear
                        Title = record.Title == null ? null : record.Title.Trim(),
                        RecordType = string.IsNullOrEmpty(record.RecordType) ? null : record.RecordType,
                        Notes = record.Notes,
                        Fields = HasImportFieldPayload(record)
                            ? BuildNsfFieldsFromImportRecord(vault, record)
                            : null,
                    });
                }

                return requests;
            }

            /// <summary>
            /// True when the import record explicitly provided login, password, URL, and/or custom fields
            /// (including empty strings, which clear those values on update).
            /// </summary>
            private static bool HasImportFieldPayload(ImportRecord import)
            {
                if (import == null)
                {
                    return false;
                }

                return import.Login != null
                    || import.Password != null
                    || import.LoginUrl != null
                    || (import.CustomFields != null && import.CustomFields.Count > 0);
            }

            private static string ResolveKeeperNSFFolderUid(
                VaultOnline vault,
                ImportRecord record,
                string defaultFolderUid)
            {
                if (record.Folders?.Length > 0)
                {
                    var folderRef = record.Folders[0].FolderName;
                    if (!string.IsNullOrWhiteSpace(folderRef)
                        && vault.TryResolveKeeperNSFFolder(folderRef.Trim(), out var folder))
                    {
                        return folder.FolderUid;
                    }
                }

                return string.IsNullOrWhiteSpace(defaultFolderUid) ? null : defaultFolderUid.Trim();
            }

            private static ImportRecord CloneImportRecord(ImportRecord import)
            {
                return new ImportRecord
                {
                    Uid = import.Uid,
                    Title = import.Title,
                    RecordType = import.RecordType,
                    Login = import.Login,
                    Password = import.Password,
                    LoginUrl = import.LoginUrl,
                    Notes = import.Notes,
                    CustomFields = import.CustomFields?.ToDictionary(entry => entry.Key, entry => entry.Value),
                    Folders = import.Folders?.Select(f => new ImportRecordFolder
                    {
                        FolderName = f.FolderName,
                        SharedFolderName = f.SharedFolderName,
                        CanEdit = f.CanEdit,
                        CanShare = f.CanShare,
                    }).ToArray(),
                };
            }

            private static void ApplyImportCustomFieldDictionaries(
                TypedRecord typed,
                IDictionary<string, object> customSnapshot)
            {
                if (typed == null || customSnapshot == null || customSnapshot.Count == 0)
                {
                    return;
                }

                foreach (var pair in customSnapshot)
                {
                    if (pair.Value is not IDictionary && pair.Value is not IDictionary<string, object>)
                    {
                        continue;
                    }

                    var split = SplitFieldKey(pair.Key);
                    var fieldType = split.Item1;
                    var fieldLabel = split.Item2;
                    if (string.IsNullOrEmpty(fieldType))
                    {
                        continue;
                    }

                    var field = typed.Fields.Concat(typed.Custom).FirstOrDefault(f =>
                        string.Equals(f.FieldName, fieldType, StringComparison.OrdinalIgnoreCase)
                        && (string.IsNullOrEmpty(fieldLabel)
                            || string.Equals(f.FieldLabel ?? string.Empty, fieldLabel, StringComparison.OrdinalIgnoreCase)));

                    if (field == null)
                    {
                        try
                        {
                            field = new RecordTypeField(fieldType, fieldLabel).CreateTypedField();
                            typed.Custom.Add(field);
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError($"Create field \"{pair.Key}\" error: {e.Message}");
                            continue;
                        }
                    }

                    if (field.Count == 0)
                    {
                        field.ObjectValue = pair.Value;
                    }
                }
            }

            private static IDictionary<string, object> BuildNsfFieldsFromImportRecord(
                VaultOnline vault,
                ImportRecord import)
            {
                var copy = CloneImportRecord(import);
                if (string.IsNullOrEmpty(copy.RecordType))
                {
                    return BuildNsfFieldsFromLegacyImportRecord(copy);
                }

                // Start from raw custom_fields dictionaries so complex objects (host, paymentCard, …)
                // survive even when typed schema matching is incomplete. NSF CoerceNsfFieldValue
                // converts these dictionaries into typed field objects.
                var fields = BuildNsfFieldsFromLegacyImportRecord(copy);

                var recordTypeName = copy.RecordType;
                if (!vault.TryGetRecordTypeByName(recordTypeName, out var recordType))
                {
                    recordTypeName = "login";
                    vault.TryGetRecordTypeByName(recordTypeName, out recordType);
                }

                var typed = new TypedRecord(recordTypeName);
                copy.PopulateTypedRecord(typed, recordType.Fields);
                foreach (var pair in ExtractNsfFieldsFromTypedRecord(typed))
                {
                    fields[pair.Key] = pair.Value;
                }

                return fields;
            }

            private static IDictionary<string, object> BuildNsfFieldsFromLegacyImportRecord(ImportRecord import)
            {
                var fields = new Dictionary<string, object>();
                // null = omitted from import JSON; empty string clears the field on update.
                if (import.Login != null)
                {
                    fields["login"] = import.Login;
                }

                if (import.Password != null)
                {
                    fields["password"] = import.Password;
                }

                if (import.LoginUrl != null)
                {
                    fields["url"] = import.LoginUrl;
                }

                if (import.CustomFields == null)
                {
                    return fields;
                }

                foreach (var pair in import.CustomFields)
                {
                    if (pair.Value == null)
                    {
                        continue;
                    }

                    if (string.Equals(pair.Key, TwoFactorCode, StringComparison.Ordinal))
                    {
                        fields["oneTimeCode"] = pair.Value;
                        continue;
                    }

                    var split = SplitFieldKey(pair.Key);
                    var fieldType = split.Item1;
                    var fieldLabel = split.Item2;
                    if (string.IsNullOrEmpty(fieldType))
                    {
                        continue;
                    }

                    var key = string.IsNullOrEmpty(fieldLabel)
                        ? fieldType
                        : $"{fieldType}:{fieldLabel}";
                    fields[key] = pair.Value;
                }

                return fields;
            }

            private static IDictionary<string, object> ExtractNsfFieldsFromTypedRecord(TypedRecord typed)
            {
                var fields = new Dictionary<string, object>();
                foreach (var field in typed.Fields.Concat(typed.Custom))
                {
                    if (string.IsNullOrEmpty(field.FieldName) || field.Count == 0)
                    {
                        continue;
                    }

                    // Use GetValueAt (not ObjectValue) so empty schema fields are not auto-materialized.
                    var value = field.GetValueAt(0);
                    if (!HasNsfFieldValue(value))
                    {
                        continue;
                    }

                    // Preserve labeled fields (e.g. address:Work) so same-type fields do not collapse.
                    var key = string.IsNullOrEmpty(field.FieldLabel)
                        ? field.FieldName
                        : $"{field.FieldName}:{field.FieldLabel}";
                    fields[key] = value;
                }

                return fields;
            }

            private static bool HasNsfFieldValue(object value)
            {
                if (value == null)
                {
                    return false;
                }

                if (value is string text)
                {
                    return !string.IsNullOrEmpty(text);
                }

                if (value is IFieldTypeSerialize serializer)
                {
                    return serializer.ElementValues.Any(v => !string.IsNullOrEmpty(v));
                }

                if (value is IDictionary dictionary)
                {
                    return dictionary.Count > 0;
                }

                return true;
            }
        }
    }
}
