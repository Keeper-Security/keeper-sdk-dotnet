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

        /// <summary>Name/value pair inside a structured custom field (e.g. hostName, port).</summary>
        public class ImportCustomFieldElement
        {
            /// <summary>Element name.</summary>
            public string Name { get; set; }

            /// <summary>Element value.</summary>
            public string Value { get; set; }
        }

        /// <summary>
        /// A single custom_fields entry from import JSON.
        /// Use <see cref="TextValue"/> for plain text, or <see cref="Elements"/> for objects like host/address.
        /// </summary>
        public class ImportCustomField
        {
            /// <summary>Field name, e.g. $host, $address:Work, TFC:Keeper.</summary>
            public string Name { get; set; }

            /// <summary>
            /// Plain text value. null = leave alone; "" = clear on update.
            /// Leave null when using <see cref="Elements"/>.
            /// </summary>
            public string TextValue { get; set; }

            /// <summary>Object-style value (host, address, etc.).</summary>
            public ImportCustomFieldElement[] Elements { get; set; }

            /// <summary>
            /// True if this field has something to write.
            /// Text that is not null counts (use "" to clear a field on update).
            /// Object fields count when Elements has at least one named entry; empty lists do not.
            /// </summary>
            public bool HasValue
            {
                get
                {
                    if (TextValue != null)
                    {
                        return true;
                    }

                    if (Elements == null)
                    {
                        return false;
                    }

                    for (var i = 0; i < Elements.Length; i++)
                    {
                        if (Elements[i]?.Name != null)
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
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

            /// <summary>
            /// Custom fields loaded from JSON. Not part of DataContract serialization.
            /// </summary>
            [IgnoreDataMember]
            public ImportCustomField[] CustomFields { get; set; }

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
        /// Helpers for Keeper import JSON — load files, import into the vault, or build NSF batch requests.
        /// </summary>
        public static class KeeperImport
        {
            private const string TwoFactorCode = "TFC:Keeper";

            /// <summary>
            /// Fills a PasswordRecord from an import record (login, password, notes, text custom fields).
            /// TFC:Keeper becomes Totp — accepts a full otpauth:// URL or a raw secret
            /// (spaces stripped, then wrapped as otpauth://totp/?secret=...).
            /// Object-style custom fields are skipped.
            /// </summary>
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
                    foreach (var customField in import.CustomFields)
                    {
                        if (customField == null || string.IsNullOrEmpty(customField.Name) || !customField.HasValue)
                        {
                            continue;
                        }

                        var strValue = customField.TextValue;
                        if (string.IsNullOrEmpty(strValue))
                        {
                            continue;
                        }

                        if (customField.Name == TwoFactorCode)
                        {
                            password.Totp = NormalizeImportTotpValue(strValue);
                        }
                        else
                        {
                            password.SetCustomField(customField.Name, strValue);
                        }
                    }
                }
            }

            /// <summary>
            /// Normalizes an import TOTP value for PasswordRecord / oneTimeCode.
            /// Full otpauth:// URLs are kept as-is. Anything else is treated as a secret
            /// (spaces removed) and wrapped as otpauth://totp/?secret=...
            /// Secrets are URL-encoded; base32 shape is not strictly validated here.
            /// </summary>
            private static string NormalizeImportTotpValue(string value)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }

                value = value.Trim();
                if (value.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
                {
                    return value;
                }

                var secret = value.Replace(" ", string.Empty);
                return $"otpauth://totp/?secret={Uri.EscapeDataString(secret)}";
            }

            /// <summary>
            /// Pulls field type and label out of a key like $host or $address:Work.
            /// Plain names become text fields.
            /// </summary>
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

            /// <summary>Sets a typed field from a string, array, or dictionary value.</summary>
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
                                var obj = field.AppendValue();
                                if (obj is IFieldTypeSerialize fts)
                                {
                                    foreach (var key in dict.Keys)
                                    {
                                        var val = dict[key];
                                        if (key is string element)
                                        {
                                            var elementValue = val is IDictionary d
                                                ? System.Text.Encoding.UTF8.GetString(Utils.JsonUtils.DumpJson(d))
                                                : val?.ToString();

                                            if (!string.IsNullOrEmpty(elementValue) && !fts.SetElementValue(element, elementValue))
                                            {
                                                Trace.TraceWarning(
                                                    $"Field \"${field.FieldName}.{field.FieldLabel}\": Unsupported element \"{element}\"");
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    Trace.TraceWarning(
                                        $"Field \"${field.FieldName}.{field.FieldLabel}\": IFieldTypeSerialize interface is not supported");
                                }

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

            /// <summary>
            /// Builds a TypedRecord from an import record.
            /// Duplicate custom field names log a warning and keep the last value.
            /// TFC:Keeper is mapped to $oneTimeCode (same otpauth / raw-secret rules as PasswordRecord).
            /// </summary>
            static void PopulateTypedRecord(this ImportRecord import, TypedRecord typed, RecordTypeField[] schemaFields)
            {
                typed.Uid = import.Uid;
                typed.Title = import.Title;
                typed.Notes = import.Notes;

                Dictionary<string, ImportCustomField> customFields = null;
                if (import.CustomFields != null)
                {
                    var customFieldGroups = import.CustomFields
                        .Where(f => f != null && !string.IsNullOrEmpty(f.Name))
                        .GroupBy(f => f.Name, StringComparer.Ordinal)
                        .ToList();

                    foreach (var duplicate in customFieldGroups.Where(g => g.Count() > 1))
                    {
                        var recordLabel = !string.IsNullOrEmpty(import.Title)
                            ? import.Title
                            : (!string.IsNullOrEmpty(import.Uid) ? import.Uid : "(untitled)");
                        Trace.TraceWarning(
                            $"Import record \"{recordLabel}\": custom field \"{duplicate.Key}\" appears {duplicate.Count()} times; using the last value.");
                    }

                    customFields = customFieldGroups
                        .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
                    if (customFields.TryGetValue(TwoFactorCode, out var tfa))
                    {
                        customFields["$oneTimeCode"] = new ImportCustomField
                        {
                            Name = "$oneTimeCode",
                            TextValue = string.IsNullOrEmpty(tfa.TextValue)
                                ? tfa.TextValue
                                : NormalizeImportTotpValue(tfa.TextValue),
                            Elements = tfa.Elements,
                        };
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
                        if (!customFields.TryGetValue(key, out var customField)) continue;
                        if (customField != null && customField.HasValue)
                        {
                            field.AssignValueToField(ToAssignValue(customField));
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
                        var customField = pair.Value;
                        if (customField == null || !customField.HasValue)
                        {
                            continue;
                        }

                        var t = SplitFieldKey(fk);
                        var fieldType = t.Item1;
                        var fieldLabel = t.Item2;

                        try
                        {
                            var field = new RecordTypeField(fieldType, fieldLabel).CreateTypedField();
                            field.AssignValueToField(ToAssignValue(customField));
                            typed.Custom.Add(field);
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError($"Create field \"{fk}\" error: {e.Message}");
                        }
                    }
                }
            }

            /// <summary>Creates any missing folders in the path for a batch import.</summary>
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
            /// Treats a JSON array or a single object the same (PowerShell often unwraps one-item arrays).
            /// </summary>
            private static IEnumerable<ImportJsonValue> EnumerateImportItems(ImportJsonValue value)
            {
                if (value == null || value.Kind == ImportJsonValue.JsonKind.Null)
                {
                    yield break;
                }

                if (value.Kind == ImportJsonValue.JsonKind.Array)
                {
                    if (value.ArrayValue == null)
                    {
                        yield break;
                    }

                    foreach (var item in value.ArrayValue)
                    {
                        yield return item;
                    }

                    yield break;
                }

                if (value.Kind == ImportJsonValue.JsonKind.Object)
                {
                    yield return value;
                }
            }

            /// <summary>Reads one record object from import JSON.</summary>
            private static ImportRecord ParseImportRecord(ImportJsonValue recordValue)
            {
                var rec = new ImportRecord();
                if (recordValue?.Kind != ImportJsonValue.JsonKind.Object || recordValue.ObjectValue == null)
                {
                    return rec;
                }

                foreach (var pair in recordValue.ObjectValue)
                {
                    switch (pair.Key)
                    {
                        case "title":
                            rec.Title = pair.Value?.AsString();
                            break;
                        case "uid":
                            rec.Uid = pair.Value?.AsString();
                            break;
                        case "$type":
                            rec.RecordType = pair.Value?.AsString();
                            break;
                        case "login":
                            rec.Login = pair.Value?.AsString();
                            break;
                        case "password":
                            rec.Password = pair.Value?.AsString();
                            break;
                        case "login_url":
                            rec.LoginUrl = pair.Value?.AsString();
                            break;
                        case "notes":
                            rec.Notes = pair.Value?.AsString();
                            break;
                        case "folders":
                        {
                            var fl = new List<ImportRecordFolder>();
                            foreach (var fo in EnumerateImportItems(pair.Value))
                            {
                                if (fo?.Kind != ImportJsonValue.JsonKind.Object || fo.ObjectValue == null)
                                {
                                    continue;
                                }

                                var irf = new ImportRecordFolder();
                                foreach (var fp in fo.ObjectValue)
                                {
                                    switch (fp.Key)
                                    {
                                        case "folder":
                                            irf.FolderName = fp.Value?.AsString();
                                            break;
                                        case "shared_folder":
                                            irf.SharedFolderName = fp.Value?.AsString();
                                            break;
                                        case "can_edit":
                                            irf.CanEdit = fp.Value?.AsBoolean();
                                            break;
                                        case "can_share":
                                            irf.CanShare = fp.Value?.AsBoolean();
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
                            rec.CustomFields = ParseCustomFieldsFromImportJson(pair.Value);
                            break;
                        case "fields":
                        {
                            var typedFields = ParseTypedFieldsFromImportJson(pair.Value);
                            if (typedFields != null && typedFields.Length > 0)
                            {
                                rec.CustomFields = (rec.CustomFields ?? Array.Empty<ImportCustomField>())
                                    .Concat(typedFields)
                                    .ToArray();
                            }
                        }
                            break;
                    }
                }

                return rec;
            }

            /// <summary>
            /// Loads an import file from typed JSON (preferred — keeps nested custom_fields intact).
            /// </summary>
            public static ImportFile LoadJsonDictionary(ImportJsonValue importFile)
            {
                if (importFile == null || importFile.Kind != ImportJsonValue.JsonKind.Object || importFile.ObjectValue == null)
                {
                    throw new ArgumentException("Import JSON root must be an object.", nameof(importFile));
                }

                var import = new ImportFile();
                if (importFile.ObjectValue.TryGetValue("records", out var recordsValue))
                {
                    var recordList = new List<ImportRecord>();
                    foreach (var ro in EnumerateImportItems(recordsValue))
                    {
                        recordList.Add(ParseImportRecord(ro));
                    }

                    import.Records = recordList.ToArray();
                }

                if (importFile.ObjectValue.TryGetValue("shared_folders", out var sharedFoldersValue))
                {
                    var sharedFolderList = new List<ImportSharedFolder>();
                    foreach (var sfo in EnumerateImportItems(sharedFoldersValue))
                    {
                        if (sfo?.Kind != ImportJsonValue.JsonKind.Object || sfo.ObjectValue == null)
                        {
                            continue;
                        }

                        var sf = new ImportSharedFolder();
                        foreach (var pair in sfo.ObjectValue)
                        {
                            switch (pair.Key)
                            {
                                case "path":
                                    sf.Path = pair.Value?.AsString();
                                    break;
                                case "can_edit":
                                    sf.CanEdit = pair.Value?.AsBoolean() == true;
                                    break;
                                case "can_share":
                                    sf.CanShare = pair.Value?.AsBoolean() == true;
                                    break;
                                case "manage_records":
                                    sf.ManageRecords = pair.Value?.AsBoolean() == true;
                                    break;
                                case "manage_users":
                                    sf.ManageUsers = pair.Value?.AsBoolean() == true;
                                    break;
                                case "permissions":
                                {
                                    var permissions = new List<ImportSharedFolderPermissions>();
                                    foreach (var sfp in EnumerateImportItems(pair.Value))
                                    {
                                        if (sfp?.Kind != ImportJsonValue.JsonKind.Object || sfp.ObjectValue == null)
                                        {
                                            continue;
                                        }

                                        var perm = new ImportSharedFolderPermissions();
                                        foreach (var ppair in sfp.ObjectValue)
                                        {
                                            switch (ppair.Key)
                                            {
                                                case "uid":
                                                    perm.Uid = ppair.Value?.AsString() ?? string.Empty;
                                                    break;
                                                case "name":
                                                    perm.Name = ppair.Value?.AsString() ?? string.Empty;
                                                    break;
                                                case "manage_records":
                                                    perm.ManageRecords = ppair.Value?.AsBoolean() == true;
                                                    break;
                                                case "manage_users":
                                                    perm.ManageUsers = ppair.Value?.AsBoolean() == true;
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

            /// <summary>Loads an import file from a plain dictionary (older path).</summary>
            public static ImportFile LoadJsonDictionary(IDictionary<string, object> importFile)
            {
                return LoadJsonDictionary(ImportJsonValue.FromLegacyObject(importFile));
            }

            /// <summary>
            /// Imports records and shared folders into the vault.
            /// </summary>
            /// <param name="vault">Vault to import into.</param>
            /// <param name="import">Parsed import data.</param>
            /// <returns>Batch result.</returns>
            public static Task<BatchResult> ImportJson(this VaultOnline vault, ImportFile import)
            {
                return ImportJson(vault, import, RecordMatch.AllFields);
            }

            /// <summary>
            /// Imports records and shared folders with an explicit record matching strategy.
            /// Use <see cref="RecordMatch.None"/> when every generated record must be created
            /// independently, even when its content matches an existing record.
            /// </summary>
            public static async Task<BatchResult> ImportJson(this VaultOnline vault, ImportFile import, RecordMatch recordMatch)
            {
                var bo = new BatchVaultOperations(vault, recordMatch);

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

                            var customSnapshot = record.CustomFields?
                                .Select(CloneImportCustomField)
                                .ToArray();

                            var typedRecord = new TypedRecord(record.RecordType);
                            record.PopulateTypedRecord(typedRecord, recordType.Fields);

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
            /// Turns import records into NSF create requests (same JSON layout as vault import).
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
                        Fields = ToNsfRequestFields(BuildNsfFieldsFromImportRecord(vault, record)),
                    });
                }

                return requests;
            }

            /// <summary>
            /// Turns import records into NSF update requests. Each record needs a uid.
            /// null = don't change; empty string = clear. Fields are only sent when the import included them.
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
                        Title = record.Title == null ? null : record.Title.Trim(),
                        RecordType = string.IsNullOrEmpty(record.RecordType) ? null : record.RecordType,
                        Notes = record.Notes,
                        Fields = HasImportFieldPayload(record)
                            ? ToNsfRequestFields(BuildNsfFieldsFromImportRecord(vault, record))
                            : null,
                    });
                }

                return requests;
            }

            /// <summary>True if the import has login, password, URL, or a custom field to apply.</summary>
            private static bool HasImportFieldPayload(ImportRecord import)
            {
                if (import == null)
                {
                    return false;
                }

                if (import.Login != null || import.Password != null || import.LoginUrl != null)
                {
                    return true;
                }

                if (import.CustomFields == null)
                {
                    return false;
                }

                for (var i = 0; i < import.CustomFields.Length; i++)
                {
                    var field = import.CustomFields[i];
                    if (field != null && !string.IsNullOrEmpty(field.Name) && field.HasValue)
                    {
                        return true;
                    }
                }

                return false;
            }

            /// <summary>Picks the NSF folder from the record's first folder entry, or the default.</summary>
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

            /// <summary>Copy of an import record so we can mutate without touching the original.</summary>
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
                    CustomFields = import.CustomFields?.Select(CloneImportCustomField).ToArray(),
                    Folders = import.Folders?.Select(f => new ImportRecordFolder
                    {
                        FolderName = f.FolderName,
                        SharedFolderName = f.SharedFolderName,
                        CanEdit = f.CanEdit,
                        CanShare = f.CanShare,
                    }).ToArray(),
                };
            }

            /// <summary>
            /// Fills in object-style custom fields that didn't get set during typed populate.
            /// </summary>
            private static void ApplyImportCustomFieldDictionaries(
                TypedRecord typed,
                ImportCustomField[] customSnapshot)
            {
                if (typed == null || customSnapshot == null || customSnapshot.Length == 0)
                {
                    return;
                }

                foreach (var customField in customSnapshot)
                {
                    if (customField == null
                        || string.IsNullOrEmpty(customField.Name)
                        || customField.Elements == null
                        || customField.Elements.Length == 0)
                    {
                        continue;
                    }

                    var split = SplitFieldKey(customField.Name);
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
                            Trace.TraceError($"Create field \"{customField.Name}\" error: {e.Message}");
                            continue;
                        }
                    }

                    if (field.Count == 0)
                    {
                        var assignValue = ToAssignValue(customField);
                        if (assignValue != null)
                        {
                            field.ObjectValue = assignValue;
                        }
                    }
                }
            }

            /// <summary>Builds the field list used for an NSF create/update request.</summary>
            private static ImportCustomField[] BuildNsfFieldsFromImportRecord(
                VaultOnline vault,
                ImportRecord import)
            {
                var copy = CloneImportRecord(import);
                if (string.IsNullOrEmpty(copy.RecordType))
                {
                    return BuildNsfFieldsFromLegacyImportRecord(copy);
                }

                // Start from typed fields so complex objects (host, paymentCard, …)
                // survive even when typed schema matching is incomplete. NSF CoerceNsfFieldValue
                // converts element dictionaries into typed field objects.
                var fieldsByName = BuildNsfFieldsFromLegacyImportRecord(copy)
                    .Where(f => f?.Name != null)
                    .GroupBy(f => f.Name, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);

                var recordTypeName = copy.RecordType;
                if (!vault.TryGetRecordTypeByName(recordTypeName, out var recordType))
                {
                    recordTypeName = "login";
                    vault.TryGetRecordTypeByName(recordTypeName, out recordType);
                }

                var typed = new TypedRecord(recordTypeName);
                copy.PopulateTypedRecord(typed, recordType.Fields);
                foreach (var field in ExtractNsfFieldsFromTypedRecord(typed))
                {
                    if (field?.Name != null)
                    {
                        fieldsByName[field.Name] = field;
                    }
                }

                return fieldsByName.Values.ToArray();
            }

            /// <summary>Simple field list from login/password/url and custom_fields (no record type).</summary>
            private static ImportCustomField[] BuildNsfFieldsFromLegacyImportRecord(ImportRecord import)
            {
                var fields = new List<ImportCustomField>();
                // null = omitted from import JSON; empty string clears the field on update.
                if (import.Login != null)
                {
                    fields.Add(new ImportCustomField { Name = "login", TextValue = import.Login });
                }

                if (import.Password != null)
                {
                    fields.Add(new ImportCustomField { Name = "password", TextValue = import.Password });
                }

                if (import.LoginUrl != null)
                {
                    fields.Add(new ImportCustomField { Name = "url", TextValue = import.LoginUrl });
                }

                if (import.CustomFields == null)
                {
                    return fields.ToArray();
                }

                foreach (var customField in import.CustomFields)
                {
                    if (customField == null || string.IsNullOrEmpty(customField.Name) || !customField.HasValue)
                    {
                        continue;
                    }

                    if (string.Equals(customField.Name, TwoFactorCode, StringComparison.Ordinal))
                    {
                        fields.Add(new ImportCustomField
                        {
                            Name = "oneTimeCode",
                            TextValue = string.IsNullOrEmpty(customField.TextValue)
                                ? customField.TextValue
                                : NormalizeImportTotpValue(customField.TextValue),
                            Elements = customField.Elements,
                        });
                        continue;
                    }

                    var split = SplitFieldKey(customField.Name);
                    var fieldType = split.Item1;
                    var fieldLabel = split.Item2;
                    if (string.IsNullOrEmpty(fieldType))
                    {
                        continue;
                    }

                    var key = string.IsNullOrEmpty(fieldLabel)
                        ? fieldType
                        : $"{fieldType}:{fieldLabel}";
                    fields.Add(new ImportCustomField
                    {
                        Name = key,
                        TextValue = customField.TextValue,
                        Elements = customField.Elements,
                    });
                }

                return fields.ToArray();
            }

            /// <summary>Reads filled fields off a <see cref="TypedRecord"/> for NSF.</summary>
            private static ImportCustomField[] ExtractNsfFieldsFromTypedRecord(TypedRecord typed)
            {
                var fields = new List<ImportCustomField>();
                foreach (var field in typed.Fields.Concat(typed.Custom))
                {
                    if (string.IsNullOrEmpty(field.FieldName) || field.Count == 0)
                    {
                        continue;
                    }

                    // Use GetValueAt (not ObjectValue) so empty schema fields are not auto-materialized.
                    var value = field.GetValueAt(0);
                    if (value == null)
                    {
                        continue;
                    }

                    // Preserve labeled fields (e.g. address:Work) so same-type fields do not collapse.
                    var key = string.IsNullOrEmpty(field.FieldLabel)
                        ? field.FieldName
                        : $"{field.FieldName}:{field.FieldLabel}";

                    // Empty string is kept (explicit NSF update clear); other empty payloads are skipped.
                    if (value is string text)
                    {
                        fields.Add(new ImportCustomField { Name = key, TextValue = text });
                        continue;
                    }

                    if (!HasNsfFieldValue(value))
                    {
                        continue;
                    }

                    var customField = ToImportCustomField(key, value);
                    if (customField != null)
                    {
                        fields.Add(customField);
                    }
                }

                return fields.ToArray();
            }

            /// <summary>Wraps a field value as an <see cref="ImportCustomField"/>.</summary>
            private static ImportCustomField ToImportCustomField(string name, object value)
            {
                if (string.IsNullOrEmpty(name) || value == null)
                {
                    return null;
                }

                if (value is string text)
                {
                    return new ImportCustomField { Name = name, TextValue = text };
                }

                if (value is IFieldTypeSerialize serializer)
                {
                    var elementNames = serializer.Elements?.ToArray() ?? Array.Empty<string>();
                    var elementValues = serializer.ElementValues?.ToArray() ?? Array.Empty<string>();
                    var count = Math.Min(elementNames.Length, elementValues.Length);
                    var elements = new ImportCustomFieldElement[count];
                    for (var i = 0; i < count; i++)
                    {
                        elements[i] = new ImportCustomFieldElement
                        {
                            Name = elementNames[i],
                            Value = elementValues[i],
                        };
                    }

                    return new ImportCustomField { Name = name, Elements = elements };
                }

                if (value is IDictionary dictionary)
                {
                    var elements = new List<ImportCustomFieldElement>();
                    foreach (DictionaryEntry entry in dictionary)
                    {
                        if (entry.Key is not string elementName)
                        {
                            continue;
                        }

                        elements.Add(new ImportCustomFieldElement
                        {
                            Name = elementName,
                            Value = entry.Value as string ?? entry.Value?.ToString(),
                        });
                    }

                    return new ImportCustomField { Name = name, Elements = elements.ToArray() };
                }

                return new ImportCustomField { Name = name, TextValue = value.ToString() };
            }

            /// <summary>Copies a custom field and its elements.</summary>
            private static ImportCustomField CloneImportCustomField(ImportCustomField field)
            {
                if (field == null)
                {
                    return null;
                }

                return new ImportCustomField
                {
                    Name = field.Name,
                    TextValue = field.TextValue,
                    Elements = field.Elements?
                        .Select(e => e == null
                            ? null
                            : new ImportCustomFieldElement { Name = e.Name, Value = e.Value })
                        .ToArray(),
                };
            }

            /// <summary>
            /// Reads custom_fields from import JSON.
            /// Plain values go into TextValue; objects go into Elements.
            /// Empty objects are skipped.
            /// </summary>
            private static ImportCustomField[] ParseCustomFieldsFromImportJson(ImportJsonValue value)
            {
                if (value?.Kind != ImportJsonValue.JsonKind.Object || value.ObjectValue == null || value.ObjectValue.Count == 0)
                {
                    return null;
                }

                var fields = new List<ImportCustomField>(value.ObjectValue.Count);
                foreach (var pair in value.ObjectValue)
                {
                    if (string.IsNullOrEmpty(pair.Key) || pair.Value == null || pair.Value.Kind == ImportJsonValue.JsonKind.Null)
                    {
                        continue;
                    }

                    if (pair.Value.Kind == ImportJsonValue.JsonKind.Object)
                    {
                        var elements = new List<ImportCustomFieldElement>();
                        if (pair.Value.ObjectValue != null)
                        {
                            foreach (var element in pair.Value.ObjectValue)
                            {
                                if (string.IsNullOrEmpty(element.Key))
                                {
                                    continue;
                                }

                                elements.Add(new ImportCustomFieldElement
                                {
                                    Name = element.Key,
                                    Value = element.Value?.AsString(),
                                });
                            }
                        }

                        if (elements.Count == 0)
                        {
                            continue;
                        }

                        fields.Add(new ImportCustomField
                        {
                            Name = pair.Key,
                            Elements = elements.ToArray(),
                        });
                        continue;
                    }

                    fields.Add(new ImportCustomField
                    {
                        Name = pair.Key,
                        TextValue = pair.Value.AsString() ?? string.Empty,
                    });
                }

                return fields.Count > 0 ? fields.ToArray() : null;
            }

            private static ImportCustomField[] ParseTypedFieldsFromImportJson(ImportJsonValue value)
            {
                var fields = new List<ImportCustomField>();
                foreach (var fieldValue in EnumerateImportItems(value))
                {
                    if (fieldValue?.Kind != ImportJsonValue.JsonKind.Object || fieldValue.ObjectValue == null)
                    {
                        continue;
                    }

                    fieldValue.ObjectValue.TryGetValue("type", out var typeValue);
                    fieldValue.ObjectValue.TryGetValue("label", out var labelValue);
                    fieldValue.ObjectValue.TryGetValue("value", out var valueNode);
                    var type = typeValue?.AsString();
                    var label = labelValue?.AsString();
                    if (string.IsNullOrEmpty(type) || valueNode == null)
                    {
                        continue;
                    }

                    var name = type.StartsWith("$", StringComparison.Ordinal) ? type : "$" + type;
                    if (!string.IsNullOrEmpty(label))
                    {
                        name += ":" + label;
                    }

                    if (valueNode.Kind == ImportJsonValue.JsonKind.Object && valueNode.ObjectValue != null)
                    {
                        fields.Add(new ImportCustomField
                        {
                            Name = name,
                            Elements = valueNode.ObjectValue
                                .Where(x => !string.IsNullOrEmpty(x.Key))
                                .Select(x => new ImportCustomFieldElement
                                {
                                    Name = x.Key,
                                    Value = x.Value?.AsString(),
                                })
                                .ToArray(),
                        });
                    }
                    else
                    {
                        fields.Add(new ImportCustomField
                        {
                            Name = name,
                            TextValue = valueNode.AsString(),
                        });
                    }
                }

                return fields.Count == 0 ? null : fields.ToArray();
            }

            /// <summary>
            /// Value to write for a custom field.
            /// Named Elements become a dictionary; otherwise TextValue is used
            /// ("" clears the field). Empty element lists are not sent.
            /// </summary>
            private static object ToAssignValue(ImportCustomField field)
            {
                if (field == null)
                {
                    return null;
                }

                if (field.Elements != null)
                {
                    var dict = new Dictionary<string, object>();
                    foreach (var element in field.Elements)
                    {
                        if (element?.Name == null)
                        {
                            continue;
                        }

                        dict[element.Name] = element.Value;
                    }

                    if (dict.Count > 0)
                    {
                        return dict;
                    }
                }

                return field.TextValue;
            }

            /// <summary>Builds the Fields map for an NSF create/update, skipping empty fields.</summary>
            private static IDictionary<string, object> ToNsfRequestFields(IEnumerable<ImportCustomField> fields)
            {
                var result = new Dictionary<string, object>();
                if (fields == null)
                {
                    return result;
                }

                foreach (var field in fields)
                {
                    if (field == null || string.IsNullOrEmpty(field.Name) || !field.HasValue)
                    {
                        continue;
                    }

                    var value = ToAssignValue(field);
                    if (value == null)
                    {
                        continue;
                    }

                    result[field.Name] = value;
                }

                return result;
            }

            /// <summary>True if the value is worth sending (not empty).</summary>
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
