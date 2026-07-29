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

        /// <summary>
        /// One element of a structured import/NSF field (e.g. hostName/port).
        /// </summary>
        public class ImportCustomFieldElement
        {
            public string Name { get; set; }

            public string Value { get; set; }
        }

        /// <summary>
        /// Typed custom field for <see cref="ImportRecord.CustomFields"/>.
        /// JSON <c>custom_fields</c> objects are converted into this array when parsing.
        /// </summary>
        public class ImportCustomField
        {
            /// <summary>Field key (e.g. <c>$host</c>, <c>$address:Work</c>, <c>TFC:Keeper</c>).</summary>
            public string Name { get; set; }

            /// <summary>Scalar value; empty string allowed (clear on update). Null when <see cref="Elements"/> is used.</summary>
            public string TextValue { get; set; }

            /// <summary>Structured value (host, address, paymentCard, …).</summary>
            public ImportCustomFieldElement[] Elements { get; set; }

            public bool HasValue => TextValue != null || Elements != null;
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
            /// Typed custom fields. Populated from JSON object <c>custom_fields</c> by <see cref="Vault.KeeperImport.LoadJsonDictionary(ImportJsonValue)"/>.
            /// Not serialized via DataContract (wire shape is still a JSON object).
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
                            password.Totp = strValue.StartsWith("otpauth://")
                                ? strValue
                                : $"otpauth://totp/?secret={strValue}";
                        }
                        else
                        {
                            password.SetCustomField(customField.Name, strValue);
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

                Dictionary<string, ImportCustomField> customFields = null;
                if (import.CustomFields != null)
                {
                    customFields = import.CustomFields
                        .Where(f => f != null && !string.IsNullOrEmpty(f.Name))
                        .GroupBy(f => f.Name, StringComparer.Ordinal)
                        .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
                    if (customFields.TryGetValue(TwoFactorCode, out var tfa))
                    {
                        customFields["$oneTimeCode"] = new ImportCustomField
                        {
                            Name = "$oneTimeCode",
                            TextValue = tfa.TextValue,
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

                // PowerShell unwraps single-element arrays to the element itself.
                if (value.Kind == ImportJsonValue.JsonKind.Object)
                {
                    yield return value;
                }
            }

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
                    }
                }

                return rec;
            }

            /// <summary>
            /// Parses a typed JSON document (from PowerCommander) into an import file.
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

            /// <summary>
            /// Parses a legacy untyped JSON dictionary into an import file.
            /// Prefer <see cref="LoadJsonDictionary(ImportJsonValue)"/> from PowerCommander.
            /// </summary>
            public static ImportFile LoadJsonDictionary(IDictionary<string, object> importFile)
            {
                return LoadJsonDictionary(ImportJsonValue.FromLegacyObject(importFile));
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
                            var customSnapshot = record.CustomFields?
                                .Select(CloneImportCustomField)
                                .ToArray();

                            var typedRecord = new TypedRecord(record.RecordType);
                            record.PopulateTypedRecord(typedRecord, recordType.Fields);

                            // Re-apply nested custom_fields onto any schema/custom fields
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
                        Fields = ToNsfRequestFields(BuildNsfFieldsFromImportRecord(vault, record)),
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
                            ? ToNsfRequestFields(BuildNsfFieldsFromImportRecord(vault, record))
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
                    || (import.CustomFields != null && import.CustomFields.Length > 0);
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
                        field.ObjectValue = ToAssignValue(customField);
                    }
                }
            }

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
                            TextValue = customField.TextValue,
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
                                elements.Add(new ImportCustomFieldElement
                                {
                                    Name = element.Key,
                                    Value = element.Value?.AsString(),
                                });
                            }
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

            private static object ToAssignValue(ImportCustomField field)
            {
                if (field == null)
                {
                    return null;
                }

                if (field.Elements != null)
                {
                    var dict = new Dictionary<string, object>(field.Elements.Length);
                    foreach (var element in field.Elements)
                    {
                        if (element?.Name == null)
                        {
                            continue;
                        }

                        dict[element.Name] = element.Value;
                    }

                    return dict;
                }

                return field.TextValue;
            }

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

                    result[field.Name] = ToAssignValue(field);
                }

                return result;
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
