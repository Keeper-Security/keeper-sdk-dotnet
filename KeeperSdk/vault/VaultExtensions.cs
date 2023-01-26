using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <exclude/>
    public static class VaultExtensions
    {
        public static byte[] PadRecordData(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            var padBytes = 0;
            if (data.Length < 384)
            {
                padBytes = 384 - data.Length;
            }
            else
            {
                padBytes = data.Length % 16;
                if (padBytes > 0)
                {
                    padBytes = 16 - padBytes;
                }
            }
            if (padBytes > 0)
            {
                return data.Concat(Enumerable.Repeat((byte) 0x20, padBytes)).ToArray();
            }
            return data;
        }
        
        public static IRecordMetadata ResolveRecordAccessPath(this IVault vault, IRecordAccessPath path,
            bool forEdit = false,
            bool forShare = false, bool forView = false)
        {
            if (string.IsNullOrEmpty(path.RecordUid))
            {
                return null;
            }

            foreach (var rmd in vault.Storage.RecordKeys.GetLinksForSubject(path.RecordUid))
            {
                if (forEdit && !rmd.CanEdit) continue;
                if (forShare && !rmd.CanShare) continue;
                if (string.IsNullOrEmpty(rmd.SharedFolderUid) || rmd.SharedFolderUid == vault.Storage.PersonalScopeUid)
                {
                    return rmd;
                }

                foreach (var sfmd in vault.Storage.SharedFolderKeys.GetLinksForSubject(rmd.SharedFolderUid))
                {
                    if (string.IsNullOrEmpty(sfmd.TeamUid))
                    {
                        path.SharedFolderUid = sfmd.SharedFolderUid;
                        return rmd;
                    }

                    if (!forEdit && !forShare && !forView)
                    {
                        path.SharedFolderUid = sfmd.SharedFolderUid;
                        path.TeamUid = sfmd.TeamUid;
                        return rmd;
                    }

                    if (!vault.TryGetTeam(sfmd.TeamUid, out var team)) continue;
                    if (forEdit && team.RestrictEdit) continue;
                    if (forShare && team.RestrictShare) continue;
                    if (forView && team.RestrictView) continue;

                    path.SharedFolderUid = sfmd.SharedFolderUid;
                    path.TeamUid = sfmd.TeamUid;
                    return rmd;
                }
            }

            return null;
        }

        public static SharedFolderPermission ResolveSharedFolderAccessPath(this IVault vault, string username,
            string sharedFolderUid, bool forManageUsers = false, bool forManageRecords = false)
        {
            if (string.IsNullOrEmpty(sharedFolderUid)) return null;
            if (!vault.TryGetSharedFolder(sharedFolderUid, out var sf)) return null;

            var permissions = sf.UsersPermissions
                .Where(x =>
                    x.UserType == UserType.User && x.UserId == username ||
                    x.UserType == UserType.Team && vault.TryGetTeam(x.UserId, out _))
                .Where(x => (!forManageUsers || x.ManageUsers) && (!forManageRecords || x.ManageRecords))
                .ToArray();

            if (permissions.Length <= 0) return null;
            return permissions.FirstOrDefault(x => x.UserType == UserType.User) ?? permissions[0];
        }


        internal static RecordData ExtractRecordData(this PasswordRecord record)
        {
            return new RecordData
            {
                title = record.Title,
                secret1 = record.Login,
                secret2 = record.Password,
                link = record.Link,
                notes = record.Notes,
                custom = record.Custom?.Select(x => new RecordDataCustom
                {
                    name = x.Name,
                    value = x.Value,
                    type = x.Type
                }).ToArray()
            };
        }

        internal static RecordExtra ExtractRecordExtra(this PasswordRecord record, RecordExtra existingExtra = null)
        {
            IDictionary<string, RecordExtraFile> extraFiles = null;
            if (existingExtra?.files != null && existingExtra.files.Length > 0)
            {
                extraFiles = new Dictionary<string, RecordExtraFile>();
                foreach (var f in existingExtra.files)
                {
                    extraFiles.Add(f.id, f);
                }
            }

            List<Dictionary<string, object>> extraFields = new List<Dictionary<string, object>>();
            if (existingExtra?.fields != null && existingExtra.fields.Length > 0)
            {
                extraFields.AddRange(existingExtra.fields);
            }
            Dictionary<string, object> totpField = extraFields.FirstOrDefault(x =>
            {
                if (x.TryGetValue("field_type", out var value))
                {
                    if (value is string field_type)
                    {
                        return string.Equals(field_type, "totp", StringComparison.InvariantCultureIgnoreCase);
                    }
                }
                return false;
            });

            if (string.IsNullOrEmpty(record.Totp))
            {
                if (totpField != null)
                {
                    extraFields.Remove(totpField);
                }
            }
            else
            {
                if (totpField == null)
                {
                    totpField = new Dictionary<string, object>
                    {
                        ["id"] = CryptoUtils.GetRandomBytes(8).Base64UrlEncode(),
                        ["field_type"] = "totp",
                        ["field_title"] = "",
                        ["data"] = record.Totp,
                    };
                    extraFields.Add(totpField);
                }
            }

            return new RecordExtra
            {
                files = record.Attachments?.Select(x =>
                {
                    RecordExtraFile extraFile;
                    if (extraFiles != null)
                    {
                        if (extraFiles.TryGetValue(x.Id, out extraFile))
                        {
                            return extraFile;
                        }
                    }

                    extraFile = new RecordExtraFile
                    {
                        id = x.Id,
                        key = x.Key,
                        name = x.Name,
                        title = x.Title ?? x.Name,
                        size = x.Size,
                        type = x.MimeType
                    };
                    if (x.Thumbnails != null && x.Thumbnails.Length > 0)
                    {
                        extraFile.thumbs = x.Thumbnails.Select(y =>
                                new RecordExtraFileThumb
                                {
                                    id = y.Id,
                                    size = y.Size,
                                    type = y.Type
                                })
                            .ToArray();
                    }

                    return extraFile;
                }).ToArray(),
                fields = extraFields.ToArray(),
                ExtensionData = existingExtra?.ExtensionData
            };
        }

        internal static IEnumerable<string> ExtractRecordRefs(this TypedRecord typedRecord)
        {
            foreach (var field in typedRecord.Fields.Concat(typedRecord.Custom))
            {
                if (!(field is TypedField<string> tfs)) continue;
                if (!RecordTypesConstants.TryGetRecordField(tfs.FieldName, out var rf)) continue;
                switch (rf.Type.Name)
                {
                    case "fileRef":
                    case "addressRef":
                    case "cardRef":
                    {
                        foreach (var value in tfs.Values)
                        {
                            yield return value;
                        }

                        break;
                    }
                }
            }
        }

        internal static RecordAuditData ExtractRecordAuditData(this KeeperRecord record)
        {
            var auditData = new RecordAuditData
            {
                Title = record.Title,
            };
            string url = null;
            if (record is PasswordRecord password)
            {
                url = password.Link;
            }
            else if (record is TypedRecord typed)
            {
                auditData.RecordType = typed.TypeName;
                var urlField = typed.Fields.OfType<TypedField<string>>().FirstOrDefault(x => x.FieldName == "url") ??
                               typed.Custom.OfType<TypedField<string>>().FirstOrDefault(x => x.FieldName == "url");
                url = urlField?.TypedValue;
            }

            if (!string.IsNullOrEmpty(url))
            {
                auditData.Url = url.StripUrl();
            }

            return auditData;
        }

        internal static RecordTypeData ExtractRecordV3Data(this TypedRecord typedRecord)
        {
            return new RecordTypeData
            {
                Type = typedRecord.TypeName ?? "login",
                Title = typedRecord.Title ?? "",
                Notes = typedRecord.Notes ?? "",
                Fields = typedRecord.Fields
                    .OfType<IToRecordTypeDataField>()
                    .Select(x => x.ToRecordTypeDataField())
                    .ToArray(),
                Custom = typedRecord.Custom
                    .OfType<IToRecordTypeDataField>()
                    .Select(x => x.ToRecordTypeDataField())
                    .ToArray()
            };
        }

        private static readonly DataContractJsonSerializer DataSerializer =
            new DataContractJsonSerializer(typeof(RecordData), JsonUtils.JsonSettings);

        private static readonly DataContractJsonSerializer ExtraSerializer =
            new DataContractJsonSerializer(typeof(RecordExtra), JsonUtils.JsonSettings);

        public static PasswordRecord LoadV2(this IStorageRecord r, byte[] key)
        {
            var record = new PasswordRecord()
            {
                RecordKey = key,
                Uid = r.RecordUid,
                Version = 2,
                Shared = r.Shared,
                Owner = r.Owner,
                ClientModified = r.ClientModifiedTime != 0
                    ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(r.ClientModifiedTime)
                    : DateTimeOffset.Now,
            };

            var data = r.Data.Base64UrlDecode();
            data = CryptoUtils.DecryptAesV1(data, key);
            using (var ms = new MemoryStream(data))
            {
                var parsedData = (RecordData) DataSerializer.ReadObject(ms);
                record.Title = parsedData.title;
                record.Login = parsedData.secret1;
                record.Password = parsedData.secret2;
                record.Link = parsedData.link;
                record.Notes = parsedData.notes;
                if (parsedData.custom != null)
                {
                    foreach (var cr in parsedData.custom.Where(x => x != null))
                    {
                        record.Custom.Add(new CustomField
                        {
                            Name = cr.name,
                            Value = cr.value,
                            Type = cr.type
                        });
                    }
                }
            }

            if (!string.IsNullOrEmpty(r.Extra))
            {
                var extra = CryptoUtils.DecryptAesV1(r.Extra.Base64UrlDecode(), key);
                using (var ms = new MemoryStream(extra))
                {
                    var parsedExtra = (RecordExtra) ExtraSerializer.ReadObject(ms);
                    if (parsedExtra.files != null && parsedExtra.files.Length > 0)
                    {
                        foreach (var file in parsedExtra.files.Where(x => x != null))
                        {
                            var atta = new AttachmentFile
                            {
                                Id = file.id,
                                Key = file.key,
                                Name = file.name,
                                Title = file.title ?? "",
                                MimeType = file.type ?? "",
                                Size = file.size ?? 0,
                                LastModified = file.lastModified != null
                                    ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(file.lastModified.Value)
                                    : DateTimeOffset.Now
                            };
                            if (file.thumbs != null)
                            {
                                atta.Thumbnails = file.thumbs
                                    .Where(x => x != null)
                                    .Select(t => new AttachmentFileThumb
                                    {
                                        Id = t.id,
                                        Type = t.type,
                                        Size = t.size ?? 0
                                    })
                                    .ToArray();
                            }

                            record.Attachments.Add(atta);
                        }
                    }

                    if (parsedExtra.fields != null)
                    {
                        var totpField = parsedExtra.fields.FirstOrDefault(x =>
                        {
                            if (x.TryGetValue("field_type", out var value))
                            {
                                if (value is string field_type)
                                {
                                    return string.Equals(field_type, "totp", StringComparison.InvariantCultureIgnoreCase);
                                }
                            }
                            return false;
                        });
                        if (totpField != null)
                        {
                            if (totpField.TryGetValue("data", out var value))
                            {
                                if (value is string totpUrl)
                                {
                                    record.Totp = totpUrl;
                                }
                            }
                        }
                    }
                }
            }

            return record;
        }

        internal static ITypedField ConvertToTypedField(this RecordTypeDataFieldBase field)
        {
            try
            {
                if (string.IsNullOrEmpty(field.Type))
                {
                    field.Type = "text";
                }
                if (RecordTypesConstants.TryGetRecordField(field.Type, out var rf))
                {
                    if (RecordTypesConstants.GetJsonParser(rf.Type.Type, out var serializer))
                    {
                        var xb = JsonUtils.DumpJson(field);
                        using (var ms = new MemoryStream(xb))
                        {
                            var f = (RecordTypeDataFieldBase) serializer.ReadObject(ms);
                            return f.CreateTypedField();
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"Unsupported field type: {rf.Type.Type}");
                    }
                }
                else
                {
                    Debug.WriteLine($"Unsupported record field: {field.Type}");
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }

            return new UnsupportedField(field);
        }

        public static TypedRecord LoadV3(this IStorageRecord r, byte[] key)
        {
            var data = CryptoUtils.DecryptAesV2(r.Data.Base64UrlDecode(), key);
            var rtd = JsonUtils.ParseJson<RecordTypeData>(data);
            var typedRecord = new TypedRecord(rtd.Type)
            {
                Uid = r.RecordUid,
                Version = 3,
                RecordKey = key,
                Shared = r.Shared,
                Owner = r.Owner,
                ClientModified = r.ClientModifiedTime != 0
                    ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(r.ClientModifiedTime)
                    : DateTimeOffset.Now,
                Title = rtd.Title,
                Notes = rtd.Notes,
            };

            if (rtd.Fields != null)
            {
                typedRecord.Fields.AddRange(rtd.Fields.Select(ConvertToTypedField));
            }

            if (rtd.Custom != null)
            {
                typedRecord.Custom.AddRange(rtd.Custom.Select(ConvertToTypedField));
            }

            return typedRecord;
        }

        public static FileRecord LoadV4(this IStorageRecord r, byte[] key)
        {
            var data = CryptoUtils.DecryptAesV2(r.Data.Base64UrlDecode(), key);
            var rfd = JsonUtils.ParseJson<RecordFileData>(data);
            var fileRecord = new FileRecord()
            {
                RecordKey = key,
                Uid = r.RecordUid,
                Version = 4,
                Shared = r.Shared,
                Owner = r.Owner,
                ClientModified = r.ClientModifiedTime != 0
                    ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(r.ClientModifiedTime)
                    : DateTimeOffset.Now,
                Title = rfd.Title,
                Name = rfd.Name,
                FileSize = rfd.Size ?? 0,
                MimeType = rfd.Type,
                LastModified = rfd.LastModified != null
                    ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds((long)rfd.LastModified.Value)
                    : DateTimeOffset.Now
            };
            if (!string.IsNullOrEmpty(r.Udata))
            {
                var uData = JsonUtils.ParseJson<SyncDownRecordUData>(r.Udata.Base64UrlDecode());
                fileRecord.StorageFileSize = uData.FileSize;
                fileRecord.StorageThumbnailSize = uData.ThumbnailSize;
            }

            return fileRecord;
        }

        public static ApplicationRecord LoadV5(this IStorageRecord r, byte[] key) 
        {
            var data = CryptoUtils.DecryptAesV2(r.Data.Base64UrlDecode(), key);
            var rad = JsonUtils.ParseJson<RecordApplicationData>(data);
            var applicationRecord = new ApplicationRecord()
            {
                RecordKey = key,
                Uid = r.RecordUid,
                Version = 5,
                Shared = r.Shared,
                Owner = r.Owner,
                ClientModified = r.ClientModifiedTime != 0
                    ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(r.ClientModifiedTime)
                    : DateTimeOffset.Now,
                Title = rad.Title,
                Type = rad.Type,
            };
            return applicationRecord;
        }

        public static SharedFolder Load(this ISharedFolder sf, IEnumerable<IRecordMetadata> records,
            IEnumerable<ISharedFolderPermission> users, byte[] sharedFolderKey)
        {
            var sharedFolder = new SharedFolder
            {
                Uid = sf.SharedFolderUid,
                Name = Encoding.UTF8.GetString(CryptoUtils.DecryptAesV1(sf.Name.Base64UrlDecode(), sharedFolderKey)),
                DefaultManageRecords = sf.DefaultManageRecords,
                DefaultManageUsers = sf.DefaultManageUsers,
                DefaultCanEdit = sf.DefaultCanEdit,
                DefaultCanShare = sf.DefaultCanShare,
                SharedFolderKey = sharedFolderKey,
            };

            if (users != null)
            {
                foreach (var u in users)
                {
                    sharedFolder.UsersPermissions.Add(new SharedFolderPermission
                    {
                        UserId = u.UserId,
                        UserType = (UserType) u.UserType,
                        ManageRecords = u.ManageRecords,
                        ManageUsers = u.ManageUsers
                    });
                }
            }

            if (records != null)
            {
                foreach (var r in records)
                {
                    sharedFolder.RecordPermissions.Add(new SharedFolderRecord
                    {
                        RecordUid = r.RecordUid,
                        CanEdit = r.CanEdit,
                        CanShare = r.CanShare
                    });
                }
            }

            return sharedFolder;
        }

        public static Team Load(this IEnterpriseTeam team, byte[] teamKey)
        {
            var pk = team.TeamPrivateKey.Base64UrlDecode();
            return new Team
            {
                TeamUid = team.TeamUid,
                Name = team.Name,
                TeamKey = teamKey,
                TeamPrivateKey = CryptoUtils.LoadPrivateKey(CryptoUtils.DecryptAesV1(pk, teamKey)),
                RestrictEdit = team.RestrictEdit,
                RestrictShare = team.RestrictShare,
                RestrictView = team.RestrictView,
            };
        }

        /// <summary>
        /// Gets a custom field.
        /// </summary>
        /// <param name="record">KeeperRecord</param>
        /// <param name="name">Custom field Name.</param>
        /// <returns>Returns custom field or <c>null</c> is it was not found.</returns>
        public static ICustomField GetCustomField(this KeeperRecord record, string name)
        {
            switch (record)
            {
                case PasswordRecord password:
                {
                    return password.Custom
                        .FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
                }
                case TypedRecord typed:
                {
                    return typed.Custom
                        .OfType<TypedField<string>>()
                        .FirstOrDefault(x => string.Equals(name, x.FieldLabel, StringComparison.CurrentCultureIgnoreCase));
                }
            }

            return null;
        }

        /// <summary>
        /// Deletes a custom field.
        /// </summary>
        /// <param name="record">KeeperRecord</param>
        /// <param name="name">Custom field Name.</param>
        /// <returns>Deleted custom field or <c>null</c> is it was not found.</returns>
        public static ICustomField DeleteCustomField(this KeeperRecord record, string name)
        {
            switch (record)
            {
                case PasswordRecord password:
                {
                    var cf = password.Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
                    if (cf != null)
                    {
                        if (password.Custom.Remove(cf))
                        {
                            return cf;
                        }
                    }

                    break;
                }
                case TypedRecord typed:
                {
                    var field = typed.Custom
                        .OfType<TypedField<string>>()
                        .FirstOrDefault(x => string.Equals(name, x.FieldLabel, StringComparison.CurrentCultureIgnoreCase));
                    if (field != null)
                    {
                        typed.Custom.Remove(field);
                        return field;
                    }

                    break;
                }
            }

            return null;
        }

        /// <summary>
        /// Adds or Changes custom field.
        /// </summary>
        /// <param name="record">KeeperRecord</param>
        /// <param name="name">Name.</param>
        /// <param name="value">Value.</param>
        /// <returns>Added or modified custom field.</returns>
        public static ICustomField SetCustomField(this KeeperRecord record, string name, string value)
        {
            switch (record)
            {
                case PasswordRecord password:
                {
                    var cf = password.Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
                    if (cf == null)
                    {
                        cf = new CustomField
                        {
                            Name = name
                        };
                        password.Custom.Add(cf);
                    }

                    cf.Value = value ?? "";
                    return cf;
                }
                case TypedRecord typed:
                {
                    var field = typed.Custom
                        .OfType<TypedField<string>>()
                        .FirstOrDefault(x => string.Equals(name, x.FieldLabel, StringComparison.CurrentCultureIgnoreCase));
                    if (field == null)
                    {
                        field = new TypedField<string>("text", name);
                        typed.Custom.Add(field);
                    }

                    field.TypedValue = value;
                    return field;
                }
                default:
                    return null;
            }
        }
    }
}