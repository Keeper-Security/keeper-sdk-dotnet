﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;

namespace KeeperSecurity.Sdk
{
    public static class VaultExtensions
    {
        internal static RecordData ExtractRecordData(this PasswordRecord record, RecordData existingData = null)
        {
            return new RecordData
            {
                title = record.Title,
                folder = existingData?.folder,
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
            if (existingExtra != null && existingExtra.files != null && existingExtra.files.Length > 0)
            {
                extraFiles = new Dictionary<string, RecordExtraFile>();
                foreach (var f in existingExtra.files)
                {
                    extraFiles.Add(f.id, f);
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
                        type = x.Type
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
                ExtensionData = existingExtra?.ExtensionData
            };
        }

        private static DataContractJsonSerializerSettings JsonSettings = new DataContractJsonSerializerSettings
        {
            UseSimpleDictionaryFormat = true
        };

        private static DataContractJsonSerializer DataSerializer = new DataContractJsonSerializer(typeof(RecordData), JsonSettings);
        private static DataContractJsonSerializer ExtraSerializer = new DataContractJsonSerializer(typeof(RecordExtra), JsonSettings);

        public static PasswordRecord Load(this IPasswordRecord r, byte[] key)
        {
            var record = new PasswordRecord()
            {
                RecordKey = key,
                Uid = r.RecordUid,
                Shared = r.Shared,
                Owner = r.Owner,
            };

            var data = r.Data.Base64UrlDecode();
            data = CryptoUtils.DecryptAesV1(data, key);
            using (var ms = new MemoryStream(data))
            {
                var parsedData = (RecordData)DataSerializer.ReadObject(ms);
                record.Title = parsedData.title;
                record.Login = parsedData.secret1;
                record.Password = parsedData.secret2;
                record.Link = parsedData.link;
                record.Notes = parsedData.notes;
                if (parsedData.custom != null)
                {
                    foreach (var cr in parsedData.custom)
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
                    var parsedExtra = (RecordExtra)ExtraSerializer.ReadObject(ms);
                    if (parsedExtra.files != null && parsedExtra.files.Length > 0)
                    {
                        foreach (var file in parsedExtra.files)
                        {
                            var atta = new AttachmentFile
                            {
                                Id = file.id,
                                Key = file.key,
                                Name = file.name,
                                Title = file.title ?? "",
                                Type = file.type ?? "",
                                Size = file.size ?? 0,
                                LastModified = file.lastModified != null ? file.lastModified.Value.FromUnixTimeMilliseconds() : DateTimeOffset.Now
                            };
                            if (file.thumbs != null)
                            {
                                atta.Thumbnails = file.thumbs
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
                }
            }
            return record;
        }


        internal static SharedFolder Load(this ISharedFolder sf, IEnumerable<IRecordMetadata> records, 
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

    }
}
