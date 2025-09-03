using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Records;

namespace KeeperSecurity.Vault
{
    /// <inheritdoc/>>
    public class SharedFolderRecordOptions : ISharedFolderRecordOptions
    {
        /// <inheritdoc/>>
        public bool? CanEdit { get; set; }
        /// <inheritdoc/>>
        public bool? CanShare { get; set; }
    }

    /// <inheritdoc/>>
    public class SharedFolderUserOptions : ISharedFolderUserOptions
    {
        /// <inheritdoc/>>
        public bool? ManageRecords { get; set; }
        /// <inheritdoc/>>
        public bool? ManageUsers { get; set; }
    }

    /// <summary>
    ///  Defines shared folder user and record permissions.
    /// </summary>
    public class SharedFolderOptions : ISharedFolderRecordOptions, ISharedFolderUserOptions
    {
        /// <inheritdoc/>>
        public bool? CanEdit { get; set; }
        /// <inheritdoc/>>
        public bool? CanShare { get; set; }
        /// <inheritdoc/>>
        public bool? ManageUsers { get; set; }
        /// <inheritdoc/>>
        public bool? ManageRecords { get; set; }
    }

    internal static class VaultOnlineFunctions
    {
        public static async Task<KeeperRecord> AddRecordToFolder(this VaultOnline vault, KeeperRecord record,
            string folderUid = null)
        {
            record.Uid = CryptoUtils.GenerateUid();
            record.RecordKey = CryptoUtils.GenerateEncryptionKey();
            FolderNode node = null;
            if (!string.IsNullOrEmpty(folderUid))
            {
                vault.TryGetFolder(folderUid, out node);
            }

            folderUid = null;
            byte[] folderKey = null;
            if (node != null)
            {
                switch (node.FolderType)
                {
                    case FolderType.UserFolder:
                        folderUid = node.FolderUid;
                        break;
                    case FolderType.SharedFolder:
                    case FolderType.SharedFolderFolder:
                        folderUid = node.FolderUid;
                        if (vault.TryGetSharedFolder(node.SharedFolderUid, out var sf))
                        {
                            folderKey = sf.SharedFolderKey;
                        }

                        if (folderKey == null)
                        {
                            throw new Exception($"Cannot resolve shared folder for folder UID: {folderUid}");
                        }

                        break;
                }
            }

            if (record is PasswordRecord pr)
            {
                var ft = "user_folder";
                switch (node?.FolderType)
                {
                    case FolderType.SharedFolder:
                        ft = "shared_folder";
                        break;
                    case FolderType.SharedFolderFolder:
                        ft = "shared_folder_folder";
                        break;
                }

                var recordAdd = new RecordAddCommand
                {
                    RecordUid = record.Uid,
                    RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, vault.Auth.AuthContext.DataKey)
                        .Base64UrlEncode(),
                    RecordType = "password",
                    FolderType = ft,
                };
                if (!string.IsNullOrEmpty(folderUid))
                {
                    recordAdd.FolderUid = folderUid;
                    if (folderKey != null)
                    {
                        recordAdd.FolderKey = CryptoUtils.EncryptAesV1(record.RecordKey, folderKey).Base64UrlEncode();
                    }
                }

                var dataSerializer = new DataContractJsonSerializer(typeof(KeeperSecurity.Commands.RecordData), JsonUtils.JsonSettings);
                var data = pr.ExtractRecordData();
                using (var ms = new MemoryStream())
                {
                    dataSerializer.WriteObject(ms, data);
                    recordAdd.Data = CryptoUtils.EncryptAesV1(ms.ToArray(), record.RecordKey).Base64UrlEncode();
                }

                await vault.Auth.ExecuteAuthCommand(recordAdd);
                vault.ScheduleForAudit(record.Uid);
            }
            else if (record is TypedRecord typed)
            {
                var ft = Records.RecordFolderType.UserFolder;
                switch (node?.FolderType)
                {
                    case FolderType.SharedFolder:
                        ft = Records.RecordFolderType.SharedFolder;
                        break;
                    case FolderType.SharedFolderFolder:
                        ft = Records.RecordFolderType.SharedFolderFolder;
                        break;
                }

                var recordAddProto = new Records.RecordAdd
                {
                    RecordUid = ByteString.CopyFrom(typed.Uid.Base64UrlDecode()),
                    RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(record.RecordKey,
                        vault.Auth.AuthContext.DataKey)),
                    ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    FolderType = ft,
                };
                if (!string.IsNullOrEmpty(folderUid))
                {
                    recordAddProto.FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode());
                    if (folderKey != null)
                    {
                        recordAddProto.FolderKey =
                            ByteString.CopyFrom(CryptoUtils.EncryptAesV2(record.RecordKey, folderKey));
                    }
                }

                vault.AdjustTypedRecord(typed);
                var recordData = typed.ExtractRecordV3Data();
                var jsonData = JsonUtils.DumpJson(recordData);
                jsonData = VaultExtensions.PadRecordData(jsonData);
                recordAddProto.Data =
                    ByteString.CopyFrom(CryptoUtils.EncryptAesV2(jsonData, record.RecordKey));
                var refKeys = new Dictionary<string, byte[]>();
                foreach (var recordUid in typed.ExtractRecordRefs())
                {
                    if (refKeys.ContainsKey(recordUid)) continue;
                    if (vault.TryGetKeeperRecord(recordUid, out var keeperRecord))
                    {
                        refKeys.Add(recordUid, keeperRecord.RecordKey);
                    }
                }

                if (refKeys.Count > 0)
                {
                    recordAddProto.RecordLinks.AddRange(refKeys.Select(pair => new Records.RecordLink
                    {
                        RecordUid = ByteString.CopyFrom(pair.Key.Base64UrlDecode()),
                        RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(pair.Value, record.RecordKey))
                    }));
                }

                if (vault.Auth.AuthContext.EnterprisePublicEcKey != null)
                {
                    var auditData = typed.ExtractRecordAuditData();
                    var data = JsonUtils.DumpJson(auditData);
                    recordAddProto.Audit = new Records.RecordAudit
                    {
                        Version = 0,
                        Data = ByteString.CopyFrom(CryptoUtils.EncryptEc(data,
                            vault.Auth.AuthContext.EnterprisePublicEcKey))
                    };
                }

                var rq = new Records.RecordsAddRequest
                {
                    ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                };
                rq.Records.Add(recordAddProto);
                var rs = await vault.Auth.ExecuteAuthRest<Records.RecordsAddRequest, Records.RecordsModifyResponse>(
                    "vault/records_add", rq);
                var modifyResult = rs.Records[0];
                if (modifyResult.Status != Records.RecordModifyResult.RsSuccess)
                {
                    var status = modifyResult.Status.ToString().ToSnakeCase();
                    if (status.StartsWith("rs_"))
                    {
                        status = status.Substring(3);
                    }

                    throw new KeeperApiException(status, modifyResult.Message);
                }
            }
            else
            {
                throw new Exception($"Unsupported record type: {record.GetType().Name}");
            }

            await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));

            return vault.TryGetKeeperRecord(record.Uid, out var r) ? r : record;
        }

        public static async Task MoveToFolder(this VaultOnline vault, IEnumerable<RecordPath> objects, string toFolderUid, bool link = false)
        {
            var destinationFolder = vault.GetFolder(toFolderUid);
            var destinationFolderScope = destinationFolder.FolderType != FolderType.UserFolder
                ? destinationFolder.FolderType == FolderType.SharedFolderFolder ? destinationFolder.SharedFolderUid : destinationFolder.FolderUid
                : "";
            var encryptionKey = vault.Auth.AuthContext.DataKey;
            if (!string.IsNullOrEmpty(destinationFolderScope))
            {
                if (!vault.TryGetSharedFolder(destinationFolderScope, out var sf))
                {
                    throw new VaultException($"Cannot find destination shared folder");
                }

                encryptionKey = sf.SharedFolderKey;
            }

            var moveObjects = new List<MoveObject>();
            var keyObjects = new Dictionary<string, TransitionKey>();

            void TraverseFolderForRecords(FolderNode folder)
            {
                if (folder.FolderType == FolderType.SharedFolder && destinationFolder.FolderType != FolderType.UserFolder)
                {
                    throw new VaultException($"Cannot move shared folder \"{folder.Name}\" to another shared folder");
                }

                var scope = folder.FolderType != FolderType.UserFolder
                    ? folder.FolderType == FolderType.SharedFolderFolder ? folder.SharedFolderUid : destinationFolder.FolderUid
                    : "";
                if (scope != destinationFolderScope)
                {
                    foreach (var recordUid in folder.Records)
                    {
                        if (keyObjects.ContainsKey(recordUid)) continue;
                        if (!vault.TryGetKeeperRecord(recordUid, out var record))
                        {
                            keyObjects.Add(recordUid,
                                new TransitionKey
                                {
                                    uid = recordUid,
                                    key = CryptoUtils.EncryptAesV1(record.RecordKey, encryptionKey).Base64UrlEncode(),
                                });
                        }
                    }
                }

                foreach (var fUid in folder.Subfolders)
                {
                    TraverseFolderForRecords(vault.GetFolder(fUid));
                }
            }

            foreach (var mo in objects)
            {
                var sourceFolder = vault.GetFolder(mo.FolderUid);

                if (string.IsNullOrEmpty(mo.RecordUid)) // move folder
                {
                    var f = destinationFolder;
                    while (!string.IsNullOrEmpty(f.ParentUid))
                    {
                        if (f.FolderUid == sourceFolder.FolderUid)
                        {
                            throw new VaultException($"Cannot move the folder into its subfolder.");
                        }

                        f = vault.GetFolder(f.ParentUid);
                    }

                    TraverseFolderForRecords(sourceFolder);

                    var parentFolder = vault.GetFolder(sourceFolder.ParentUid);
                    moveObjects.Add(new MoveObject
                    {
                        fromUid = string.IsNullOrEmpty(sourceFolder.FolderUid) ? null : sourceFolder.FolderUid,
                        fromType = parentFolder.FolderType.GetFolderTypeText(),
                        uid = mo.FolderUid,
                        type = sourceFolder.FolderType.GetFolderTypeText(),
                        cascade = true,
                    });
                }
                else
                {
                    if (!vault.TryGetKeeperRecord(mo.RecordUid, out var record))
                    {
                        throw new VaultException("");
                    }

                    var scope = sourceFolder.FolderType != FolderType.UserFolder
                        ? sourceFolder.FolderType == FolderType.SharedFolderFolder ? sourceFolder.SharedFolderUid : sourceFolder.FolderUid
                        : "";

                    if (scope != destinationFolderScope && !keyObjects.ContainsKey(mo.RecordUid))
                    {
                        keyObjects.Add(mo.RecordUid,
                            new TransitionKey
                            {
                                uid = mo.RecordUid,
                                key = CryptoUtils.EncryptAesV1(record.RecordKey, encryptionKey).Base64UrlEncode(),
                            });
                    }

                    moveObjects.Add(new MoveObject
                    {
                        fromUid = string.IsNullOrEmpty(sourceFolder.FolderUid) ? null : sourceFolder.FolderUid,
                        fromType = sourceFolder.FolderType.GetFolderTypeText(),
                        uid = mo.RecordUid,
                        type = "record",
                        cascade = false
                    });
                }
            }

            var request = new MoveCommand
            {
                toUid = destinationFolder.FolderUid,
                toType = destinationFolder.FolderType.GetFolderTypeText(),
                isLink = link,
                moveObjects = moveObjects.ToArray(),
                transitionKeys = keyObjects.Count == 0 ? null : keyObjects.Values.ToArray(),
            };

            await vault.Auth.ExecuteAuthCommand(request);
            await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
        }

        public static async Task<IList<RecordUpdateStatus>> UpdateRecordBatch(this VaultOnline vault, IEnumerable<KeeperRecord> records)
        {
            var v2Records = new Dictionary<string, RecordUpdateRecord>();
            var v3Records = new Dictionary<string, RecordUpdate>();
            var results = new List<RecordUpdateStatus>();
            var passwordChanged = new HashSet<string>();
            var isEnterpriseAccount = vault.Auth.AuthContext.EnterprisePublicEcKey != null;
            foreach (var record in records)
            {
                var existingRecord = vault.Storage.Records.GetEntity(record.Uid);
                if (existingRecord == null)
                {
                    results.Add(new RecordUpdateStatus
                    {
                        RecordUid = record.Uid,
                        Status = "not_found",
                        Message = $"Record \"{record.Uid}\" not found.",
                    });
                }

                if (record is PasswordRecord password)
                {
                    if (!v2Records.ContainsKey(password.Uid))
                    {
                        v2Records.Add(password.Uid, vault.ExtractPasswordRecordForUpdate(password, existingRecord));
                        if (isEnterpriseAccount)
                        {
                            var er = existingRecord.LoadV2(record.RecordKey);
                            if ((er.Password ?? "") != (password.Password ?? ""))
                            {
                                passwordChanged.Add(record.Uid);
                            }
                        }
                    }
                }
                else if (record is TypedRecord typed)
                {
                    if (!v3Records.ContainsKey(typed.Uid))
                    {
                        v3Records.Add(typed.Uid, vault.ExtractTypedRecordForUpdate(typed, existingRecord));
                        if (isEnterpriseAccount)
                        {
                            var er = existingRecord.LoadV3(record.RecordKey);
                            if (typed.FindTypedField(new RecordTypeField("password"), out var f1) &&
                                er.FindTypedField(new RecordTypeField("password"), out var f2))
                            {
                                var password1 = (f1.ObjectValue ?? "").ToString();
                                var password2 = (f2.ObjectValue ?? "").ToString();

                                if (password1 != password2)
                                {
                                    passwordChanged.Add(record.Uid);
                                }
                            }
                        }
                    }
                }
                else
                {
                    results.Add(new RecordUpdateStatus
                    {
                        RecordUid = record.Uid,
                        Status = "not_supported",
                        Message = $"Record \"{record.Uid}\" update is not supported.",
                    });
                }
            }
            while (v2Records.Count > 0)
            {
                var chunk = v2Records.Take(99).ToArray();
                foreach (var pair in chunk)
                {
                    v2Records.Remove(pair.Key);
                }
                var command = new RecordUpdateCommand
                {
                    deviceId = vault.Auth.Endpoint.DeviceName,
                    UpdateRecords = chunk.Select(x => x.Value).ToArray(),
                };

                var rs = await vault.Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
                results.AddRange(rs.UpdateRecords);

                foreach (var status in rs.UpdateRecords)
                {
                    if (status.Status == "success")
                    {
                        vault.ScheduleForAudit(status.RecordUid);
                    }
                }
                if (v2Records.Count > 50)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5));
                }
            }
            while (v3Records.Count > 0)
            {
                var rq = new RecordsUpdateRequest
                {
                    ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                var chunk = v3Records.Take(900).ToArray();
                foreach (var pair in chunk)
                {
                    v3Records.Remove(pair.Key);
                }
                rq.Records.AddRange(chunk.Select(x => x.Value).ToArray());

                var rs = await vault.Auth.ExecuteAuthRest<RecordsUpdateRequest, RecordsModifyResponse>("vault/records_update", rq);
                results.AddRange(rs.Records.Select(x =>
                {
                    var recordUid = x.RecordUid.ToByteArray().Base64UrlEncode();
                    if (x.Status == RecordModifyResult.RsSuccess)
                    {
                        return new RecordUpdateStatus
                        {
                            RecordUid = recordUid,
                            Status = "success",
                        };
                    }
                    else
                    {
                        var status = Enum.GetName(typeof(RecordModifyResult), x.Status);
                        if (status.StartsWith("Rs"))
                        {
                            status = status.Substring(2);
                        }
                        return new RecordUpdateStatus
                        {
                            RecordUid = recordUid,
                            Status = status.ToSnakeCase(),
                            Message = x.Message,
                        };
                    }
                }));
                if (v3Records.Count > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5));
                }
            }

            if (vault.Auth.AuthContext.EnterprisePublicEcKey != null)
            {
                if (passwordChanged.Count > 0) {
                    foreach (var status in results)
                    {
                        if (passwordChanged.Contains(status.RecordUid) && status.Status == "success")
                        {
                            vault.Auth.ScheduleAuditEventLogging("record_password_change", new AuditEventInput { RecordUid = status.RecordUid });
                        }
                    }
                    await vault.Auth.FlushAuditEvents();
                }
            }

            await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));

            return results;
        }

        public static async Task<KeeperRecord> PutRecord(this VaultOnline vault, KeeperRecord record, bool skipExtra = true)
        {
            IStorageRecord existingRecord = null;
            if (!string.IsNullOrEmpty(record.Uid))
            {
                existingRecord = vault.Storage.Records.GetEntity(record.Uid);
            }

            if (existingRecord == null)
            {
                return await vault.AddRecordToFolder(record);
            }

            var statuses = await vault.UpdateRecords(new[] { record });
            if (statuses?.Count > 0)
            {
                var status = statuses[0];
                if (status.Status != "success")
                {
                    throw new KeeperApiException(status.Status, status.Message);
                }
            }
            return vault.TryGetKeeperRecord(record.Uid, out var r) ? r : record;
        }

        public static async Task PutNonSharedData<T>(this VaultOnline vault, string recordUid, T nonSharedData)
            where T : RecordNonSharedData, new()
        {
            if (vault.TryGetKeeperRecord(recordUid, out var record))
            {
                var existingData = vault.LoadNonSharedData<T>(record.Uid) ?? new T();
                nonSharedData.ExtensionData = existingData.ExtensionData;
                var data = JsonUtils.DumpJson(nonSharedData);

                var existingRecord = vault.Storage.Records.GetEntity(recordUid);
                if (record.Version >= 3)
                {
                    var rq = new RecordsUpdateRequest
                    {
                        ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    };
                    rq.Records.Add(new RecordUpdate
                    {
                        RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                        ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        Revision = existingRecord?.Revision ?? 0,
                        NonSharedData = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(data, vault.Auth.AuthContext.DataKey)),
                    });
                    var rs = await vault.Auth.ExecuteAuthRest<RecordsUpdateRequest, RecordsModifyResponse>("vault/records_update", rq);
                    if (rs.Records.Count > 0)
                    {
                        var status = rs.Records[0];
                        if (status.Status != RecordModifyResult.RsSuccess)
                        {
                            throw new KeeperApiException(status.Status.ToString(), status.Message);
                        }
                    }
                }
                else
                {
                    var updateRecord = new RecordUpdateRecord
                    {
                        RecordUid = recordUid,
                        Revision = existingRecord?.Revision ?? 0,
                        NonSharedData = CryptoUtils.EncryptAesV1(data, vault.Auth.AuthContext.DataKey).Base64UrlEncode()
                    };
                    var command = new RecordUpdateCommand
                    {
                        deviceId = vault.Auth.Endpoint.DeviceName,
                        UpdateRecords = new[] { updateRecord }
                    };
                    await vault.Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
                }
                await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
            }
        }

        public static async Task<FolderNode> AddFolder<T>(this VaultOnline vault, string folderName, string parentFolderUid = null, T sharedFolderOptions = null)
            where T : class, ISharedFolderUserOptions, ISharedFolderRecordOptions
        {
            var parent = vault.GetFolder(parentFolderUid);
            FolderType folderType;
            if (sharedFolderOptions != null)
            {
                if (parent.FolderType != FolderType.UserFolder)
                {
                    throw new VaultException($"Shared folder cannot be created");
                }

                folderType = FolderType.SharedFolder;
            }
            else
            {
                folderType = parent.FolderType == FolderType.UserFolder ? FolderType.UserFolder : FolderType.SharedFolderFolder;
            }

            var encryptionKey = vault.Auth.AuthContext.DataKey;
            SharedFolder sharedFolder = null;
            if (folderType == FolderType.SharedFolderFolder)
            {
                var sharedFolderUid = parent.FolderType == FolderType.SharedFolder ? parent.FolderUid : parent.SharedFolderUid;
                sharedFolder = vault.GetSharedFolder(sharedFolderUid);
                encryptionKey = sharedFolder.SharedFolderKey;
            }

            var data = new FolderData
            {
                name = folderName ?? "",
            };
            var dataBytes = JsonUtils.DumpJson(data);

            var folderKey = CryptoUtils.GenerateEncryptionKey();

            var request = new FolderAddCommand
            {
                FolderUid = CryptoUtils.GenerateUid(),
                FolderType = folderType.GetFolderTypeText(),
                Key = CryptoUtils.EncryptAesV1(folderKey, encryptionKey).Base64UrlEncode(),
                Data = CryptoUtils.EncryptAesV1(dataBytes, folderKey).Base64UrlEncode(),
                ParentUid = string.IsNullOrEmpty(parent.FolderUid) || parent.FolderType == FolderType.SharedFolder ? null : parent.FolderUid,
                SharedFolderUid = sharedFolder?.Uid,
            };

            if (sharedFolderOptions != null)
            {
                request.Name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(folderName), folderKey).Base64UrlEncode();
                request.ManageUsers = sharedFolderOptions.ManageUsers ?? false;
                request.ManageRecords = sharedFolderOptions.ManageRecords ?? false;
                request.CanEdit = sharedFolderOptions.CanEdit ?? false;
                request.CanShare = sharedFolderOptions.CanShare ?? false;
            }

            _ = await vault.Auth.ExecuteAuthCommand<FolderAddCommand, AddFolderResponse>(request);
            await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
            return vault.TryGetFolder(request.FolderUid, out var f) ? f : null;
        }

        public static async Task<FolderNode> FolderUpdate(this VaultOnline vault, string folderUid, string folderName, SharedFolderOptions sharedFolderOptions = null)
        {
            if (string.IsNullOrEmpty(folderName) && sharedFolderOptions == null)
            {
                throw new VaultException("Folder name cannot be empty");
            }

            var folder = vault.GetFolder(folderUid);
            if (string.IsNullOrEmpty(folderName))
            {
                folderName = folder.Name;
            }

            var parent = vault.RootFolder;
            if (!string.IsNullOrEmpty(folder.ParentUid))
            {
                vault.TryGetFolder(folder.ParentUid, out parent);
            }

            var nameExists = parent.Subfolders
                .Select(x => vault.TryGetFolder(x, out var v) ? v : null)
                .Any(x => x != null && x.FolderUid != folderUid && string.Compare(x.Name, folderName, StringComparison.InvariantCultureIgnoreCase) == 0);

            if (nameExists)
            {
                throw new VaultException($"Folder with name {folderName} already exists in {parent.Name}");
            }

            var request = new FolderUpdateCommand
            {
                FolderUid = folder.FolderUid,
                FolderType = folder.FolderType.GetFolderTypeText(),
                ParentUid = string.IsNullOrEmpty(folder.ParentUid) ? null : folder.ParentUid,
                SharedFolderUid = string.IsNullOrEmpty(folder.SharedFolderUid) ? null : folder.SharedFolderUid,
            };

            FolderData data = null;
            try
            {
                var existingFolder = vault.Storage.Folders.GetEntity(folderUid);
                if (folder.FolderKey != null && !string.IsNullOrEmpty(existingFolder?.Data))
                {
                    data = JsonUtils.ParseJson<FolderData>(CryptoUtils.DecryptAesV1(existingFolder.Data.Base64UrlDecode(), folder.FolderKey));
                }
            }
            catch
            {
                // ignored
            }

            if (data == null)
            {
                data = new FolderData();
            }
            data.name = folderName;
            var dataBytes = JsonUtils.DumpJson(data);
            request.Data = CryptoUtils.EncryptAesV1(dataBytes, folder.FolderKey).Base64UrlEncode();

            if (folder.FolderType != FolderType.UserFolder)
            {
                var sharedFolderUid = folder.FolderType == FolderType.UserFolder ? folder.FolderUid : folder.SharedFolderUid;
                var perm = vault.ResolveSharedFolderAccessPath(vault.Auth.Username, sharedFolderUid, false, true);
                if (perm != null)
                {
                    if (perm.UserType == UserType.Team)
                    {
                        request.TeamUid = perm.UserId;
                    }
                }
            }

            if (folder.FolderType == FolderType.SharedFolder)
            {
                request.Name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(folderName), folder.FolderKey).Base64UrlEncode();

                if (sharedFolderOptions != null)
                {
                    request.ManageUsers = sharedFolderOptions.ManageUsers;
                    request.ManageRecords = sharedFolderOptions.ManageRecords;
                    request.CanEdit = sharedFolderOptions.CanEdit;
                    request.CanShare = sharedFolderOptions.CanShare;
                }
            }

            await vault.Auth.ExecuteAuthCommand(request);
            await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
            return vault.TryGetFolder(request.FolderUid, out var f) ? f : null;
        }

        public static async Task DeleteVaultObjects(this VaultOnline vault, IEnumerable<RecordPath> objectsToDelete, bool forceDelete = false)
        {
            var preDeleteObjects = new Dictionary<string, PreDeleteObject>();

            foreach (var toDelete in objectsToDelete)
            {
                var folder = vault.GetFolder(toDelete.FolderUid);
                string teamUid = null;
                if (folder.FolderType != FolderType.UserFolder)
                {
                    var sharedFolderUid = folder.FolderType == FolderType.SharedFolder ? folder.FolderUid : folder.SharedFolderUid;
                    var perm = vault.ResolveSharedFolderAccessPath(vault.Auth.Username, sharedFolderUid, false, true);
                    if (perm != null)
                    {
                        if (perm.UserType == UserType.Team)
                        {
                            teamUid = perm.UserId;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(toDelete.RecordUid)) // delete record
                {
                    if (folder.Records.Any(x => x == toDelete.RecordUid))
                    {
                        preDeleteObjects[folder.FolderUid] = new PreDeleteObject
                        {
                            fromUid = string.IsNullOrEmpty(folder.FolderUid) ? null : folder.FolderUid,
                            fromType = folder.FolderType == FolderType.UserFolder
                                ? FolderType.UserFolder.GetFolderTypeText()
                                : FolderType.SharedFolderFolder.GetFolderTypeText(),
                            objectUid = toDelete.RecordUid,
                            objectType = "record",
                            deleteResolution = "unlink",
                        };
                    }
                    else
                    {
                        throw new VaultException($"Record UID ({toDelete.RecordUid}) does not exist in folder \"{folder.Name}\"");
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(folder.FolderUid))
                    {
                        throw new VaultException("Cannot delete root folder.");
                    }

                    var parent = vault.GetFolder(folder.ParentUid);
                    preDeleteObjects[folder.FolderUid] = new PreDeleteObject
                    {
                        fromUid = string.IsNullOrEmpty(parent.FolderUid) ? null : parent.FolderUid,
                        fromType = parent.FolderType == FolderType.UserFolder
                            ? FolderType.UserFolder.GetFolderTypeText()
                            : FolderType.SharedFolderFolder.GetFolderTypeText(),
                        objectUid = folder.FolderUid,
                        objectType = folder.FolderType.GetFolderTypeText(),
                        deleteResolution = "unlink",
                    };
                }
            }

            if (preDeleteObjects.Count > 0)
            {
                var preRequest = new PreDeleteCommand
                {
                    objects = preDeleteObjects.Values.ToArray(),
                };

                var preResponse = await vault.Auth.ExecuteAuthCommand<PreDeleteCommand, PreDeleteResponse>(preRequest);
                var ok = forceDelete || vault.VaultUi == null;
                if (!ok)
                {
                    ok = await vault.VaultUi.Confirmation(string.Join("\n", preResponse.preDeleteResponse.wouldDelete.deletionSummary));
                }

                if (ok)
                {
                    await vault.Auth.ExecuteAuthCommand(new DeleteCommand
                    {
                        preDeleteToken = preResponse.preDeleteResponse.preDeleteToken,
                    });
                }
            }

            await vault.ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
        }
    }
}