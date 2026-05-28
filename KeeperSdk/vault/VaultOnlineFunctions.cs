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
    /// <summary>
    /// Represents shared folder record permissions.
    /// </summary>
    public class SharedFolderRecordOptions : IRecordShareOptions
    {
        /// <inheritdoc/>
        public bool? CanEdit { get; set; }
        /// <inheritdoc/>
        public bool? CanShare { get; set; }
        /// <inheritdoc/>
        public DateTimeOffset? Expiration { get; set; }
    }

    /// <summary>
    /// Defines shared folder user permissions.
    /// </summary>

    public class SharedFolderUserOptions : IUserShareOptions
    {
        /// <inheritdoc/>
        public bool? ManageRecords { get; set; }
        /// <inheritdoc/>
        public bool? ManageUsers { get; set; }
        /// <inheritdoc/>
        public DateTimeOffset? Expiration { get; set; }
    }

    /// <summary>
    ///  Defines shared folder user and record permissions.
    /// </summary>
    public class SharedFolderOptions
    {
        /// <summary>
        /// Record can be edited.
        /// </summary>
        public bool? CanEdit { get; set; }
        /// <summary>
        /// Record can be re-shared.
        /// </summary>
        public bool? CanShare { get; set; }
        /// <summary>
        /// User can manage other users.
        /// </summary>
        public bool? ManageUsers { get; set; }
        /// <summary>
        /// User can manage records.
        /// </summary>
        public bool? ManageRecords { get; set; }
    }

    internal static partial class VaultOnlineFunctions
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
                var ft = RecordFolderType.UserFolder;
                switch (node?.FolderType)
                {
                    case FolderType.SharedFolder:
                        ft = RecordFolderType.SharedFolder;
                        break;
                    case FolderType.SharedFolderFolder:
                        ft = RecordFolderType.SharedFolderFolder;
                        break;
                }

                var recordAddProto = new RecordAdd
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
                    recordAddProto.RecordLinks.AddRange(refKeys.Select(pair => new RecordLink
                    {
                        RecordUid = ByteString.CopyFrom(pair.Key.Base64UrlDecode()),
                        RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(pair.Value, record.RecordKey))
                    }));
                }

                if (vault.Auth.AuthContext.EnterprisePublicEcKey != null)
                {
                    var auditData = typed.ExtractRecordAuditData();
                    var data = JsonUtils.DumpJson(auditData);
                    recordAddProto.Audit = new RecordAudit
                    {
                        Version = 0,
                        Data = ByteString.CopyFrom(CryptoUtils.EncryptEc(data,
                            vault.Auth.AuthContext.EnterprisePublicEcKey))
                    };
                }

                var rq = new RecordsAddRequest
                {
                    ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                };
                rq.Records.Add(recordAddProto);
                var rs = await vault.Auth.ExecuteAuthRest<RecordsAddRequest, RecordsModifyResponse>(
                    "vault/records_add", rq);
                var modifyResult = rs.Records[0];
                if (modifyResult.Status != RecordModifyResult.RsSuccess)
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
                    throw new VaultException("Cannot find destination shared folder");
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
                            throw new VaultException("Cannot move the folder into its subfolder.");
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
                else if (record is PasswordRecord password)
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
                        var status = Enum.GetName(typeof(RecordModifyResult), x.Status) ?? "";
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
                if (passwordChanged.Count > 0)
                {
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

        public static async Task<FolderNode> AddFolder(this VaultOnline vault, string folderName, string parentFolderUid = null, SharedFolderOptions sharedFolderOptions = null)
        {
            if (string.IsNullOrEmpty(folderName))
            {
                throw new ArgumentNullException(nameof(folderName));
            }

            var parent = vault.GetFolder(parentFolderUid);
            FolderType folderType;
            if (sharedFolderOptions != null)
            {
                if (parent.FolderType != FolderType.UserFolder)
                {
                    throw new VaultException("Shared folder cannot be created");
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
                name = folderName,
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

        public static async Task<string> AddKeeperNSFFolder(this VaultOnline vault, string folderName, string parentFolderUid = null, string color = null, bool inheritPermissions = true)
        {
            if (string.IsNullOrEmpty(folderName))
            {
                throw new ArgumentNullException(nameof(folderName));
            }

            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                if (!vault.TryGetKeeperNSFFolder(parentFolderUid, out _))
                {
                    throw new VaultException($"Parent Keeper NSF folder '{parentFolderUid}' not found");
                }
            }

            var nameLower = folderName.ToLowerInvariant();
            foreach (var existing in vault.KeeperNSFFolderNodes)
            {
                if (existing.Name != null && existing.Name.ToLowerInvariant() == nameLower)
                {
                    var existingParent = existing.ParentUid ?? "";
                    var expectedParent = parentFolderUid ?? "";
                    if (existingParent == expectedParent)
                    {
                        throw new VaultException($"Keeper NSF folder '{folderName}' already exists");
                    }
                }
            }

            var folderUid = CryptoUtils.GenerateUid();
            var folderKey = CryptoUtils.GenerateEncryptionKey();

            var encryptionKey = vault.Auth.AuthContext.DataKey;
            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                if (vault.TryGetKeeperNSFFolder(parentFolderUid, out var parentFolder) && parentFolder.FolderKey != null)
                {
                    encryptionKey = parentFolder.FolderKey;
                }
            }

            var folderData = new FolderDataJson { name = folderName };
            if (!string.IsNullOrEmpty(color) && color != "none")
            {
                folderData.color = color;
            }
            var dataJson = JsonUtils.DumpJson(folderData, false);
            var encryptedData = CryptoUtils.EncryptAesV2(dataJson, folderKey);
            var encryptedFolderKey = CryptoUtils.EncryptAesV2(folderKey, encryptionKey);

            var fd = new Folder.FolderData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                Data = ByteString.CopyFrom(encryptedData),
                FolderKey = ByteString.CopyFrom(encryptedFolderKey),
                Type = Folder.FolderUsageType.UtNormal,
                InheritUserPermissions = inheritPermissions
                    ? Folder.SetBooleanValue.BooleanTrue
                    : Folder.SetBooleanValue.BooleanFalse,
            };

            if (!string.IsNullOrEmpty(parentFolderUid))
            {
                fd.ParentUid = ByteString.CopyFrom(parentFolderUid.Base64UrlDecode());
            }

            var rq = new Folder.FolderAddRequest();
            rq.FolderData.Add(fd);

            var response = await vault.Auth.ExecuteAuthRest<Folder.FolderAddRequest, Folder.FolderAddResponse>("vault/folders/v3/add", rq);

            if (response.FolderAddResults.Count > 0)
            {
                var result = response.FolderAddResults[0];
                if (result.Status == Folder.FolderModifyStatus.Success)
                {
                    return folderUid;
                }
                throw new VaultException($"Failed to create Keeper NSF folder: {result.Message}");
            }
            throw new VaultException("No response from server for folder creation");
        }

        private static global::Folder.AccessRoleType ResolveAccessRole(string role)
        {
            switch (role?.ToLowerInvariant())
            {
                case "viewer": return global::Folder.AccessRoleType.Viewer;
                case "shared-manager": return global::Folder.AccessRoleType.SharedManager;
                case "content-manager": return global::Folder.AccessRoleType.ContentManager;
                case "content-share-manager": return global::Folder.AccessRoleType.ContentShareManager;
                case "full-manager": return global::Folder.AccessRoleType.Manager;
                default:
                    throw new ArgumentException($"Unknown access role '{role}'. Valid roles: viewer, shared-manager, content-manager, content-share-manager, full-manager");
            }
        }

        public static async Task GrantKeeperNSFFolderAccessInternal(this VaultOnline vault, string folderUid, string userEmail, string role)
        {
            if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            var pkRq = new global::Authentication.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<global::Authentication.GetPublicKeysRequest, global::Authentication.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
                throw new KeeperApiException("public_key_error", $"User '{userEmail}' not found or has no public key: {pkRs.Message}");

            var folderKey = folder.FolderKey;
            if (folderKey == null)
                throw new VaultException($"Cannot share folder: folder key is not available for '{folderUid}'");

            byte[] encryptedFolderKey;
            global::Folder.EncryptedKeyType keyType;
            if (!pkRs.PublicKey.IsEmpty)
            {
                var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                encryptedFolderKey = CryptoUtils.EncryptRsa(folderKey, rsaPk);
                keyType = global::Folder.EncryptedKeyType.EncryptedByPublicKey;
            }
            else if (!pkRs.PublicEccKey.IsEmpty)
            {
                var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                encryptedFolderKey = CryptoUtils.EncryptEc(folderKey, ecPk);
                keyType = global::Folder.EncryptedKeyType.EncryptedByPublicKeyEcc;
            }
            else
            {
                throw new VaultException($"User '{userEmail}' has no public key available");
            }

            var accessRole = ResolveAccessRole(role);
            var accessData = new global::Folder.FolderAccessData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                AccessTypeUid = pkRs.AccountUid,
                AccessType = global::Folder.AccessType.AtUser,
                AccessRoleType = accessRole,
            };
            accessData.FolderKey = new global::Folder.EncryptedDataKey
            {
                EncryptedKey = ByteString.CopyFrom(encryptedFolderKey),
                EncryptedKeyType = keyType,
            };

            var rq = new global::Folder.FolderAccessRequest();
            rq.FolderAccessAdds.Add(accessData);

            var rs = await vault.Auth.ExecuteAuthRest<global::Folder.FolderAccessRequest, global::Folder.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != global::Folder.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to grant access: {result.Message}");
                }
            }
        }

        public static async Task RevokeKeeperNSFFolderAccessInternal(this VaultOnline vault, string folderUid, string userEmail)
        {
            if (!vault.TryGetKeeperNSFFolder(folderUid, out _))
                throw new VaultException($"Keeper NSF folder '{folderUid}' not found");

            var pkRq = new global::Authentication.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<global::Authentication.GetPublicKeysRequest, global::Authentication.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.AccountUid.IsEmpty)
                throw new KeeperApiException("user_not_found", $"User '{userEmail}' not found");

            var accessData = new global::Folder.FolderAccessData
            {
                FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode()),
                AccessTypeUid = pkRs.AccountUid,
                AccessType = global::Folder.AccessType.AtUser,
            };

            var rq = new global::Folder.FolderAccessRequest();
            rq.FolderAccessRemoves.Add(accessData);

            var rs = await vault.Auth.ExecuteAuthRest<global::Folder.FolderAccessRequest, global::Folder.FolderAccessResponse>(
                "vault/folders/v3/access_update", rq);

            foreach (var result in rs.FolderAccessResults)
            {
                if (result.Status != global::Folder.FolderModifyStatus.Success)
                {
                    throw new VaultException($"Failed to revoke access: {result.Message}");
                }
            }
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
            catch { }

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
                        request.TeamUid = perm.Uid;
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
            var preDeleteObjects = new List<PreDeleteObject>();

            foreach (var toDelete in objectsToDelete)
            {
                var folder = vault.GetFolder(toDelete.FolderUid);
                if (!string.IsNullOrEmpty(toDelete.RecordUid)) // delete record
                {
                    if (folder.Records.Any(x => x == toDelete.RecordUid))
                    {
                        preDeleteObjects.Add(new PreDeleteObject
                        {
                            fromUid = string.IsNullOrEmpty(folder.FolderUid) ? null : folder.FolderUid,
                            fromType = folder.FolderType == FolderType.UserFolder
                                    ? FolderType.UserFolder.GetFolderTypeText()
                                    : FolderType.SharedFolderFolder.GetFolderTypeText(),
                            objectUid = toDelete.RecordUid,
                            objectType = "record",
                            deleteResolution = "unlink",
                        }
                        );
                    }
                    else
                    {
                        KeeperRecord record;
                        if (vault.TryGetKeeperRecord(toDelete.RecordUid, out record))
                        {
                            preDeleteObjects.Add(new PreDeleteObject
                            {
                                fromUid = null,
                                fromType = FolderType.UserFolder.GetFolderTypeText(),
                                objectUid = toDelete.RecordUid,
                                objectType = "record",
                                deleteResolution = "unlink",
                            }
                            );
                        }
                        else
                        {
                            throw new VaultException($"Record UID ({toDelete.RecordUid}) does not exist in folder \"{folder.Name}\"");
                        }

                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(folder.FolderUid))
                    {
                        throw new VaultException("Cannot delete root folder.");
                    }

                    var parent = vault.GetFolder(folder.ParentUid);
                    preDeleteObjects.Add(new PreDeleteObject
                    {
                        fromUid = string.IsNullOrEmpty(parent.FolderUid) ? null : parent.FolderUid,
                        fromType = parent.FolderType == FolderType.UserFolder
                            ? FolderType.UserFolder.GetFolderTypeText()
                            : FolderType.SharedFolderFolder.GetFolderTypeText(),
                        objectUid = folder.FolderUid,
                        objectType = folder.FolderType.GetFolderTypeText(),
                        deleteResolution = "unlink",
                    });
                }
            }

            if (preDeleteObjects.Count > 0)
            {
                var preRequest = new PreDeleteCommand
                {
                    objects = preDeleteObjects.ToArray(),
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

        public static async Task<string> CreateKeeperNSFRecordInternal(this VaultOnline vault, string title, string recordType, string folderUid, string notes, IDictionary<string, string> fields)
        {
            if (string.IsNullOrEmpty(title))
                throw new VaultException("Record title cannot be empty");

            var recordUid = CryptoUtils.GenerateUid();
            var recordKey = CryptoUtils.GenerateEncryptionKey();

            byte[] encryptionKey;
            global::Folder.FolderKeyEncryptionType keyEncryptedBy;

            if (!string.IsNullOrEmpty(folderUid))
            {
                if (!vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                    throw new VaultException($"Keeper NSF folder '{folderUid}' not found");
                if (folder.FolderKey == null)
                    throw new VaultException($"Folder key not available for folder '{folderUid}'");
                encryptionKey = folder.FolderKey;
                keyEncryptedBy = global::Folder.FolderKeyEncryptionType.EncryptedByParentKey;
            }
            else
            {
                encryptionKey = vault.Auth.AuthContext.DataKey;
                keyEncryptedBy = global::Folder.FolderKeyEncryptionType.EncryptedByUserKey;
            }

            var dataObj = new NsfRecordDataJson
            {
                type = recordType ?? "general",
                title = title,
                notes = notes,
                fields = new List<NsfRecordFieldJson>()
            };

            if (fields != null)
            {
                foreach (var kvp in fields)
                {
                    dataObj.fields.Add(new NsfRecordFieldJson
                    {
                        type = kvp.Key,
                        value = new[] { kvp.Value }
                    });
                }
            }

            var jsonData = JsonUtils.DumpJson(dataObj, false);
            jsonData = VaultExtensions.PadRecordData(jsonData);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, recordKey);
            var encryptedRecordKey = CryptoUtils.EncryptAesV2(recordKey, encryptionKey);

            var ra = new global::Record.V3.RecordAdd
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                RecordKeyType = global::Folder.EncryptedKeyType.EncryptedByDataKeyGcm,
                RecordKeyEncryptedBy = keyEncryptedBy,
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Data = ByteString.CopyFrom(encryptedData),
            };

            if (!string.IsNullOrEmpty(folderUid))
            {
                ra.FolderUid = ByteString.CopyFrom(folderUid.Base64UrlDecode());
            }

            var rq = new global::Record.V3.RecordsAddRequest();
            rq.Records.Add(ra);

            var rs = await vault.Auth.ExecuteAuthRest<global::Record.V3.RecordsAddRequest, RecordsModifyResponse>(
                "vault/records/v3/add", rq);

            if (rs.Records.Count > 0)
            {
                var result = rs.Records[0];
                if (result.Status != RecordModifyResult.RsSuccess)
                {
                    throw new VaultException($"Failed to create record: {result.Message}");
                }
            }

            return recordUid;
        }

        public static async Task UpdateKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string title, string recordType, string notes, IDictionary<string, string> fields)
        {
            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                throw new VaultException($"Keeper NSF record '{recordUid}' not found");

            if (record.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");

            if (string.IsNullOrEmpty(record.DecryptedData))
                throw new VaultException($"Record '{recordUid}' has no decrypted data available. Cannot update.");

            NsfRecordDataJson dataObj;
            try
            {
                var dataBytes = System.Text.Encoding.UTF8.GetBytes(record.DecryptedData);
                dataObj = JsonUtils.ParseJson<NsfRecordDataJson>(dataBytes);
            }
            catch (Exception ex)
            {
                throw new VaultException($"Failed to parse existing record data for '{recordUid}': {ex.Message}");
            }

            if (dataObj.fields == null)
            {
                dataObj.fields = new List<NsfRecordFieldJson>();
            }

            if (title != null) dataObj.title = title;
            if (recordType != null) dataObj.type = recordType;
            if (notes != null) dataObj.notes = notes;

            if (fields != null)
            {
                foreach (var kvp in fields)
                {
                    var existing = dataObj.fields.FirstOrDefault(f => f.type == kvp.Key);
                    if (existing != null)
                    {
                        existing.value = new[] { kvp.Value };
                    }
                    else
                    {
                        dataObj.fields.Add(new NsfRecordFieldJson
                        {
                            type = kvp.Key,
                            value = new[] { kvp.Value },
                        });
                    }
                }
            }

            var jsonData = JsonUtils.DumpJson(dataObj, false);
            jsonData = VaultExtensions.PadRecordData(jsonData);
            var encryptedData = CryptoUtils.EncryptAesV2(jsonData, record.RecordKey);

            var ru = new RecordUpdate
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                ClientModifiedTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Revision = record.Revision,
                Data = ByteString.CopyFrom(encryptedData),
            };

            var rq = new RecordsUpdateRequest();
            rq.Records.Add(ru);

            var rs = await vault.Auth.ExecuteAuthRest<RecordsUpdateRequest, RecordsModifyResponse>(
                "vault/records/v3/update", rq);

            if (rs.Records.Count > 0)
            {
                var result = rs.Records[0];
                if (result.Status != RecordModifyResult.RsSuccess)
                {
                    throw new VaultException($"Failed to update record: {result.Message}");
                }
            }
        }

        private static async Task<global::Record.V3.Sharing.Permissions> BuildRecordSharePermissions(
            VaultOnline vault, string recordUid, string userEmail, string role)
        {
            if (!vault.TryGetKeeperNSFRecord(recordUid, out var record))
                throw new VaultException($"Keeper NSF record '{recordUid}' not found");
            if (record.RecordKey == null)
                throw new VaultException($"Record key not available for record '{recordUid}'");

            var pkRq = new global::Authentication.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<global::Authentication.GetPublicKeysRequest, global::Authentication.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.PublicEccKey.IsEmpty && pkRs.PublicKey.IsEmpty)
                throw new KeeperApiException("public_key_error", $"User '{userEmail}' not found or has no public key: {pkRs.Message}");

            byte[] encryptedRecordKey;
            bool useEcc;
            if (!pkRs.PublicKey.IsEmpty)
            {
                var rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptRsa(record.RecordKey, rsaPk);
                useEcc = false;
            }
            else
            {
                var ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
                encryptedRecordKey = CryptoUtils.EncryptEc(record.RecordKey, ecPk);
                useEcc = true;
            }

            var accessRole = ResolveAccessRole(role);
            var perm = new global::Record.V3.Sharing.Permissions
            {
                RecipientUid = pkRs.AccountUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                RecordKey = ByteString.CopyFrom(encryptedRecordKey),
                UseEccKey = useEcc,
            };
            perm.Rules = new global::Folder.RecordAccessData
            {
                AccessTypeUid = pkRs.AccountUid,
                AccessType = global::Folder.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                Owner = false,
                AccessRoleType = accessRole,
            };
            return perm;
        }

        public static async Task ShareKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string userEmail, string role)
        {
            var perm = await BuildRecordSharePermissions(vault, recordUid, userEmail, role);

            var rq = new global::Record.V3.Sharing.Request();
            rq.CreateSharingPermissions.Add(perm);

            var rs = await vault.Auth.ExecuteAuthRest<global::Record.V3.Sharing.Request, global::Record.V3.Sharing.Response>(
                "vault/records/v3/share", rq);

            foreach (var status in rs.CreatedSharingStatus)
            {
                if (status.Status_ != global::Record.V3.Sharing.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to share record: {status.Message}");
                }
            }
        }

        public static async Task UnshareKeeperNSFRecordInternal(this VaultOnline vault, string recordUid, string userEmail)
        {
            var pkRq = new global::Authentication.GetPublicKeysRequest();
            pkRq.Usernames.Add(userEmail);
            var pkRss = await vault.Auth.ExecuteAuthRest<global::Authentication.GetPublicKeysRequest, global::Authentication.GetPublicKeysResponse>(
                "vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];

            if (pkRs.AccountUid.IsEmpty)
                throw new KeeperApiException("user_not_found", $"User '{userEmail}' not found");

            var perm = new global::Record.V3.Sharing.Permissions
            {
                RecipientUid = pkRs.AccountUid,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };
            perm.Rules = new global::Folder.RecordAccessData
            {
                AccessTypeUid = pkRs.AccountUid,
                AccessType = global::Folder.AccessType.AtUser,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };

            var rq = new global::Record.V3.Sharing.Request();
            rq.RevokeSharingPermissions.Add(perm);

            var rs = await vault.Auth.ExecuteAuthRest<global::Record.V3.Sharing.Request, global::Record.V3.Sharing.Response>(
                "vault/records/v3/share", rq);

            foreach (var status in rs.RevokedSharingStatus)
            {
                if (status.Status_ != global::Record.V3.Sharing.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to revoke record access: {status.Message}");
                }
            }
        }

        private static string GetRoleLabel(int roleType)
        {
            var enumValue = (global::Folder.AccessRoleType)roleType;
            switch (enumValue)
            {
                case global::Folder.AccessRoleType.Navigator: return "contributor";
                case global::Folder.AccessRoleType.Requestor: return "contributor";
                case global::Folder.AccessRoleType.Viewer: return "viewer";
                case global::Folder.AccessRoleType.SharedManager: return "shared-manager";
                case global::Folder.AccessRoleType.ContentManager: return "content-manager";
                case global::Folder.AccessRoleType.ContentShareManager: return "content-share-manager";
                case global::Folder.AccessRoleType.Manager: return "full-manager";
                default: return "unknown";
            }
        }

        private static void CollectRecordUids(VaultOnline vault, string folderUid, bool recursive, HashSet<string> recordUids, HashSet<string> visited)
        {
            if (folderUid != null)
            {
                if (visited.Contains(folderUid)) return;
                visited.Add(folderUid);

                if (vault.TryGetKeeperNSFFolder(folderUid, out var folder))
                {
                    foreach (var recUid in folder.Records)
                    {
                        recordUids.Add(recUid);
                    }

                    if (recursive)
                    {
                        foreach (var subUid in folder.Subfolders)
                        {
                            CollectRecordUids(vault, subUid, true, recordUids, visited);
                        }
                    }
                }
            }
            else
            {
                foreach (var folder in vault.KeeperNSFFolderNodes)
                {
                    if (visited.Contains(folder.FolderUid)) continue;
                    visited.Add(folder.FolderUid);

                    foreach (var recUid in folder.Records)
                    {
                        recordUids.Add(recUid);
                    }
                }
            }
        }

        public static async Task<KeeperNSFPermissionResult> UpdateKeeperNSFRecordPermissionsInternal(
            this VaultOnline vault, string folderUid, string action, string role, bool recursive, bool dryRun = false)
        {
            var recordUids = new HashSet<string>();
            CollectRecordUids(vault, folderUid, recursive, recordUids, new HashSet<string>());

            if (recordUids.Count == 0)
                throw new VaultException("No records found in the specified folder");

            var accessRq = new global::Record.V3.Details.RecordAccessRequest();
            foreach (var uid in recordUids)
            {
                accessRq.RecordUids.Add(ByteString.CopyFrom(uid.Base64UrlDecode()));
            }

            var accessRs = await vault.Auth.ExecuteAuthRest<global::Record.V3.Details.RecordAccessRequest,
                global::Record.V3.Details.RecordAccessResponse>(
                "vault/records/v3/details/access", accessRq);

            var currentUser = vault.Auth.Username;
            var forbidden = new HashSet<string>();
            foreach (var fu in accessRs.ForbiddenRecords)
            {
                forbidden.Add(CryptoUtils.Base64UrlEncode(fu.ToByteArray()));
            }

            var accesses = new List<KeeperNSFAccessEntry>();
            var canUpdateMap = new Dictionary<string, bool>();

            foreach (var ra in accessRs.RecordAccesses)
            {
                var d = ra.Data;
                var ai = ra.AccessorInfo;
                var recUid = CryptoUtils.Base64UrlEncode(d.RecordUid.ToByteArray());
                var accessorName = ai?.Name ?? "";

                if (accessorName == currentUser)
                {
                    canUpdateMap[recUid] = d.CanUpdateAccess;
                }

                accesses.Add(new KeeperNSFAccessEntry
                {
                    RecordUid = recUid,
                    AccessorName = accessorName,
                    AccessTypeUid = CryptoUtils.Base64UrlEncode(d.AccessTypeUid.ToByteArray()),
                    Owner = d.Owner,
                    Inherited = d.Inherited,
                    AccessRoleType = (int)d.AccessRoleType,
                    CanEdit = d.CanEdit,
                    CanView = d.CanView,
                    CanUpdateAccess = d.CanUpdateAccess,
                    CanDelete = d.CanDelete,
                });
            }

            var result = new KeeperNSFPermissionResult();

            foreach (var recUid in recordUids)
            {
                if (forbidden.Contains(recUid))
                {
                    result.Skipped.Add(new KeeperNSFPermissionChange
                    {
                        RecordUid = recUid, Email = "", CurrentRole = "",
                        ChangeType = "skip", Message = "No access - record is forbidden",
                    });
                }
            }

            foreach (var access in accesses)
            {
                if (!recordUids.Contains(access.RecordUid) || access.Owner)
                    continue;
                if (string.IsNullOrEmpty(access.AccessorName) || access.AccessorName == currentUser)
                    continue;

                var curRole = GetRoleLabel(access.AccessRoleType);

                if (!canUpdateMap.TryGetValue(access.RecordUid, out var canUpdate) || !canUpdate)
                {
                    result.Skipped.Add(new KeeperNSFPermissionChange
                    {
                        RecordUid = access.RecordUid, Email = access.AccessorName,
                        CurrentRole = curRole, ChangeType = "skip",
                        Message = "Insufficient permission (can_update_access is false)",
                    });
                    continue;
                }

                if (action == "grant")
                {
                    if (curRole != role)
                    {
                        if (dryRun)
                        {
                            result.Grants.Add(new KeeperNSFPermissionChange
                            {
                                RecordUid = access.RecordUid, Email = access.AccessorName,
                                CurrentRole = curRole, NewRole = role,
                                ChangeType = access.Inherited ? "create" : "update",
                                Success = true, Message = "dry-run",
                            });
                        }
                        else
                        {
                            try
                            {
                                if (access.Inherited)
                                {
                                    await vault.ShareKeeperNSFRecordInternal(access.RecordUid, access.AccessorName, role);
                                }
                                else
                                {
                                    await UpdateKeeperNSFRecordShareInternal(vault, access.RecordUid, access.AccessorName, role);
                                }
                                result.Grants.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, NewRole = role,
                                    ChangeType = access.Inherited ? "create" : "update",
                                    Success = true,
                                });
                            }
                            catch (Exception ex)
                            {
                                result.Grants.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, NewRole = role,
                                    ChangeType = access.Inherited ? "create" : "update",
                                    Success = false, Message = ex.Message,
                                });
                            }
                        }
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(role) || curRole == role)
                    {
                        if (access.Inherited)
                        {
                            result.Skipped.Add(new KeeperNSFPermissionChange
                            {
                                RecordUid = access.RecordUid, Email = access.AccessorName,
                                CurrentRole = curRole, ChangeType = "skip",
                                Message = "Inherited from a shared folder - revoke at the parent shared folder",
                            });
                        }
                        else if (dryRun)
                        {
                            result.Revokes.Add(new KeeperNSFPermissionChange
                            {
                                RecordUid = access.RecordUid, Email = access.AccessorName,
                                CurrentRole = curRole, ChangeType = "revoke",
                                Success = true, Message = "dry-run",
                            });
                        }
                        else
                        {
                            try
                            {
                                await vault.UnshareKeeperNSFRecordInternal(access.RecordUid, access.AccessorName);
                                result.Revokes.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, ChangeType = "revoke", Success = true,
                                });
                            }
                            catch (Exception ex)
                            {
                                result.Revokes.Add(new KeeperNSFPermissionChange
                                {
                                    RecordUid = access.RecordUid, Email = access.AccessorName,
                                    CurrentRole = curRole, ChangeType = "revoke",
                                    Success = false, Message = ex.Message,
                                });
                            }
                        }
                    }
                }
            }

            return result;
        }

        private static async Task UpdateKeeperNSFRecordShareInternal(VaultOnline vault, string recordUid, string userEmail, string role)
        {
            var perm = await BuildRecordSharePermissions(vault, recordUid, userEmail, role);

            var rq = new global::Record.V3.Sharing.Request();
            rq.UpdateSharingPermissions.Add(perm);

            var rs = await vault.Auth.ExecuteAuthRest<global::Record.V3.Sharing.Request, global::Record.V3.Sharing.Response>(
                "vault/records/v3/share", rq);

            foreach (var status in rs.UpdatedSharingStatus)
            {
                if (status.Status_ != global::Record.V3.Sharing.SharingStatus.Success)
                {
                    throw new VaultException($"Failed to update record share: {status.Message}");
                }
            }
        }

        private static Dictionary<string, HashSet<string>> BuildShortcutMap(VaultOnline vault)
        {
            var knownFolders = new HashSet<string>();
            foreach (var f in vault.KeeperNSFFolderNodes)
            {
                knownFolders.Add(f.FolderUid);
            }

            var recordFolders = new Dictionary<string, HashSet<string>>();
            foreach (var link in vault.Storage.KdFolderRecords.GetAllLinks())
            {
                if (!knownFolders.Contains(link.FolderUid))
                    continue;
                if (!recordFolders.TryGetValue(link.RecordUid, out var folders))
                {
                    folders = new HashSet<string>();
                    recordFolders[link.RecordUid] = folders;
                }
                folders.Add(link.FolderUid);
            }

            var shortcuts = new Dictionary<string, HashSet<string>>();
            foreach (var kvp in recordFolders)
            {
                if (kvp.Value.Count > 1)
                {
                    shortcuts[kvp.Key] = kvp.Value;
                }
            }
            return shortcuts;
        }

        private static string GetRecordTitle(VaultOnline vault, string recordUid)
        {
            if (vault.TryGetKeeperNSFRecord(recordUid, out var rec))
            {
                if (!string.IsNullOrEmpty(rec.Name))
                    return rec.Name;
                if (!string.IsNullOrEmpty(rec.DecryptedData))
                {
                    try
                    {
                        var data = JsonUtils.ParseJson<Dictionary<string, object>>(
                            Encoding.UTF8.GetBytes(rec.DecryptedData));
                        if (data != null && data.TryGetValue("title", out var titleObj) && titleObj is string title)
                            return title;
                    }
                    catch { }
                }
            }
            return recordUid;
        }

        private static string GetFolderName(VaultOnline vault, string folderUid)
        {
            if (vault.TryGetKeeperNSFFolder(folderUid, out var folder) && !string.IsNullOrEmpty(folder.Name))
                return folder.Name;
            return folderUid;
        }

        public static IList<KeeperNSFShortcutEntry> GetKeeperNSFShortcutsInternal(
            this VaultOnline vault, string recordUid = null, string folderUid = null)
        {
            var shortcuts = BuildShortcutMap(vault);
            var result = new List<KeeperNSFShortcutEntry>();

            IEnumerable<string> recordUids;
            if (!string.IsNullOrEmpty(recordUid))
            {
                if (!shortcuts.ContainsKey(recordUid))
                    return result;
                recordUids = new[] { recordUid };
            }
            else if (!string.IsNullOrEmpty(folderUid))
            {
                recordUids = shortcuts.Keys.Where(r => shortcuts[r].Contains(folderUid));
            }
            else
            {
                recordUids = shortcuts.Keys;
            }

            foreach (var rUid in recordUids.OrderBy(x => x))
            {
                var entry = new KeeperNSFShortcutEntry
                {
                    RecordUid = rUid,
                    Title = GetRecordTitle(vault, rUid),
                };
                foreach (var fUid in shortcuts[rUid].OrderBy(x => x))
                {
                    entry.Folders.Add(new KeeperNSFShortcutFolder
                    {
                        FolderUid = fUid,
                        Name = GetFolderName(vault, fUid),
                    });
                }
                result.Add(entry);
            }

            return result;
        }

        public static async Task<KeeperNSFShortcutKeepResult> KeepKeeperNSFRecordInFolderInternal(
            this VaultOnline vault, string recordUid, string keepFolderUid)
        {
            var shortcuts = BuildShortcutMap(vault);

            if (!shortcuts.TryGetValue(recordUid, out var folderSet))
                throw new VaultException($"Record '{recordUid}' does not appear in multiple folders");
            if (!folderSet.Contains(keepFolderUid))
                throw new VaultException($"Record '{recordUid}' is not in folder '{keepFolderUid}'");

            var foldersToRemove = folderSet.Where(f => f != keepFolderUid).ToList();
            if (foldersToRemove.Count == 0)
                throw new VaultException("Record is already in only one folder");

            var result = new KeeperNSFShortcutKeepResult
            {
                RecordUid = recordUid,
                KeptFolderUid = keepFolderUid,
                KeptFolderName = GetFolderName(vault, keepFolderUid),
            };

            var recordUidBytes = ByteString.CopyFrom(recordUid.Base64UrlDecode());
            var removalMetadata = new global::Folder.RecordMetadata
            {
                RecordUid = recordUidBytes,
                EncryptedRecordKey = ByteString.Empty,
                EncryptedRecordKeyType = global::Folder.EncryptedKeyType.NoKey,
            };

            foreach (var fUid in foldersToRemove)
            {
                var removal = new KeeperNSFShortcutRemoval
                {
                    FolderUid = fUid,
                    FolderName = GetFolderName(vault, fUid),
                };
                try
                {
                    var rq = new global::Folder.FolderRecordUpdateRequest
                    {
                        FolderUid = ByteString.CopyFrom(fUid.Base64UrlDecode()),
                    };
                    rq.RemoveRecords.Add(removalMetadata);

                    var rs = await vault.Auth.ExecuteAuthRest<global::Folder.FolderRecordUpdateRequest,
                        global::Folder.FolderRecordUpdateResponse>(
                        "vault/folders/v3/record_update", rq);

                    var hasError = false;
                    foreach (var r in rs.FolderRecordUpdateResult)
                    {
                        if (r.Status != global::Folder.FolderModifyStatus.Success)
                        {
                            hasError = true;
                            removal.Message = r.Message;
                        }
                    }
                    removal.Success = !hasError;
                }
                catch (Exception ex)
                {
                    removal.Success = false;
                    removal.Message = ex.Message;
                }
                result.Removals.Add(removal);
            }

            return result;
        }
    }
}
