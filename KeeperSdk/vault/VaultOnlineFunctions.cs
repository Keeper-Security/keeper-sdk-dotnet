using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Represents shared folder record permissions.
    /// </summary>
    public class SharedFolderRecordOptions : ISharedFolderRecordOptions
    {
        public bool? CanEdit { get; set; }
        public bool? CanShare { get; set; }
    }

    /// <summary>
    /// Defines shared folder user permissions.
    /// </summary>

    public class SharedFolderUserOptions : ISharedFolderUserOptions
    {
        public bool? ManageRecords { get; set; }
        public bool? ManageUsers { get; set; }
    }

    /// <summary>
    ///  Defines shared folder user and record permissions.
    /// </summary>
    public class SharedFolderOptions : ISharedFolderRecordOptions, ISharedFolderUserOptions
    {
        public bool? CanEdit { get; set; }
        public bool? CanShare { get; set; }
        public bool? ManageUsers { get; set; }
        public bool? ManageRecords { get; set; }
    }

    internal static class VaultOnlineFunctions
    {
        public static async Task<PasswordRecord> AddRecordToFolder(this VaultOnline vault, PasswordRecord record, string folderUid = null)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(folderUid))
            {
                vault.TryGetFolder(folderUid, out node);
            }

            record.Uid = CryptoUtils.GenerateUid();
            record.RecordKey = CryptoUtils.GenerateEncryptionKey();
            var recordAdd = new RecordAddCommand
            {
                RecordUid = record.Uid,
                RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, vault.Auth.AuthContext.DataKey).Base64UrlEncode(),
                RecordType = "password"
            };
            if (node == null)
            {
                recordAdd.FolderType = "user_folder";
            }
            else
            {
                switch (node.FolderType)
                {
                    case FolderType.UserFolder:
                        recordAdd.FolderType = "user_folder";
                        recordAdd.FolderUid = node.FolderUid;
                        break;
                    case FolderType.SharedFolder:
                    case FolderType.SharedFolderFolder:
                        recordAdd.FolderUid = node.FolderUid;
                        recordAdd.FolderType = node.FolderType == FolderType.SharedFolder
                            ? "shared_folder"
                            : "shared_folder_folder";
                        if (vault.TryGetSharedFolder(node.SharedFolderUid, out var sf))
                        {
                            recordAdd.FolderKey = CryptoUtils.EncryptAesV1(record.RecordKey, sf.SharedFolderKey)
                                .Base64UrlEncode();
                        }

                        if (string.IsNullOrEmpty(recordAdd.FolderKey))
                        {
                            throw new Exception($"Cannot resolve shared folder for folder UID: {folderUid}");
                        }

                        break;
                }
            }

            var dataSerializer = new DataContractJsonSerializer(typeof(RecordData), JsonUtils.JsonSettings);
            var data = record.ExtractRecordData();
            using (var ms = new MemoryStream())
            {
                dataSerializer.WriteObject(ms, data);
                recordAdd.Data = CryptoUtils.EncryptAesV1(ms.ToArray(), record.RecordKey).Base64UrlEncode();
            }

            await vault.Auth.ExecuteAuthCommand(recordAdd);
            await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
            return vault.TryGetRecord(record.Uid, out var r) ? r : record;
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
                        if (!vault.TryGetRecord(recordUid, out var record))
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
                    if (string.IsNullOrEmpty(sourceFolder.ParentUid))
                    {
                        throw new VaultException("Cannot move root folder");
                    }

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
                        uid = mo.RecordUid,
                        type = sourceFolder.FolderType.GetFolderTypeText(),
                        cascade = true,
                    });
                }
                else
                {
                    if (!vault.TryGetRecord(mo.RecordUid, out var record))
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
        }

        public static async Task<PasswordRecord> PutRecord(this VaultOnline vault, PasswordRecord record, bool skipData = false, bool skipExtra = true)
        {
            IPasswordRecord existingRecord = null;
            if (!string.IsNullOrEmpty(record.Uid))
            {
                existingRecord = vault.Storage.Records.GetEntity(record.Uid);
            }

            if (existingRecord == null)
            {
                return await vault.AddRecordToFolder(record);
            }

            var updateRecord = new RecordUpdateRecord
            {
                RecordUid = existingRecord.RecordUid
            };

            var rmd = vault.ResolveRecordAccessPath(updateRecord, true);
            if (rmd != null)
            {
                if (rmd.RecordKeyType == (int) KeyType.NoKey || rmd.RecordKeyType == (int) KeyType.PrivateKey)
                {
                    updateRecord.RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, vault.Auth.AuthContext.DataKey)
                        .Base64UrlEncode();
                }
            }

            updateRecord.Revision = existingRecord.Revision;

            if (!skipData)
            {
                var dataSerializer = new DataContractJsonSerializer(typeof(RecordData), JsonUtils.JsonSettings);
                RecordData existingData = null;
                try
                {
                    var unencryptedData =
                        CryptoUtils.DecryptAesV1(existingRecord.Data.Base64UrlDecode(), record.RecordKey);
                    using (var ms = new MemoryStream(unencryptedData))
                    {
                        existingData = (RecordData) dataSerializer.ReadObject(ms);
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"",
                        existingRecord.RecordUid,
                        e.GetType().Name,
                        e.Message);
                }

                var data = record.ExtractRecordData(existingData);
                using (var ms = new MemoryStream())
                {
                    dataSerializer.WriteObject(ms, data);
                    updateRecord.Data = CryptoUtils.EncryptAesV1(ms.ToArray(), record.RecordKey).Base64UrlEncode();
                }
            }

            if (!skipExtra)
            {
                var extraSerializer = new DataContractJsonSerializer(typeof(RecordExtra), JsonUtils.JsonSettings);
                RecordExtra existingExtra = null;
                try
                {
                    var unencryptedExtra =
                        CryptoUtils.DecryptAesV1(existingRecord.Extra.Base64UrlDecode(), record.RecordKey);
                    using (var ms = new MemoryStream(unencryptedExtra))
                    {
                        existingExtra = (RecordExtra) extraSerializer.ReadObject(ms);
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"",
                        existingRecord.RecordUid,
                        e.GetType().Name,
                        e.Message);

                }

                var extra = record.ExtractRecordExtra(existingExtra);
                using (var ms = new MemoryStream())
                {
                    extraSerializer.WriteObject(ms, extra);
                    updateRecord.Extra = CryptoUtils.EncryptAesV1(ms.ToArray(), record.RecordKey).Base64UrlEncode();
                }

                var udata = new RecordUpdateUData();
                var ids = new HashSet<string>();
                if (record.Attachments != null)
                {
                    foreach (var atta in record.Attachments)
                    {
                        ids.Add(atta.Id);
                        if (atta.Thumbnails != null)
                        {
                            foreach (var thumb in atta.Thumbnails)
                            {
                                ids.Add(thumb.Id);
                            }
                        }
                    }
                }

                udata.FileIds = ids.ToArray();
                updateRecord.Udata = udata;
            }

            var command = new RecordUpdateCommand
            {
                deviceId = vault.Auth.DeviceToken.Base64UrlEncode(),
                UpdateRecords = new[] {updateRecord}
            };

            await vault.Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
            await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));

            return vault.TryGetRecord(record.Uid, out var r) ? r : record;
        }

        public static async Task PutNonSharedData<T>(this VaultOnline vault, string recordUid, T nonSharedData) 
            where T : RecordNonSharedData, new()
        {
            var existingData = vault.LoadNonSharedData<T>(recordUid) ?? new T();
            nonSharedData.ExtensionData = existingData.ExtensionData;
            var data = JsonUtils.DumpJson(nonSharedData);

            var existingRecord = vault.Storage.Records.GetEntity(recordUid);
            var updateRecord = new RecordUpdateRecord
            {
                RecordUid = recordUid,
                Revision = existingRecord?.Revision ?? 0,
                NonSharedData = CryptoUtils.EncryptAesV1(data, vault.Auth.AuthContext.DataKey).Base64UrlEncode()
            };
            var command = new RecordUpdateCommand
            {
                deviceId = vault.Auth.DeviceToken.Base64UrlEncode(),
                UpdateRecords = new[] {updateRecord}
            };
            await vault.Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
            await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
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
            await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
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

            var existingRecord = vault.Storage.Folders.GetEntity(folderUid);
            var data = string.IsNullOrEmpty(existingRecord?.Data)
                ? new FolderData()
                : JsonUtils.ParseJson<FolderData>(existingRecord.Data.Base64UrlDecode());
            data.name = folderName;
            var dataBytes = JsonUtils.DumpJson(data);

            var encryptionKey = vault.Auth.AuthContext.DataKey;
            if (folder.FolderType == FolderType.SharedFolderFolder)
            {
                encryptionKey = vault.GetSharedFolder(folder.SharedFolderUid).SharedFolderKey;
            }

            request.Data = CryptoUtils.EncryptAesV1(dataBytes, encryptionKey).Base64UrlEncode();

            if (folder.FolderType != FolderType.UserFolder)
            {
                var sharedFolderUid = folder.FolderType == FolderType.UserFolder ? folder.FolderUid : folder.SharedFolderUid;
                var perm = vault.ResolveSharedFolderAccessPath(vault.Auth.Username, sharedFolderUid, true, true);
                if (perm != null)
                {
                    if (perm.UserType == UserType.Team)
                    {
                        request.TeamUid = perm.UserId;
                    }
                }
                else
                {
                    throw new VaultException($"You don't have permissions to modify shared folder ({sharedFolderUid})");
                }
            }

            if (sharedFolderOptions != null && folder.FolderType == FolderType.SharedFolder)
            {
                if (!vault.TryGetSharedFolder(folder.FolderUid, out var sharedFolder))
                {
                    request.Name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(folderName), sharedFolder.SharedFolderKey).Base64UrlEncode();
                }

                request.ManageUsers = sharedFolderOptions.ManageUsers;
                request.ManageRecords = sharedFolderOptions.ManageRecords;
                request.CanEdit = sharedFolderOptions.CanEdit;
                request.CanShare = sharedFolderOptions.CanShare;
            }

            await vault.Auth.ExecuteAuthCommand(request);
            await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
            return vault.TryGetFolder(request.FolderUid, out var f) ? f : null;
        }

        public static async Task DeleteVaultObjects(this VaultOnline vault, IEnumerable<RecordPath> objectsToDelete, bool forceDelete = false)
        {
            var sharedFoldersToDelete = new Dictionary<string, Tuple<SharedFolder, string>>();
            var preDeleteObjects = new Dictionary<string, PreDeleteObject>();

            foreach (var toDelete in objectsToDelete)
            {
                var folder = vault.GetFolder(toDelete.FolderUid);
                string teamUid = null;
                if (folder.FolderType != FolderType.UserFolder)
                {
                    var sharedFolderUid = folder.FolderType == FolderType.SharedFolder ? folder.FolderUid : folder.SharedFolderUid;
                    var perm = vault.ResolveSharedFolderAccessPath(vault.Auth.Username, sharedFolderUid, true, true);
                    if (perm == null)
                    {
                        throw new VaultException($"You don't have delete permissions in shared folder \"{folder.Name}\" ({sharedFolderUid})");
                    }

                    if (perm.UserType == UserType.Team)
                    {
                        teamUid = perm.UserId;
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

                    if (folder.FolderType == FolderType.SharedFolder)
                    {
                        sharedFoldersToDelete[folder.FolderUid] = Tuple.Create(vault.GetSharedFolder(folder.FolderUid), teamUid);
                    }
                    else
                    {
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
            }

            if (sharedFoldersToDelete.Count > 0)
            {
                var requests = new List<SharedFolderUpdateCommand>();
                var recordCount = 0;
                foreach (var tuple in sharedFoldersToDelete.Values)
                {
                    var sharedFolder = tuple.Item1;
                    var teamUid = tuple.Item2;
                    recordCount += sharedFolder.RecordPermissions?.Count ?? 0;
                    requests.Add(new SharedFolderUpdateCommand
                    {
                        pt = vault.Auth.AuthContext.SessionToken.Base64UrlEncode(),
                        operation = "delete",
                        shared_folder_uid = tuple.Item1.Uid,
                        from_team_uid = tuple.Item2,
                    });
                }

                var ok = forceDelete || vault.VaultUi == null;
                if (!ok)
                {
                    var confirmation = $"Your request will result in the deletion of:\n{sharedFoldersToDelete.Count} Shared Folder(s)";
                    if (recordCount > 0)
                    {
                        confirmation += $"{recordCount} Record(s)";
                    }

                    ok = await vault.VaultUi.Confirmation(confirmation);
                    if (ok)
                    {
                        foreach (var rq in requests)
                        {
                            _ = vault.Auth.ExecuteAuthCommand<SharedFolderUpdateCommand, SharedFolderUpdateResponse>(rq);
                        }
                    }
                }
            }
            else
            {
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
                        await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
                    }
                }
            }

            await vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }
    }
}
