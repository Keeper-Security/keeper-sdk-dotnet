//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.Serialization.Json;
using System.IO;
using System.Diagnostics;

namespace KeeperSecurity.Sdk
{
    public class Vault : VaultData
    {
        public Vault(IAuthentication auth, IKeeperStorage storage = null) : base(auth.AuthContext.ClientKey,
            storage ?? new InMemoryKeeperStorage())
        {
            Auth = auth;
        }

        public IAuthentication Auth { get; }

        private long scheduledAt;
        private Task syncDownTask;

        public Task ScheduleSyncDown(TimeSpan delay)
        {
            if (delay > TimeSpan.FromSeconds(5))
            {
                delay = TimeSpan.FromSeconds(5);
            }

            var now = DateTimeOffset.Now.ToUnixTimeMilliseconds();

            if (syncDownTask != null && scheduledAt > now)
            {
                if (now + (long) delay.TotalMilliseconds < scheduledAt)
                {
                    return syncDownTask;
                }
            }

            Task myTask = null;
            myTask = Task.Run(async () =>
            {
                try
                {
                    if (delay.TotalMilliseconds > 10)
                    {
                        await Task.Delay(delay);
                    }

                    if (myTask == syncDownTask)
                    {
                        scheduledAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() + 1000;
                        await this.SyncDown();
                    }
                }
                finally
                {
                    if (myTask == syncDownTask)
                    {
                        syncDownTask = null;
                        scheduledAt = 0;
                    }
                }
            });
            scheduledAt = now + (long) delay.TotalMilliseconds;
            syncDownTask = myTask;
            return myTask;
        }

        public void OnNotificationReceived(NotificationEvent evt)
        {
            if (evt != null & evt?.notificationEvent == "sync")
            {
                if (evt.sync)
                {
                    ScheduleSyncDown(TimeSpan.FromSeconds(5));
                }
            }
        }

        public IRecordMetadata ResolveRecordAccessPath(IRecordAccessPath path, bool forEdit = false,
            bool forShare = false, bool forView = false)
        {
            if (string.IsNullOrEmpty(path.RecordUid))
            {
                return null;
            }

            foreach (var rmd in Storage.RecordKeys.GetLinksForSubject(path.RecordUid))
            {
                if (forEdit && !rmd.CanEdit) continue;
                if (forShare && !rmd.CanShare) continue;
                if (string.IsNullOrEmpty(rmd.SharedFolderUid) || rmd.SharedFolderUid == Storage.PersonalScopeUid)
                {
                    return rmd;
                }

                foreach (var sfmd in Storage.SharedFolderKeys.GetLinksForSubject(rmd.SharedFolderUid))
                {
                    if (string.IsNullOrEmpty(sfmd.TeamUid))
                    {
                        path.SharedFolderUid = sfmd.SharedFolderUid;
                        return rmd;
                    }

                    if (!forEdit && !forShare && !forView)
                    {
                        path.TeamUid = sfmd.TeamUid;
                        return rmd;
                    }

                    if (!keeperTeams.TryGetValue(sfmd.TeamUid, out var team)) continue;
                    if (forEdit && team.RestrictEdit) continue;
                    if (forShare && team.RestrictShare) continue;
                    if (forView && team.RestrictView) continue;
                    
                    path.TeamUid = sfmd.TeamUid;
                    return rmd;
                }
            }

            return null;
        }

        public async Task AddRecord(PasswordRecord record, string folderUid)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(folderUid))
            {
                keeperFolders.TryGetValue(folderUid, out node);
            }

            record.Uid = CryptoUtils.GenerateUid();
            record.RecordKey = CryptoUtils.GenerateEncryptionKey();
            var recordAdd = new RecordAddCommand
            {
                RecordUid = record.Uid,
                RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, Auth.AuthContext.DataKey).Base64UrlEncode(),
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
                        if (keeperSharedFolders.TryGetValue(node.SharedFolderUid, out var sf))
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

            await Auth.ExecuteAuthCommand(recordAdd);
            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        public async Task PutRecord(PasswordRecord record, bool skipData = false, bool skipExtra = true)
        {
            IPasswordRecord existingRecord = null;
            if (!string.IsNullOrEmpty(record.Uid))
            {
                existingRecord = Storage.Records.Get(record.Uid);
            }

            var updateRecord = new RecordUpdateRecord();

            if (existingRecord != null)
            {
                updateRecord.RecordUid = existingRecord.RecordUid;
                var rmd = ResolveRecordAccessPath(updateRecord, forEdit: true);
                if (rmd != null)
                {
                    if (rmd.RecordKeyType == (int) KeyType.NoKey || rmd.RecordKeyType == (int) KeyType.PrivateKey)
                    {
                        updateRecord.RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, Auth.AuthContext.DataKey)
                            .Base64UrlEncode();
                    }
                }

                updateRecord.Revision = existingRecord.Revision;
            }
            else
            {
                record.Uid = CryptoUtils.GenerateUid();
                record.RecordKey = CryptoUtils.GenerateEncryptionKey();
                updateRecord.RecordUid = record.Uid;
                updateRecord.RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, Auth.AuthContext.DataKey)
                    .Base64UrlEncode();
                updateRecord.Revision = 0;
            }

            if (!skipData)
            {
                var dataSerializer = new DataContractJsonSerializer(typeof(RecordData), JsonUtils.JsonSettings);
                RecordData existingData = null;
                if (existingRecord != null)
                {
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
                        Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", existingRecord.RecordUid,
                            e.GetType().Name, e.Message);
                    }
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
                if (existingRecord != null)
                {
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
                        Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", existingRecord.RecordUid,
                            e.GetType().Name, e.Message);
                    }
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
                deviceId = Auth.AuthContext.DeviceToken.Base64UrlEncode()
            };
            if (existingRecord != null)
            {
                command.UpdateRecords = new[] {updateRecord};
            }
            else
            {
                command.AddRecords = new[] {updateRecord};
            }

            await Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        public async Task PutNonSharedData(string recordUid, byte[] data)
        {
            var existingRecord = Storage.Records.Get(recordUid);
            var updateRecord = new RecordUpdateRecord
            {
                RecordUid = recordUid,
                Revision = existingRecord?.Revision ?? 0,
                NonSharedData = CryptoUtils.EncryptAesV1(data, Auth.AuthContext.DataKey).Base64UrlEncode()
            };
            var command = new RecordUpdateCommand
            {
                deviceId = Auth.AuthContext.DeviceToken.Base64UrlEncode(),
                UpdateRecords = new[] {updateRecord}
            };
            await Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
            await ScheduleSyncDown(TimeSpan.FromSeconds(0));
        }

        public SharedFolderPermission ResolveSharedFolderAccessPath(ISharedFolderAccessPath path,
            bool forManageUsers = false, bool forManageRecords = false)
        {
            if (!string.IsNullOrEmpty(path.SharedFolderUid))
            {
                if (TryGetSharedFolder(path.SharedFolderUid, out var sf))
                {
                    var permissions = sf.UsersPermissions
                        .Where(x => (x.UserType == UserType.User && x.UserId == Auth.AuthContext.Username) ||
                                    (x.UserType == UserType.Team && keeperTeams.ContainsKey(x.UserId)))
                        .Where(x => (!forManageUsers || x.ManageUsers) && (!forManageRecords || x.ManageRecords))
                        .ToArray();

                    if (permissions.Length > 0)
                    {
                        if (permissions[0].UserType == UserType.Team)
                        {
                            path.TeamUid = permissions[0].UserId;
                        }

                        return permissions[0];
                    }
                }
            }

            return null;
        }
    }
}