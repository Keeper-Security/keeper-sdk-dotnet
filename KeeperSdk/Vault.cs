//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
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
        public Vault(IAuth auth, IKeeperStorage storage = null) : base(auth.AuthContext.ClientKey, storage ?? new InMemoryKeeperStorage())
        {
            Auth = auth;
        }

        public IAuth Auth { get; }

        public IRecordMetadata ResolveRecordAccessPath(IRecordAccessPath path, bool forEdit = false, bool forShare = false)
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
                    if (!forEdit && !forShare)
                    {
                        path.TeamUid = sfmd.TeamUid;
                        return rmd;
                    }
                    if (keeperTeams.TryGetValue(sfmd.TeamUid, out EnterpriseTeam team))
                    {
                        if (forEdit && team.RestrictEdit) continue;
                        if (forShare && team.RestrictShare) continue;
                        path.TeamUid = sfmd.TeamUid;
                        return rmd;
                    }
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
            var recordKey = CryptoUtils.GenerateEncryptionKey();
            var recordAdd = new RecordAddCommand
            {
                RecordUid = CryptoUtils.GenerateUid(),
                RecordKey = CryptoUtils.EncryptAesV1(recordKey, Auth.AuthContext.DataKey).Base64UrlEncode(),
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
                    case FolderType.SharedFolderForder:
                        recordAdd.FolderUid = node.FolderUid;
                        recordAdd.FolderType = node.FolderType == FolderType.SharedFolder ? "shared_folder" : "shared_folder_folder";
                        if (keeperSharedFolders.TryGetValue(node.SharedFolderUid, out SharedFolder sf))
                        {
                            recordAdd.FolderKey = CryptoUtils.EncryptAesV1(recordKey, sf.SharedFolderKey).Base64UrlEncode();
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
                recordAdd.Data = CryptoUtils.EncryptAesV1(ms.ToArray(), recordKey).Base64UrlEncode();
            }

            await Auth.ExecuteAuthCommand(recordAdd);
            await this.SyncDown();
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
                    if (rmd.RecordKeyType == (int)KeyType.NoKey || rmd.RecordKeyType == (int)KeyType.PrivateKey)
                    {
                        updateRecord.RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, Auth.AuthContext.DataKey).Base64UrlEncode();
                    }
                }
                updateRecord.Revision = existingRecord.Revision;
            }
            else
            {
                updateRecord.RecordUid = CryptoUtils.GenerateUid();
                record.RecordKey = CryptoUtils.GenerateEncryptionKey();
                updateRecord.RecordKey = CryptoUtils.EncryptAesV1(record.RecordKey, Auth.AuthContext.DataKey).Base64UrlEncode();
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
                        var unencryptedData = CryptoUtils.DecryptAesV1(existingRecord.Data.Base64UrlDecode(), record.RecordKey);
                        using (var ms = new MemoryStream(unencryptedData))
                        {
                            existingData = (RecordData)dataSerializer.ReadObject(ms);
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", existingRecord.RecordUid, e.GetType().Name, e.Message);
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
                        var unencryptedExtra = CryptoUtils.DecryptAesV1(existingRecord.Extra.Base64UrlDecode(), record.RecordKey);
                        using (var ms = new MemoryStream(unencryptedExtra))
                        {
                            existingExtra = (RecordExtra)extraSerializer.ReadObject(ms);
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError("Decrypt Record: UID: {0}, {1}: \"{2}\"", existingRecord.RecordUid, e.GetType().Name, e.Message);
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

            var command = new RecordUpdateCommand();
            if (existingRecord != null)
            {
                command.UpdateRecords = new[] { updateRecord };
            }
            else
            {
                command.AddRecords = new[] { updateRecord };
            }

            await Auth.ExecuteAuthCommand<RecordUpdateCommand, RecordUpdateResponse>(command);
            await this.SyncDown();
        }

        public SharedFolderPermission ResolveSharedFolderAccessPath(ISharedFolderAccessPath path, bool forManageUsers = false, bool forManageRecords = false)
        {
            if (!string.IsNullOrEmpty(path.SharedFolderUid))
            {
                if (TryGetSharedFolder(path.SharedFolderUid, out SharedFolder sf))
                {
                    var permissions = sf.UsersPermissions
                        .Where(x => (x.UserType == UserType.User && x.UserId == Auth.AuthContext.Username) || (x.UserType == UserType.Team && keeperTeams.ContainsKey(x.UserId)))
                        .Where(x => (!forManageUsers || x.ManageUsers) && (!forManageRecords || x.ManageRecords))
                        .ToArray();

                    if (permissions.Length > 0) {
                        if (permissions[0].UserType == UserType.Team) {
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
