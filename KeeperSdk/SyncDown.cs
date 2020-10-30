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
using System.Threading.Tasks;
using System.Linq;
using System.Diagnostics;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.Serialization.Json;
using System.IO;

namespace KeeperSecurity.Sdk
{
    public static class SyncDownExtension
    {
        public static async Task SyncDown(this Vault vault)
        {
            var storage = vault.Storage;
            var context = vault.Auth.AuthContext;
            var clientKey = vault.ClientKey;

            var command = new SyncDownCommand
            {
                revision = storage.Revision,
                include = new string[] {"sfheaders", "sfrecords", "sfusers", "teams", "folders"},
                deviceName = vault.Auth.Endpoint.DeviceName,
                deviceId = vault.Auth.DeviceToken.Base64UrlEncode()
            };

            var rs = await vault.Auth.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(command);

            var isFullSync = rs.fullSync;
            var result = new RebuildTask(isFullSync);
            if (isFullSync)
            {
                storage.Clear();
            }

            if (rs.removedRecords != null)
            {
                foreach (var recordUid in rs.removedRecords)
                {
                    result.AddRecord(recordUid);

                    storage.RecordKeys.Delete(recordUid, storage.PersonalScopeUid);
                    var links = storage.FolderRecords.GetLinksForObject(recordUid).ToArray();
                    foreach (var link in links)
                    {
                        var folderUid = link.FolderUid;
                        if (string.IsNullOrEmpty(folderUid) && folderUid == storage.PersonalScopeUid)
                        {
                            storage.FolderRecords.Delete(link);
                        }
                        else
                        {
                            var folder = storage.Folders.Get(folderUid);
                            if (folder?.FolderType == "user_folder")
                            {
                                storage.FolderRecords.Delete(link);
                            }
                        }
                    }
                }
            }

            if (rs.removedTeams != null)
            {
                foreach (var teamUid in rs.removedTeams)
                {
                    var sfLinks = storage.SharedFolderKeys.GetLinksForObject(teamUid).ToArray();
                    foreach (var sfLink in sfLinks)
                    {
                        var recLinks = storage.RecordKeys.GetLinksForObject(sfLink.SharedFolderUid).ToArray();
                        foreach (var recLink in recLinks)
                        {
                            result.AddRecord(recLink.RecordUid);
                        }

                        result.AddSharedFolder(sfLink.SharedFolderUid);
                    }

                    storage.SharedFolderKeys.DeleteObject(teamUid);
                    storage.Teams.Delete(teamUid);
                }
            }

            if (rs.removedSharedFolders != null)
            {
                foreach (var sharedFolderUid in rs.removedSharedFolders)
                {
                    result.AddSharedFolder(sharedFolderUid);
                    var links = storage.RecordKeys.GetLinksForObject(sharedFolderUid).ToArray();
                    foreach (var recLink in links)
                    {
                        result.AddRecord(recLink.RecordUid);
                    }

                    storage.SharedFolderKeys.Delete(sharedFolderUid, storage.PersonalScopeUid);
                }
            }

            if (rs.userFoldersRemoved != null)
            {
                foreach (var ufr in rs.userFoldersRemoved)
                {
                    var folderUid = ufr.folderUid;
                    storage.FolderRecords.DeleteSubject(folderUid);
                    storage.Folders.Delete(folderUid);
                }
            }

            if (rs.sharedFolderFolderRemoved != null)
            {
                foreach (var sffr in rs.sharedFolderFolderRemoved)
                {
                    var folderUid = sffr.FolderUid ?? sffr.SharedFolderUid;
                    storage.FolderRecords.DeleteSubject(folderUid);
                    storage.Folders.Delete(folderUid);
                }
            }

            if (rs.userFolderSharedFoldersRemoved != null)
            {
                foreach (var ufsfr in rs.userFolderSharedFoldersRemoved)
                {
                    var folderUid = ufsfr.SharedFolderUid;
                    storage.FolderRecords.DeleteSubject(folderUid);
                    storage.Folders.Delete(folderUid);
                }
            }

            if (rs.userFoldersRemovedRecords != null)
            {
                foreach (var ufrr in rs.userFoldersRemovedRecords)
                {
                    var folderUid = ufrr.folderUid ?? storage.PersonalScopeUid;
                    var recordUid = ufrr.RecordUid;

                    storage.FolderRecords.Delete(recordUid, folderUid);
                }
            }

            if (rs.sharedFolderFolderRecordsRemoved != null)
            {
                foreach (var sffrr in rs.sharedFolderFolderRecordsRemoved)
                {
                    var folderUid = sffrr.folderUid ?? sffrr.sharedFolderUid;
                    var recordUid = sffrr.recordUid;

                    storage.FolderRecords.Delete(recordUid, folderUid);
                }
            }

            if (rs.sharedFolders != null)
            {
                foreach (var sf in rs.sharedFolders)
                {
                    var sharedFolderUid = sf.SharedFolderUid;
                    if (sf.fullSync == true)
                    {
                        storage.RecordKeys.DeleteObject(sharedFolderUid);
                        storage.SharedFolderKeys.DeleteSubject(sharedFolderUid);
                        storage.SharedFolderPermissions.DeleteSubject(sharedFolderUid);
                    }
                    else
                    {
                        if (sf.recordsRemoved != null)
                        {
                            foreach (var recordUid in sf.recordsRemoved)
                            {
                                result.AddRecord(recordUid);
                                storage.RecordKeys.Delete(recordUid, sharedFolderUid);
                            }
                        }

                        if (sf.teamsRemoved != null)
                        {
                            foreach (var teamUid in sf.teamsRemoved)
                            {
                                storage.SharedFolderKeys.Delete(sharedFolderUid, teamUid);
                                storage.SharedFolderPermissions.Delete(sharedFolderUid, teamUid);
                            }
                        }

                        if (sf.usersRemoved != null)
                        {
                            foreach (var username in sf.usersRemoved)
                            {
                                storage.SharedFolderPermissions.Delete(sharedFolderUid, username);
                            }
                        }
                    }
                }
            }

            if (rs.nonSharedData != null)
            {
                foreach (var nsd in rs.nonSharedData)
                {
                    if (string.IsNullOrEmpty(nsd.Data))
                    {
                        continue;
                    }

                    try
                    {
                        var data = nsd.data.Base64UrlDecode();
                        data = CryptoUtils.DecryptAesV1(data, context.DataKey);
                        data = CryptoUtils.EncryptAesV1(data, clientKey);
                        nsd.data = data.Base64UrlEncode();
                        storage.NonSharedData.Put(nsd);
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError(e.Message);
                    }
                }
            }

            if (rs.records != null)
            {
                foreach (var r in rs.records)
                {
                    var recordUid = r.RecordUid;
                    result.AddRecord(recordUid);
                    r.AdjustUdata();
                    storage.Records.Put(r);
                }
            }

            if (rs.recordMetaData != null)
            {
                foreach (var rmd in rs.recordMetaData)
                {
                    var recordUid = rmd.RecordUid;
                    result.AddRecord(recordUid);

                    var record = storage.Records.Get(recordUid);
                    if (record != null)
                    {
                        if (record.Owner != rmd.Owner)
                        {
                            record.Owner = rmd.Owner;
                            storage.Records.Put(record);
                        }
                    }

                    try
                    {
                        byte[] key = null;
                        switch (rmd.RecordKeyType)
                        {
                            case 0:
                                key = context.DataKey;
                                break;
                            case 1:
                                key = CryptoUtils.DecryptAesV1(rmd.RecordKey.Base64UrlDecode(), context.DataKey);
                                break;
                            case 2:
                                key = CryptoUtils.DecryptRsa(rmd.RecordKey.Base64UrlDecode(), context.PrivateKey);
                                break;
                            default:
                                throw new Exception(
                                    $"Record metadata UID {recordUid}: unsupported key type {rmd.RecordKeyType}");
                        }

                        if (key != null)
                        {
                            rmd.RecordKey = CryptoUtils.EncryptAesV1(key, context.ClientKey).Base64UrlEncode();
                            rmd.SharedFolderUid = storage.PersonalScopeUid;
                            storage.RecordKeys.Put(rmd);
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError(e.Message);
                    }
                }
            }

            if (rs.teams != null)
            {
                foreach (var t in rs.teams)
                {
                    var teamUid = t.TeamUid;

                    if (t.removedSharedFolders != null)
                    {
                        foreach (var sharedFolderUid in t.removedSharedFolders)
                        {
                            result.AddSharedFolder(sharedFolderUid);
                            storage.SharedFolderKeys.Delete(sharedFolderUid, teamUid);
                        }
                    }

                    try
                    {
                        byte[] teamKey;
                        switch (t.KeyType)
                        {
                            case (int) KeyType.DataKey:
                                teamKey = CryptoUtils.DecryptAesV1(t.TeamKey.Base64UrlDecode(), context.DataKey);
                                break;
                            case (int) KeyType.PrivateKey:
                                teamKey = CryptoUtils.DecryptRsa(t.TeamKey.Base64UrlDecode(), context.PrivateKey);
                                break;
                            default:
                                throw new Exception($"Team UID {teamUid}: unsupported key type {t.KeyType}");
                        }

                        if (teamKey != null)
                        {
                            t.TeamKey = CryptoUtils.EncryptAesV1(teamKey, clientKey).Base64UrlEncode();
                            storage.Teams.Put(t);
                            if (t.sharedFolderKeys != null)
                            {
                                RsaPrivateCrtKeyParameters teamPrivateKey = null;
                                foreach (var sft in t.sharedFolderKeys)
                                {
                                    try
                                    {
                                        byte[] sharedFolderKey = null;
                                        switch (sft.KeyType)
                                        {
                                            case 1:
                                                sharedFolderKey = sft.SharedFolderKey.Base64UrlDecode();
                                                break;
                                            case 2:
                                                if (teamPrivateKey == null)
                                                {
                                                    teamPrivateKey =
                                                        CryptoUtils.LoadPrivateKey(
                                                            CryptoUtils.DecryptAesV1(t.TeamPrivateKey.Base64UrlDecode(),
                                                                teamKey));
                                                }

                                                sharedFolderKey =
                                                    CryptoUtils.DecryptRsa(sft.SharedFolderKey.Base64UrlDecode(), teamPrivateKey);
                                                sharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolderKey, teamKey);
                                                break;
                                        }

                                        if (sharedFolderKey != null)
                                        {
                                            sft.TeamUid = teamUid;
                                            sft.SharedFolderKey = sharedFolderKey.Base64UrlEncode();
                                            sft.KeyType = (int) KeyType.TeamKey;
                                            storage.SharedFolderKeys.Put(sft);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        Trace.TraceError(e.Message);
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError(e.Message);
                    }
                }
            }

            if (rs.sharedFolders != null)
            {
                foreach (var sf in rs.sharedFolders)
                {
                    var sharedFolderUid = sf.SharedFolderUid;

                    result.AddSharedFolder(sharedFolderUid);

                    if (!string.IsNullOrEmpty(sf.SharedFolderKey))
                    {
                        try
                        {
                            byte[] sharedFolderKey = sf.SharedFolderKey.Base64UrlDecode();
                            switch (sf.KeyType)
                            {
                                case 1:
                                    sharedFolderKey = CryptoUtils.DecryptAesV1(sharedFolderKey, context.DataKey);
                                    break;
                                case 2:
                                    sharedFolderKey = CryptoUtils.DecryptRsa(sharedFolderKey, context.PrivateKey);
                                    break;
                                default:
                                    throw new Exception(
                                        $"Shared Folder UID {sharedFolderUid}: unsupported key type {sf.KeyType}");
                            }

                            if (sharedFolderKey != null)
                            {
                                var sharedFolderMetadata = new SyncDownSharedFolderKey
                                {
                                    SharedFolderUid = sharedFolderUid,
                                    TeamUid = storage.PersonalScopeUid,
                                    SharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolderKey, clientKey)
                                        .Base64UrlEncode(),
                                    KeyType = (int) KeyType.DataKey
                                };

                                storage.SharedFolderKeys.Put(sharedFolderMetadata);
                            }
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                        }
                    }

                    if (sf.records != null)
                    {
                        foreach (var sfr in sf.records)
                        {
                            result.AddRecord(sfr.RecordUid);

                            var recordMetadata = new SyncDownRecordMetaData
                            {
                                SharedFolderUid = sharedFolderUid,
                                RecordUid = sfr.RecordUid,
                                RecordKey = sfr.RecordKey,
                                RecordKeyType = (int) KeyType.SharedFolderKey,
                                CanEdit = sfr.CanEdit,
                                CanShare = sfr.CanShare
                            };
                            storage.RecordKeys.Put(recordMetadata);
                        }
                    }

                    if (sf.teams != null)
                    {
                        foreach (var sft in sf.teams)
                        {
                            sft.SharedFolderUid = sharedFolderUid;
                            storage.SharedFolderPermissions.Put(sft);
                        }
                    }

                    if (sf.users != null)
                    {
                        foreach (var sfu in sf.users)
                        {
                            sfu.SharedFolderUid = sharedFolderUid;
                            storage.SharedFolderPermissions.Put(sfu);
                        }
                    }

                    storage.SharedFolders.Put(sf);
                }
            }

            if (rs.userFolders != null)
            {
                foreach (var uf in rs.userFolders)
                {
                    var folderUid = uf.FolderUid;
                    try
                    {
                        var folderKey = uf.FolderKey.Base64UrlDecode();
                        switch (uf.keyType)
                        {
                            case 1:
                                folderKey = CryptoUtils.DecryptAesV1(folderKey, context.DataKey);
                                break;
                            case 2:
                                folderKey = CryptoUtils.DecryptRsa(folderKey, context.PrivateKey);
                                break;
                            default:
                                throw new Exception($"User Folder UID {folderUid}: unsupported key type {uf.keyType}");
                        }

                        uf.FolderKey = CryptoUtils.EncryptAesV1(folderKey, clientKey).Base64UrlEncode();
                        storage.Folders.Put(uf);
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError(e.Message);
                    }
                }
            }

            if (rs.sharedFolderFolders != null)
            {
                foreach (var sff in rs.sharedFolderFolders)
                {
                    storage.Folders.Put(sff);
                }
            }

            if (rs.userFolderSharedFolders != null)
            {
                foreach (var ufsf in rs.userFolderSharedFolders)
                {
                    storage.Folders.Put(ufsf);
                }
            }

            if (rs.userFolderRecords != null)
            {
                foreach (var ufr in rs.userFolderRecords)
                {
                    if (string.IsNullOrEmpty(ufr.FolderUid))
                    {
                        ufr.FolderUid = storage.PersonalScopeUid;
                    }

                    storage.FolderRecords.Put(ufr);
                }
            }

            if (rs.sharedFolderFolderRecords != null)
            {
                foreach (var sffr in rs.sharedFolderFolderRecords)
                {
                    storage.FolderRecords.Put(sffr);
                }
            }

            storage.Revision = rs.revision;

            vault.RebuildData(result);
        }

        private static readonly DataContractJsonSerializer UdataSerializer =
            new DataContractJsonSerializer(typeof(SyncDownRecordUData), JsonUtils.JsonSettings);

        private static void AdjustUdata(this SyncDownRecord syncDownRecord)
        {
            if (syncDownRecord.udata == null) return;

            using (var ms = new MemoryStream())
            {
                UdataSerializer.WriteObject(ms, syncDownRecord.udata);
                syncDownRecord.Udata = ms.ToArray().Base64UrlEncode();
            }
        }
    }
}