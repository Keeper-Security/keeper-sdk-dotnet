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
            var command = new SyncDownCommand
            {
                revision = vault.Storage.Revision,
                include = new string[] { "sfheaders", "sfrecords", "sfusers", "teams", "folders" },
                deviceName = KeeperEndpoint.DefaultDeviceName,
                deviceId = KeeperEndpoint.DefaultDeviceName
            };

            var rs = await vault.Auth.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(command);

            var isFullSync = rs.fullSync;
            var result = new RebuildTask(isFullSync);
            if (isFullSync)
            {
                vault.Storage.Clear();
            }

            vault.Storage.Revision = rs.revision;

            if (rs.removedRecords != null)
            {
                foreach (var recordUid in rs.removedRecords)
                {
                    result.AddRecord(recordUid);

                    vault.Storage.RecordKeys.Delete(recordUid, vault.Storage.PersonalScopeUid);
                    var links = vault.Storage.FolderRecords.GetLinksForObject(recordUid).ToArray();
                    foreach (var link in links)
                    {
                        var folderUid = link.FolderUid;
                        if (string.IsNullOrEmpty(folderUid) && folderUid == vault.Storage.PersonalScopeUid)
                        {
                            vault.Storage.FolderRecords.Delete(link);
                        }
                        else
                        {
                            var folder = vault.Storage.Folders.Get(folderUid);
                            if (folder != null)
                            {
                                if (folder.FolderType == "user_folder")
                                {
                                    vault.Storage.FolderRecords.Delete(link);
                                }
                            }
                        }
                    }
                }
            }

            if (rs.removedTeams != null)
            {
                foreach (var teamUid in rs.removedTeams)
                {
                    var sfLinks = vault.Storage.SharedFolderKeys.GetLinksForObject(teamUid).ToArray();
                    foreach (var sfLink in sfLinks)
                    {
                        var recLinks = vault.Storage.RecordKeys.GetLinksForObject(sfLink.SharedFolderUid).ToArray();
                        foreach (var recLink in recLinks)
                        {
                            result.AddRecord(recLink.RecordUid);
                        }

                        result.AddSharedFolder(sfLink.SharedFolderUid);
                    }
                    vault.Storage.SharedFolderKeys.DeleteObject(teamUid);
                    vault.Storage.Teams.Delete(teamUid);
                }
            }

            if (rs.removedSharedFolders != null)
            {
                foreach (var sharedFolderUid in rs.removedSharedFolders)
                {
                    result.AddSharedFolder(sharedFolderUid);
                    var links = vault.Storage.RecordKeys.GetLinksForObject(sharedFolderUid).ToArray();
                    foreach (var recLink in links)
                    {
                        result.AddRecord(recLink.RecordUid);
                    }

                    vault.Storage.SharedFolderKeys.Delete(sharedFolderUid, vault.Storage.PersonalScopeUid);
                }
            }

            if (rs.userFoldersRemoved != null)
            {
                foreach (var ufr in rs.userFoldersRemoved)
                {
                    var folderUid = ufr.folderUid;
                    vault.Storage.FolderRecords.DeleteSubject(folderUid);
                    vault.Storage.Folders.Delete(folderUid);
                }
            }

            if (rs.sharedFolderFolderRemoved != null)
            {
                foreach (var sffr in rs.sharedFolderFolderRemoved)
                {
                    var folderUid = sffr.FolderUid ?? sffr.SharedFolderUid;
                    vault.Storage.FolderRecords.DeleteSubject(folderUid);
                    vault.Storage.Folders.Delete(folderUid);
                }
            }

            if (rs.userFolderSharedFoldersRemoved != null)
            {
                foreach (var ufsfr in rs.userFolderSharedFoldersRemoved)
                {
                    var folderUid = ufsfr.SharedFolderUid;
                    vault.Storage.FolderRecords.DeleteSubject(folderUid);
                    vault.Storage.Folders.Delete(folderUid);
                }
            }

            if (rs.userFoldersRemovedRecords != null)
            {
                foreach (var ufrr in rs.userFoldersRemovedRecords)
                {
                    var folderUid = ufrr.folderUid ?? vault.Storage.PersonalScopeUid;
                    var recordUid = ufrr.RecordUid;

                    vault.Storage.FolderRecords.Delete(recordUid, folderUid);
                }
            }

            if (rs.sharedFolderFolderRecordsRemoved != null)
            {
                foreach (var sffrr in rs.sharedFolderFolderRecordsRemoved)
                {
                    var folderUid = sffrr.folderUid ?? sffrr.sharedFolderUid;
                    var recordUid = sffrr.recordUid;

                    vault.Storage.FolderRecords.Delete(recordUid, folderUid);
                }
            }

            if (rs.sharedFolders != null)
            {
                foreach (var sf in rs.sharedFolders)
                {
                    var sharedFolderUid = sf.SharedFolderUid;
                    if (sf.fullSync == true)
                    {
                        vault.Storage.RecordKeys.DeleteObject(sharedFolderUid);
                        vault.Storage.SharedFolderKeys.DeleteSubject(sharedFolderUid);
                        vault.Storage.SharedFolderPermissions.DeleteSubject(sharedFolderUid);
                    }
                    else
                    {
                        if (sf.recordsRemoved != null)
                        {
                            foreach (var recordUid in sf.recordsRemoved)
                            {
                                result.AddRecord(recordUid);
                                vault.Storage.RecordKeys.Delete(recordUid, sharedFolderUid);
                            }
                        }
                        if (sf.teamsRemoved != null)
                        {
                            foreach (var teamUid in sf.teamsRemoved)
                            {
                                vault.Storage.SharedFolderKeys.Delete(sharedFolderUid, teamUid);
                                vault.Storage.SharedFolderPermissions.Delete(sharedFolderUid, teamUid);
                            }
                        }
                        if (sf.usersRemoved != null)
                        {
                            foreach (var username in sf.usersRemoved)
                            {
                                vault.Storage.SharedFolderPermissions.Delete(sharedFolderUid, username);
                            }
                        }
                    }
                }
            }

            if (rs.nonSharedData != null)
            {
                foreach (var nsd in rs.nonSharedData)
                {
                    try
                    {
                        var data = nsd.data.Base64UrlDecode();
                        data = CryptoUtils.DecryptAesV1(data, vault.Auth.AuthContext.DataKey);
                        data = CryptoUtils.EncryptAesV1(data, vault.ClientKey);
                        nsd.data = data.Base64UrlEncode();
                        vault.Storage.NonSharedData.Put(nsd);
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
                    vault.Storage.Records.Put(r);
                }
            }

            if (rs.recordMetaData != null)
            {
                foreach (var rmd in rs.recordMetaData)
                {
                    var recordUid = rmd.RecordUid;
                    result.AddRecord(recordUid);

                    var record = vault.Storage.Records.Get(recordUid);
                    if (record != null)
                    {
                        if (record.Owner != rmd.Owner)
                        {
                            record.Owner = rmd.Owner;
                            vault.Storage.Records.Put(record);
                        }
                    }
                    try
                    {
                        byte[] key = null;
                        switch (rmd.RecordKeyType)
                        {
                            case 0:
                                key = vault.Auth.AuthContext.DataKey;
                                break;
                            case 1:
                                key = CryptoUtils.DecryptAesV1(rmd.RecordKey.Base64UrlDecode(), vault.Auth.AuthContext.DataKey);
                                break;
                            case 2:
                                key = CryptoUtils.DecryptRsa(rmd.RecordKey.Base64UrlDecode(), vault.Auth.AuthContext.PrivateKey);
                                break;
                            default:
                                throw new Exception($"Record metadata UID {recordUid}: unsupported key type {rmd.RecordKeyType}");
                        }
                        if (key != null)
                        {
                            rmd.RecordKey = CryptoUtils.EncryptAesV1(key, vault.Auth.AuthContext.ClientKey).Base64UrlEncode();
                            rmd.SharedFolderUid = vault.Storage.PersonalScopeUid;
                            vault.Storage.RecordKeys.Put(rmd);
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
                            vault.Storage.SharedFolderKeys.Delete(sharedFolderUid, teamUid);
                        }
                    }

                    try
                    {
                        byte[] teamKey = null;
                        switch (t.KeyType)
                        {
                            case (int)KeyType.DataKey:
                                teamKey = CryptoUtils.DecryptAesV1(t.TeamKey.Base64UrlDecode(), vault.Auth.AuthContext.DataKey);
                                break;
                            case (int)KeyType.PrivateKey:
                                teamKey = CryptoUtils.DecryptRsa(t.TeamKey.Base64UrlDecode(), vault.Auth.AuthContext.PrivateKey);
                                break;
                            default:
                                throw new Exception($"Team UID {teamUid}: unsupported key type {t.KeyType}");
                        }
                        if (teamKey != null)
                        {
                            t.TeamKey = CryptoUtils.EncryptAesV1(teamKey, vault.ClientKey).Base64UrlEncode();
                            vault.Storage.Teams.Put(t);
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
                                                    teamPrivateKey = CryptoUtils.LoadPrivateKey(CryptoUtils.DecryptAesV1(t.TeamPrivateKey.Base64UrlDecode(), teamKey));
                                                }
                                                sharedFolderKey = CryptoUtils.DecryptRsa(sharedFolderKey, teamPrivateKey);
                                                sharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolderKey, teamKey);
                                                break;

                                        }
                                        if (sharedFolderKey != null)
                                        {
                                            sft.TeamUid = teamUid;
                                            sft.SharedFolderKey = sharedFolderKey.Base64UrlEncode();
                                            sft.KeyType = (int)KeyType.TeamKey;
                                            vault.Storage.SharedFolderKeys.Put(sft);
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
                            byte[] sharedFolderKey = null;
                            switch (sf.KeyType)
                            {
                                case 1:
                                    sharedFolderKey = CryptoUtils.DecryptAesV1(sf.SharedFolderKey.Base64UrlDecode(), vault.Auth.AuthContext.DataKey);
                                    break;
                                case 2:
                                    sharedFolderKey = CryptoUtils.DecryptRsa(sf.SharedFolderKey.Base64UrlDecode(), vault.Auth.AuthContext.PrivateKey);
                                    break;
                                default:
                                    throw new Exception($"Shared Folder UID {sharedFolderUid}: unsupported key type {sf.KeyType}");
                            }
                            if (sharedFolderKey != null)
                            {
                                var sharedFolderMetadata = new SyncDownSharedFolderKey
                                {
                                    SharedFolderUid = sharedFolderUid,
                                    TeamUid = vault.Storage.PersonalScopeUid,
                                    SharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolderKey, vault.ClientKey).Base64UrlEncode(),
                                    KeyType = (int)KeyType.DataKey
                                };

                                vault.Storage.SharedFolderKeys.Put(sharedFolderMetadata);
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
                                RecordKeyType = (int)KeyType.SharedFolderKey,
                                CanEdit = sfr.CanEdit,
                                CanShare = sfr.CanShare
                            };
                            vault.Storage.RecordKeys.Put(recordMetadata);
                        }
                    }

                    if (sf.teams != null)
                    {
                        foreach (var sft in sf.teams)
                        {
                            sft.SharedFolderUid = sharedFolderUid;
                            vault.Storage.SharedFolderPermissions.Put(sft);
                        }
                    }
                    if (sf.users != null)
                    {
                        foreach (var sfu in sf.users)
                        {
                            sfu.SharedFolderUid = sharedFolderUid;
                            vault.Storage.SharedFolderPermissions.Put(sfu);
                        }
                    }
                    vault.Storage.SharedFolders.Put(sf);
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
                                folderKey = CryptoUtils.DecryptAesV1(folderKey, vault.Auth.AuthContext.DataKey);
                                break;
                            case 2:
                                folderKey = CryptoUtils.DecryptRsa(folderKey, vault.Auth.AuthContext.PrivateKey);
                                break;
                            default:
                                throw new Exception($"User Folder UID {folderUid}: unsupported key type {uf.keyType}");
                        }
                        uf.FolderKey = CryptoUtils.EncryptAesV1(folderKey, vault.ClientKey).Base64UrlEncode();
                        vault.Storage.Folders.Put(uf);
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError(e.Message);
                    }
                }
            }

            if (rs.sharedFolderFolders != null)
            {
                foreach (IFolder sff in rs.sharedFolderFolders)
                {
                    var folderUid = sff.FolderUid;
                    vault.Storage.Folders.Put(sff);
                }
            }

            if (rs.userFolderSharedFolders != null)
            {
                foreach (IFolder ufsf in rs.userFolderSharedFolders)
                {
                    var folderUid = ufsf.FolderUid;
                    vault.Storage.Folders.Put(ufsf);
                }
            }

            if (rs.userFolderRecords != null)
            {
                foreach (var ufr in rs.userFolderRecords)
                {
                    if (string.IsNullOrEmpty(ufr.FolderUid))
                    {
                        ufr.FolderUid = vault.Storage.PersonalScopeUid;
                    }
                    vault.Storage.FolderRecords.Put(ufr);
                }
            }

            if (rs.sharedFolderFolderRecords != null)
            {
                foreach (IFolderRecordLink sffr in rs.sharedFolderFolderRecords)
                {
                    vault.Storage.FolderRecords.Put(sffr);
                }
            }

            vault.RebuildData(result);
        }

        private static readonly DataContractJsonSerializer UdataSerializer = new DataContractJsonSerializer(typeof(SyncDownRecordUData), JsonUtils.JsonSettings);

        private static void AdjustUdata(this SyncDownRecord syncDownRecord)
        {
            if (syncDownRecord.udata != null) {
                using (var ms = new MemoryStream())
                {
                    UdataSerializer.WriteObject(ms, syncDownRecord.udata);
                    syncDownRecord.Udata = ms.ToArray().Base64UrlEncode();
                }
            }
        }
    }
}
