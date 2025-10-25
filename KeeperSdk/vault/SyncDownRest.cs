using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using VaultProto = Vault;
using RecordProto = Records;
using System;
using System.Text;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    public static class SyncDownRestExtension
    {
        /// <summary>
        /// Incrementally downloads vault data.
        /// </summary>
        /// <param name="vault">Vault connected to Keeper.</param>
        /// <param name="fullSync">Force full synchronization</param>
        /// <returns></returns>
        internal static async Task RunSyncDownRest(this VaultOnline vault, bool fullSync = false)
        {
            var auth = vault.Auth;
            var storage = vault.Storage;
            var context = vault.Auth.AuthContext;
            var clientKey = vault.ClientKey;

            if (fullSync)
            {
                vault.RecordTypesLoaded = false;
            }

            var settings = storage.VaultSettings.Load();
            byte[] token = null;
            if (!fullSync && settings?.SyncDownToken != null)
            {
                token = settings.SyncDownToken;
            }

            var done = false;
            var rq = new VaultProto.SyncDownRequest();
            var result = new RebuildTask(token == null);

            while (!done)
            {
                if (token != null)
                {
                    rq.ContinuationToken = ByteString.CopyFrom(token);
                }

                var rs =
                    await auth.ExecuteAuthRest<VaultProto.SyncDownRequest, VaultProto.SyncDownResponse>(
                        "vault/sync_down", rq);
                token = rs.ContinuationToken.ToByteArray();
                done = !rs.HasMore;
                if (rs.CacheStatus == VaultProto.CacheStatus.Clear)
                {
                    vault.RecordTypesLoaded = false;
                    storage.Clear();
                    if (!result.IsFullSync)
                    {
                        result = new RebuildTask(true);
                    }
                }

                if (rs.RemovedRecords.Count > 0)
                {
                    var recordUids = rs.RemovedRecords.Select(x => x.ToByteArray().Base64UrlEncode()).ToArray();
                    result.AddRecords(recordUids);
                    storage.RecordKeys.DeleteLinks(recordUids.Select(x => UidLink.Create(x, storage.PersonalScopeUid)));

                    // linked records
                    var recordLinks = new HashSet<IUidLink>(EqualityComparerIUidLink.Instance);
                    foreach (var recordUid in recordUids)
                    {
                        recordLinks.UnionWith(storage.RecordKeys.GetLinksForObject(recordUid));
                    }

                    if (recordLinks.Count > 0)
                    {
                        storage.RecordKeys.DeleteLinks(recordLinks);
                        result.AddRecords(recordLinks.Select(x => x.SubjectUid));
                    }

                    // unlink records from user_folders
                    recordLinks.Clear();
                    foreach (var recordUid in recordUids)
                    {
                        recordLinks.UnionWith(storage.FolderRecords.GetLinksForObject(recordUid));
                    }

                    if (recordLinks.Count > 0)
                    {

                        var folderUids = new HashSet<string>();
                        folderUids.UnionWith(recordLinks.Select(x => x.SubjectUid));
                        var userFolderText = FolderType.UserFolder.GetFolderTypeText();
                        foreach (var folderUid in folderUids.ToArray())
                        {
                            if (!string.Equals(folderUid, storage.PersonalScopeUid))
                            {
                                var folderEntity = storage.Folders.GetEntity(folderUid);
                                if (folderEntity == null || !string.Equals(folderEntity.FolderType, userFolderText))
                                {
                                    folderUids.Remove(folderUid);
                                }
                            }
                        }

                        if (folderUids.Count > 0)
                        {
                            storage.FolderRecords.DeleteLinks(recordLinks.Where(x =>
                                folderUids.Contains(x.SubjectUid)));
                        }
                    }
                }

                if (rs.RemovedTeams.Count > 0)
                {
                    var removedTeams = rs.RemovedTeams.Select(x => x.ToByteArray().Base64UrlEncode()).ToArray();
                    storage.Teams.DeleteUids(removedTeams);

                    var sfLinks = new HashSet<IUidLink>(EqualityComparerIUidLink.Instance);
                    foreach (var teamUid in removedTeams)
                    {
                        sfLinks.UnionWith(storage.SharedFolderKeys.GetLinksForObject(teamUid));
                    }

                    if (sfLinks.Count > 0)
                    {
                        result.AddSharedFolders(sfLinks.Select(x => x.SubjectUid));
                        storage.SharedFolderKeys.DeleteLinks(sfLinks);
                    }
                }

                if (rs.RemovedSharedFolders.Count > 0)
                {
                    var removedSFs = rs.RemovedSharedFolders.Select(x => x.ToByteArray().Base64UrlEncode()).ToArray();
                    result.AddSharedFolders(removedSFs);
                    storage.SharedFolderKeys.DeleteLinks(removedSFs.Select(x =>
                        UidLink.Create(x, storage.PersonalScopeUid)));
                }

                if (rs.RemovedRecordLinks.Count > 0)
                {
                    var links = rs.RemovedRecordLinks.Select(x => UidLink.Create(
                        x.ChildRecordUid.ToByteArray().Base64UrlEncode(),
                        x.ParentRecordUid.ToByteArray().Base64UrlEncode())).ToArray();
                    result.AddRecords(links.Select(x => x.SubjectUid));
                    storage.RecordKeys.DeleteLinks(links);
                }

                if (rs.RemovedUserFolders.Count > 0)
                {
                    var uids = rs.RemovedUserFolders.Select(x => x.ToByteArray().Base64UrlEncode()).ToArray();
                    storage.FolderRecords.DeleteLinksForSubjects(uids);
                    storage.Folders.DeleteUids(uids);
                }

                if (rs.RemovedSharedFolderFolders.Count > 0)
                {
                    var uids = rs.RemovedSharedFolderFolders.Select(x => x.FolderUid.ToByteArray().Base64UrlEncode())
                        .ToArray();
                    if (uids.Length > 0)
                    {
                        storage.FolderRecords.DeleteLinksForSubjects(uids);
                        storage.Folders.DeleteUids(uids);
                    }
                }

                if (rs.RemovedUserFolderSharedFolders.Count > 0)
                {
                    Debug.WriteLine("??????????");
                }

                if (rs.RemovedUserFolderRecords.Count > 0)
                {
                    storage.FolderRecords.DeleteLinks(rs.RemovedUserFolderRecords
                        .Select(x => UidLink.Create(
                            x.FolderUid.Length > 0
                                ? x.FolderUid.ToByteArray().Base64UrlEncode()
                                : storage.PersonalScopeUid,
                            x.RecordUid.ToByteArray().Base64UrlEncode())));
                }

                if (rs.RemovedSharedFolderFolderRecords.Count > 0)
                {
                    storage.FolderRecords.DeleteLinks(rs.RemovedSharedFolderFolderRecords
                        .Select(x => UidLink.Create(
                            (x.FolderUid.Length > 0 ? x.FolderUid : x.SharedFolderUid).ToByteArray().Base64UrlEncode(),
                            x.RecordUid.ToByteArray().Base64UrlEncode())));
                }

                if (rs.RemovedUsers.Count > 0)
                {
                    storage.UserEmails.DeleteLinksForSubjects(rs.RemovedUsers.Select(x => x.ToByteArray().Base64UrlEncode()));
                }

                if (rs.Users.Count > 0)
                {
                    storage.UserEmails.PutLinks(rs.Users.Select(x => new StorageUserEmail
                    {
                        AccountUid = x.AccountUid.ToByteArray().Base64UrlEncode(),
                        Email = x.Username,
                    }));
                }

                if (rs.RecordMetaData.Count > 0)
                {
                    StorageRecordKey ToRecordKey(VaultProto.RecordMetaData rmd)
                    {
                        try
                        {
                            var key = DecryptKeeperKey(context, rmd.RecordKey.ToByteArray(), rmd.RecordKeyType);
                            key = CryptoUtils.EncryptAesV2(key, clientKey);
                            var srk = new StorageRecordKey
                            {
                                RecordUid = rmd.RecordUid.ToByteArray().Base64UrlEncode(),
                                SharedFolderUid = storage.PersonalScopeUid,
                                RecordKey = key.Base64UrlEncode(),
                                RecordKeyType = (int) KeyType.ClientKeyAesGcm,
                                CanEdit = rmd.CanEdit,
                                CanShare = rmd.CanShare,
                                Expiration = rmd.Expiration,
                                Owner = rmd.Owner,
                                OwnerAccountUid = rmd.OwnerAccountUid.Length > 0
                                    ? rmd.OwnerAccountUid.ToByteArray().Base64UrlEncode()
                                    : null,
                            };
                            return srk;
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                        }

                        return null;
                    }

                    storage.RecordKeys.PutLinks(rs.RecordMetaData.Select(ToRecordKey).Where(x => x != null));
                }

                if (rs.RecordLinks.Count > 0)
                {
                    StorageRecordKey ToLinkKey(VaultProto.RecordLink rl)
                    {
                        try
                        {
                            var srk = new StorageRecordKey
                            {
                                RecordUid = rl.ChildRecordUid.ToByteArray().Base64UrlEncode(),
                                SharedFolderUid = rl.ParentRecordUid.ToByteArray().Base64UrlEncode(),
                                RecordKey = rl.RecordKey.ToByteArray().Base64UrlEncode(),
                                RecordKeyType = (int) KeyType.RecordKeyAesGcm,
                            };
                            return srk;
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                        }

                        return null;
                    }

                    var recordLinks = rs.RecordLinks.Select(ToLinkKey).Where(x => x != null).ToArray();
                    storage.RecordKeys.PutLinks(recordLinks);
                    result.AddRecords(recordLinks.Select(x => x.RecordUid));
                }

                if (rs.Records.Count > 0)
                {
                    StorageRecord ToRecord(VaultProto.Record r)
                    {
                        return new StorageRecord
                        {
                            RecordUid = r.RecordUid.ToByteArray().Base64UrlEncode(),
                            Version = r.Version,
                            Revision = r.Revision,
                            ClientModifiedTime = r.ClientModifiedTime,
                            Data = r.Data.ToByteArray().Base64UrlEncode(),
                            Extra = r.Extra.ToByteArray().Base64UrlEncode(),
                            Udata = r.Udata,
                            Shared = r.Shared,
                        };
                    }

                    var records = rs.Records.Select(ToRecord).ToArray();
                    storage.Records.PutEntities(records);
                    result.AddRecords(records.Select(x => x.RecordUid));
                }

                if (rs.NonSharedData.Count > 0)
                {
                    StorageNonSharedData ToNonSharedData(VaultProto.NonSharedData nsd)
                    {
                        return new StorageNonSharedData
                        {
                            RecordUid = nsd.RecordUid.ToByteArray().Base64UrlEncode(),
                            Data = nsd.Data.ToByteArray().Base64UrlEncode(),
                        };
                    }

                    storage.NonSharedData.PutEntities(rs.NonSharedData.Select(ToNonSharedData));
                }

                if (rs.Teams.Count > 0)
                {
                    var sfLinks = rs.Teams.SelectMany(x => x.RemovedSharedFolders,
                        (t, rsf) => UidLink.Create(t.TeamUid.ToByteArray().Base64UrlEncode(),
                            rsf.ToByteArray().Base64UrlEncode())).ToArray();
                    if (sfLinks.Length > 0)
                    {
                        storage.SharedFolderKeys.DeleteLinks(sfLinks);
                        result.AddSharedFolders(sfLinks.Select(x => x.SubjectUid));
                    }

                    var sfKeys = new List<StorageSharedFolderKey>();

                    StorageTeam ToTeam(VaultProto.Team team)
                    {
                        var teamUid = team.TeamUid.ToByteArray().Base64UrlEncode();
                        byte[] teamKey;
                        try
                        {
                            teamKey = DecryptKeeperKey(context, team.TeamKey.ToByteArray(), team.TeamKeyType);
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError($"Decrypt team \"{teamUid}\" key error: {e.Message}");
                            return null;
                        }

                        foreach (var sfk in team.SharedFolderKeys)
                        {
                            var sharedFolderKey = sfk.SharedFolderKey_.ToByteArray();
                            try
                            {
                                switch (sfk.KeyType)
                                {
                                    case RecordProto.RecordKeyType.EncryptedByDataKey:
                                        sharedFolderKey = CryptoUtils.DecryptAesV1(sharedFolderKey, teamKey);
                                        break;

                                    case RecordProto.RecordKeyType.EncryptedByPublicKey:
                                        var rsaPrivateKey = CryptoUtils.DecryptAesV1(team.TeamPrivateKey.ToByteArray(),
                                            teamKey);
                                        var rsaPk = CryptoUtils.LoadRsaPrivateKey(rsaPrivateKey);
                                        sharedFolderKey = CryptoUtils.DecryptRsa(sharedFolderKey, rsaPk);
                                        break;

                                    case RecordProto.RecordKeyType.EncryptedByDataKeyGcm:
                                        sharedFolderKey = CryptoUtils.DecryptAesV2(sharedFolderKey, teamKey);
                                        break;

                                    // TODO
                                    /*
                                    case RecordProto.RecordKeyType.EncryptedByPublicKeyEcc:
                                        var ecPrivateKey = CryptoUtils.DecryptAesV2(team.TeamEcPrivateKey.ToByteArray(), teamKey);
                                        var ecPk = CryptoUtils.LoadPrivateEcKey(ecPrivateKey);
                                        sharedFolderKey = CryptoUtils.DecryptEc(sharedFolderKey, context.PrivateEcKey);
                                        break;
                                    */
                                    default:
                                        throw new Exception($"Unsupported shared folder key type: {sfk.KeyType}");
                                }

                                sfKeys.Add(new StorageSharedFolderKey
                                {
                                    SharedFolderUid = sfk.SharedFolderUid.ToByteArray().Base64UrlEncode(),
                                    SharedFolderKey = CryptoUtils.EncryptAesV2(sharedFolderKey, teamKey)
                                        .Base64UrlEncode(),
                                    KeyType = (int) KeyType.TeamKeyAesGcm,
                                    TeamUid = teamUid,
                                });
                            }
                            catch (Exception ex)
                            {
                                Trace.TraceError(ex.Message);
                            }
                        }

                        return new StorageTeam
                        {
                            TeamUid = teamUid,
                            Name = team.Name,
                            TeamKey = CryptoUtils.EncryptAesV2(teamKey, clientKey).Base64UrlEncode(),
                            KeyType = (int) KeyType.ClientKeyAesGcm,
                            TeamRsaPrivateKey = team.TeamPrivateKey.ToByteArray().Base64UrlEncode(),
                            TeamEcPrivateKey = null, // TODO
                            RestrictEdit = team.RestrictEdit,
                            RestrictShare = team.RestrictShare,
                            RestrictView = team.RestrictView,
                        };
                    }

                    var storageTeams = rs.Teams.Select(ToTeam).Where(x => x != null).ToArray();
                    if (storageTeams.Length > 0)
                    {
                        storage.Teams.PutEntities(storageTeams);
                        if (sfKeys.Count > 0)
                        {
                            storage.SharedFolderKeys.PutLinks(sfKeys);
                            result.AddSharedFolders(sfKeys.Select(x => x.SharedFolderUid));
                        }
                    }
                }

                if (rs.SharedFolders.Count > 0)
                {
                    // delete sf user keys if cache id clear
                    var uids = rs.SharedFolders.Where(x => x.CacheStatus == VaultProto.CacheStatus.Clear)
                        .Select(x => x.SharedFolderUid.ToByteArray().Base64UrlEncode()).ToArray();
                    if (uids.Length > 0)
                    {
                        storage.SharedFolderPermissions.DeleteLinksForSubjects(uids);

                        var sfLinks = uids
                            .SelectMany(
                                x => storage.SharedFolderKeys.GetLinksForSubject(x)
                                    .Where(y => y.TeamUid == storage.PersonalScopeUid), (_, y) => y).ToArray();
                        if (sfLinks.Length > 0)
                        {
                            storage.SharedFolderKeys.DeleteLinks(sfLinks);
                        }
                    }

                    var sfKeys = new List<StorageSharedFolderKey>();

                    StorageSharedFolder ToSharedFolder(VaultProto.SharedFolder sf)
                    {
                        var sharedFolderUid = sf.SharedFolderUid.ToByteArray().Base64UrlEncode();
                        if (sf.SharedFolderKey.Length > 0)
                        {
                            try
                            {
                                var sfKey = DecryptKeeperKey(context, sf.SharedFolderKey.ToByteArray(), sf.KeyType);
                                sfKeys.Add(new StorageSharedFolderKey
                                {
                                    SharedFolderUid = sharedFolderUid,
                                    TeamUid = storage.PersonalScopeUid,
                                    KeyType = (int) KeyType.ClientKeyAesGcm,
                                    SharedFolderKey = CryptoUtils.EncryptAesV2(sfKey, clientKey).Base64UrlEncode(),
                                });
                            }
                            catch (Exception ex)
                            {
                                Trace.TraceError(ex.Message);
                            }
                        }

                        return new StorageSharedFolder
                        {
                            SharedFolderUid = sharedFolderUid,
                            OwnerAccountUid = sf.OwnerAccountUid.ToByteArray().Base64UrlEncode(),
                            Name = sf.Name.ToByteArray().Base64UrlEncode(),
                            Data = sf.Data.ToByteArray().Base64UrlEncode(),
                            Revision = sf.Revision,
                            DefaultCanEdit = sf.DefaultCanEdit,
                            DefaultCanShare = sf.DefaultCanReshare,
                            DefaultManageRecords = sf.DefaultManageRecords,
                            DefaultManageUsers = sf.DefaultManageUsers,
                        };
                    }

                    var sfs = rs.SharedFolders.Select(ToSharedFolder).Where(x => x != null).ToArray();
                    if (sfs.Length > 0)
                    {
                        result.AddSharedFolders(sfs.Select(x => x.SharedFolderUid));
                        storage.SharedFolders.PutEntities(sfs);
                    }

                    if (sfKeys.Count > 0)
                    {
                        storage.SharedFolderKeys.PutLinks(sfKeys);
                    }
                }

                // shared folder records
                if (rs.RemovedSharedFolderRecords.Count > 0)
                {
                    var rsfr = rs.RemovedSharedFolderRecords
                        .Select(x => UidLink.Create(x.RecordUid.ToByteArray().Base64UrlEncode(),
                            x.SharedFolderUid.ToByteArray().Base64UrlEncode()))
                        .ToArray();
                    storage.RecordKeys.DeleteLinks(rsfr);
                    result.AddRecords(rsfr.Select(x => x.SubjectUid));
                }

                if (rs.SharedFolderRecords.Count > 0)
                {
                    StorageRecordKey ToSfRecord(VaultProto.SharedFolderRecord sfr)
                    {
                        return new StorageRecordKey
                        {
                            RecordUid = sfr.RecordUid.ToByteArray().Base64UrlEncode(),
                            SharedFolderUid = sfr.SharedFolderUid.ToByteArray().Base64UrlEncode(),
                            RecordKeyType = (int) KeyType.SharedFolderKeyAesAny,
                            RecordKey = sfr.RecordKey.ToByteArray().Base64UrlEncode(),
                            Owner = sfr.Owner,
                            OwnerAccountUid = sfr.OwnerAccountUid.Length > 0
                                ? sfr.OwnerAccountUid.ToByteArray().Base64UrlEncode()
                                : null,
                            CanEdit = sfr.CanEdit,
                            CanShare = sfr.CanShare,
                            Expiration = sfr.Expiration
                        };
                    }

                    var sfrs = rs.SharedFolderRecords.Select(ToSfRecord).ToArray();
                    storage.RecordKeys.PutLinks(sfrs);
                    result.AddRecords(sfrs.Select(x => x.RecordUid));
                }

                // shared folder users
                if (rs.RemovedSharedFolderUsers.Count > 0)
                {
                    var rsfu = rs.RemovedSharedFolderUsers
                        .Select(x =>
                        {
                            string accountUid = null;
                            if (string.IsNullOrEmpty(x.Username))
                            {
                                accountUid = auth.AuthContext.AccountUid.Base64UrlEncode();
                            }
                            else
                            {
                                accountUid = storage.UserEmails.GetLinksForObject(x.Username)
                                    .Select(y => y.AccountUid)
                                    .FirstOrDefault();
                            }

                            if (string.IsNullOrEmpty(accountUid)) return null;
                            return UidLink.Create(x.SharedFolderUid.ToByteArray().Base64UrlEncode(), accountUid);
                        })
                        .Where(x => x != null)
                        .ToArray();
                    storage.SharedFolderPermissions.DeleteLinks(rsfu);
                    result.AddSharedFolders(rsfu.Select(x => x.SubjectUid));
                }

                if (rs.SharedFolderUsers.Count > 0)
                {
                    var sfus = rs.SharedFolderUsers.Select(x => new StorageSharedFolderPermission
                    {
                        SharedFolderUid = x.SharedFolderUid.ToByteArray().Base64UrlEncode(),
                        UserId = (x.AccountUid.Length > 0 ? x.AccountUid.ToByteArray() : context.AccountUid)
                            .Base64UrlEncode(),
                        UserType = (int) UserType.User,
                        ManageUsers = x.ManageUsers,
                        ManageRecords = x.ManageRecords,
                        Expiration = x.Expiration,
                    }).ToArray();
                    storage.SharedFolderPermissions.PutLinks(sfus);
                    result.AddSharedFolders(sfus.Select(x => x.SharedFolderUid));
                }

                // shared folder teams
                if (rs.RemovedSharedFolderTeams.Count > 0)
                {
                    var rsft = rs.RemovedSharedFolderTeams
                        .Select(x => UidLink.Create(x.SharedFolderUid.ToByteArray().Base64UrlEncode(),
                            x.TeamUid.ToByteArray().Base64UrlEncode()))
                        .ToArray();
                    storage.SharedFolderPermissions.DeleteLinks(rsft);
                    storage.SharedFolderKeys.DeleteLinks(rsft);
                    result.AddSharedFolders(rsft.Select(x => x.SubjectUid));
                }

                if (rs.SharedFolderTeams.Count > 0)
                {
                    var sfts = rs.SharedFolderTeams.Select(x => new StorageSharedFolderPermission
                    {
                        SharedFolderUid = x.SharedFolderUid.ToByteArray().Base64UrlEncode(),
                        UserId = x.TeamUid.ToByteArray().Base64UrlEncode(),
                        UserType = (int) UserType.Team,
                        ManageUsers = x.ManageUsers,
                        ManageRecords = x.ManageRecords,
                        Expiration = x.Expiration,
                    }).ToArray();
                    storage.SharedFolderPermissions.PutLinks(sfts);
                    result.AddSharedFolders(sfts.Select(x => x.SharedFolderUid));
                }

                // folders
                if (rs.UserFolders.Count > 0)
                {
                    StorageFolder ToUserFolder(VaultProto.UserFolder uf)
                    {
                        var folderUid = uf.FolderUid.ToByteArray().Base64UrlEncode();
                        try
                        {
                            var folderKey = DecryptKeeperKey(context, uf.UserFolderKey.ToByteArray(), uf.KeyType);
                            return new StorageFolder
                            {
                                FolderUid = folderUid,
                                ParentUid = uf.ParentUid.Length > 0
                                    ? uf.ParentUid.ToByteArray().Base64UrlEncode()
                                    : null,
                                SharedFolderUid = null,
                                FolderType = FolderType.UserFolder.GetFolderTypeText(),
                                Revision = uf.Revision,
                                FolderKey = CryptoUtils.EncryptAesV1(folderKey, clientKey).Base64UrlEncode(),
                                Data = uf.Data.ToByteArray().Base64UrlEncode(),
                            };
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError($"Decrypt user folder \"{folderUid}\" error: {e.Message}");
                            return null;
                        }
                    }

                    storage.Folders.PutEntities(rs.UserFolders.Select(ToUserFolder).Where(x => x != null));
                }

                if (rs.UserFolderSharedFolders.Count > 0)
                {
                    StorageFolder ToUserFolderSharedFolder(VaultProto.UserFolderSharedFolder ufsf)
                    {
                        var folderUid = ufsf.SharedFolderUid.ToByteArray().Base64UrlEncode();
                        return new StorageFolder
                        {
                            FolderUid = folderUid,
                            ParentUid = ufsf.FolderUid.Length > 0
                                ? ufsf.FolderUid.ToByteArray().Base64UrlEncode()
                                : null,
                            SharedFolderUid = folderUid,
                            FolderType = FolderType.SharedFolder.GetFolderTypeText(),
                        };
                    }

                    storage.Folders.PutEntities(rs.UserFolderSharedFolders.Select(ToUserFolderSharedFolder)
                        .Where(x => x != null));
                }

                if (rs.SharedFolderFolders.Count > 0)
                {
                    StorageFolder ToSharedFolderFolder(VaultProto.SharedFolderFolder sff)
                    {
                        var folderUid = sff.FolderUid.ToByteArray().Base64UrlEncode();
                        var sharedFolderUid = sff.SharedFolderUid.ToByteArray().Base64UrlEncode();
                        return new StorageFolder
                        {
                            FolderUid = folderUid,
                            ParentUid = sff.ParentUid.Length > 0
                                ? sff.ParentUid.ToByteArray().Base64UrlEncode()
                                : sharedFolderUid,
                            SharedFolderUid = sharedFolderUid,
                            FolderType = FolderType.SharedFolderFolder.GetFolderTypeText(),
                            Revision = sff.Revision,
                            FolderKey = sff.SharedFolderFolderKey.ToByteArray().Base64UrlEncode(),
                            Data = sff.Data.ToByteArray().Base64UrlEncode(),
                        };
                    }

                    storage.Folders.PutEntities(rs.SharedFolderFolders.Select(ToSharedFolderFolder)
                        .Where(x => x != null));
                }

                if (rs.UserFolderRecords.Count > 0)
                {
                    StorageFolderRecord ToUserFolderRecord(VaultProto.UserFolderRecord ufr)
                    {
                        return new StorageFolderRecord
                        {
                            FolderUid = ufr.FolderUid.Length > 0
                                ? ufr.FolderUid.ToByteArray().Base64UrlEncode()
                                : storage.PersonalScopeUid,
                            RecordUid = ufr.RecordUid.ToByteArray().Base64UrlEncode(),
                        };
                    }

                    storage.FolderRecords.PutLinks(rs.UserFolderRecords.Select(ToUserFolderRecord));
                }

                if (rs.SharedFolderFolderRecords.Count > 0)
                {
                    StorageFolderRecord ToSharedFolderFolderRecord(VaultProto.SharedFolderFolderRecord ufr)
                    {
                        return new StorageFolderRecord
                        {
                            FolderUid = (ufr.FolderUid.Length > 0 ? ufr.FolderUid : ufr.SharedFolderUid).ToByteArray()
                                .Base64UrlEncode(),
                            RecordUid = ufr.RecordUid.ToByteArray().Base64UrlEncode(),
                        };
                    }

                    storage.FolderRecords.PutLinks(rs.SharedFolderFolderRecords.Select(ToSharedFolderFolderRecord));
                }

                if (rs.SharingChanges.Count > 0)
                {
                    var records = new List<IStorageRecord>();
                    foreach (var sch in rs.SharingChanges)
                    {
                        var recordUid = sch.RecordUid.ToByteArray().Base64UrlEncode();
                        var r = storage.Records.GetEntity(recordUid);
                        if (r != null)
                        {
                            if (r.Shared != sch.Shared)
                            {
                                r.Shared = sch.Shared;
                                records.Add(r);
                            }
                        }
                    }

                    if (records.Count > 0)
                    {
                        storage.Records.PutEntities(records);
                    }

                }

                // BreachWatch Records
                if (rs.BreachWatchRecords.Count > 0)
                {
                    var BreachWatchRecords = new List<IStorageBreachWatchRecord>();

                    StorageBreachWatchRecord ToBreachWatchRecord(VaultProto.BreachWatchRecord record)
                    {
                        return new StorageBreachWatchRecord
                        {
                            RecordUid = record.RecordUid.ToByteArray().Base64UrlEncode(),
                            Revision = record.Revision,
                            Type = (int) record.Type,
                            Data = record.Data.ToByteArray().Base64UrlEncode(),
                        };
                    }

                    var breachWatchRecords = rs.BreachWatchRecords.Select(ToBreachWatchRecord).ToArray();
                    storage.BreachWatchRecords.PutEntities(breachWatchRecords);
                    result.AddBreachWatchRecords(breachWatchRecords.Select(x => x.RecordUid));
                }
            }

            var sds = new VaultSettings
            {
                SyncDownToken = token
            };
            storage.VaultSettings.Store(sds);
            Debug.WriteLine("Sync Down: Process Leave");
            if (!vault.RecordTypesLoaded)
            {
                var recordTypesRq = new RecordProto.RecordTypesRequest
                {
                    Standard = true,
                    Enterprise = true,
                    User = true,
                };
                var recordTypesRs =
                    await auth.ExecuteAuthRest<RecordProto.RecordTypesRequest, RecordProto.RecordTypesResponse>(
                        "vault/get_record_types", recordTypesRq);
                var recordTypes = recordTypesRs.RecordTypes.Select(x =>
                {
                    try
                    {
                        var cnt = JsonUtils.ParseJson<RecordTypeContent>(Encoding.UTF8.GetBytes(x.Content));
                        return new StorageRecordType
                        {
                            Name = cnt.Name,
                            RecordTypeId = x.RecordTypeId,
                            Content = x.Content,
                            Scope = (int) x.Scope
                        };
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Error parsing record type: {e}");
                    }

                    return null;
                }).Where(x => x != null).ToList();
                var existingRecordTypes = new HashSet<string>(storage.RecordTypes.GetAll().Select(x => x.Name),
                    StringComparer.InvariantCultureIgnoreCase);
                existingRecordTypes.ExceptWith(recordTypes.Select(x => x.Name));
                if (existingRecordTypes.Count > 0)
                {
                    storage.RecordTypes.DeleteUids(existingRecordTypes);
                }

                storage.RecordTypes.PutEntities(recordTypes);
                vault.RecordTypesLoaded = true;
            }

            Debug.WriteLine("Rebuild Data: Enter");
            vault.RebuildData(result);
            Debug.WriteLine("Rebuild Data: Leave");
        }

        private static byte[] DecryptKeeperKey(IAuthContext context, byte[] encryptedKey,
            RecordProto.RecordKeyType keyType)
        {
            return keyType switch
            {
                RecordProto.RecordKeyType.NoKey => context.DataKey,
                RecordProto.RecordKeyType.EncryptedByDataKey => CryptoUtils.DecryptAesV1(encryptedKey, context.DataKey),
                RecordProto.RecordKeyType.EncryptedByPublicKey => CryptoUtils.DecryptRsa(encryptedKey,
                    context.PrivateRsaKey),
                RecordProto.RecordKeyType.EncryptedByDataKeyGcm => CryptoUtils.DecryptAesV2(encryptedKey,
                    context.DataKey),
                RecordProto.RecordKeyType.EncryptedByPublicKeyEcc => CryptoUtils.DecryptEc(encryptedKey,
                    context.PrivateEcKey),
                _ => throw new Exception($"Unsupported key type {keyType}"),
            };
        }
    }
}
