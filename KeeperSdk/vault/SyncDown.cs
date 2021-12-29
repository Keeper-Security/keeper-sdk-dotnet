using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.Serialization.Json;
using System.IO;
using System.Linq;
using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Provides a set of static methods for syncing down vault.
    /// </summary>
    public static class SyncDownExtensions
    {
        /// <summary>
        /// Incrementally downloads vault data.
        /// </summary>
        /// <param name="vault">Vault connected to Keeper.</param>
        /// <returns></returns>
        internal static async Task RunSyncDown(this VaultOnline vault)
        {
            var auth = vault.Auth;
            if (auth.AuthContext.Settings?.RecordTypesEnabled == true)
            {
                if (vault.RecordTypeStorage == null)
                {
                    var rtStorage = new KeeperRecordTypeStorage();
                    await rtStorage.Load(auth);
                    vault.RecordTypeStorage = rtStorage;
                }
            }

            var storage = vault.Storage;
            var context = vault.Auth.AuthContext;
            var clientKey = vault.ClientKey;

            var command = new SyncDownCommand
            {
                revision = storage.Revision,
                include = new[] {"sfheaders", "sfrecords", "sfusers", "teams", "folders", "typed_record"},
                deviceName = vault.Auth.Endpoint.DeviceName,
                deviceId = vault.Auth.Endpoint.DeviceName
            };

            var rs = await auth.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(command);

            Debug.WriteLine("Sync Down: Enter");
            var isFullSync = rs.fullSync;
            if (isFullSync)
            {
                storage.Clear();
            }

            var result = new RebuildTask(isFullSync);
            if (rs.removedRecords != null)
            {
                result.AddRecords(rs.removedRecords);
                storage.RecordKeys.DeleteLinks(
                    rs.removedRecords
                        .Select(recordUid => UidLink.Create(recordUid, storage.PersonalScopeUid)));

                var recordLinks = rs.removedRecords
                    .SelectMany(x => storage.RecordKeys.GetLinksForSubject(x), (s, md) => md)
                    .Cast<IUidLink>()
                    .ToArray();
                result.AddRecords(recordLinks.Select(x => x.ObjectUid));
                storage.RecordKeys.DeleteLinks(recordLinks);

                var folderRecords = new List<IUidLink>();
                foreach (var recordUid in rs.removedRecords)
                {
                    var links = storage.FolderRecords.GetLinksForObject(recordUid).ToArray();
                    foreach (var link in links)
                    {
                        var folderUid = link.FolderUid;
                        if (string.IsNullOrEmpty(folderUid) && folderUid == storage.PersonalScopeUid)
                        {
                            folderRecords.Add(link);
                        }
                        else
                        {
                            var folder = storage.Folders.GetEntity(folderUid);
                            if (folder?.FolderType == "user_folder")
                            {
                                folderRecords.Add(link);
                            }
                        }
                    }
                }
                storage.FolderRecords.DeleteLinks(folderRecords);
            }

            if (rs.removedTeams != null)
            {
                foreach (var teamUid in rs.removedTeams)
                {
                    var sfLinks = storage.SharedFolderKeys.GetLinksForObject(teamUid).ToArray();
                    foreach (var sfLink in sfLinks)
                    {
                        result.AddSharedFolder(sfLink.SharedFolderUid);
                    }

                    storage.SharedFolderKeys.DeleteLinks(sfLinks);
                }
                storage.Teams.DeleteUids(rs.removedTeams);
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
                }
                storage.SharedFolderKeys.DeleteLinks(
                    rs.removedSharedFolders
                        .Select(x => UidLink.Create(x, storage.PersonalScopeUid)));
            }

            if (rs.userFoldersRemoved != null)
            {

                storage.FolderRecords.DeleteLinksForSubjects(rs.userFoldersRemoved.Select(x => x.folderUid));
                storage.Folders.DeleteUids(rs.userFoldersRemoved.Select(x => x.folderUid));
            }

            if (rs.sharedFolderFolderRemoved != null)
            {
                var folderUids = rs.sharedFolderFolderRemoved
                    .Select(x => x.FolderUid ?? x.SharedFolderUid).ToArray();

                storage.FolderRecords.DeleteLinksForSubjects(folderUids);
                storage.Folders.DeleteUids(folderUids);
            }

            if (rs.userFolderSharedFoldersRemoved != null)
            {
                storage.FolderRecords.DeleteLinksForSubjects(rs.userFolderSharedFoldersRemoved
                    .Select(x => x.SharedFolderUid));
                storage.Folders.DeleteUids(rs.userFolderSharedFoldersRemoved
                    .Select(x => x.SharedFolderUid));
            }

            if (rs.userFoldersRemovedRecords != null)
            {
                var links = rs.userFoldersRemovedRecords
                    .Select(x => UidLink.Create(x.folderUid ?? storage.PersonalScopeUid, x.RecordUid))
                    .ToArray();
                storage.FolderRecords.DeleteLinks(links);
            }

            if (rs.sharedFolderFolderRecordsRemoved != null)
            {
                var links = rs.sharedFolderFolderRecordsRemoved
                    .Select(x => UidLink.Create(x.folderUid ?? x.sharedFolderUid, x.recordUid))
                    .ToArray();

                storage.FolderRecords.DeleteLinks(links);
            }

            if (rs.removedLinks != null)
            {
                result.AddRecords(rs.removedLinks.Select(x => x.recordUid));
                storage.RecordKeys.DeleteLinks(rs.removedLinks);
            }

            if (rs.sharedFolders != null)
            {
                // full sync shared folders
                var fullSyncSharedFolders = rs.sharedFolders
                    .Where(x => x.fullSync == true)
                    .Select(x => x.SharedFolderUid)
                    .ToArray();

                storage.RecordKeys.DeleteLinksForObjects(fullSyncSharedFolders);
                storage.SharedFolderKeys.DeleteLinksForSubjects(fullSyncSharedFolders);
                storage.SharedFolderPermissions.DeleteLinksForSubjects(fullSyncSharedFolders);

                // records
                var affectedLinks = rs.sharedFolders
                    .Where(x => !x.fullSync.HasValue || !x.fullSync.Value)
                    .Where(x => x.recordsRemoved != null)
                    .SelectMany(x => x.recordsRemoved,
                        (x, recordUid) => UidLink.Create(recordUid, x.SharedFolderUid))
                    .Cast<IUidLink>()
                    .ToArray();

                if (affectedLinks.Any())
                {
                    storage.RecordKeys.DeleteLinks(affectedLinks);
                    foreach (var x in affectedLinks)
                    {
                        result.AddRecord(x.SubjectUid);
                    }
                }

                // teams
                var affectedTeams = rs.sharedFolders
                    .Where(x => !x.fullSync.HasValue || !x.fullSync.Value)
                    .Where(x => x.teamsRemoved != null)
                    .SelectMany(x => x.teamsRemoved,
                        (x, teamUid) => UidLink.Create(x.SharedFolderUid, teamUid))
                    .Cast<IUidLink>()
                    .ToArray();
                if (affectedTeams.Any())
                {
                    storage.SharedFolderKeys.DeleteLinks(affectedTeams);
                }

                //users
                var affectedUsers = rs.sharedFolders
                    .Where(x => !x.fullSync.HasValue || !x.fullSync.Value)
                    .Where(x => x.usersRemoved != null)
                    .SelectMany(x => x.usersRemoved,
                        (x, username) => UidLink.Create(x.SharedFolderUid, username))
                    .Cast<IUidLink>()
                    .ToArray();


                if (affectedTeams.Any() || affectedLinks.Any())
                {
                    storage.SharedFolderPermissions.DeleteLinks(affectedTeams.Concat(affectedUsers));
                }
            }

            if (rs.nonSharedData != null)
            {
                storage.NonSharedData.PutEntities(rs.nonSharedData
                    .Where(x => !string.IsNullOrEmpty(x.data))
                    .Select(x =>
                    {
                        try
                        {
                            var data = x.data.Base64UrlDecode();
                            data = CryptoUtils.DecryptAesV1(data, context.DataKey);
                            data = CryptoUtils.EncryptAesV1(data, clientKey);
                            x.data = data.Base64UrlEncode();
                            return x;
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                            return null;
                        }
                    })
                    .Where(x => x != null));
            }

            var recordOwnership = new Dictionary<string, bool>();
            if (rs.recordMetaData != null)
            {
                foreach (var rmd in rs.recordMetaData)
                {
                    recordOwnership[rmd.RecordUid] = rmd.Owner;
                }
            }

            if (rs.records != null)
            {
                result.AddRecords(rs.records.Select(x => x.RecordUid));

                foreach (var recordUid in rs.records
                    .Where(x => !recordOwnership.ContainsKey(x.RecordUid))
                    .Select(x => storage.Records.GetEntity(x.RecordUid))
                    .Where(x => x != null)
                    .Where(x => x.Owner)
                    .Select(x => x.RecordUid)
                )
                {
                    recordOwnership[recordUid] = true;
                }

                storage.Records.PutEntities(rs.records
                    .Select(x =>
                    {
                        x.AdjustUdata();
                        if (recordOwnership.ContainsKey(x.RecordUid))
                        {
                            x.Owner = recordOwnership[x.RecordUid];
                            recordOwnership.Remove(x.RecordUid);
                        }

                        return x;
                    }));

                var recordLinks = rs.records
                    .Where(x => !string.IsNullOrEmpty(x.OwnerRecordId) && !string.IsNullOrEmpty(x.LinkKey))
                    .Select(x => new SyncDownRecordMetaData
                    {
                        RecordUid = x.RecordUid,
                        SharedFolderUid = x.OwnerRecordId,
                        RecordKey = x.LinkKey,
                        RecordKeyType = (int) KeyType.RecordKey,
                        CanEdit = false,
                        CanShare = false,
                    })
                    .ToArray();
                if (recordLinks.Length > 0)
                {
                    storage.RecordKeys.PutLinks(recordLinks);
                }
            }

            if (rs.recordMetaData != null)
            {
                result.AddRecords(rs.recordMetaData.Select(x => x.RecordUid));

                var toUpdate = rs.recordMetaData
                    .Where(x => recordOwnership.ContainsKey(x.RecordUid))
                    .Select(x =>
                    {
                        var sr = storage.Records.GetEntity(x.RecordUid);
                        if (sr == null) return null;
                        if (sr.Owner == x.Owner) return null;

                        sr.Owner = x.Owner;
                        return sr;

                    })
                    .Where(x => x != null)
                    .ToArray();
                if (toUpdate.Any())
                {
                    storage.Records.PutEntities(toUpdate);
                }

                var rmds = rs.recordMetaData
                    .Select(rmd =>
                    {
                        try
                        {
                            byte[] key;
                            switch (rmd.RecordKeyType)
                            {
                                case 0:
                                    key = context.DataKey;
                                    break;
                                case 1:
                                    key = CryptoUtils.DecryptAesV1(rmd.RecordKey.Base64UrlDecode(), context.DataKey);
                                    break;
                                case 2:
                                    key = CryptoUtils.DecryptRsa(rmd.RecordKey.Base64UrlDecode(), context.PrivateRsaKey);
                                    break;
                                case 3:
                                    key = CryptoUtils.DecryptAesV2(rmd.RecordKey.Base64UrlDecode(), context.DataKey);
                                    break;
                                case 4:
                                    key = CryptoUtils.DecryptEc(rmd.RecordKey.Base64UrlDecode(), context.PrivateEcKey);
                                    break;
                                default:
                                    throw new Exception(
                                        $"Record metadata UID {rmd.RecordUid}: unsupported key type {rmd.RecordKeyType}");
                            }

                            if (key != null)
                            {
                                rmd.RecordKey = CryptoUtils.EncryptAesV1(key, context.ClientKey).Base64UrlEncode();
                                rmd.RecordKeyType = (int) KeyType.DataKey;
                                rmd.SharedFolderUid = storage.PersonalScopeUid;
                                return rmd;
                            }
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                        }

                        return null;
                    })
                    .ToArray();

                storage.RecordKeys.PutLinks(rmds);
            }

            if (rs.teams != null)
            {
                var removedSharedFolderLinks = rs.teams
                    .Where(x => x.removedSharedFolders != null)
                    .SelectMany(x => x.removedSharedFolders,
                        (team, sharedFolderUid) => UidLink.Create(sharedFolderUid, team.TeamUid))
                    .Cast<IUidLink>()
                    .ToArray();
                if (removedSharedFolderLinks.Any())
                {
                    result.AddSharedFolders(removedSharedFolderLinks.Select(x => x.SubjectUid));
                    storage.SharedFolderKeys.DeleteLinks(removedSharedFolderLinks);
                }

                var teams = rs.teams
                    .Select(x =>
                    {
                        try
                        {
                            byte[] teamKey;
                            switch (x.KeyType)
                            {
                                case 1:
                                    teamKey = CryptoUtils.DecryptAesV1(x.TeamKey.Base64UrlDecode(), context.DataKey);
                                    break;
                                case 2:
                                    teamKey = CryptoUtils.DecryptRsa(x.TeamKey.Base64UrlDecode(), context.PrivateRsaKey);
                                    break;
                                case 3:
                                    teamKey = CryptoUtils.DecryptAesV2(x.TeamKey.Base64UrlDecode(), context.DataKey);
                                    break;
                                case 4:
                                    teamKey = CryptoUtils.DecryptEc(x.TeamKey.Base64UrlDecode(), context.PrivateEcKey);
                                    break;
                                default:
                                    throw new Exception($"Team UID {x.TeamUid}: unsupported key type {x.KeyType}");
                            }

                            x.TeamKey = CryptoUtils.EncryptAesV1(teamKey, clientKey).Base64UrlEncode();
                            x.KeyType = (int) KeyType.DataKey;
                            return x;
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                            return null;
                        }

                    })
                    .Where(x => x != null)
                    .ToArray();
                storage.Teams.PutEntities(teams);

                var sharedFolderKeys = rs.teams
                    .Where(x => x.sharedFolderKeys != null)
                    .SelectMany(x => x.sharedFolderKeys,
                        (team, sharedFolderKey) =>
                        {
                            sharedFolderKey.TeamUid = team.TeamUid;
                            sharedFolderKey.KeyType = sharedFolderKey.KeyType == 2 ? (int) KeyType.TeamPrivateKey : (int)KeyType.TeamKey;
                            return sharedFolderKey;
                        })
                    .ToArray();
                storage.SharedFolderKeys.PutLinks(sharedFolderKeys);
            }

            if (rs.sharedFolders != null)
            {
                result.AddSharedFolders(rs.sharedFolders.Select(x => x.SharedFolderUid));

                // shared folders
                storage.SharedFolders.PutEntities(rs.sharedFolders);

                // shared folder keys
                var sharedFolderKeys = rs.sharedFolders
                    .Where(x => !string.IsNullOrEmpty(x.SharedFolderKey))
                    .Select(x =>
                    {
                        try
                        {
                            var sharedFolderKey = x.SharedFolderKey.Base64UrlDecode();
                            switch (x.KeyType)
                            {
                                case 1:
                                    sharedFolderKey = CryptoUtils.DecryptAesV1(sharedFolderKey, context.DataKey);
                                    break;
                                case 2:
                                    sharedFolderKey = CryptoUtils.DecryptRsa(sharedFolderKey, context.PrivateRsaKey);
                                    break;
                                case 3:
                                    sharedFolderKey = CryptoUtils.DecryptAesV2(sharedFolderKey, context.DataKey);
                                    break;
                                case 4:
                                    sharedFolderKey = CryptoUtils.DecryptEc(sharedFolderKey, context.PrivateEcKey);
                                    break;
                                default:
                                    throw new Exception(
                                        $"Shared Folder UID {x.SharedFolderUid}: unsupported key type {x.KeyType}");
                            }

                            return new SyncDownSharedFolderKey
                            {
                                SharedFolderUid = x.SharedFolderUid,
                                TeamUid = storage.PersonalScopeUid,
                                SharedFolderKey = CryptoUtils.EncryptAesV1(sharedFolderKey, clientKey)
                                    .Base64UrlEncode(),
                                KeyType = (int) KeyType.DataKey
                            };
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                            return null;
                        }
                    })
                    .ToArray();
                if (sharedFolderKeys.Any())
                {
                    storage.SharedFolderKeys.PutLinks(sharedFolderKeys);
                }

                result.AddRecords(rs.sharedFolders
                    .Where(x => x.records != null)
                    .SelectMany(x => x.records,
                        (sf, r) => r.RecordUid));

                // Records
                var sharedFolderRecords = rs.sharedFolders
                    .Where(x => x.records != null)
                    .SelectMany(x => x.records,
                        (sf, sfr) => new SyncDownRecordMetaData
                        {
                            SharedFolderUid = sf.SharedFolderUid,
                            RecordUid = sfr.RecordUid,
                            RecordKey = sfr.RecordKey,
                            RecordKeyType = (int) KeyType.SharedFolderKey,
                            CanEdit = sfr.CanEdit,
                            CanShare = sfr.CanShare
                        })
                    .ToArray();
                if (sharedFolderRecords.Any())
                {
                    storage.RecordKeys.PutLinks(sharedFolderRecords);
                }

                // Teams
                var teams = rs.sharedFolders
                    .Where(x => x.teams != null)
                    .SelectMany(x => x.teams,
                        (sf, sft) =>
                        {
                            sft.SharedFolderUid = sf.SharedFolderUid;
                            return sft;
                        })
                    .Cast<ISharedFolderPermission>()
                    .ToArray();
                // Users
                var users = rs.sharedFolders
                    .Where(x => x.users != null)
                    .SelectMany(x => x.users,
                        (sf, sfu) =>
                        {
                            sfu.SharedFolderUid = sf.SharedFolderUid;
                            return sfu;
                        })
                    .Cast<ISharedFolderPermission>()
                    .ToArray();

                if (teams.Any() || users.Any())
                {
                    storage.SharedFolderPermissions.PutLinks(teams.Concat(users));
                }
            }

            if (rs.userFolders != null)
            {
                var userFolders = rs.userFolders
                    .Select(uf =>
                    {
                        try
                        {
                            var folderKey = uf.FolderKey.Base64UrlDecode();
                            switch (uf.keyType)
                            {
                                case 1:
                                    folderKey = CryptoUtils.DecryptAesV1(folderKey, context.DataKey);
                                    break;
                                case 2:
                                    folderKey = CryptoUtils.DecryptRsa(folderKey, context.PrivateRsaKey);
                                    break;
                                case 3:
                                    folderKey = CryptoUtils.DecryptAesV1(folderKey, context.DataKey);
                                    break;
                                case 4:
                                    folderKey = CryptoUtils.DecryptEc(folderKey, context.PrivateEcKey);
                                    break;
                                default:
                                    throw new Exception($"User Folder UID {uf.FolderUid}: unsupported key type {uf.keyType}");
                            }

                            uf.FolderKey = CryptoUtils.EncryptAesV1(folderKey, clientKey).Base64UrlEncode();
                            uf.keyType = (int) KeyType.DataKey;
                            return uf;
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                            return null;
                        }
                    })
                    .ToArray();

                storage.Folders.PutEntities(userFolders);
            }

            if (rs.sharedFolderFolders != null)
            {
                storage.Folders.PutEntities(rs.sharedFolderFolders);
            }

            if (rs.userFolderSharedFolders != null)
            {
                storage.Folders.PutEntities(rs.userFolderSharedFolders);
            }

            if (rs.userFolderRecords != null)
            {
                storage.FolderRecords.PutLinks(rs.userFolderRecords
                    .Select(ufr =>
                    {
                        ufr.FolderUid = string.IsNullOrEmpty(ufr.FolderUid) ? storage.PersonalScopeUid : ufr.FolderUid;
                        return ufr;
                    }));
            }

            if (rs.sharedFolderFolderRecords != null)
            {
                storage.FolderRecords.PutLinks(rs.sharedFolderFolderRecords);
            }

            storage.Revision = rs.revision;
            Debug.WriteLine("Sync Down: Leave");

            Debug.WriteLine("Rebuild Data: Enter");
            vault.RebuildData(result);
            Debug.WriteLine("Rebuild Data: Leave");
        }

        private static readonly DataContractJsonSerializer UdataSerializer =
            new DataContractJsonSerializer(typeof(SyncDownRecordUData), JsonUtils.JsonSettings);

        private static void AdjustUdata(this SyncDownRecord syncDownRecord)
        {
            if (syncDownRecord.Version == 4)
            {
                if (syncDownRecord.udata == null)
                {
                    syncDownRecord.udata = new SyncDownRecordUData();
                }

                syncDownRecord.udata.FileSize = syncDownRecord.fileSize;
                syncDownRecord.udata.ThumbnailSize = syncDownRecord.thumbnailSize;
            }

            if (syncDownRecord.udata == null) return;

            using (var ms = new MemoryStream())
            {
                UdataSerializer.WriteObject(ms, syncDownRecord.udata);
                syncDownRecord.Udata = ms.ToArray().Base64UrlEncode();
            }
        }
    }
}