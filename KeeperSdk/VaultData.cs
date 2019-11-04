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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;

namespace KeeperSecurity.Sdk
{
    public class RebuildTask
    {
        internal RebuildTask(bool isFullSync)
        {
            IsFullSync = isFullSync;
        }
        public bool IsFullSync { get; }

        public void AddRecord(string recordUid)
        {
            if (!IsFullSync)
            {
                if (_records == null)
                {
                    _records = new HashSet<string>();
                }
                _records.Add(recordUid);
            }
        }

        public void AddSharedFolder(string sharedFolderUid)
        {
            if (!IsFullSync)
            {
                if (_sharedFolders == null)
                {
                    _sharedFolders = new HashSet<string>();
                }
                _sharedFolders.Add(sharedFolderUid);
            }
        }

        public IEnumerable<string> SharedFolderUids => _sharedFolders ?? Enumerable.Empty<string>();
        public IEnumerable<string> RecordUids => _records ?? Enumerable.Empty<string>();

        private ISet<string> _records;
        private ISet<string> _sharedFolders;
    }

    public class VaultData
    {
        public VaultData(byte[] clientKey, IKeeperStorage storage)
        {
            ClientKey = clientKey;
            Storage = storage;

            rootFolder = new FolderNode
            {
                FolderUid = "",
                Name = "My Vault",
                FolderType = FolderType.UserFolder
            };
        }

        public int RecordCount => keeperRecords.Count;
        public IEnumerable<PasswordRecord> Records => keeperRecords.Values;
        public bool TryGetRecord(string recordUid, out PasswordRecord node)
        {
            return keeperRecords.TryGetValue(recordUid, out node);
        }

        public int SharedFolderCount => keeperSharedFolders.Count;
        public IEnumerable<SharedFolder> SharedFolders => keeperSharedFolders.Values;
        public bool TryGetSharedFolder(string sharedFolderUid, out SharedFolder sharedFolder)
        {
            return keeperSharedFolders.TryGetValue(sharedFolderUid, out sharedFolder);
        }

        public int TeamCount => keeperTeams.Count;
        public IEnumerable<EnterpriseTeam> Teams => keeperTeams.Values;
        public bool TryGetTeam(string teamUid, out EnterpriseTeam team)
        {
            return keeperTeams.TryGetValue(teamUid, out team);
        }

        public IEnumerable<FolderNode> Folders => keeperFolders.Values;
        public bool TryGetFolder(string folderUid, out FolderNode node)
        {
            return keeperFolders.TryGetValue(folderUid, out node);
        }

        public FolderNode RootFolder => rootFolder;

        protected internal readonly ConcurrentDictionary<string, PasswordRecord> keeperRecords = new ConcurrentDictionary<string, PasswordRecord>();
        protected internal readonly ConcurrentDictionary<string, SharedFolder> keeperSharedFolders = new ConcurrentDictionary<string, SharedFolder>();
        protected internal readonly ConcurrentDictionary<string, EnterpriseTeam> keeperTeams = new ConcurrentDictionary<string, EnterpriseTeam>();

        protected internal readonly ConcurrentDictionary<string, FolderNode> keeperFolders = new ConcurrentDictionary<string, FolderNode>();
        protected internal readonly FolderNode rootFolder;

        protected internal IKeeperStorage Storage { get; }
        protected internal byte[] ClientKey { get; }

        public void RebuildData(RebuildTask changes = null)
        {
            bool fullRebuild = true;// changes == null || changes.IsFullSync;

            keeperTeams.Clear();
            foreach (var team in Storage.Teams.GetAll())
            {
                try
                {
                    var teamKey = CryptoUtils.DecryptAesV1(team.TeamKey.Base64UrlDecode(), ClientKey);
                    var t = new EnterpriseTeam(team, teamKey);
                    keeperTeams.TryAdd(t.TeamUid, t);
                }
                catch (Exception e)
                {
                    Trace.TraceError(e.Message);
                }
            }

            if (fullRebuild)
            {
                keeperSharedFolders.Clear();
            }
            else
            {
                foreach (var sharedFolderUid in changes.SharedFolderUids)
                {
                    keeperSharedFolders.TryRemove(sharedFolderUid, out SharedFolder sf);
                }
            }

            var uids = new HashSet<string>();

            var sharedFolders = fullRebuild ? Storage.SharedFolders.GetAll() : changes.SharedFolderUids.Select(x => Storage.SharedFolders.Get(x));
            foreach (var sharedFolder in sharedFolders)
            {
                if (sharedFolder == null) continue;

                var sfMetadata = Storage.SharedFolderKeys.GetLinksForSubject(sharedFolder.SharedFolderUid).ToArray();
                if (sfMetadata.Length > 0)
                {
                    foreach (var sfmd in sfMetadata)
                    {
                        try
                        {
                            var sfKey = sfmd.SharedFolderKey.Base64UrlDecode();
                            switch (sfmd.KeyType)
                            {
                                case (int)KeyType.DataKey:
                                    sfKey = CryptoUtils.DecryptAesV1(sfKey, ClientKey);
                                    break;
                                case (int)KeyType.TeamKey:
                                    if (keeperTeams.TryGetValue(sfmd.TeamUid, out EnterpriseTeam team))
                                    {
                                        sfKey = CryptoUtils.DecryptAesV1(sfKey, team.TeamKey);
                                    }
                                    break;
                                default:
                                    sfKey = null;
                                    Debug.Assert(false, "Unsupported shared folder key type");
                                    break;
                            }
                            if (sfKey != null)
                            {
                                var sfmds = Storage.RecordKeys.GetLinksForObject(sharedFolder.SharedFolderUid).ToArray();
                                var sfus = Storage.SharedFolderPermissions.GetLinksForSubject(sharedFolder.SharedFolderUid).ToArray();
                                var sf = sharedFolder.Load(sfmds, sfus, sfKey);
                                keeperSharedFolders.TryAdd(sharedFolder.SharedFolderUid, sf);
                                break;
                            }
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                        }
                    }
                }
                else
                {
                    uids.Add(sharedFolder.SharedFolderUid);
                }
            }
            if (uids.Count > 0)
            {
                foreach (var sharedFolderUid in uids)
                {
                    Storage.SharedFolders.Delete(sharedFolderUid);
                    Storage.RecordKeys.DeleteObject(sharedFolderUid);
                    Storage.SharedFolderKeys.DeleteSubject(sharedFolderUid);
                    Storage.SharedFolderPermissions.DeleteSubject(sharedFolderUid);
                }
            }

            if (fullRebuild)
            {
                keeperRecords.Clear();
            }
            else
            {
                foreach (var recordUid in changes.RecordUids)
                {
                    keeperRecords.TryRemove(recordUid, out PasswordRecord r);
                }
            }

            uids.Clear();
            var records = fullRebuild ? Storage.Records.GetAll() : changes.RecordUids.Select(x => Storage.Records.Get(x));
            foreach (var record in records)
            {
                if (record == null) continue;

                var rMetadata = Storage.RecordKeys.GetLinksForSubject(record.RecordUid).ToArray();
                if (rMetadata.Length > 0)
                {
                    foreach (var rmd in rMetadata)
                    {
                        try
                        {
                            var rKey = rmd.RecordKey.Base64UrlDecode();
                            switch (rmd.RecordKeyType)
                            {
                                case (int)KeyType.NoKey:
                                case (int)KeyType.DataKey:
                                case (int)KeyType.PrivateKey:
                                    rKey = CryptoUtils.DecryptAesV1(rKey, ClientKey);
                                    break;
                                case (int)KeyType.SharedFolderKey:
                                    if (keeperSharedFolders.TryGetValue(rmd.SharedFolderUid, out SharedFolder sf))
                                    {
                                        rKey = CryptoUtils.DecryptAesV1(rKey, sf.SharedFolderKey);
                                    }
                                    break;
                                default:
                                    rKey = null;
                                    Debug.Assert(false, "Unsupported record key type");
                                    break;

                            }
                            if (rKey != null)
                            {
                                var r = record.Load(rKey);
                                keeperRecords.TryAdd(record.RecordUid, r);
                                break;
                            }
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError(e.Message);
                        }
                    }
                }
                else
                {
                    uids.Add(record.RecordUid);
                }
            }
            if (uids.Count > 0)
            {
                foreach (var uid in uids)
                {
                    Storage.Records.Delete(uid);
                }
            }
            BuildFolders();
        }

        public void BuildFolders()
        {
            keeperFolders.Clear();
            rootFolder.Records.Clear();
            rootFolder.Subfolders.Clear();
            foreach (var folder in Storage.Folders.GetAll())
            {
                var node = new FolderNode
                {
                    FolderUid = folder.FolderUid,
                    ParentUid = folder.ParentUid
                };
                try
                {
                    byte[] data = null;
                    if (folder.FolderType == "user_folder")
                    {
                        node.FolderType = FolderType.UserFolder;
                        var key = CryptoUtils.DecryptAesV1(folder.FolderKey.Base64UrlDecode(), ClientKey);
                        data = CryptoUtils.DecryptAesV1(folder.Data.Base64UrlDecode(), key);
                    }
                    else
                    {
                        node.SharedFolderUid = folder.SharedFolderUid;
                        node.FolderType = folder.FolderType == "shared_folder_folder" ? FolderType.SharedFolderForder : FolderType.SharedFolder;
                        if (keeperSharedFolders.TryGetValue(folder.SharedFolderUid, out SharedFolder sf))
                        {
                            if (folder.FolderType == "shared_folder_folder")
                            {
                                var key = CryptoUtils.DecryptAesV1(folder.FolderKey.Base64UrlDecode(), sf.SharedFolderKey);
                                data = CryptoUtils.DecryptAesV1(folder.Data.Base64UrlDecode(), key);
                            }
                            else
                            {
                                node.Name = sf.Name;
                            }
                        }
                        else
                        {
                            Trace.TraceError($"Missing Shared Folder UID {folder.SharedFolderUid} for Folder UID {folder.FolderUid}");
                        }
                    }
                    if (data != null)
                    {
                        var serializer = new DataContractJsonSerializer(typeof(FolderData));
                        using (var stream = new MemoryStream(data))
                        {
                            var folderData = serializer.ReadObject(stream) as FolderData;
                            node.Name = folderData.name;
                        }
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceError(e.Message);
                }
                if (string.IsNullOrEmpty(node.Name))
                {
                    node.Name = node.FolderUid;
                }
                keeperFolders.TryAdd(node.FolderUid, node);
            }

            foreach (var folderUid in keeperFolders.Keys.ToArray())
            {
                if (keeperFolders.TryGetValue(folderUid, out FolderNode node))
                {
                    FolderNode parent = null;
                    if (string.IsNullOrEmpty(node.ParentUid) || node.ParentUid == Storage.PersonalScopeUid)
                    {
                        parent = rootFolder;
                    }
                    else
                    {
                        keeperFolders.TryGetValue(node.ParentUid, out parent);
                    }
                    if (parent != null)
                    {
                        parent.Subfolders.Add(folderUid);
                    }
                }
            }

            foreach (var link in Storage.FolderRecords.GetAllLinks())
            {
                FolderNode node = null;
                if (string.IsNullOrEmpty(link.FolderUid) || link.FolderUid == Storage.PersonalScopeUid || link.FolderUid == rootFolder.FolderUid)
                {
                    node = rootFolder;
                }
                else
                {
                    keeperFolders.TryGetValue(link.FolderUid, out node);
                }
                if (node != null)
                {
                    node.Records.Add(link.RecordUid);
                }
                else
                {
                    Trace.TraceError("Unresolved folder UID");
                }
            }
        }
    }
}
