using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Vault
{
    internal class RebuildTask
    {
        internal RebuildTask(bool isFullSync)
        {
            IsFullSync = isFullSync;
        }

        public bool IsFullSync { get; }

        public void AddRecord(string recordUid)
        {
            if (IsFullSync) return;
            if (Records == null)
            {
                Records = new HashSet<string>();
            }

            Records.Add(recordUid);
        }

        public void AddRecords(IEnumerable<string> recordUids)
        {
            foreach (var recordUid in recordUids)
            {
                AddRecord(recordUid);
            }
        }

        public void AddSharedFolder(string sharedFolderUid)
        {
            if (IsFullSync) return;
            if (SharedFolders == null)
            {
                SharedFolders = new HashSet<string>();
            }

            SharedFolders.Add(sharedFolderUid);
        }

        public void AddSharedFolders(IEnumerable<string> sharedFolderUids)
        {
            foreach (var sharedFolderUid in sharedFolderUids)
            {
                AddSharedFolder(sharedFolderUid);
            }
        }

        public ISet<string> Records { get; private set; }
        public ISet<string> SharedFolders { get; private set; }
    }

    /// <summary>
    /// Represents Keeper vault loaded from the <see cref="IKeeperStorage"/> and decrypted.
    /// </summary>
    public class VaultData: IVaultData, IDisposable
    {
        /// <summary>
        /// Instantiates <see cref="VaultData"/> instance. 
        /// </summary>
        /// <param name="clientKey"><see cref="IKeeperStorage"/> encryption key.</param>
        /// <param name="storage">Vault storage.</param>
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
        public IEnumerable<Team> Teams => keeperTeams.Values;

        public bool TryGetTeam(string teamUid, out Team team)
        {
            return keeperTeams.TryGetValue(teamUid, out team);
        }

        public IEnumerable<FolderNode> Folders => keeperFolders.Values;

        public bool TryGetFolder(string folderUid, out FolderNode node)
        {
            return keeperFolders.TryGetValue(folderUid, out node);
        }

        public T LoadNonSharedData<T>(string recordUid)
            where T : RecordNonSharedData, new()
        {
            var nsd = Storage.NonSharedData.GetEntity(recordUid);
            if (string.IsNullOrEmpty(nsd?.Data)) return new T();

            try
            {
                var data = CryptoUtils.DecryptAesV1(nsd.Data.Base64UrlDecode(), ClientKey);
                return JsonUtils.ParseJson<T>(data);
            }
            catch (Exception e)
            {
                Trace.TraceError($"Record UID \"{recordUid}\": Non-shared data loading error: {e.Message}");
                return new T();
            }
        }

        public FolderNode RootFolder => rootFolder;

        protected readonly ConcurrentDictionary<string, PasswordRecord> keeperRecords =
            new ConcurrentDictionary<string, PasswordRecord>();

        protected readonly ConcurrentDictionary<string, SharedFolder> keeperSharedFolders =
            new ConcurrentDictionary<string, SharedFolder>();

        protected readonly ConcurrentDictionary<string, Team> keeperTeams =
            new ConcurrentDictionary<string, Team>();

        protected readonly ConcurrentDictionary<string, FolderNode> keeperFolders =
            new ConcurrentDictionary<string, FolderNode>();

        protected readonly FolderNode rootFolder;

        public IKeeperStorage Storage { get; }
        public byte[] ClientKey { get; }

        private long _dataRevision = 0;

        private bool DecryptSharedFolderKey(ISharedFolderKey sfmd, out byte[] sharedFolderKey)
        {
            try
            {
                var sfKey = sfmd.SharedFolderKey.Base64UrlDecode();
                switch (sfmd.KeyType)
                {
                    case (int) KeyType.DataKey:
                        sharedFolderKey = CryptoUtils.DecryptAesV1(sfKey, ClientKey);
                        return true;
                    case (int) KeyType.TeamKey:
                    {
                        if (keeperTeams.TryGetValue(sfmd.TeamUid, out var team))
                        {
                            if (sfKey.Length < 100)
                            {
                                sharedFolderKey = CryptoUtils.DecryptAesV1(sfKey, team.TeamKey);
                                return true;
                            }

                            sharedFolderKey = CryptoUtils.DecryptRsa(sfKey, team.TeamPrivateKey);
                            return true;

                        }
                        Trace.TraceError($"Shared Folder key: Team {sfmd.TeamUid} not found");
                    }

                    break;

                    case (int) KeyType.TeamPrivateKey:
                    {
                        if (keeperTeams.TryGetValue(sfmd.TeamUid, out var team))
                        {
                            sharedFolderKey = CryptoUtils.DecryptRsa(sfKey, team.TeamPrivateKey);
                            return true;
                        }

                        Trace.TraceError($"Shared Folder key: Team {sfmd.TeamUid} not found");

                    }
                    break;

                    default:
                        Trace.TraceError($"Unsupported key type {KeyType.DataKey} for shared folder {sfmd.SharedFolderUid}.");
                        break;
                }
            }
            catch (Exception e)
            {
                Trace.TraceError(e.Message);
            }

            sharedFolderKey = null;
            return false;
        }

        private bool DecryptRecordKey(IRecordMetadata rmd, out byte[] recordKey)
        {
            try
            {
                var rKey = rmd.RecordKey.Base64UrlDecode();
                switch (rmd.RecordKeyType)
                {
                    case (int) KeyType.NoKey:
                    case (int) KeyType.DataKey:
                    case (int) KeyType.PrivateKey:
                        recordKey = CryptoUtils.DecryptAesV1(rKey, ClientKey);
                        return true;

                    case (int) KeyType.SharedFolderKey:
                        if (keeperSharedFolders.TryGetValue(rmd.SharedFolderUid, out var sf))
                        {
                            recordKey = CryptoUtils.DecryptAesV1(rKey, sf.SharedFolderKey);
                            return true;
                        }
                        else
                        {
                            Trace.TraceError($"Record UID \"{rmd.RecordUid}\": Shared Folder \"{rmd.SharedFolderUid}\" not found.");
                            break;
                        }

                    default:
                        Trace.TraceError($"Record UID \"{rmd.RecordUid}\": Unsupported record key type.");
                        break;
                }
            }
            catch (Exception e)
            {
                Trace.TraceError(e.Message);
            }

            recordKey = null;
            return false;
        }

        internal void RebuildData(RebuildTask changes = null)
        {
            var fullRebuild = _dataRevision == 0 || changes == null || changes.IsFullSync;
            var entityKeys = new Dictionary<string, byte[]>();

            // teams
            keeperTeams.Clear();
            foreach (var team in Storage.Teams.GetAll())
            {
                try
                {

                    var teamKey = CryptoUtils.DecryptAesV1(team.TeamKey.Base64UrlDecode(), ClientKey);
                    var t = new Team(team, teamKey);
                    keeperTeams.TryAdd(t.TeamUid, t);
                }
                catch (Exception e)
                {
                    Trace.TraceError(e.Message);
                }
            }

            var uids = new HashSet<string>();

            // shared folders
            {
                entityKeys.Clear();
                var sharedFoldersToLoad = new List<ISharedFolder>();
                if (!fullRebuild && (changes.SharedFolders?.Count ?? 0) * 4 > keeperSharedFolders.Count)
                {
                    fullRebuild = true;
                }

                if (fullRebuild)
                {
                    keeperSharedFolders.Clear();
                    sharedFoldersToLoad.AddRange(Storage.SharedFolders.GetAll());
                    foreach (var sfKey in Storage.SharedFolderKeys.GetAllLinks())
                    {
                        if (entityKeys.ContainsKey(sfKey.SharedFolderUid)) continue;

                        if (DecryptSharedFolderKey(sfKey, out var key))
                        {
                            entityKeys[sfKey.SharedFolderUid] = key;
                        }
                    }
                }
                else
                {
                    if (changes.SharedFolders != null)
                    {
                        foreach (var sharedFolderUid in changes.SharedFolders)
                        {
                            if (keeperSharedFolders.TryRemove(sharedFolderUid, out var sharedFolder))
                            {
                                changes.AddRecords(sharedFolder.RecordPermissions.Select(x => x.RecordUid));
                            }

                            var sf = Storage.SharedFolders.GetEntity(sharedFolderUid);
                            if (sf != null)
                            {
                                sharedFoldersToLoad.Add(sf);
                            }

                            foreach (var sfKey in Storage.SharedFolderKeys.GetLinksForSubject(sharedFolderUid))
                            {
                                if (!DecryptSharedFolderKey(sfKey, out var key)) continue;
                                
                                entityKeys[sfKey.SharedFolderUid] = key;
                                break;
                            }
                        }
                    }
                }

                uids.Clear();
                foreach (var sharedFolder in sharedFoldersToLoad)
                {
                    if (sharedFolder == null) continue;
                    if (entityKeys.ContainsKey(sharedFolder.SharedFolderUid))
                    {
                        var sfKey = entityKeys[sharedFolder.SharedFolderUid];
                        var sfmds = Storage.RecordKeys.GetLinksForObject(sharedFolder.SharedFolderUid)
                            .ToArray();
                        var sfus = Storage.SharedFolderPermissions
                            .GetLinksForSubject(sharedFolder.SharedFolderUid).ToArray();
                        var sf = sharedFolder.Load(sfmds, sfus, sfKey);
                        keeperSharedFolders.TryAdd(sharedFolder.SharedFolderUid, sf);
                    }
                    else
                    {
                        uids.Add(sharedFolder.SharedFolderUid);
                    }

                }

                if (uids.Count > 0)
                {
                    Storage.SharedFolders.DeleteUids(uids);
                    Storage.RecordKeys.DeleteLinksForObjects(uids);
                    Storage.SharedFolderKeys.DeleteLinksForSubjects(uids);
                    Storage.SharedFolderPermissions.DeleteLinksForSubjects(uids);
                }
            }

            // records
            {
                entityKeys.Clear();
                var lostKeys = new List<IUidLink>();
                var recordsToLoad = new Dictionary<string, IPasswordRecord>();
                if (!fullRebuild && (changes.Records?.Count ?? 0) * 5 > keeperRecords.Count)
                {
                    fullRebuild = true;
                }
                if (fullRebuild)
                {
                    keeperRecords.Clear();
                    foreach (var record in Storage.Records.GetAll())
                    {
                        recordsToLoad[record.RecordUid] = record;
                    }

                    foreach (var rmd in Storage.RecordKeys.GetAllLinks())
                    {
                        if (entityKeys.ContainsKey(rmd.RecordUid)) continue;
                        if (!recordsToLoad.ContainsKey(rmd.RecordUid))
                        {
                            lostKeys.Add(rmd);
                            continue;
                        }

                        if (DecryptRecordKey(rmd, out var rKey))
                        {
                            entityKeys[rmd.RecordUid] = rKey;
                        }
                        else
                        {
                            lostKeys.Add(rmd);
                        }
                    }
                }
                else
                {
                    if (changes.Records != null)
                    {
                        foreach (var recordUid in changes.Records)
                        {
                            var r = Storage.Records.GetEntity(recordUid);
                            if (r == null) continue;
                            recordsToLoad[r.RecordUid] = r;

                            keeperRecords.TryRemove(recordUid, out _);

                            foreach (var rmd in Storage.RecordKeys.GetLinksForSubject(r.RecordUid))
                            {
                                if (DecryptRecordKey(rmd, out var rKey))
                                {
                                    entityKeys[rmd.RecordUid] = rKey;
                                    break;
                                }

                                lostKeys.Add(rmd);
                            }
                        }
                    }
                }

                uids.Clear();
                foreach (var r in recordsToLoad.Values)
                {
                    if (entityKeys.ContainsKey(r.RecordUid))
                    {
                        var rKey = entityKeys[r.RecordUid];
                        try
                        {
                            var record = r.Load(rKey);
                            keeperRecords.TryAdd(r.RecordUid, record);
                        }
                        catch (Exception e) 
                        {
                            Trace.TraceError($"Error decoding record \"{r.RecordUid}\": {e.Message}");
                        }
                    }
                    else
                    {
                        uids.Add(r.RecordUid);
                    }
                }

                if (lostKeys.Any())
                {
                    Storage.RecordKeys.DeleteLinks(lostKeys);
                }

                if (uids.Any())
                {
                    Storage.RecordKeys.DeleteLinksForSubjects(uids);
                    Storage.Records.DeleteUids(uids);
                }
            }

            BuildFolders();
            _dataRevision = Storage.Revision;
        }

        internal void BuildFolders()
        {
            var folderMap = new Dictionary<string, IFolder>();
            foreach (var folder in Storage.Folders.GetAll())
            {
                folderMap[folder.FolderUid] = folder;
            }
            var uids = new HashSet<string>();
            
            // check shared folder exists. 
            foreach (var folder in folderMap.Values)
            {
                if (folder.FolderType == "user_folder") continue;
                if (string.IsNullOrEmpty(folder.SharedFolderUid)) continue;

                if (!keeperSharedFolders.ContainsKey(folder.SharedFolderUid))
                {
                    uids.Add(folder.FolderUid);
                }
            }

            if (uids.Count > 0)
            {
                Storage.FolderRecords.DeleteLinksForObjects(uids);
                Storage.Folders.DeleteUids(uids);
                foreach (var folderUid in uids)
                {
                    folderMap.Remove(folderUid);
                }
            }

            keeperFolders.Clear();
            rootFolder.Records.Clear();
            rootFolder.Subfolders.Clear();
            foreach (var folder in folderMap.Values)
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
                        node.FolderType = folder.FolderType == "shared_folder_folder"
                            ? FolderType.SharedFolderFolder
                            : FolderType.SharedFolder;
                        if (keeperSharedFolders.TryGetValue(folder.SharedFolderUid, out var sf))
                        {
                            if (node.FolderType == FolderType.SharedFolderFolder)
                            {
                                if (string.IsNullOrEmpty(node.ParentUid))
                                {
                                    node.ParentUid = node.SharedFolderUid;
                                }

                                var key = CryptoUtils.DecryptAesV1(folder.FolderKey.Base64UrlDecode(),
                                    sf.SharedFolderKey);
                                data = CryptoUtils.DecryptAesV1(folder.Data.Base64UrlDecode(), key);
                            }
                            else
                            {
                                node.Name = sf.Name;
                            }
                        }
                        else
                        {
                            Trace.TraceError(
                                $"Missing Shared Folder UID {folder.SharedFolderUid} for Folder UID {folder.FolderUid}");
                        }
                    }

                    if (data != null)
                    {
                        var serializer = new DataContractJsonSerializer(typeof(FolderData));
                        using (var stream = new MemoryStream(data))
                        {
                            var folderData = serializer.ReadObject(stream) as FolderData;
                            node.Name = folderData?.name;
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

            foreach (var folderUid in keeperFolders.Keys)
            {
                if (keeperFolders.TryGetValue(folderUid, out FolderNode node))
                {
                    FolderNode parent;

                    if (string.IsNullOrEmpty(node.ParentUid))
                    {
                        parent = rootFolder;
                    }
                    else
                    {
                        if (!keeperFolders.TryGetValue(node.ParentUid, out parent))
                        {
                            parent = rootFolder;
                        }
                    }

                    parent.Subfolders.Add(folderUid);
                }
            }

            foreach (var link in Storage.FolderRecords.GetAllLinks())
            {
                FolderNode node;
                if (string.IsNullOrEmpty(link.FolderUid))
                {
                    node = rootFolder;
                }
                else
                {
                    if (!keeperFolders.TryGetValue(link.FolderUid, out node))
                    {
                        node = rootFolder;
                    }
                }

                node.Records.Add(link.RecordUid);
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}