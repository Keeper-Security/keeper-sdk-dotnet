using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
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
    public class VaultData : IVaultData, IDisposable
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

        /// <inheritdoc/>
        public int RecordCount => keeperRecords.Count;

        /// <inheritdoc/>
        public IEnumerable<KeeperRecord> KeeperRecords => keeperRecords.Values;

        /// <inheritdoc/>
        public bool TryGetKeeperRecord(string recordUid, out KeeperRecord record)
        {
            return keeperRecords.TryGetValue(recordUid, out record);
        }

        /// <inheritdoc/>
        public bool TryLoadKeeperRecord(string recordUid, out KeeperRecord record)
        {
            record = null;
            if (TryGetKeeperRecord(recordUid, out var r))
            {
                var storageRecord = Storage.Records.GetEntity(recordUid);
                if (storageRecord != null)
                {
                    record = storageRecord.Load(r.RecordKey);
                }
            }

            return record != null;
        }

        IEnumerable<PasswordRecord> IVaultData.Records => keeperRecords.Values.OfType<PasswordRecord>();

        bool IVaultData.TryGetRecord(string recordUid, out PasswordRecord record)
        {
            if (keeperRecords.TryGetValue(recordUid, out KeeperRecord r))
            {
                record = r as PasswordRecord;
                return record != null;
            }
            record = null;
            return false;
        }

        /// <inheritdoc/>
        public int SharedFolderCount => keeperSharedFolders.Count;
        /// <inheritdoc/>
        public IEnumerable<SharedFolder> SharedFolders => keeperSharedFolders.Values;

        /// <inheritdoc/>
        public bool TryGetSharedFolder(string sharedFolderUid, out SharedFolder sharedFolder)
        {
            return keeperSharedFolders.TryGetValue(sharedFolderUid, out sharedFolder);
        }

        /// <inheritdoc/>
        public int TeamCount => keeperTeams.Count;
        /// <inheritdoc/>
        public IEnumerable<Team> Teams => keeperTeams.Values;

        /// <inheritdoc/>
        public bool TryGetTeam(string teamUid, out Team team)
        {
            return keeperTeams.TryGetValue(teamUid, out team);
        }

        /// <inheritdoc/>
        public IEnumerable<FolderNode> Folders => keeperFolders.Values;

        /// <inheritdoc/>
        public bool TryGetFolder(string folderUid, out FolderNode node)
        {
            return keeperFolders.TryGetValue(folderUid, out node);
        }

        /// <inheritdoc/>
        public T LoadNonSharedData<T>(string recordUid)
            where T : RecordNonSharedData, new()
        {
            if (TryGetKeeperRecord(recordUid, out var record))
            {
                var nsd = Storage.NonSharedData.GetEntity(recordUid);
                if (string.IsNullOrEmpty(nsd?.Data)) return new T();

                byte[] data = null;
                try
                {
                    if (record.Version <= 2)
                    {
                        data = CryptoUtils.DecryptAesV1(nsd.Data.Base64UrlDecode(), ClientKey);
                    }
                    else
                    {
                        data = CryptoUtils.DecryptAesV2(nsd.Data.Base64UrlDecode(), ClientKey);
                    }
                }
                catch
                {
                    try {
                        if (record.Version > 2)
                        {
                            data = CryptoUtils.DecryptAesV1(nsd.Data.Base64UrlDecode(), ClientKey);
                        }
                        else
                        {
                            data = CryptoUtils.DecryptAesV2(nsd.Data.Base64UrlDecode(), ClientKey);
                        }
                    }
                    catch { }
                }
                if (data != null)
                {
                    try
                    {
                        return JsonUtils.ParseJson<T>(data);
                    }
                    catch (Exception e)
                    {
                        Trace.TraceError($"Record UID \"{recordUid}\": Non-shared data loading error: {e.Message}");
                    }
                }

                return new T();
            }
            else
            {
                Debug.WriteLine($"Record UID \"{recordUid}\" is not found");
            }
            return default;
        }

        /// <inheritdoc/>
        public FolderNode RootFolder => rootFolder;

        protected readonly ConcurrentDictionary<string, KeeperRecord> keeperRecords =
            new ConcurrentDictionary<string, KeeperRecord>();

        protected readonly ConcurrentDictionary<string, SharedFolder> keeperSharedFolders =
            new ConcurrentDictionary<string, SharedFolder>();

        protected readonly ConcurrentDictionary<string, Team> keeperTeams =
            new ConcurrentDictionary<string, Team>();

        protected readonly ConcurrentDictionary<string, FolderNode> keeperFolders =
            new ConcurrentDictionary<string, FolderNode>();

        protected readonly FolderNode rootFolder;

        /// <inheritdoc/>
        public IKeeperStorage Storage { get; }
        /// <inheritdoc/>
        public byte[] ClientKey { get; }

        protected readonly ConcurrentDictionary<string, RecordType> _keeperRecordTypes =
            new ConcurrentDictionary<string, RecordType>(StringComparer.InvariantCultureIgnoreCase);

        protected readonly ConcurrentBag<RecordType> _customRecordTypes =
            new ConcurrentBag<RecordType>();

        protected readonly ConcurrentDictionary<string, string> _keeperUserAccounts =
            new ConcurrentDictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        /// <inheritdoc/>
        public IEnumerable<RecordType> RecordTypes => _keeperRecordTypes.Values.Concat(_customRecordTypes);

        /// <inheritdoc/>
        public bool TryGetRecordTypeByName(string name, out RecordType recordType)
        {
            if (_keeperRecordTypes.TryGetValue(name, out recordType))
            {
                return true;
            }
            foreach (var rt in _customRecordTypes)
            {
                if (string.Equals(name, rt.Name, StringComparison.InvariantCultureIgnoreCase))
                {
                    recordType = rt;
                    return true;
                }
            }
            return false;
        }

        /// <inheritdoc/>
        public bool TryGetUsername(string accountUid, out string username)
        {
            return _keeperUserAccounts.TryGetValue(accountUid, out username);
        }

        /// <inheritdoc/>
        public bool TryGetAccountUid(string username, out string accountUid)
        {
            foreach(var ae in _keeperUserAccounts) 
            {
                if (string.Equals(ae.Value, username, StringComparison.InvariantCultureIgnoreCase)) 
                {
                    accountUid = ae.Key;
                    return true;
                }
            }
            accountUid = null;
            return false;
        }


        private void LoadRecordTypes()
        {
            _keeperRecordTypes.Clear();
            while (!_customRecordTypes.IsEmpty)
            {
                _customRecordTypes.TryTake(out _);
            }

            foreach (var field in Storage.RecordTypes.GetAll())
            {
                var content = JsonUtils.ParseJson<RecordTypeContent>(Encoding.UTF8.GetBytes(field.Content));
                var recordType = new RecordType
                {
                    Id = field.Id,
                    Scope = field.Scope,
                    Name = content.Name,
                    Description = content.Description,
                    Fields = content.Fields
                    .Select(x =>
                    {
                        if (RecordTypesConstants.TryGetRecordField(x.Ref, out RecordField rf))
                        {
                            RecordTypeField typeField;
                            if (x.Complexity != null)
                            {
                                typeField = new RecordTypePasswordField(rf, x.Label)
                                {
                                    PasswordOptions = new PasswordGenerationOptions
                                    {
                                        Length = x.Complexity.Length,
                                        Upper = x.Complexity.Upper,
                                        Lower = x.Complexity.Lower,
                                        Digit = x.Complexity.Digit,
                                        Special = x.Complexity.Special,
                                    }
                                };
                            }
                            else
                            {
                                typeField = new RecordTypeField(rf, x.Label);
                            }
                            typeField.Required = x.Required ?? false;
                            return typeField;
                        }
                        else
                        {
                            Debug.WriteLine($"Load Record Types: Cannot resolve field: {x.Ref}.");
                        }
                        return null;
                    })
                    .Where(x => x != null)
                    .ToArray(),
                };
                if (recordType.Scope == RecordTypeScope.Standard)
                {
                    _keeperRecordTypes.TryAdd(recordType.Name, recordType);
                }
                else if (recordType.Scope == RecordTypeScope.Enterprise)
                {
                    _customRecordTypes.Add(recordType);
                }
            }
        }

        private bool DecryptSharedFolderKey(ISharedFolderKey sfmd, out byte[] sharedFolderKey)
        {
            try
            {
                var sfKey = sfmd.SharedFolderKey.Base64UrlDecode();
                switch (sfmd.KeyType)
                {
                    case (int) KeyType.ClientKey_AES_GCM:
                        sharedFolderKey = CryptoUtils.DecryptAesV2(sfKey, ClientKey);
                        return true;
                    case (int) KeyType.TeamKey_AES_GCM:
                    {
                        if (keeperTeams.TryGetValue(sfmd.TeamUid, out var team))
                        {
                            sharedFolderKey = CryptoUtils.DecryptAesV2(sfKey, team.TeamKey);
                            return true;

                        }
                        Trace.TraceError($"Shared Folder key: Team {sfmd.TeamUid} not found");
                    }

                    break;

                    default:
                        Trace.TraceError($"Unsupported key type {sfmd.KeyType} for shared folder {sfmd.SharedFolderUid}.");
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
                    case (int) KeyType.ClientKey_AES_GCM:
                        recordKey = CryptoUtils.DecryptAesV2(rKey, ClientKey);
                        return true;

                    case (int) KeyType.SharedFolderKey_AES_Any:
                        if (keeperSharedFolders.TryGetValue(rmd.SharedFolderUid, out var sf))
                        {
                            recordKey = rKey.Length == 60 ? CryptoUtils.DecryptAesV2(rKey, sf.SharedFolderKey) : CryptoUtils.DecryptAesV1(rKey, sf.SharedFolderKey);
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
            var fullRebuild = changes == null || changes.IsFullSync;
            var entityKeys = new Dictionary<string, byte[]>();

            // teams
            keeperTeams.Clear();
            foreach (var team in Storage.Teams.GetAll())
            {
                try
                {
                    var teamKey = CryptoUtils.DecryptAesV2(team.TeamKey.Base64UrlDecode(), ClientKey);
                    var t = team.Load(teamKey);
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
                        var sf = sharedFolder.Load(Storage, sfKey);
                        keeperSharedFolders.TryAdd(sharedFolder.SharedFolderUid, sf);
                    }
                    else
                    {
                        uids.Add(sharedFolder.SharedFolderUid);
                    }

                }

                if (uids.Count > 0)
                {
                    Trace.WriteLine($"Detected {uids.Count} shared folders to delete.");
                    Storage.RecordKeys.DeleteLinksForObjects(uids);
                    Storage.SharedFolderPermissions.DeleteLinksForSubjects(uids);
                    Storage.SharedFolderKeys.DeleteLinksForSubjects(uids);
                    Storage.SharedFolders.DeleteUids(uids);
                }
            }

            // records
            {
                var recordOwnership = new HashSet<string>();
                entityKeys.Clear();
                var lostKeys = new List<IUidLink>();
                var recordKeyLinks = new List<IRecordMetadata>();
                var recordsToLoad = new Dictionary<string, IStorageRecord>();
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
                        if (rmd.Owner && !recordOwnership.Contains(rmd.RecordUid))
                        {
                            recordOwnership.Add(rmd.RecordUid);
                        }
                        if (entityKeys.ContainsKey(rmd.RecordUid)) continue;
                        if (!recordsToLoad.ContainsKey(rmd.RecordUid))
                        {
                            lostKeys.Add(rmd);
                        }
                        else if (rmd.RecordKeyType == (int) KeyType.RecordKey_AES_GCM)
                        {
                            if (recordsToLoad.ContainsKey(rmd.SubjectUid))
                            {
                                recordKeyLinks.Add(rmd);
                            }
                            else
                            {
                                lostKeys.Add(rmd);
                            }
                        }
                        else if (DecryptRecordKey(rmd, out var rKey))
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
                                if (rmd.Owner && !recordOwnership.Contains(rmd.RecordUid))
                                {
                                    recordOwnership.Add(rmd.RecordUid);
                                }
                                if (rmd.RecordKeyType == (int) KeyType.RecordKey_AES_GCM)
                                {
                                    recordKeyLinks.Add(rmd);
                                }
                                else if (DecryptRecordKey(rmd, out var rKey))
                                {
                                    entityKeys[rmd.RecordUid] = rKey;
                                    break;
                                }
                                else
                                {
                                    lostKeys.Add(rmd);
                                }
                            }
                        }
                    }
                }

                foreach (var rkl in recordKeyLinks)
                {
                    if (entityKeys.ContainsKey(rkl.RecordUid)) continue;
                    if (!entityKeys.TryGetValue(rkl.SharedFolderUid, out byte[] recordKey))
                    {
                        if (keeperRecords.TryGetValue(rkl.SharedFolderUid, out var r))
                        {
                            recordKey = r.RecordKey;
                        }
                    }
                    if (recordKey != null)
                    {
                        try
                        {
                            var rk = CryptoUtils.DecryptAesV2(rkl.RecordKey.Base64UrlDecode(), recordKey);
                            entityKeys[rkl.RecordUid] = rk;
                        }
                        catch (Exception e)
                        {
                            Trace.TraceError($"Record UID \"{rkl.RecordUid}\": Key decryption error: {e.Message}.");
                        }
                    }
                }

                uids.Clear();
                foreach (var r in recordsToLoad.Values)
                {
                    if (entityKeys.TryGetValue(r.RecordUid, out var rKey))
                    {
                        try
                        {
                            KeeperRecord record = r.Load(rKey);
                            if (record != null)
                            {
                                record.Owner = recordOwnership.Contains(r.RecordUid);
                                record.Revision = r.Revision;
                                keeperRecords.TryAdd(r.RecordUid, record);
                            }
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
            if (fullRebuild)
            {
                LoadRecordTypes();
            }
        

            foreach (var u in Storage.UserEmails.GetAll())
            {
                _keeperUserAccounts[u.AccountUid] = u.Email;
            }
        }

        internal void BuildFolders()
        {
            var uids = new HashSet<string>();
            var folderMap = new Dictionary<string, IFolder>();
            foreach (var folder in Storage.Folders.GetAll())
            {
                if (folder.FolderType != VaultTypeExtensions.GetFolderTypeText(FolderType.UserFolder)) 
                {
                    if (!keeperSharedFolders.ContainsKey(folder.SharedFolderUid))
                    {
                        uids.Add(folder.FolderUid);
                        continue;
                    }
                }
                folderMap[folder.FolderUid] = folder;
            }
            if (uids.Count > 0)
            {
                Storage.FolderRecords.DeleteLinksForObjects(uids);
                Storage.Folders.DeleteUids(uids);
            }
            uids.Clear();

            var folderUids = folderMap.Keys.ToArray();
            foreach (var folderUid in folderUids)
            {
                var folder = folderMap[folderUid];
                while (!string.IsNullOrEmpty(folder.ParentUid))
                {
                    if (uids.Contains(folder.ParentUid))
                    {
                        uids.Add(folder.Uid);
                        break;
                    }
                    if (folderMap.ContainsKey(folder.ParentUid))
                    {
                        folder = folderMap[folder.ParentUid];
                    }
                    else
                    {
                        uids.Add(folder.Uid);
                        break;
                    }
                }
            }
            if (uids.Count > 0)
            {
                Storage.FolderRecords.DeleteLinksForObjects(uids);
                Storage.Folders.DeleteUids(uids);
                foreach (var uid in uids)
                {
                    folderMap.Remove(uid);
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
                    if (folder.FolderType == "user_folder")
                    {
                        node.FolderType = FolderType.UserFolder;
                        node.FolderKey = CryptoUtils.DecryptAesV1(folder.FolderKey.Base64UrlDecode(), ClientKey);
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

                                node.FolderKey = CryptoUtils.DecryptAesV1(folder.FolderKey.Base64UrlDecode(),
                                    sf.SharedFolderKey);
                            }
                            else
                            {
                                node.Name = sf.Name;
                                node.FolderKey = sf.SharedFolderKey;
                            }
                        }
                        else
                        {
                            Trace.TraceError(
                                $"Missing Shared Folder UID {folder.SharedFolderUid} for Folder UID {folder.FolderUid}");
                        }
                    }

                    if (!string.IsNullOrEmpty(folder.Data) && node.FolderKey != null)
                    {
                        var data = CryptoUtils.DecryptAesV1(folder.Data.Base64UrlDecode(), node.FolderKey);
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