using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using BreachWatchProto = BreachWatch;
using KeeperSecurity.Commands;
using KeeperSecurity.Storage;
using KeeperSecurity.Utils;
using Tokens;

namespace KeeperSecurity.Vault
{
    internal class RebuildTask
    {
        internal RebuildTask(bool isFullSync)
        {
            IsFullSync = isFullSync;
        }

        public bool IsFullSync { get; }

        private void AddRecord(string recordUid)
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
        
        public void AddBreachWatchRecords(IEnumerable<string> recordUids)
        {
            foreach (var recordUid in recordUids)
            {
                AddRecord(recordUid);
            }
        }

        private void AddSharedFolder(string sharedFolderUid)
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
        public ISet<BreachWatchInfo> BreachWatchRecords { get; private set; }
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

            // Initialize BreachWatchService with required delegates
            _breachWatchService = new BreachWatchService(
                storage,
                (recordKey) => DecryptRecordKey(recordKey, out var key) ? key : null,
                (recordUid) => TryLoadKeeperRecord(recordUid, out var record) ? record : null);

            RootFolder = new FolderNode
            {
                FolderUid = "",
                Name = "My Vault",
                FolderType = FolderType.UserFolder
            };
            RebuildData(new RebuildTask(true));
        }

        /// <inheritdoc/>
        public int RecordCount => _keeperRecords.Count;

        /// <inheritdoc/>
        public IEnumerable<KeeperRecord> KeeperRecords => _keeperRecords.Values;

        /// <inheritdoc/>
        public bool TryGetKeeperRecord(string recordUid, out KeeperRecord record)
        {
            return _keeperRecords.TryGetValue(recordUid, out record);
        }

        /// <inheritdoc/>
        public bool TryLoadKeeperRecord(string recordUid, out KeeperRecord record)
        {
            if (!TryGetKeeperRecord(recordUid, out record)) return false;
            var storageRecord = Storage.Records.GetEntity(recordUid);
            if (storageRecord != null)
            {
                record = storageRecord.Load(record.RecordKey);
            }

            return record != null;
        }

        IEnumerable<PasswordRecord> IVaultData.Records => _keeperRecords.Values.OfType<PasswordRecord>();

        bool IVaultData.TryGetRecord(string recordUid, out PasswordRecord record)
        {
            if (_keeperRecords.TryGetValue(recordUid, out var r))
            {
                record = r as PasswordRecord;
                return record != null;
            }

            record = null;
            return false;
        }

        /// <inheritdoc/>
        public int SharedFolderCount => _keeperSharedFolders.Count;

        /// <inheritdoc/>
        public IEnumerable<SharedFolder> SharedFolders => _keeperSharedFolders.Values;

        /// <inheritdoc/>
        public bool TryGetSharedFolder(string sharedFolderUid, out SharedFolder sharedFolder)
        {
            return _keeperSharedFolders.TryGetValue(sharedFolderUid, out sharedFolder);
        }

        /// <inheritdoc/>
        public int TeamCount => _keeperTeams.Count;

        /// <inheritdoc/>
        public IEnumerable<Team> Teams => _keeperTeams.Values;

        /// <inheritdoc/>
        public bool TryGetTeam(string teamUid, out Team team)
        {
            return _keeperTeams.TryGetValue(teamUid, out team);
        }

        /// <inheritdoc/>
        public IEnumerable<FolderNode> Folders => _keeperFolders.Values;

        /// <inheritdoc/>
        public bool TryGetFolder(string folderUid, out FolderNode node)
        {
            return _keeperFolders.TryGetValue(folderUid, out node);
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
                    data = record.Version <= 2
                        ? CryptoUtils.DecryptAesV1(nsd.Data.Base64UrlDecode(), ClientKey)
                        : CryptoUtils.DecryptAesV2(nsd.Data.Base64UrlDecode(), ClientKey);
                }
                catch
                {
                    try
                    {
                        data = record.Version > 2
                            ? CryptoUtils.DecryptAesV1(nsd.Data.Base64UrlDecode(), ClientKey)
                            : CryptoUtils.DecryptAesV2(nsd.Data.Base64UrlDecode(), ClientKey);
                    }
                    catch
                    {
                        /* ignored */
                    }
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
            }
            else
            {
                Debug.WriteLine($"Record UID \"{recordUid}\" is not found");
            }

            return default;
        }

        /// <inheritdoc/>
        public FolderNode RootFolder { get; }

        protected readonly ConcurrentDictionary<string, KeeperRecord> _keeperRecords = new();
        private readonly ConcurrentDictionary<string, SharedFolder> _keeperSharedFolders = new();
        private readonly ConcurrentDictionary<string, Team> _keeperTeams = new();
        private readonly ConcurrentDictionary<string, FolderNode> _keeperFolders = new();
        private readonly BreachWatchService _breachWatchService;

        /// <inheritdoc/>
        public IKeeperStorage Storage { get; }

        /// <summary>
        /// Gets client key. AES encryption key that encrypts data in the local storage <see cref="Storage"/>
        /// </summary>
        public byte[] ClientKey { get; }

        private readonly ConcurrentDictionary<string, RecordType> _keeperRecordTypes =
            new ConcurrentDictionary<string, RecordType>(StringComparer.InvariantCultureIgnoreCase);

        private readonly ConcurrentBag<RecordType> _customRecordTypes =
            new ConcurrentBag<RecordType>();

        private readonly ConcurrentDictionary<string, string> _keeperUserAccounts =
            new ConcurrentDictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        /// <inheritdoc/>
        public IEnumerable<RecordType> RecordTypes => _keeperRecordTypes.Values.Concat(_customRecordTypes);

        ///<inheritdoc/>
        public IEnumerable<BreachWatchInfo> BreachWatchRecords()
        {
            return _breachWatchService.GetBreachWatchRecords();
        }

        /// <inheritdoc/>
        public bool TryGetRecordTypeByName(string name, out RecordType recordType)
        {
            if (_keeperRecordTypes.TryGetValue(name, out recordType))
            {
                return true;
            }

            foreach (var rt in _customRecordTypes)
            {
                if (!string.Equals(name, rt.Name, StringComparison.InvariantCultureIgnoreCase)) continue;
                recordType = rt;
                return true;
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
            foreach (var ae in _keeperUserAccounts)
            {
                if (!string.Equals(ae.Value, username, StringComparison.InvariantCultureIgnoreCase)) continue;
                accountUid = ae.Key;
                return true;
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
                    Id = field.RecordTypeId,
                    Scope = (RecordTypeScope)field.Scope,
                    Name = content.Name,
                    Description = content.Description,
                    Fields = content.Fields
                        .Select(x =>
                        {
                            if (RecordTypesConstants.TryGetRecordField(x.Ref, out var rf))
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

                            Debug.WriteLine($"Load Record Types: Cannot resolve field: {x.Ref}.");
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

        private bool DecryptSharedFolderKey(IStorageSharedFolderKey sfmd, out byte[] sharedFolderKey)
        {
            try
            {
                var sfKey = sfmd.SharedFolderKey.Base64UrlDecode();
                switch (sfmd.KeyType)
                {
                    case (int) KeyType.ClientKeyAesGcm:
                        sharedFolderKey = CryptoUtils.DecryptAesV2(sfKey, ClientKey);
                        return true;
                    case (int) KeyType.TeamKeyAesGcm:
                    {
                        if (_keeperTeams.TryGetValue(sfmd.TeamUid, out var team))
                        {
                            sharedFolderKey = CryptoUtils.DecryptAesV2(sfKey, team.TeamKey);
                            return true;

                        }

                        Trace.TraceError($"Shared Folder key: Team {sfmd.TeamUid} not found");
                    }

                        break;

                    default:
                        Trace.TraceError(
                            $"Unsupported key type {sfmd.KeyType} for shared folder {sfmd.SharedFolderUid}.");
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

        private bool DecryptRecordKey(IStorageRecordKey rmd, out byte[] recordKey)
        {
            try
            {
                var rKey = rmd.RecordKey.Base64UrlDecode();
                switch (rmd.RecordKeyType)
                {
                    case (int) KeyType.ClientKeyAesGcm:
                        recordKey = CryptoUtils.DecryptAesV2(rKey, ClientKey);
                        return true;

                    case (int) KeyType.SharedFolderKeyAesAny:
                        if (_keeperSharedFolders.TryGetValue(rmd.SharedFolderUid, out var sf))
                        {
                            recordKey = rKey.Length == 60
                                ? CryptoUtils.DecryptAesV2(rKey, sf.SharedFolderKey)
                                : CryptoUtils.DecryptAesV1(rKey, sf.SharedFolderKey);
                            return true;
                        }

                        Trace.TraceError(
                            $"Record UID \"{rmd.RecordUid}\": Shared Folder \"{rmd.SharedFolderUid}\" not found.");
                        break;

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
            _keeperTeams.Clear();
            foreach (var team in Storage.Teams.GetAll())
            {
                try
                {
                    var teamKey = CryptoUtils.DecryptAesV2(team.TeamKey.Base64UrlDecode(), ClientKey);
                    var t = team.Load(teamKey);
                    _keeperTeams.TryAdd(t.TeamUid, t);
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
                var sharedFoldersToLoad = new List<IStorageSharedFolder>();
                if (!fullRebuild && (changes.SharedFolders?.Count ?? 0) * 4 > _keeperSharedFolders.Count)
                {
                    fullRebuild = true;
                }

                if (fullRebuild)
                {
                    _keeperSharedFolders.Clear();
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
                            if (_keeperSharedFolders.TryRemove(sharedFolderUid, out var sharedFolder))
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
                    if (entityKeys.TryGetValue(sharedFolder.SharedFolderUid, value: out var sfKey))
                    {
                        var sf = sharedFolder.Load(Storage, sfKey);
                        _keeperSharedFolders.TryAdd(sharedFolder.SharedFolderUid, sf);
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
                var recordKeyLinks = new List<IStorageRecordKey>();
                var recordsToLoad = new Dictionary<string, IStorageRecord>();
                if (!fullRebuild && (changes.Records?.Count ?? 0) * 5 > _keeperRecords.Count)
                {
                    fullRebuild = true;
                }

                if (fullRebuild)
                {
                    _keeperRecords.Clear();
                    foreach (var record in Storage.Records.GetAll())
                    {
                        recordsToLoad[record.RecordUid] = record;
                    }

                    foreach (var rmd in Storage.RecordKeys.GetAllLinks())
                    {
                        if (rmd.Owner)
                        {
                            recordOwnership.Add(rmd.RecordUid);
                        }

                        if (entityKeys.ContainsKey(rmd.RecordUid)) continue;
                        if (!recordsToLoad.ContainsKey(rmd.RecordUid))
                        {
                            lostKeys.Add(rmd);
                        }
                        else if (rmd.RecordKeyType == (int) KeyType.RecordKeyAesGcm)
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

                            _keeperRecords.TryRemove(recordUid, out _);

                            foreach (var rmd in Storage.RecordKeys.GetLinksForSubject(r.RecordUid))
                            {
                                if (rmd.Owner)
                                {
                                    recordOwnership.Add(rmd.RecordUid);
                                }

                                if (rmd.RecordKeyType == (int) KeyType.RecordKeyAesGcm)
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
                        if (_keeperRecords.TryGetValue(rkl.SharedFolderUid, out var r))
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
                            var record = r.Load(rKey);
                            if (record != null)
                            {
                                record.Owner = recordOwnership.Contains(r.RecordUid);
                                record.Revision = r.Revision;
                                _keeperRecords.TryAdd(r.RecordUid, record);
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

            // Handle BreachWatch updates 
            if (fullRebuild)
            {
                _breachWatchService.RefreshBreachWatchData();
            }
            else if (changes?.Records != null)
            {
                _breachWatchService.UpdateBreachWatchRecords(changes.Records);
            }

            BuildFolders();
            if (fullRebuild)
            {
                LoadRecordTypes();
            }
            foreach (var u in Storage.UserEmails.GetAllLinks())
            {
                _keeperUserAccounts[u.AccountUid] = u.Email;
            }
        }

        private void BuildFolders()
        {
            var uids = new HashSet<string>();
            var folderMap = new Dictionary<string, IStorageFolder>();
            foreach (var folder in Storage.Folders.GetAll())
            {
                if (folder.FolderType != FolderType.UserFolder.GetFolderTypeText())
                {
                    if (!_keeperSharedFolders.ContainsKey(folder.SharedFolderUid))
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

                    if (folderMap.TryGetValue(folder.ParentUid, out var value))
                    {
                        folder = value;
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

            _keeperFolders.Clear();
            RootFolder.Records.Clear();
            RootFolder.Subfolders.Clear();
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
                        if (_keeperSharedFolders.TryGetValue(folder.SharedFolderUid, out var sf))
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
                        using var stream = new MemoryStream(data);
                        var folderData = serializer.ReadObject(stream) as FolderData;
                        node.Name = folderData?.name;
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

                _keeperFolders.TryAdd(node.FolderUid, node);
            }

            foreach (var folderUid in _keeperFolders.Keys)
            {
                if (_keeperFolders.TryGetValue(folderUid, out var node))
                {
                    FolderNode parent;

                    if (string.IsNullOrEmpty(node.ParentUid))
                    {
                        parent = RootFolder;
                    }
                    else
                    {
                        if (!_keeperFolders.TryGetValue(node.ParentUid, out parent))
                        {
                            parent = RootFolder;
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
                    node = RootFolder;
                }
                else
                {
                    if (!_keeperFolders.TryGetValue(link.FolderUid, out node))
                    {
                        node = RootFolder;
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