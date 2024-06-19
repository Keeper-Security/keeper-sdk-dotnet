using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using Folder;
using KeeperSecurity.Commands;
using Records;
using Org.BouncyCastle.Crypto.Digests;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Specifies log message severity
    /// </summary>
    public enum Severity
    {
        /// <summary>
        /// Fatal error
        /// </summary>
        Error,

        /// <summary>
        /// Warning
        /// </summary>
        Warning,

        /// <summary>
        /// Information
        /// </summary>
        Information,
    }

    /// <summary>
    /// Represents record existing match strategy
    /// </summary>
    public enum RecordMatch
    {
        /// <summary>
        /// Do not match existing records when added.
        /// </summary>
        None,

        /// <summary>
        /// Match only main fields. Skip notes and custom fields
        /// </summary>
        MainFields,

        /// <summary>
        /// Match all record fields.
        /// </summary>
        AllFields,
    }

    /// <summary>
    /// Represents Batch Vault Updater Summary
    /// </summary>
    public class BatchResult
    {
        /// <summary>
        /// Gets number of added shared folders
        /// </summary>
        public int SharedFolderCount { get; internal set; }

        /// <summary>
        /// Gets number of added folders
        /// </summary>
        public int FolderCount { get; internal set; }

        /// <summary>
        /// Gets number of added legacy records
        /// </summary>
        public int LegacyRecordCount { get; internal set; }

        /// <summary>
        /// Get number of added typed records
        /// </summary>
        public int TypedRecordCount { get; internal set; }

        /// <summary>
        /// Get number of updated records
        /// </summary>
        public int UpdatedRecordCount { get; internal set; }

        /// <summary>
        /// Get number of updated folders
        /// </summary>
        public int UpdatedFolderCount { get; internal set; }

        public IDictionary<string, string> FolderFailure { get; } = new Dictionary<string, string>();
        public IDictionary<string, string> RecordFailure { get; } = new Dictionary<string, string>();
    }

    /// <summary>
    /// Declares Batch Vault Updater methods
    /// </summary>
    public interface IBatchVaultOperations
    {
        /// <summary>
        /// Gets the root folder
        /// </summary>
        FolderNode RootFolder { get; }

        /// <summary>
        /// Gets folder node by folder UID
        /// </summary>
        /// <param name="folderUid">folder UID</param>
        /// <param name="folder">folder node</param>
        /// <seealso cref="FolderNode"/>
        /// <returns>true if folder is found</returns>
        bool TryGetFolderByUid(string folderUid, out FolderNode folder);

        /// <summary>
        /// Gets record by record UID. Returns both pending and active records.
        /// </summary>
        /// <param name="recordUid">record UID</param>
        /// <param name="record">Keeper record</param>
        /// <returns></returns>
        bool TryGetRecordByUid(string recordUid, out KeeperRecord record);

        /// <summary>
        /// Finds folder node by folder path
        /// </summary>
        /// <param name="folderPath">Folder Path</param>
        /// <seealso cref="FolderNode"/>
        /// <returns>folder node</returns>
        FolderNode GetFolderByPath(string folderPath);

        /// <summary>
        /// Appends folder to folder structure
        /// </summary>
        /// <param name="folderName">folder name</param>
        /// <param name="parentUid">parent folder</param>
        /// <param name="sharedFolderOptions">shared folder options</param>
        /// <returns>folder node to be added</returns>
        FolderNode AddFolder(string folderName, string parentUid = null,
            SharedFolderOptions sharedFolderOptions = null);

        /// <summary>
        /// Checks if the folder has to be created
        /// </summary>
        /// <param name="folderUid"></param>
        /// <returns>true if folder is scheduled to be added</returns>
        bool IsFolderPending(string folderUid);

        /// <summary>
        /// Checks if the record has to be created
        /// </summary>
        /// <param name="recordUid"></param>
        /// <returns>true if record is scheduled to be added</returns>
        bool IsRecordPending(string recordUid);

        /// <summary>
        /// Updates folder name
        /// </summary>
        /// <param name="folderUid">folder UID</param>
        /// <param name="folderName">new folder name</param>
        /// <returns>true if folder is scheduled to be added</returns>
        bool UpdateFolderName(string folderUid, string folderName);

        /// <summary>
        /// Update a record
        /// </summary>
        /// <param name="record">Keeper record</param>
        /// <returns>true is record is scheduled to be updated</returns>
        bool UpdateRecord(KeeperRecord record);

        /// <summary>
        /// Appends record
        /// </summary>
        /// <param name="record">record</param>
        /// <param name="folder">folder</param>
        /// <returns>true is record is scheduled to be added</returns>
        bool AddRecord(KeeperRecord record, FolderNode folder);

        /*
        /// <summary>
        /// Adds user or team to a shared folder
        /// </summary>
        /// <param name="folder">shared folder</param>
        /// <param name="accountType">account type: User or Team</param>
        /// <param name="accountId">Email or Team UID</param>
        /// <param name="canEdit">Can Edit permission</param>
        /// <param name="canShare">Can Share permission</param>
        /// <returns></returns>
        bool AddAccountToFolder(string folderUid, UserType accountType, string accountId, bool? manageUsers = null, bool? manageRecords = null);
        */
        /// <summary>
        /// Applies pending changes
        /// </summary>
        /// <returns>Change status</returns>
        Task<BatchResult> ApplyChanges();

        /// <summary>
        /// Resets pending changes
        /// </summary>
        void Reset();

        /// <summary>
        /// Gets record matching strategy
        /// </summary>
        RecordMatch RecordMatch { get; }
    }

    /// <summary>
    /// Represents Batch Vault Updater
    /// </summary>
    public class BatchVaultOperations : IBatchVaultOperations
    {
        private readonly VaultOnline _vault;

        private readonly FolderNode _rootFolder = new FolderNode
        {
            FolderType = FolderType.UserFolder,
        };

        private readonly List<Tuple<FolderNode, SharedFolderOptions>> _foldersToAdd =
            new List<Tuple<FolderNode, SharedFolderOptions>>();

        private readonly List<Tuple<PasswordRecord, FolderNode>> _legacyRecordsToAdd =
            new List<Tuple<PasswordRecord, FolderNode>>();

        private readonly List<Tuple<TypedRecord, FolderNode>> _typedRecordsToAdd =
            new List<Tuple<TypedRecord, FolderNode>>();

        private readonly List<KeeperRecord> _recordsToUpdate = new List<KeeperRecord>();

        private readonly Dictionary<string, FolderNode> _folderInfoLookup = new Dictionary<string, FolderNode>();
        private readonly Dictionary<string, string> _folderPathLookup = new Dictionary<string, string>();
        private readonly HashSet<string> _recordSet = new HashSet<string>();
        private readonly Dictionary<string, string> _recordFullHashes = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _recordMainHashes = new Dictionary<string, string>();

        private readonly Dictionary<string, string> _folderNameUpdates = new Dictionary<string, string>();

        /// <summary>
        /// Instantiate <see cref="BatchVaultOperations"/>.
        /// </summary>
        /// <param name="vault">Vault instance</param>
        /// <param name="recordMatch">Record matching strategy</param>
        public BatchVaultOperations(VaultOnline vault, RecordMatch recordMatch = RecordMatch.AllFields)
        {
            _vault = vault;
            RecordMatch = recordMatch;
            Reset();
        }

        /// <inheritdoc/>
        public void Reset()
        {
            _rootFolder.Subfolders.Clear();
            _rootFolder.Records.Clear();

            _foldersToAdd.Clear();
            _legacyRecordsToAdd.Clear();
            _typedRecordsToAdd.Clear();
            _recordsToUpdate.Clear();
            _folderInfoLookup.Clear();
            _folderPathLookup.Clear();
            _recordSet.Clear();
            _folderNameUpdates.Clear();
            _recordFullHashes.Clear();
            _recordMainHashes.Clear();

            // Load folders
            var folders = _vault.Folders.ToArray();
            foreach (var folder in folders)
            {
                var f = new FolderNode
                {
                    FolderUid = folder.FolderUid,
                    Name = folder.Name,
                    ParentUid = folder.ParentUid,
                    FolderType = folder.FolderType,
                    SharedFolderUid = folder.SharedFolderUid,
                    FolderKey = folder.FolderKey,
                };
                _folderInfoLookup[folder.FolderUid] = f;
            }

            foreach (var folder in folders)
            {
                var path = GetFolderPath(folder.FolderUid).ToLower();
                if (!_folderPathLookup.ContainsKey(path))
                {
                    _folderPathLookup.Add(path, folder.FolderUid);
                }

                FolderNode parentFolder;
                if (string.IsNullOrEmpty(folder.ParentUid))
                {
                    parentFolder = _rootFolder;
                }
                else
                {
                    _folderInfoLookup.TryGetValue(folder.ParentUid, out parentFolder);
                }

                parentFolder?.Subfolders.Add(folder.FolderUid);
            }

            // Load records
            if (RecordMatch != RecordMatch.None)
            {
                var hash = new Sha256Digest();
                foreach (var record in _vault.KeeperRecords)
                {
                    if (record is PasswordRecord || record is TypedRecord)
                    {
                        hash.Reset();
                        foreach (var token in TokenizeKeeperRecord(record, RecordMatch.AllFields))
                        {
                            var buffer = Encoding.UTF8.GetBytes(token);
                            hash.BlockUpdate(buffer, 0, buffer.Length);
                        }

                        var hashValue = new byte[hash.GetDigestSize()];
                        hash.DoFinal(hashValue, 0);
                        _recordFullHashes[hashValue.Base64UrlEncode()] = record.Uid;

                        if (RecordMatch == RecordMatch.MainFields)
                        {
                            hash.Reset();
                            foreach (var token in TokenizeKeeperRecord(record, RecordMatch))
                            {
                                var buffer = Encoding.UTF8.GetBytes(token);
                                hash.BlockUpdate(buffer, 0, buffer.Length);
                            }

                            var hashMatchValue = new byte[hash.GetDigestSize()];
                            hash.DoFinal(hashMatchValue, 0);
                            _recordMainHashes[hashMatchValue.Base64UrlEncode()] = record.Uid;
                        }
                    }
                }

                var loadedRecords = new HashSet<string>(_recordFullHashes.Values);
                foreach (var folder in _vault.Folders)
                {
                    if (_folderInfoLookup.TryGetValue(folder.FolderUid, out var f))
                    {
                        if (folder.Records != null)
                        {
                            foreach (var recordUid in folder.Records)
                            {
                                if (loadedRecords.Contains(recordUid))
                                {
                                    f.Records.Add(recordUid);
                                }
                            }
                        }
                    }
                }
            }
        }

        private static IEnumerable<string> TokenizeKeeperRecord(KeeperRecord record, RecordMatch match)
        {
            var fields = new List<string>
            {
                $"$title:{record.Title}"
            };
            if (record is PasswordRecord password)
            {
                if (!string.IsNullOrEmpty(password.Login))
                {
                    fields.Add($"$login:{password.Login}");
                }

                if (!string.IsNullOrEmpty(password.Password))
                {
                    fields.Add($"$password:{password.Password}");
                }

                if (!string.IsNullOrEmpty(password.Link))
                {
                    fields.Add($"$url:{password.Link}");
                }

                if (match == RecordMatch.AllFields)
                {
                    if (!string.IsNullOrEmpty(password.Notes))
                    {
                        fields.Add($"$notes:{password.Notes}");
                    }

                    var cfs = new List<CustomField>(password.Custom);
                    cfs.Sort((x, y) =>
                    {
                        if (x == null || y == null)
                        {
                            if (x == null && y == null)
                            {
                                return 0;
                            }

                            return x == null ? 1 : -1;
                        }

                        return string.CompareOrdinal(x.Name, y.Name);
                    });
                    fields.AddRange(cfs.Select(x => $"{x.Name ?? string.Empty}:{x.Value ?? string.Empty}"));
                }
            }
            else if (record is TypedRecord typed)
            {
                fields.Add($"$type:{typed.TypeName}");

                foreach (var field in typed.Fields)
                {
                    var token = GetRecordFieldToken(field);
                    if (!string.IsNullOrEmpty(token))
                    {
                        fields.Add(token);
                    }
                }

                if (match == RecordMatch.AllFields)
                {
                    if (!string.IsNullOrEmpty(typed.Notes))
                    {
                        fields.Add($"$notes:{typed.Notes}");
                    }

                    foreach (var field in typed.Custom)
                    {
                        var token = GetRecordFieldToken(field);
                        if (!string.IsNullOrEmpty(token))
                        {
                            fields.Add(token);
                        }
                    }
                }
            }

            fields.Sort(StringComparer.InvariantCulture);
            foreach (var token in fields)
            {
                yield return token;
            }
        }
        internal static string GetRecordFieldToken(ITypedField field)
        {
            var value = field.GetExternalValue();
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            string key = "$" + field.FieldName;
            if (!string.IsNullOrEmpty(field.FieldLabel))
            {
                key += "." + field.FieldLabel;
            }

            return key + ":" + value;
        }

        /// <exclude />
        public const char PathDelimiter = '\\';

        private const string EscapedPathDelimiter = "\\\\";

        private string GetFolderPath(string folderUid)
        {
            if (!_folderInfoLookup.TryGetValue(folderUid, out var folder))
            {
                return null;
            }

            var path = new List<string>();

            while (folder != null)
            {
                path.Add(folder.Name);
                if (string.IsNullOrEmpty(folder.ParentUid))
                {
                    break;
                }
                else if (!_folderInfoLookup.TryGetValue(folder.ParentUid, out folder))
                {
                    break;
                }
            }

            path.Reverse();
            return CreateFolderPath(path);
        }

        /// <inheritdoc />
        public FolderNode RootFolder => _rootFolder;

        /// <inheritdoc />
        public FolderNode GetFolderByPath(string folderPath)
        {
            if (_folderPathLookup.TryGetValue(folderPath.ToLower(), out var folderUid))
            {
                if (_folderInfoLookup.TryGetValue(folderUid, out var f))
                {
                    return f;
                }
            }

            return null;
        }

        /// <inheritdoc />
        public bool TryGetFolderByUid(string folderUid, out FolderNode folder)
        {
            return _folderInfoLookup.TryGetValue(folderUid, out folder);
        }


        /// <summary>
        /// Composes folder path
        /// </summary>
        /// <param name="folderNames">folder name list</param>
        /// <returns>folder path</returns>
        public static string CreateFolderPath(IEnumerable<string> folderNames)
        {
            var folderPath = "";
            foreach (var folderName in folderNames)
            {
                if (folderPath.Length > 0)
                {
                    folderPath += PathDelimiter;
                }

                folderPath += folderName.Replace(PathDelimiter.ToString(), EscapedPathDelimiter);
            }

            return folderPath;
        }

        /// <summary>
        /// Parses folder path to names
        /// </summary>
        /// <param name="folderPath">folder path</param>
        /// <returns>folder name list</returns>
        public static IEnumerable<string> ParseFolderPath(string folderPath)
        {
            var startPos = 0;
            var searchPos = 0;
            while (startPos < folderPath.Length)
            {
                var found = folderPath.IndexOf(PathDelimiter, searchPos);
                if (found >= 0)
                {
                    if (found < folderPath.Length - 1 && folderPath[found + 1] == PathDelimiter)
                    {
                        searchPos = found + 2;
                    }
                    else
                    {
                        if (found > startPos)
                        {
                            var folderName = folderPath.Substring(startPos, found - startPos);
                            folderName = folderName.Replace(EscapedPathDelimiter, PathDelimiter.ToString());
                            yield return folderName;
                        }

                        searchPos = found + 1;
                        startPos = searchPos;
                    }
                }
                else
                {
                    break;
                }
            }

            if (startPos < folderPath.Length)
            {
                var folderName = folderPath.Substring(startPos);
                folderName = folderName.Replace(EscapedPathDelimiter, PathDelimiter.ToString());
                yield return folderName;
            }
        }

        /// <inheritdoc/>
        public FolderNode AddFolder(string folderName, string parentUid = null,
            SharedFolderOptions sharedFolderOptions = null)
        {
            var f = new FolderNode
            {
                FolderUid = CryptoUtils.GenerateUid(),
                Name = folderName,
                ParentUid = parentUid,
                FolderKey = CryptoUtils.GenerateEncryptionKey()
            };
            FolderNode parentFolder;
            if (!string.IsNullOrEmpty(parentUid))
            {
                if (_folderInfoLookup.TryGetValue(parentUid, out parentFolder))
                {
                    if (sharedFolderOptions != null && parentFolder.FolderType != FolderType.UserFolder)
                    {
                        BatchLogger?.Invoke(Severity.Warning,
                            $"Add Folder {folderName}: Folder cannot be added as a shared folder.");
                        sharedFolderOptions = null;
                    }
                }
                else
                {
                    BatchLogger?.Invoke(Severity.Error,
                        $"Add Folder {folderName}: Parent folder UID \"{parentUid}\" not found");
                    return null;
                }
            }
            else
            {
                parentFolder = _rootFolder;
            }

            if (!string.IsNullOrEmpty(parentFolder.FolderUid))
            {
                f.ParentUid = parentFolder.FolderUid;
            }

            if (sharedFolderOptions != null && parentFolder.FolderType == FolderType.UserFolder)
            {
                f.FolderType = FolderType.SharedFolder;
                f.SharedFolderUid = f.FolderUid;
            }
            else if (parentFolder.FolderType == FolderType.UserFolder)
            {
                f.FolderType = FolderType.UserFolder;
            }
            else
            {
                f.FolderType = FolderType.SharedFolderFolder;
                f.SharedFolderUid = parentFolder.SharedFolderUid;
            }

            parentFolder.Subfolders.Add(f.FolderUid);
            _foldersToAdd.Add(Tuple.Create(f, sharedFolderOptions));
            _folderInfoLookup[f.FolderUid] = f;
            var path = GetFolderPath(f.FolderUid).ToLower();
            if (!string.IsNullOrEmpty(path) && !_folderPathLookup.ContainsKey(path))
            {
                _folderPathLookup.Add(path, f.FolderUid);
            }

            return f;
        }

        /// <inheritdoc/>
        public bool UpdateFolderName(string folderUid, string folderName)
        {
            if (TryGetFolderByUid(folderUid, out var folder))
            {
                if (string.Equals(folder.Name, folderName))
                {
                    return true;
                }

                var added = _foldersToAdd.FirstOrDefault(x => x.Item1.FolderUid == folderUid);
                if (added != null)
                {
                    added.Item1.Name = folderName;
                }
                else
                {
                    _folderNameUpdates[folderUid] = folderName;
                }

                return true;
            }

            return false;
        }

        /// <inheritdoc/>
        public bool TryGetRecordByUid(string recordUid, out KeeperRecord record)
        {
            record = null;
            if (_recordSet.Contains(recordUid))
            {
                record = _legacyRecordsToAdd.Select(x => x.Item1).FirstOrDefault(x => x.Uid == recordUid);
                if (record == null)
                {
                    record = _typedRecordsToAdd.Select(x => x.Item1).FirstOrDefault(x => x.Uid == recordUid);
                }
            }
            else
            {
                record = _recordsToUpdate.FirstOrDefault(x => x.Uid == recordUid);
                if (record == null)
                {
                    _vault.TryGetKeeperRecord(recordUid, out record);
                }
            }
            return record != null;
        }

        /// <inheritdoc/>
        public bool UpdateRecord(KeeperRecord record)
        {
            if (_vault.TryGetKeeperRecord(record.Uid, out var r))
            {
                if (ReferenceEquals(record, r))
                {
                    BatchLogger?.Invoke(Severity.Information,
                        $"Update Record \"{record.Title}\": Same instance. Skipped.");
                    return false;
                }

                if (!ReferenceEquals(record.GetType(), r.GetType()))
                {
                    BatchLogger?.Invoke(Severity.Warning,
                        $"Update Record \"{record.Title}\": Record types do not match. Skipped.");
                    return false;
                }

                _recordsToUpdate.Add(record);
            }
            else
            {
                BatchLogger?.Invoke(Severity.Warning,
                    $"Update Record \"{record.Title}\": Cannot find existing record. Skipped.");
                return false;
            }

            // TODO check added records UID
            return true;
        }

        /// <inheritdoc/>
        public bool AddRecord(KeeperRecord record, FolderNode folder)
        {
            var recordHasher = new Sha256Digest();
            foreach (var token in TokenizeKeeperRecord(record, RecordMatch.AllFields))
            {
                var buffer = Encoding.UTF8.GetBytes(token);
                recordHasher.BlockUpdate(buffer, 0, buffer.Length);
            }

            var hashValue = new byte[recordHasher.GetDigestSize()];
            recordHasher.DoFinal(hashValue, 0);
            var recordHashStr = hashValue.Base64UrlEncode();

            if (_recordFullHashes.TryGetValue(recordHashStr, out var recordUid))
            {
                record.Uid = recordUid;
                BatchLogger?.Invoke(Severity.Warning,
                    $"Add Record \"{record.Title}\": A full record match already exists. Skipped.");
                return false;
            }

            if (!string.IsNullOrEmpty(record.Uid))
            {
                if (_vault.TryGetKeeperRecord(record.Uid, out var r))
                {
                    BatchLogger?.Invoke(Severity.Information,
                        $"Add Record \"{record.Title}\": Record UID \"{record.Uid}\" exists: Updated.");
                    record.RecordKey = r.RecordKey;
                    return UpdateRecord(record);
                }

                if (_recordSet.Contains(record.Uid))
                {
                    BatchLogger?.Invoke(Severity.Warning,
                        $"Add Record \"{record.Title}\": Record UID \"{record.Uid}\" already added. Skipped.");
                    return false;
                }
            }

            string mainHashStr = null;
            if (RecordMatch != RecordMatch.MainFields)
            {
                recordHasher.Reset();
                foreach (var token in TokenizeKeeperRecord(record, RecordMatch))
                {
                    var buffer = Encoding.UTF8.GetBytes(token);
                    recordHasher.BlockUpdate(buffer, 0, buffer.Length);
                }

                hashValue = new byte[recordHasher.GetDigestSize()];
                recordHasher.DoFinal(hashValue, 0);
                mainHashStr = hashValue.Base64UrlEncode();
                if (_recordMainHashes.TryGetValue(mainHashStr, out recordUid))
                {
                    if (_vault.TryGetKeeperRecord(recordUid, out var r))
                    {
                        record.Uid = r.Uid;
                        record.RecordKey = r.RecordKey;
                        BatchLogger?.Invoke(Severity.Information,
                            $"Add Record \"{record.Title}\": Matching record found: Updated.");
                        return UpdateRecord(record);
                    }
                }
            }

            if (folder != null)
            {
                if (_folderInfoLookup.TryGetValue(folder.FolderUid, out var f))
                {
                    folder = f;
                }
                else
                {
                    BatchLogger?.Invoke(Severity.Warning,
                        $"Add Record \"{record.Title}\": Folder \"{folder.Name}\" has not been created. Skipped.");
                    return false;
                }
            }

            if (string.IsNullOrEmpty(record.Uid))
            {
                record.Uid = CryptoUtils.GenerateUid();
            }

            record.RecordKey = CryptoUtils.GenerateEncryptionKey();
            if (record is PasswordRecord password)
            {
                _legacyRecordsToAdd.Add(Tuple.Create(password, folder));
            }
            else if (record is TypedRecord typed)
            {
                _typedRecordsToAdd.Add(Tuple.Create(typed, folder));
            }
            else
            {
                BatchLogger?.Invoke(Severity.Warning,
                    $"Add Record \"{record.Title}\": Record type is not supported. Skipped.");
                return false;
            }

            _recordSet.Add(record.Uid);
            _recordFullHashes[recordHashStr] = record.Uid;
            if (!string.IsNullOrEmpty(mainHashStr))
            {
                _recordMainHashes[mainHashStr] = record.Uid;
            }

            if (folder != null)
            {
                folder.Records.Add(record.Uid);
            }

            return true;
        }

        /// <inheritdoc/>
        public bool IsFolderPending(string folderUid)
        {
            return _foldersToAdd.Any(x => x.Item1.FolderUid == folderUid);
        }

        /// <inheritdoc/>
        public bool IsRecordPending(string recordUid)
        {
            return _recordSet.Contains(recordUid);
        }

        /// <inheritdoc/>
        public async Task<BatchResult> ApplyChanges()
        {
            var result = new BatchResult();
            var round = 0;
            while (_foldersToAdd.Count > 0 || _legacyRecordsToAdd.Count > 0)
            {
                if (round > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10));
                }

                round++;

                var left = 999;
                var rq = new ImportFolderRecordRequest();
                if (_foldersToAdd.Count > 0)
                {
                    Tuple<FolderNode, SharedFolderOptions>[] chunk;
                    if (_foldersToAdd.Count > left)
                    {
                        chunk = _foldersToAdd.Take(left).ToArray();
                        _foldersToAdd.RemoveRange(0, chunk.Length);
                    }
                    else
                    {
                        chunk = _foldersToAdd.ToArray();
                        _foldersToAdd.Clear();
                    }

                    left -= chunk.Length;
                    
                    foreach (var f in chunk)
                    {
                        var folder = f.Item1;
                        var sharedFolderOptions = f.Item2;
                        var frq = new FolderRequest
                        {
                            FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                        };
                        if (!string.IsNullOrEmpty(folder.ParentUid))
                        {
                            var parentFolder = folder.ParentUid;
                            if (folder.FolderType == FolderType.SharedFolderFolder &&
                                string.Equals(parentFolder, folder.SharedFolderUid))
                            {
                                parentFolder = null;
                            }

                            if (!string.IsNullOrEmpty(parentFolder))
                            {
                                frq.ParentFolderUid = ByteString.CopyFrom(parentFolder.Base64UrlDecode());
                            }
                        }

                        var fd = new FolderData
                        {
                            name = folder.Name,
                        };
                        var data = JsonUtils.DumpJson(fd);
                        frq.FolderData = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(data, folder.FolderKey));

                        switch (folder.FolderType)
                        {
                            case FolderType.UserFolder:
                            {
                                frq.FolderType = Folder.FolderType.UserFolder;
                                frq.EncryptedFolderKey = ByteString.CopyFrom(
                                    CryptoUtils.EncryptAesV1(folder.FolderKey, _vault.Auth.AuthContext.DataKey));
                            }
                                break;
                            case FolderType.SharedFolder:
                            {
                                frq.FolderType = Folder.FolderType.SharedFolder;
                                frq.EncryptedFolderKey = ByteString.CopyFrom(
                                    CryptoUtils.EncryptAesV1(folder.FolderKey, _vault.Auth.AuthContext.DataKey));
                                var encName = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(folder.Name),
                                    folder.FolderKey);
                                frq.SharedFolderFields = new SharedFolderFields
                                {
                                    EncryptedFolderName = ByteString.CopyFrom(encName),
                                    ManageUsers = (sharedFolderOptions?.ManageUsers ?? false),
                                    ManageRecords = (sharedFolderOptions?.ManageRecords ?? false),
                                    CanEdit = (sharedFolderOptions?.CanEdit ?? false),
                                    CanShare = (sharedFolderOptions?.CanShare ?? false),
                                };

                            }
                                break;
                            case FolderType.SharedFolderFolder:
                            {
                                if (!_folderInfoLookup.TryGetValue(folder.SharedFolderUid, out var sharedFolder))
                                {
                                    var message =
                                        $"Prepare Shared Folder Folder {folder.FolderUid}: Parent Shared Folder UID {folder.SharedFolderUid} not found";
                                    BatchLogger?.Invoke(Severity.Warning, message);
                                    result.FolderFailure[folder.FolderUid] = message;
                                    continue;
                                }

                                frq.FolderType = Folder.FolderType.SharedFolderFolder;
                                frq.EncryptedFolderKey =
                                    ByteString.CopyFrom(CryptoUtils.EncryptAesV1(folder.FolderKey,
                                        sharedFolder.FolderKey));
                                frq.SharedFolderFolderFields = new SharedFolderFolderFields
                                {
                                    SharedFolderUid = ByteString.CopyFrom(folder.SharedFolderUid.Base64UrlDecode()),
                                };
                            }
                                break;
                        }

                        rq.FolderRequest.Add(frq);
                    }
                }

                if (_legacyRecordsToAdd.Count > 0 && left > 10)
                {
                    Tuple<PasswordRecord, FolderNode>[] chunk;
                    if (_legacyRecordsToAdd.Count > left)
                    {
                        chunk = _legacyRecordsToAdd.Take(left).ToArray();
                        _legacyRecordsToAdd.RemoveRange(0, chunk.Length);
                    }
                    else
                    {
                        chunk = _legacyRecordsToAdd.ToArray();
                        _legacyRecordsToAdd.Clear();
                    }

                    foreach (var r in chunk)
                    {
                        var record = r.Item1;
                        var folder = r.Item2;
                        var rrq = new RecordRequest
                        {
                            RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
                            EncryptedRecordKey =
                                ByteString.CopyFrom(CryptoUtils.EncryptAesV1(record.RecordKey,
                                    _vault.Auth.AuthContext.DataKey)),
                        };
                        if (folder != null)
                        {
                            FolderNode sharedFolder = null;
                            switch (folder.FolderType)
                            {
                                case FolderType.UserFolder:
                                    rrq.FolderType = Folder.FolderType.UserFolder;
                                    break;
                                case FolderType.SharedFolder:
                                {
                                    rrq.FolderType = Folder.FolderType.SharedFolder;
                                    sharedFolder = folder;
                                }
                                    break;
                                case FolderType.SharedFolderFolder:
                                {
                                    rrq.FolderType = Folder.FolderType.SharedFolderFolder;
                                    if (!_folderInfoLookup.TryGetValue(folder.SharedFolderUid, out sharedFolder))
                                    {
                                        var message =
                                            $"Prepare Shared Folder Folder {folder.FolderUid}: Parent Shared Folder UID {folder.SharedFolderUid} not found";
                                        BatchLogger?.Invoke(Severity.Warning, message);
                                        result.FolderFailure[folder.FolderUid] = message;
                                        continue;
                                    }
                                }
                                    break;
                            }

                            rrq.FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode());

                            if (sharedFolder != null)
                            {
                                rrq.EncryptedRecordFolderKey =
                                    ByteString.CopyFrom(CryptoUtils.EncryptAesV1(record.RecordKey,
                                        sharedFolder.FolderKey));
                            }
                        }
                        else
                        {
                            rrq.FolderType = Folder.FolderType.UserFolder;
                        }

                        var rd = record.ExtractRecordData();
                        var data = JsonUtils.DumpJson(rd);
                        data = CryptoUtils.EncryptAesV1(data, record.RecordKey);
                        rrq.RecordData = ByteString.CopyFrom(data);

                        rq.RecordRequest.Add(rrq);
                    }
                }

                BatchLogger?.Invoke(Severity.Information, "Create Folders and Legacy Records");
                var rs = await _vault.Auth.ExecuteAuthRest<ImportFolderRecordRequest, ImportFolderRecordResponse>(
                    "folder/import_folders_and_records", rq);
                foreach (var frs in rs.FolderResponse)
                {
                    if (frs.Status.ToLower() == "success")
                    {
                        var folderUid = frs.FolderUid.ToArray().Base64UrlEncode();
                        if (_folderInfoLookup.TryGetValue(folderUid, out var f))
                        {
                            if (f.FolderType == FolderType.SharedFolder)
                            {
                                result.SharedFolderCount++;
                            }
                            else
                            {
                                result.FolderCount++;
                            }
                        }
                        else
                        {
                            result.FolderCount++;
                        }
                    }
                    else
                    {
                        var folderUid = frs.FolderUid.ToByteArray().Base64UrlEncode();
                        var message = $"Add folder \"{folderUid}\" error: {frs.Status}";
                        BatchLogger?.Invoke(Severity.Warning, message);
                        result.FolderFailure[folderUid] = message;
                    }
                }

                foreach (var rrs in rs.RecordResponse)
                {
                    if (rrs.Status.ToLower() == "success")
                    {
                        result.LegacyRecordCount++;
                    }
                    else
                    {
                        var recordUid = rrs.RecordUid.ToByteArray().Base64UrlEncode();
                        var message = $"Add legacy record \"{recordUid}\" error: {rrs.Status}";
                        BatchLogger?.Invoke(Severity.Warning, message);
                        result.RecordFailure[recordUid] = message;
                    }
                }
            }


            BatchLogger?.Invoke(Severity.Information, "Create Typed Records");
            while (_typedRecordsToAdd.Count > 0)
            {
                var left = 999;

                Tuple<TypedRecord, FolderNode>[] chunk;
                if (_typedRecordsToAdd.Count > left)
                {
                    chunk = _typedRecordsToAdd.Take(left).ToArray();
                    _typedRecordsToAdd.RemoveRange(0, chunk.Length);
                }
                else
                {
                    chunk = _typedRecordsToAdd.ToArray();
                    _typedRecordsToAdd.Clear();
                }

                var rq = new RecordsAddRequest
                {
                    ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                };
                foreach (var pair in chunk)
                {
                    var typed = pair.Item1;
                    var folder = pair.Item2;

                    var ra = new RecordAdd
                    {
                        RecordUid = ByteString.CopyFrom(typed.Uid.Base64UrlDecode()),
                        ClientModifiedTime = rq.ClientTime,
                        RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(typed.RecordKey,
                            _vault.Auth.AuthContext.DataKey)),
                    };

                    if (folder != null)
                    {
                        FolderNode sharedFolder = null;
                        switch (folder.FolderType)
                        {
                            case FolderType.UserFolder:
                                ra.FolderType = RecordFolderType.UserFolder;
                                break;
                            case FolderType.SharedFolder:
                            {
                                ra.FolderType = RecordFolderType.SharedFolder;
                                sharedFolder = folder;
                            }
                                break;
                            case FolderType.SharedFolderFolder:
                            {
                                ra.FolderType = RecordFolderType.SharedFolderFolder;
                                if (!_folderInfoLookup.TryGetValue(folder.SharedFolderUid, out sharedFolder))
                                {
                                    var message =
                                        $"Prepare Shared Folder Folder {folder.FolderUid}: Parent Shared Folder UID {folder.SharedFolderUid} not found";
                                    BatchLogger?.Invoke(Severity.Warning, message);
                                    result.RecordFailure[typed.Uid] = message;
                                    continue;
                                }
                            }
                                break;
                        }

                        ra.FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode());

                        if (sharedFolder != null)
                        {
                            ra.FolderKey =
                                ByteString.CopyFrom(CryptoUtils.EncryptAesV2(typed.RecordKey, sharedFolder.FolderKey));
                        }
                    }
                    else
                    {
                        ra.FolderType = RecordFolderType.UserFolder;
                    }

                    _vault.AdjustTypedRecord(typed);
                    var recordData = typed.ExtractRecordV3Data();
                    var data = JsonUtils.DumpJson(recordData);
                    data = VaultExtensions.PadRecordData(data);
                    data = CryptoUtils.EncryptAesV2(data, typed.RecordKey);
                    ra.Data = ByteString.CopyFrom(data);
                    if (_vault.Auth.AuthContext.EnterprisePublicEcKey != null)
                    {
                        var auditData = typed.ExtractRecordAuditData();
                        data = JsonUtils.DumpJson(auditData);
                        ra.Audit = new RecordAudit
                        {
                            Version = 0,
                            Data = ByteString.CopyFrom(CryptoUtils.EncryptEc(data,
                                _vault.Auth.AuthContext.EnterprisePublicEcKey))
                        };
                    }

                    rq.Records.Add(ra);
                }

                var rs =
                    await _vault.Auth.ExecuteAuthRest<RecordsAddRequest, RecordsModifyResponse>("vault/records_add",
                        rq);
                foreach (var ar in rs.Records)
                {
                    if (ar.Status == RecordModifyResult.RsSuccess)
                    {
                        result.TypedRecordCount++;
                    }
                    else
                    {
                        var recordUid = ar.RecordUid.ToByteArray().Base64UrlEncode();
                        var message = $"Add typed record \"{recordUid}\" error: {ar.Message}";
                        BatchLogger?.Invoke(Severity.Warning, message);
                        result.RecordFailure[recordUid] = message;
                    }
                }

                if (_typedRecordsToAdd.Count > 100)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10));
                }
            }

            if (_recordsToUpdate.Count > 0)
            {
                // discard duplicates keeping the last update
                var toUpdate = new Dictionary<string, KeeperRecord>();
                foreach (var r in _recordsToUpdate)
                {
                    toUpdate[r.Uid] = r;
                }

                var statuses = await _vault.UpdateRecordBatch(toUpdate.Values);
                foreach (var status in statuses)
                {
                    if (status.Status != "success")
                    {
                        var recordUid = status.RecordUid;
                        if (toUpdate.TryGetValue(recordUid, out var r))
                        {
                            BatchLogger?.Invoke(Severity.Warning,
                                $"Update record \"{r.Title}\" error: {status.Message}");
                        }
                        else
                        {
                            BatchLogger?.Invoke(Severity.Warning,
                                $"Update record UID \"{recordUid}\" error: {status.Message}");
                        }

                        result.RecordFailure[recordUid] = $"Update record UID \"{recordUid}\" error: {status.Message}";
                    }
                    else
                    {
                        result.UpdatedRecordCount++;
                    }
                }
            }

            if (_folderNameUpdates.Count > 0)
            {
                var folderUpdateRequests = new List<KeeperApiCommand>();
                foreach (var folderUid in _folderNameUpdates.Keys)
                {
                    if (TryGetFolderByUid(folderUid, out var folder))
                    {
                        var request = new FolderUpdateCommand
                        {
                            FolderUid = folder.FolderUid,
                            FolderType = folder.FolderType.GetFolderTypeText(),
                            ParentUid = string.IsNullOrEmpty(folder.ParentUid) ? null : folder.ParentUid,
                            SharedFolderUid = string.IsNullOrEmpty(folder.SharedFolderUid)
                                ? null
                                : folder.SharedFolderUid,
                        };

                        var newName = _folderNameUpdates[folderUid];
                        FolderData data = null;
                        try
                        {
                            var existingFolder = _vault.Storage.Folders.GetEntity(folderUid);
                            if (folder.FolderKey != null && !string.IsNullOrEmpty(existingFolder?.Data))
                            {
                                data = JsonUtils.ParseJson<FolderData>(
                                    CryptoUtils.DecryptAesV1(existingFolder.Data.Base64UrlDecode(), folder.FolderKey));
                            }
                        }
                        catch
                        {
                            // ignored
                        }

                        if (data == null)
                        {
                            data = new FolderData();
                        }

                        data.name = newName;
                        var dataBytes = JsonUtils.DumpJson(data);
                        request.Data = CryptoUtils.EncryptAesV1(dataBytes, folder.FolderKey).Base64UrlEncode();
                        if (folder.FolderType != FolderType.UserFolder)
                        {
                            var sharedFolderUid = folder.FolderType == FolderType.UserFolder
                                ? folder.FolderUid
                                : folder.SharedFolderUid;
                            var perm = _vault.ResolveSharedFolderAccessPath(_vault.Auth.Username, sharedFolderUid,
                                false, true);
                            if (perm != null)
                            {
                                if (perm.UserType == UserType.Team)
                                {
                                    request.TeamUid = perm.UserId;
                                }
                            }
                        }

                        if (folder.FolderType == FolderType.SharedFolder)
                        {
                            request.Name = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(newName), folder.FolderKey)
                                .Base64UrlEncode();
                        }

                        folderUpdateRequests.Add(request);
                    }
                }

                if (folderUpdateRequests.Count > 0)
                {
                    var updateResults = await _vault.Auth.ExecuteBatch(folderUpdateRequests);
                    if (updateResults?.Count > 0)
                    {
                        for (int i = 0; i < updateResults.Count; i++)
                        {
                            var rs = updateResults[i];
                            var rq = folderUpdateRequests[i];
                            if (rs.IsSuccess)
                            {
                                result.UpdatedRecordCount++;
                            }
                            else
                            {
                                if (rq is FolderUpdateCommand fuc)
                                {
                                    var message = $"Rename folder \"{fuc.FolderUid}\" error: {rs.message}";
                                    BatchLogger?.Invoke(Severity.Warning, message);
                                    result.FolderFailure[fuc.FolderUid] = message;
                                }
                                else
                                {
                                    BatchLogger?.Invoke(Severity.Warning, rs.message);
                                }
                            }
                        }
                    }
                }
            }

            await _vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
            Reset();
            return result;
        }

       /// <inheritdoc/>
        public RecordMatch RecordMatch { get; }

        /// <summary>
        /// Gets or sets logger
        /// </summary>
        public Action<Severity, string> BatchLogger { get; set; }

        /// <summary>
        /// Gets number of folders to be added
        /// </summary>
        public int FoldersToAdd => _foldersToAdd.Count;

        /// <summary>
        /// Gets number of legacy records to be added
        /// </summary>
        public int LegacyRecordsToAdd => _legacyRecordsToAdd.Count;

        /// <summary>
        /// Gets number of typed records to be added
        /// </summary>
        public int TypedRecordsToAdd => _typedRecordsToAdd.Count;

        /// <summary>
        /// Gets number of typed records to be updated
        /// </summary>
        public int RecordsToUpdate => _recordsToUpdate.Count;

        /// <summary>
        /// Gets the number od folder to be renamed
        /// </summary>
        /// <returns></returns>
        public int FoldersToRename() => _folderNameUpdates.Count;
    }
}

