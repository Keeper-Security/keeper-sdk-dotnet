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

namespace KeeperSecurity
{
    namespace Vault
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
            /// Skippable error
            /// </summary>
            Warning,
            /// <summary>
            /// Infomation
            /// </summary>
            Information,
        }

        public enum RecordMatch
        {
            MainFields,
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
        }

        /// <summary>
        /// Represents Batch Vault Updater
        /// </summary>
        public class BatchVaultOperations
        {
            private readonly VaultOnline _vault;
            private readonly List<Tuple<FolderNode, SharedFolderOptions>> _foldersToAdd = new List<Tuple<FolderNode, SharedFolderOptions>>();
            private readonly List<Tuple<PasswordRecord, FolderNode>> _legacyRecordsToAdd = new List<Tuple<PasswordRecord, FolderNode>>();
            private readonly List<Tuple<TypedRecord, FolderNode>> _typedRecordsToAdd = new List<Tuple<TypedRecord, FolderNode>>();
            private readonly List<KeeperRecord> _recordsToUpdate = new List<KeeperRecord>();

            private readonly Dictionary<string, FolderNode> _folderInfoLookup = new Dictionary<string, FolderNode>();
            private readonly Dictionary<string, string> _folderPathLookup = new Dictionary<string, string>();
            private readonly HashSet<string> _recordSet = new HashSet<string>();
            private readonly Dictionary<string, string> _recordFullHashes = new Dictionary<string, string>();
            private readonly Dictionary<string, string> _recordMatchHashes = new Dictionary<string, string>();

            /// <summary>
            /// Instantiate <see cref="BatchVaultOperations"/>.
            /// </summary>
            /// <param name="vault">Vault instance</param>
            public BatchVaultOperations(VaultOnline vault)
            {
                _vault = vault;
                RecordMatch = RecordMatch.AllFields;
                Reset();
            }

            /// <summary>
            /// Resets all pending tasks
            /// </summary>
            public void Reset()
            {
                _foldersToAdd.Clear();
                _legacyRecordsToAdd.Clear();
                _typedRecordsToAdd.Clear();
                _recordsToUpdate.Clear();
                _folderInfoLookup.Clear();
                _folderPathLookup.Clear();
                _recordSet.Clear();
                _recordFullHashes.Clear();
                _recordMatchHashes.Clear();

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
                }

                var hash = new Sha256Digest();
                foreach (var record in _vault.KeeperRecords)
                {
                    if (record is PasswordRecord || record is TypedRecord)
                    {
                        hash.Reset();
                        foreach (var token in tokenizeKeeperRecord(record, RecordMatch.AllFields))
                        {
                            var buffer = Encoding.UTF8.GetBytes(token);
                            hash.BlockUpdate(buffer, 0, buffer.Length);
                        }

                        var hashValue = new byte[hash.GetDigestSize()];
                        hash.DoFinal(hashValue, 0);
                        _recordFullHashes[hashValue.Base64UrlEncode()] = record.Uid;

                        if (RecordMatch != RecordMatch.AllFields)
                        {
                            foreach (var token in tokenizeKeeperRecord(record, RecordMatch))
                            {
                                var buffer = Encoding.UTF8.GetBytes(token);
                                hash.BlockUpdate(buffer, 0, buffer.Length);
                            }
                            var hashMatchValue = new byte[hash.GetDigestSize()];
                            hash.DoFinal(hashMatchValue, 0);
                            _recordMatchHashes[hashMatchValue.Base64UrlEncode()] = record.Uid;
                        }
                        else
                        {
                            _recordMatchHashes[hashValue.Base64UrlEncode()] = record.Uid;
                        }
                    }
                }
            }

            private static IEnumerable<string> tokenizeKeeperRecord(KeeperRecord record, RecordMatch match)
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
                        foreach (var field in password.Custom)
                        {
                            fields.Add($"{field.Name}:{field.Value ?? string.Empty}");
                        }
                    }
                }
                else if (record is TypedRecord typed)
                {
                    fields.Add($"$type:{typed.TypeName}");

                    if (!string.IsNullOrEmpty(typed.Notes))
                    {
                        fields.Add($"$notes:{typed.Notes}");
                    }
                    foreach (var field in typed.Fields)
                    {
                        var token = getRecordFieldToken(field);
                        if (!string.IsNullOrEmpty(token))
                        {
                            fields.Add(token);
                        }
                    }
                    if (match == RecordMatch.AllFields)
                    {
                        foreach (var field in typed.Custom)
                        {
                            var token = getRecordFieldToken(field);
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

            private static string getRecordFieldToken(ITypedField field)
            {
                if (field.FieldName.EndsWith("Ref"))
                {
                    return null;
                }
                if (!(field is ISerializeTypedField fts))
                {
                    return null;
                }
                var value = fts.ExportTypedField();
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

            /// <summary>
            /// Finds folder node by folder path
            /// </summary>
            /// <param name="folderPath">Folder Path</param>
            /// <seealso cref="FolderNode"/>
            /// <returns>folder node</returns>
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

            /// <summary>
            /// Appends folder to folder structure
            /// </summary>
            /// <param name="folder">folder node</param>
            /// <param name="sharedFolderOptions">shared folder options</param>
            /// <returns>folder node</returns>
            public FolderNode AddFolder(FolderNode folder, SharedFolderOptions sharedFolderOptions = null)
            {
                if (string.IsNullOrEmpty(folder.FolderUid))
                {
                    folder.FolderUid = CryptoUtils.GenerateUid();
                }
                else
                {
                    if (_folderInfoLookup.TryGetValue(folder.FolderUid, out var existingFolder))
                    {
                        BatchLogger?.Invoke(Severity.Warning, $"Add Folder {folder.Name}: Folder UID \"{folder.FolderUid}\" already exists");
                        return existingFolder;
                    }
                }

                FolderNode parentFolder = null;
                if (!string.IsNullOrEmpty(folder.ParentUid))
                {
                    if (_folderInfoLookup.TryGetValue(folder.ParentUid, out parentFolder))
                    {
                        if (sharedFolderOptions != null && parentFolder.FolderType != FolderType.UserFolder)
                        {
                            BatchLogger?.Invoke(Severity.Warning, $"Add Folder {folder.Name}: Folder cannot be added as a shared folder.");
                            sharedFolderOptions = null;
                        }
                    }
                    else
                    {
                        BatchLogger?.Invoke(Severity.Error, $"Add Folder {folder.Name}: Parent folder UID \"{folder.ParentUid}\" not found");
                        return null;
                    }
                }

                var f = new FolderNode
                {
                    FolderUid = folder.FolderUid,
                    Name = folder.Name,
                    ParentUid = folder.ParentUid,
                    FolderKey = CryptoUtils.GenerateEncryptionKey()
                };
                if (parentFolder != null)
                {
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
                }
                else
                {
                    if (sharedFolderOptions != null)
                    {
                        f.FolderType = FolderType.SharedFolder;
                        f.SharedFolderUid = f.FolderUid;
                    }
                    else
                    {
                        f.FolderType = FolderType.UserFolder;
                    }
                }

                _foldersToAdd.Add(Tuple.Create(f, sharedFolderOptions));
                _folderInfoLookup[f.FolderUid] = f;
                var path = GetFolderPath(f.FolderUid).ToLower();
                if (!string.IsNullOrEmpty(path) && !_folderPathLookup.ContainsKey(path))
                {
                    _folderPathLookup.Add(path, f.FolderUid);
                }

                return f;
            }

            public void UpdateRecord(KeeperRecord record)
            {
                if (_vault.TryGetKeeperRecord(record.Uid, out var r))
                {
                    if (ReferenceEquals(record, r))
                    {
                        return;
                    }
                    if (!ReferenceEquals(record.GetType(), r.GetType()))
                    {
                        BatchLogger?.Invoke(Severity.Error, $"Update Record {record.Title}: Invalid record type.");
                        return;
                    }
                    _recordsToUpdate.Add(record);
                }
                else
                {
                    BatchLogger?.Invoke(Severity.Error, $"Update Record {record.Title}: Cannot find existing record.");
                }
            }

            /// <summary>
            /// Appends record
            /// </summary>
            /// <param name="record">record</param>
            /// <param name="folder">folder</param>
            public void AddRecord(KeeperRecord record, FolderNode folder)
            {
                var fullRecordHash = new Sha256Digest();
                foreach (var token in tokenizeKeeperRecord(record, RecordMatch.AllFields))
                {
                    var buffer = Encoding.UTF8.GetBytes(token);
                    fullRecordHash.BlockUpdate(buffer, 0, buffer.Length);
                }

                var fullHashValue = new byte[fullRecordHash.GetDigestSize()];
                fullRecordHash.DoFinal(fullHashValue, 0);
                if (_recordFullHashes.ContainsKey(fullHashValue.Base64UrlEncode()))
                {
                    BatchLogger?.Invoke(Severity.Error, $"Add Record {record.Title}: Duplicated record. Skipping.");
                    return;
                }

                if (!string.IsNullOrEmpty(record.Uid))
                {
                    if (_vault.TryGetKeeperRecord(record.Uid, out var r))
                    {
                        BatchLogger?.Invoke(Severity.Information, $"Add Record: Existing Record UID {record.Uid}: Update record.");
                        record.RecordKey = r.RecordKey;
                        UpdateRecord(record);
                        return;
                    }
                    if (_recordSet.Contains(record.Uid))
                    {
                        BatchLogger?.Invoke(Severity.Error, $"Add Record {record.Uid}: Record already added. Skipping.");
                        return;
                    }
                }

                byte[] matchHashValue;
                if (RecordMatch != RecordMatch.MainFields)
                {
                    var matchRecordHash = new Sha256Digest();
                    foreach (var token in tokenizeKeeperRecord(record, RecordMatch))
                    {
                        var buffer = Encoding.UTF8.GetBytes(token);
                        matchRecordHash.BlockUpdate(buffer, 0, buffer.Length);
                    }

                    matchHashValue = new byte[matchRecordHash.GetDigestSize()];
                    matchRecordHash.DoFinal(matchHashValue, 0);
                    if (_recordMatchHashes.TryGetValue(matchHashValue.Base64UrlEncode(), out var recordUid))
                    {
                        if (_vault.TryGetKeeperRecord(recordUid, out var r))
                        {
                            record.Uid = r.Uid;
                            record.RecordKey = r.RecordKey;
                            BatchLogger?.Invoke(Severity.Information, $"Add Record: Matching record {record.Title}: Update record.");
                            UpdateRecord(record);
                            return;
                        }
                    }
                }
                else
                {
                    matchHashValue = fullHashValue;
                }

                if (folder != null)
                {
                    if (!_folderInfoLookup.TryGetValue(folder.FolderUid, out folder))
                    {
                        BatchLogger?.Invoke(Severity.Error, $"Add Record {record.Uid}: Folder UID {folder.FolderUid} was not created");
                        return;
                    }
                }

                record.Uid = CryptoUtils.GenerateUid();
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
                    BatchLogger?.Invoke(Severity.Error, $"Add Record {record.Uid}: Record version is not supported");
                    return;
                }
                _recordSet.Add(record.Uid);
                _recordFullHashes[fullHashValue.Base64UrlEncode()] = record.Uid;
                _recordMatchHashes[matchHashValue.Base64UrlEncode()] = record.Uid;
            }

            /// <summary>
            /// Applies pending changes
            /// </summary>
            /// <returns>Summary of changes</returns>
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
                    var rq = new ImportFolderRecordRequest
                    {
                    };

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
                        foreach (var f in chunk)
                        {
                            var folder = f.Item1;
                            var sharedFolderOptions = f.Item2;
                            var frq = new Folder.FolderRequest
                            {
                                FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode()),
                            };
                            if (!string.IsNullOrEmpty(folder.ParentUid))
                            {
                                frq.ParentFolderUid = ByteString.CopyFrom(folder.ParentUid.Base64UrlDecode());
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
                                    frq.EncryptedFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(folder.FolderKey, _vault.Auth.AuthContext.DataKey));
                                }
                                break;
                                case FolderType.SharedFolder:
                                {
                                    frq.FolderType = Folder.FolderType.SharedFolder;
                                    frq.EncryptedFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(folder.FolderKey, _vault.Auth.AuthContext.DataKey));
                                    var encName = CryptoUtils.EncryptAesV1(Encoding.UTF8.GetBytes(folder.Name), folder.FolderKey);
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
                                        BatchLogger?.Invoke(Severity.Warning, $"Prepare Shared Folder Folder {folder.FolderUid}: Parent Shared Folder UID {folder.SharedFolderUid} not found");
                                        continue;
                                    }
                                    frq.FolderType = Folder.FolderType.SharedFolderFolder;
                                    frq.EncryptedFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(folder.FolderKey, sharedFolder.FolderKey));
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
                            var rrq = new Folder.RecordRequest
                            {
                                RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
                                EncryptedRecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(record.RecordKey, _vault.Auth.AuthContext.DataKey)),
                            };
                            if (folder != null)
                            {
                                FolderNode sharedFolder = null;
                                switch (folder.FolderType)
                                {
                                    case FolderType.UserFolder:
                                        rrq.FolderType = Folder.FolderType.UserFolder; break;
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
                                            BatchLogger?.Invoke(Severity.Warning, $"Prepare Shared Folder Folder {folder.FolderUid}: Parent Shared Folder UID {folder.SharedFolderUid} not found");
                                            continue;
                                        }
                                    }
                                    break;
                                }
                                rrq.FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode());

                                if (sharedFolder != null)
                                {
                                    rrq.EncryptedRecordFolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(record.RecordKey, sharedFolder.FolderKey));
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
                    var rs = await _vault.Auth.ExecuteAuthRest<ImportFolderRecordRequest, ImportFolderRecordResponse>("folder/import_folders_and_records", rq);
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
                            BatchLogger?.Invoke(Severity.Warning, $"Add folder \"{frs.FolderUid.ToByteArray().Base64UrlEncode()}\" error: {frs.Status}");
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
                            BatchLogger?.Invoke(Severity.Warning, $"Add legacy record \"{rrs.RecordUid.ToByteArray().Base64UrlEncode()}\" error: {rrs.Status}");
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
                    var rq = new Records.RecordsAddRequest
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
                            RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(typed.RecordKey, _vault.Auth.AuthContext.DataKey)),
                        };

                        if (folder != null)
                        {
                            FolderNode sharedFolder = null;
                            switch (folder.FolderType)
                            {
                                case FolderType.UserFolder:
                                    ra.FolderType = RecordFolderType.UserFolder; break;
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
                                        BatchLogger?.Invoke(Severity.Warning, $"Prepare Shared Folder Folder {folder.FolderUid}: Parent Shared Folder UID {folder.SharedFolderUid} not found");
                                        continue;
                                    }
                                }
                                break;
                            }
                            ra.FolderUid = ByteString.CopyFrom(folder.FolderUid.Base64UrlDecode());

                            if (sharedFolder != null)
                            {
                                ra.FolderKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(typed.RecordKey, sharedFolder.FolderKey));
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
                                Data = ByteString.CopyFrom(CryptoUtils.EncryptEc(data, _vault.Auth.AuthContext.EnterprisePublicEcKey))
                            };
                        }
                        rq.Records.Add(ra);
                    }
                    var rs = await _vault.Auth.ExecuteAuthRest<RecordsAddRequest, RecordsModifyResponse>("vault/records_add", rq);
                    foreach (var ar in rs.Records)
                    {
                        if (ar.Status == RecordModifyResult.RsSuccess)
                        {
                            result.TypedRecordCount++;
                        }
                        else
                        {
                            BatchLogger?.Invoke(Severity.Warning, $"Add typed record \"{ar.RecordUid.ToByteArray().Base64UrlEncode()}\" error: {ar.Message}");
                        }
                    }
                    if (_typedRecordsToAdd.Count > 100)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(10));
                    }
                }

                if (_recordsToUpdate.Count > 0)
                {
                    var statuses = await _vault.UpdateRecordBatch(_recordsToUpdate);
                    foreach (var status in statuses)
                    {
                        if (status.Status != "success")
                        {
                            BatchLogger?.Invoke(Severity.Warning, $"Update record \"{status.RecordUid}\" error: {status.Message}");
                        }
                        else 
                        {
                            result.UpdatedRecordCount++;
                        }
                    }
                }

                Reset();
                await _vault.ScheduleSyncDown(TimeSpan.FromSeconds(0));
                return result;
            }

            public RecordMatch RecordMatch { get; set; }

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
        }
    }
}
