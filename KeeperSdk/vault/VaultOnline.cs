using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using Records;
using AuthProto = Authentication;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Represents Keeper Vault connected to Keeper server.
    /// </summary>
    public partial class VaultOnline : VaultData, IVault
    {
        /// <summary>
        /// Instantiate <see cref="VaultOnline"/> instance.
        /// </summary>
        /// <param name="auth">Keeper authentication.</param>
        /// <param name="storage">Keeper offline storage.</param>
        public VaultOnline(IAuthentication auth, IKeeperStorage storage = null)
            : base(auth.AuthContext.ClientKey, storage ?? new InMemoryKeeperStorage())
        {
            Auth = auth;
        }

        /// <summary>
        /// Gets Keeper authentication.
        /// </summary>
        public IAuthentication Auth { get; }

        private bool _autoSync;

        /// <summary>
        /// Gets or sets vault auto sync flag.
        /// </summary>
        /// <remarks>When <c>True</c> the library subscribes to the Vault change notifications.</remarks>
        public bool AutoSync
        {
            get => _autoSync;
            set
            {
                _autoSync = value && Auth.PushNotifications != null;
                if (_autoSync)
                {
                    Auth.PushNotifications?.RegisterCallback(OnNotificationReceived);
                }
                else
                {
                    Auth.PushNotifications?.RemoveCallback(OnNotificationReceived);
                }
            }
        }

        /// <exclude />
        public bool RecordTypesLoaded { get; set; }

        /// <summary>
        /// Gets User Interaction interface.
        /// </summary>
        public IVaultUi VaultUi { get; set; }

        private long _scheduledAt;
        private Task _syncDownTask;

        /// <summary>
        /// Schedules sync down.
        /// </summary>
        /// <param name="delay">delay</param>
        /// <returns>Awaitable task</returns>
        public Task ScheduleSyncDown(TimeSpan delay)
        {
            if (delay > TimeSpan.FromSeconds(5))
            {
                delay = TimeSpan.FromSeconds(5);
            }

            var now = DateTimeOffset.Now.ToUnixTimeMilliseconds();

            if (_syncDownTask != null && _scheduledAt > now)
            {
                if (now + (long) delay.TotalMilliseconds < _scheduledAt)
                {
                    return _syncDownTask;
                }
            }

            Task myTask = null;
            myTask = Task.Run(async () =>
            {
                try
                {
                    if (delay.TotalMilliseconds > 10)
                    {
                        await Task.Delay(delay);
                    }

                    if (myTask == _syncDownTask)
                    {
                        _scheduledAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() + 1000;
                        await this.RunSyncDownRest();
                        OnIdle();
                    }
                }
                finally
                {
                    if (myTask == _syncDownTask)
                    {
                        _syncDownTask = null;
                        _scheduledAt = 0;
                    }
                }
            });
            _scheduledAt = now + (long) delay.TotalMilliseconds;
            _syncDownTask = myTask;
            return myTask;
        }

        /// <summary>
        /// Immediately executes sync down.
        /// </summary>
        /// <returns>Awaitable task</returns>
        public async Task SyncDown()
        {
            await ScheduleSyncDown(TimeSpan.FromMilliseconds(10));
        }

        private bool OnNotificationReceived(NotificationEvent evt)
        {
            if (evt?.Event is "sync" or "sharing_notice")
            {
                if (evt.Sync)
                {
                    ScheduleSyncDown(TimeSpan.FromSeconds(5));
                }
            }

            return false;
        }

        protected override void Dispose(bool disposing)
        {
            Auth.PushNotifications?.RemoveCallback(OnNotificationReceived);
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        public void AuditLogRecordOpen(string recordUid)
        {
            _ = Task.Run(async () =>
            {
                await Auth.AuditEventLogging("open_record", new AuditEventInput { RecordUid = recordUid });
            });
        }

        /// <inheritdoc/>
        public void AuditLogRecordCopyPassword(string recordUid)
        {
            _ = Task.Run(async () =>
            {
                await Auth.AuditEventLogging("copy_password", new AuditEventInput { RecordUid = recordUid });
            });
        }


        /// <inheritdoc/>
        public Task<KeeperRecord> CreateRecord(KeeperRecord record, string folderUid = null)
        {
            return this.AddRecordToFolder(record, folderUid);
        }

        /// <inheritdoc/>
        public Task<KeeperRecord> UpdateRecord(KeeperRecord record, bool skipExtra = true)
        {
            return this.PutRecord(record, skipExtra);
        }

        /// <inheritdoc/>
        public Task<IList<RecordUpdateStatus>> UpdateRecords(IEnumerable<KeeperRecord> records)
        {
            return this.UpdateRecordBatch(records);
        }


        /// <inheritdoc/>
        public Task StoreNonSharedData<T>(string recordUid, T nonSharedData) where T : RecordNonSharedData, new()
        {
            return this.PutNonSharedData(recordUid, nonSharedData);
        }

        /// <inheritdoc/>
        public Task DeleteRecords(RecordPath[] records)
        {
            foreach (var path in records)
            {
                if (string.IsNullOrEmpty(path.RecordUid))
                {
                    throw new VaultException("Record UID cannot be empty");
                }

                var folder = this.GetFolder(path.FolderUid);
                if (!folder.Records.Contains(path.RecordUid))
                {
                    throw new VaultException($"Record {path.RecordUid} not found in the folder {folder.Name}");
                }
            }

            return this.DeleteVaultObjects(records);
        }

        /// <inheritdoc/>
        public async Task MoveRecords(RecordPath[] records, string dstFolderUid, bool link = false)
        {
            var recordUids = new HashSet<string>();

            var toMove = new List<RecordPath>();
            var toUnlink = new List<RecordPath>();
            foreach (var path in records)
            {
                if (string.IsNullOrEmpty(path.RecordUid)) continue;

                var srcFolder = this.GetFolder(path.FolderUid);
                if (srcFolder.Records.All(x => x != path.RecordUid))
                {
                    throw new VaultException($"Record {path.RecordUid} not found in the folder {srcFolder.Name} ({srcFolder.FolderUid})");
                }
                if (!recordUids.Add(path.RecordUid))
                {
                    if (!link)
                    {
                        toUnlink.Add(path);
                    }
                }
                else
                {
                    toMove.Add(path);
                }

            }

            var dstFolder = this.GetFolder(dstFolderUid);
            await this.MoveToFolder(toMove, dstFolder.FolderUid, link);
            if (toUnlink.Count > 0)
            {
                await this.DeleteVaultObjects(toUnlink, true);
            }
        }

        /// <inheritdoc/>
        public async Task MoveFolder(string srcFolderUid, string dstFolderUid, bool link = false)
        {
            var srcFolder = this.GetFolder(srcFolderUid);
            var dstFolder = this.GetFolder(dstFolderUid);

            await this.MoveToFolder(new[] { new RecordPath { FolderUid = srcFolder.FolderUid } }, dstFolder.FolderUid, link);
        }

        /// <inheritdoc/>
        public Task<FolderNode> CreateFolder(string folderName, string parentFolderUid = null, SharedFolderOptions sharedFolderOptions = null)
        {
            if (string.IsNullOrEmpty(folderName))
            {
                throw new VaultException("Folder name cannot be empty");
            }

            var parent = this.GetFolder(parentFolderUid);
            var nameExists = parent.Subfolders
                .Select(x => this.TryGetFolder(x, out var v) ? v : null)
                .Any(x => x != null && string.Compare(x.Name, folderName, StringComparison.InvariantCultureIgnoreCase) == 0);
            if (nameExists)
            {
                throw new VaultException($"Folder with name {folderName} already exists in {parent.Name}");
            }


            return this.AddFolder(folderName, parentFolderUid, sharedFolderOptions);
        }

        /// <inheritdoc/>
        public Task<FolderNode> RenameFolder(string folderUid, string newName)
        {
            var folder = this.GetFolder(folderUid);
            if (folder == null)
            {
                throw new VaultException($"Folder \"{folderUid}\" does not exist");
            }

            return this.FolderUpdate(folder.FolderUid, newName);
        }

        /// <inheritdoc/>
        public Task<FolderNode> UpdateFolder(string folderUid, string newName, SharedFolderOptions sharedFolderOptions = null)
        {
            var folder = this.GetFolder(folderUid);
            if (folder == null)
            {
                throw new VaultException($"Folder \"{folderUid}\" does not exist");
            }

            return this.FolderUpdate(folder.FolderUid, newName, sharedFolderOptions);
        }

        /// <inheritdoc/>
        public Task DeleteFolder(string folderUid)
        {
            var folder = this.GetFolder(folderUid);
            if (string.IsNullOrEmpty(folder.FolderUid))
            {
                throw new VaultException("Cannot delete the root folder");
            }

            return this.DeleteVaultObjects(Enumerable.Repeat(new RecordPath
            {
                FolderUid = folder.FolderUid,
            },
                1));
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<TeamInfo>> GetTeamsForShare()
        {
            var request = new GetAvailableTeamsCommand();
            var response = await Auth.ExecuteAuthCommand<GetAvailableTeamsCommand, GetAvailableTeamsResponse>(request);
            return response.teams.Select(x => new TeamInfo
            {
                TeamUid = x.teamUid,
                Name = x.teamName,
            });
        }

        /// <inheritdoc/>
        public async Task<ShareWithUsers> GetUsersForShare()
        {
            var rs = await Auth.ExecuteAuthRest<GetShareObjectsRequest, GetShareObjectsResponse>("vault/get_share_objects", new GetShareObjectsRequest());

            var response = new ShareWithUsers();
            var directUsers = new HashSet<string>();
            directUsers.UnionWith(rs.ShareRelationships.Where(x => x.Status == ShareStatus.Active).Select(x => x.Username));
            response.SharesWith = directUsers.ToArray();

            var familyUsers = new HashSet<string>();
            familyUsers.UnionWith(rs.ShareFamilyUsers.Where(x => x.Status == ShareStatus.Active).Select(x => x.Username));
            familyUsers.ExceptWith(directUsers);
            familyUsers.Remove(Auth.Username);
            response.SharesFrom = familyUsers.ToArray();

            var uniqueUsers = new HashSet<string>();
            uniqueUsers.UnionWith(rs.ShareEnterpriseUsers.Where(x => x.Status == ShareStatus.Active).Select(x => x.Username));
            uniqueUsers.ExceptWith(directUsers);
            uniqueUsers.ExceptWith(familyUsers);
            uniqueUsers.Remove(Auth.Username);
            response.GroupUsers = uniqueUsers.ToArray();

            uniqueUsers.Clear();
            uniqueUsers.UnionWith(rs.ShareRelationships.Where(x => x.Status == ShareStatus.Active).Select(x => x.Username));

            return response;
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<RecordSharePermissions>> GetSharesForRecords(IEnumerable<string> recordUids)
        {
            var rq = new GetRecordDataWithAccessInfoRequest
            {
                ClientTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                RecordDetailsInclude = RecordDetailsInclude.ShareOnly,
            };
            rq.RecordUid.AddRange(recordUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));

            var rs = await Auth.ExecuteAuthRest<GetRecordDataWithAccessInfoRequest, GetRecordDataWithAccessInfoResponse>("vault/get_records_details", rq);
            return rs.RecordDataWithAccessInfo.Select(x => new RecordSharePermissions
                {
                RecordUid = x.RecordUid.ToArray().Base64UrlEncode(),
                UserPermissions = x.UserPermission.Select(y => new UserRecordPermissions
                {
                    Username = y.Username,
                    Owner = y.Owner,
                    CanEdit = y.Editable,
                    CanShare = y.Sharable,
                    AwaitingApproval = y.AwaitingApproval,
                    Expiration = y.Expiration > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(y.Expiration) : null,
                }).ToArray(),
                SharedFolderPermissions = x.SharedFolderPermission.Select(y => new SharedFolderRecordPermissions
                {
                    SharedFolderUid = y.SharedFolderUid.ToArray().Base64UrlEncode(),
                    CanEdit = y.Editable,
                    CanShare = y.Resharable,
                    Expiration = y.Expiration > 0 ? DateTimeOffsetExtensions.FromUnixTimeMilliseconds(y.Expiration) : null,

                }).ToArray()
            });
        }

        /// <inheritdoc/>
        public async Task CancelSharesWithUser(string username)
        {
            var rq = new CancelShareCommand
            {
                FromEmail = Auth.Username,
                ToEmail = username
            };

            await Auth.ExecuteAuthCommand(rq);
        }

        /// <inheritdoc/>
        public async Task SendShareInvitationRequest(string username)
        {
            var inviteRq = new AuthProto.SendShareInviteRequest
            {
                Email = username
            };
            await Auth.ExecuteAuthRest("vault/send_share_invite", inviteRq);
        }

        /// <inheritdoc/>
        public async Task ShareRecordWithUser(string recordUid, string username, IRecordShareOptions options)
        {
            if (!TryGetKeeperRecord(recordUid, out var record))
            {
                throw new KeeperApiException("not_found", "Record not found");
            }

            var recordShares = (await GetSharesForRecords(new[] { recordUid })).FirstOrDefault(x => x.RecordUid == recordUid);

            var targetPermission = recordShares?.UserPermissions
                .FirstOrDefault(x => string.Equals(x.Username, username, StringComparison.InvariantCultureIgnoreCase));

            var accessPath = new RecordAccessPath
            {
                RecordUid = recordUid,
            };
            this.ResolveRecordAccessPath(accessPath, forShare: true);

            var request = new RecordShareUpdateRequest();
            var ro = new SharedRecord
            {
                ToUsername = username,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };
            if (!string.IsNullOrEmpty(accessPath.SharedFolderUid))
            {
                ro.SharedFolderUid = ByteString.CopyFrom(accessPath.SharedFolderUid.Base64UrlDecode());
            }
            if (!string.IsNullOrEmpty(accessPath.TeamUid))
            {
                ro.TeamUid = ByteString.CopyFrom(accessPath.TeamUid.Base64UrlDecode());
            }

            if (targetPermission == null)
            {
                await Auth.LoadUsersKeys(Enumerable.Repeat(username, 1));
                if (Auth.TryGetUserKeys(username, out var keys))
                {
                    var useEcKey = keys.EcPublicKey != null && record.Version != 2;
                    if (useEcKey)
                    {
                        var pk = CryptoUtils.LoadEcPublicKey(keys.EcPublicKey);
                        ro.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(record.RecordKey, pk));
                        ro.UseEccKey = true;
                    }
                    else
                    {
                        var pk = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                        ro.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptRsa(record.RecordKey, pk));
                    }
                    ro.Shareable = options?.CanShare ?? false;
                    ro.Editable = options?.CanEdit ?? false;
                    if (options?.Expiration != null)
                    {
                        ro.Expiration = options.Expiration.Value.ToUnixTimeMilliseconds();
                    }

                }
                request.AddSharedRecord.Add(ro);
            }
            else
            {
                ro.Shareable = options?.CanShare ?? targetPermission.CanShare;
                ro.Editable = options?.CanEdit ?? targetPermission.CanEdit;
                if (options?.Expiration != null)
                {
                    ro.Expiration = options.Expiration.Value.ToUnixTimeMilliseconds();
                }

                request.UpdateSharedRecord.Add(ro);
            }

            var rsuRs = await Auth.ExecuteAuthRest<RecordShareUpdateRequest, RecordShareUpdateResponse>("vault/records_share_update", request);
            var statuses = targetPermission == null ? rsuRs.AddSharedRecordStatus : rsuRs.UpdateSharedRecordStatus;
            var status = statuses.FirstOrDefault(x => x.RecordUid.SequenceEqual(recordUid.Base64UrlDecode()) && string.Equals(x.Username, username, StringComparison.InvariantCultureIgnoreCase));
            if (status != null && status.Status != "success")
            {
                throw new KeeperApiException(status.Status, status.Message);
            }
        }

        /// <inheritdoc/>
        public async Task TransferRecordToUser(string recordUid, string username)
        {
            var pkRq = new AuthProto.GetPublicKeysRequest();
            pkRq.Usernames.Add(username);

            var pkRss = await Auth.ExecuteAuthRest<AuthProto.GetPublicKeysRequest, AuthProto.GetPublicKeysResponse>("vault/get_public_keys", pkRq);
            var pkRs = pkRss.KeyResponses[0];
            EcPublicKey ecPk = null;
            RsaPublicKey rsaPk = null;
            if (!pkRs.PublicEccKey.IsEmpty)
            {
                ecPk = CryptoUtils.LoadEcPublicKey(pkRs.PublicEccKey.ToByteArray());
            }
            else if (!pkRs.PublicKey.IsEmpty)
            {
                rsaPk = CryptoUtils.LoadRsaPublicKey(pkRs.PublicKey.ToByteArray());
            }
            else
            {
                throw new KeeperApiException("public_key_error", pkRs.Message);
            }

            if (!TryGetKeeperRecord(recordUid, out var record))
            {
                throw new KeeperApiException("not_found", "Record not found");
            }
            var tr = new TransferRecord
            {
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
                Username = username,
            };
            if (ecPk != null)
            {
                tr.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(record.RecordKey, ecPk));
                tr.UseEccKey = true;
            }
            else
            {
                tr.RecordKey = ByteString.CopyFrom(CryptoUtils.EncryptRsa(record.RecordKey, rsaPk));
            }
            var request = new RecordsOnwershipTransferRequest();
            request.TransferRecords.Add(tr);

            var response = await Auth.ExecuteAuthRest<RecordsOnwershipTransferRequest, RecordsOnwershipTransferResponse>("vault/records_ownership_transfer", request);
            var status = response.TransferRecordStatus.FirstOrDefault(x => x.RecordUid.SequenceEqual(recordUid.Base64UrlDecode()) && string.Equals(x.Username, username, StringComparison.InvariantCultureIgnoreCase));
            if (status != null && status.Status != "transfer_record_success")
            {
                throw new KeeperApiException(status.Status, status.Message);
            }
        }

        /// <inheritdoc/>
        public async Task RevokeShareFromUser(string recordUid, string username)
        {
            if (!TryGetKeeperRecord(recordUid, out _))
            {
                throw new KeeperApiException("not_found", "Record not found");
            }
            var accessPath = new RecordAccessPath
            {
                RecordUid = recordUid,
            };
            this.ResolveRecordAccessPath(accessPath, forShare: true);

            var sr = new SharedRecord
            {
                ToUsername = username,
                RecordUid = ByteString.CopyFrom(recordUid.Base64UrlDecode()),
            };
            if (!string.IsNullOrEmpty(accessPath.SharedFolderUid))
            {
                sr.SharedFolderUid = ByteString.CopyFrom(accessPath.SharedFolderUid.Base64UrlDecode());
            }
            if (!string.IsNullOrEmpty(accessPath.TeamUid))
            {
                sr.TeamUid = ByteString.CopyFrom(accessPath.TeamUid.Base64UrlDecode());
            }

            var request = new RecordShareUpdateRequest();
            request.RemoveSharedRecord.Add(sr);

            var response = await Auth.ExecuteAuthRest<RecordShareUpdateRequest, RecordShareUpdateResponse>("vault/records_share_update", request);
            var status = response.RemoveSharedRecordStatus
                .FirstOrDefault(x => x.RecordUid.SequenceEqual(recordUid.Base64UrlDecode()) &&
                                     string.Equals(x.Username, username, StringComparison.InvariantCultureIgnoreCase));
            if (status != null && status.Status != "success")
            {
                throw new KeeperApiException(status.Status, status.Message);
            }
        }

        private readonly ISet<string> _recordsForAudit = new HashSet<string>();

        internal void ScheduleForAudit(params string[] recordUids)
        {
            if (Auth?.AuthContext?.EnterprisePublicEcKey != null)
            {
                lock (_recordsForAudit)
                {
                    _recordsForAudit.UnionWith(recordUids);
                }
            }
        }

        private void OnIdle()
        {
            string[] recordUids = null;
            lock (_recordsForAudit)
            {
                if (_recordsForAudit.Count > 0)
                {
                    recordUids = _recordsForAudit.ToArray();
                    _recordsForAudit.Clear();
                }
            }

            if (recordUids == null || recordUids.Length == 0) return;
            var publicEcKey = Auth?.AuthContext?.EnterprisePublicEcKey;
            if (publicEcKey == null) return;

            _ = Task.Run(async () =>
            {
                var auditData = recordUids
                    .Select(x => TryGetKeeperRecord(x, out var r) ? r : null)
                    .OfType<PasswordRecord>()
                    .Select(x =>
                    {
                        var rad = x.ExtractRecordAuditData();
                        return new RecordAddAuditData
                        {
                            RecordUid = ByteString.CopyFrom(x.Uid.Base64UrlDecode()),
                            Revision = x.Revision,
                            Data = ByteString.CopyFrom(CryptoUtils.EncryptEc(JsonUtils.DumpJson(rad), publicEcKey))
                        };

                    })
                    .ToList();

                try
                {
                    while (auditData.Count > 0)
                    {
                        var rq = new AddAuditDataRequest();
                        rq.Records.AddRange(auditData.Take(999));
                        if (auditData.Count > 999)
                        {
                            auditData.RemoveRange(0, 999);
                        }
                        else
                        {
                            auditData.Clear();
                        }

                        await Auth.ExecuteAuthRest("vault/record_add_audit_data", rq);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

            });
        }
    }
}