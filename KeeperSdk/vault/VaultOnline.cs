using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
#if NET45
using KeeperSecurity.Utils;
#endif

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

        /// <summary>
        /// Gets User Interaction interface.
        /// </summary>
        public IVaultUi VaultUi { get; set; }

        private long scheduledAt;
        private Task syncDownTask;

        /// <summary>
        /// Schedules sync down.
        /// </summary>
        /// <param name="delay">delay</param>
        /// <returns></returns>
        public Task ScheduleSyncDown(TimeSpan delay)
        {
            if (delay > TimeSpan.FromSeconds(5))
            {
                delay = TimeSpan.FromSeconds(5);
            }

            var now = DateTimeOffset.Now.ToUnixTimeMilliseconds();

            if (syncDownTask != null && scheduledAt > now)
            {
                if (now + (long) delay.TotalMilliseconds < scheduledAt)
                {
                    return syncDownTask;
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

                    if (myTask == syncDownTask)
                    {
                        scheduledAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() + 1000;
                        await this.RunSyncDown();
                    }
                }
                finally
                {
                    if (myTask == syncDownTask)
                    {
                        syncDownTask = null;
                        scheduledAt = 0;
                    }
                }
            });
            scheduledAt = now + (long) delay.TotalMilliseconds;
            syncDownTask = myTask;
            return myTask;
        }

        public async Task SyncDown()
        {
            await ScheduleSyncDown(TimeSpan.FromMilliseconds(100));
        }

        internal bool OnNotificationReceived(NotificationEvent evt)
        {
            if (evt != null & (evt?.Event == "sync" || evt?.Event == "sharing_notice"))
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

        public Task<PasswordRecord> CreateRecord(PasswordRecord record, string folderUid = null)
        {
            return this.AddRecordToFolder(record, folderUid);
        }

        public Task<PasswordRecord> UpdateRecord(PasswordRecord record, bool skipExtra = true)
        {
            return this.PutRecord(record, false, skipExtra);
        }

        public Task StoreNonSharedData<T>(string recordUid, T nonSharedData) where T : RecordNonSharedData, new()
        {
            return this.PutNonSharedData(recordUid, nonSharedData);
        }

        public Task DeleteRecords(RecordPath[] records)
        {
            foreach (var path in records)
            {
                if (string.IsNullOrEmpty(path.RecordUid))
                {
                    throw new VaultException($"Record UID cannot be empty");
                }

                var folder = this.GetFolder(path.FolderUid);
                if (!folder.Records.Contains(path.RecordUid))
                {
                    throw new VaultException($"Record {path.RecordUid} not found in the folder {folder.Name}");
                }
            }

            return this.DeleteVaultObjects(records);
        }

        public async Task MoveRecords(RecordPath[] records, string dstFolderUid, bool link = false)
        {
            foreach (var path in records)
            {
                if (string.IsNullOrEmpty(path.RecordUid)) continue;

                var srcFolder = this.GetFolder(path.FolderUid);
                if (srcFolder.Records.All(x => x != path.RecordUid))
                {
                    throw new VaultException($"Record {path.RecordUid} not found in the folder {srcFolder.Name} ({srcFolder.FolderUid})");
                }
            }

            var dstFolder = this.GetFolder(dstFolderUid);
            await this.MoveToFolder(records, dstFolder.FolderUid, link);
        }

        /// <summary>
        /// Moves a folder to the another folder.
        /// </summary>
        /// <param name="srcFolderUid">Source Folder UID.</param>
        /// <param name="dstFolderUid">Destination Folder UID.</param>
        /// <param name="link"><c>true</c>creates a link. The source folder in not deleted; otherwise source folder will be removed.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        public async Task MoveFolder(string srcFolderUid, string dstFolderUid, bool link = false)
        {
            var srcFolder = this.GetFolder(srcFolderUid);
            var dstFolder = this.GetFolder(dstFolderUid);

            await this.MoveToFolder(new[] {new RecordPath {FolderUid = srcFolder.FolderUid}}, dstFolder.FolderUid, link);
        }

        /// <summary>
        /// Creates a folder.
        /// </summary>
        /// <param name="name">Folder Name.</param>
        /// <param name="parentFolderUid">Parent Folder UID.</param>
        /// <param name="sharedFolderOptions">Shared Folder creation options. Optional.</param>
        /// <returns>A task returning created folder.</returns>
        /// <remarks>Pass <see cref="sharedFolderOptions"/> parameter to create a Shared Folder.</remarks>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        /// <seealso cref="SharedFolderOptions"/>

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

        /// <summary>
        /// Renames a folder.
        /// </summary>
        /// <param name="folderUid">Folder UID.</param>
        /// <param name="newName">New folder name.</param>
        /// <returns>A task returning renamed folder.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        public Task<FolderNode> RenameFolder(string folderUid, string newName)
        {
            var folder = this.GetFolder(folderUid);
            if (string.IsNullOrEmpty(folder.ParentUid))
            {
                throw new VaultException("Cannot rename the root folder");
            }

            return this.FolderUpdate(folder.FolderUid, newName);
        }

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


        /// <summary>
        /// Retrieves all enterprise team descriptions.
        /// </summary>
        /// <returns></returns>
        public async Task<IEnumerable<TeamInfo>> GetAvailableTeams()
        {
            var request = new GetAvailableTeamsCommand();
            var response = await Auth.ExecuteAuthCommand<GetAvailableTeamsCommand, GetAvailableTeamsResponse>(request);
            return response.teams.Select(x => new TeamInfo
            {
                TeamUid = x.teamUid,
                Name = x.teamName,
            });
        }
    }
}