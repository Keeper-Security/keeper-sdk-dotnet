using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace KeeperSecurity.Sdk
{
    public class SyncDownTest
    {
        readonly VaultEnvironment _vaultEnv;
        public SyncDownTest()
        {
            _vaultEnv = new VaultEnvironment();
        }

        [Fact]
        public async Task TestFullSync()
        {
            var auth = _vaultEnv.GetConnectedAuthContext();
            var authMock = Mock.Get(auth);
            authMock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c,b) => Task.FromResult(_vaultEnv.GetSyncDownResponse()));

            var vault = new Vault(auth);
            await vault.SyncDown();
            Assert.NotNull(vault);
            Assert.Equal(3, vault.keeperRecords.Count);
            Assert.Single(vault.keeperSharedFolders);
            Assert.Single(vault.keeperTeams);
        }

        [Fact]
        public async Task TestRemoveOwnerRecords()
        {
            var vault = await GetVault();
            var recordsBefore = vault.keeperRecords.Count;

            var recordUids = vault.keeperRecords.Values.Where(x => x.Owner && !x.Shared).Select(x => x.Uid).ToArray();

            var authMock = Mock.Get(vault.Auth);
            authMock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(new SyncDownResponse {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedRecords = recordUids
                }));

            await vault.SyncDown();
            Assert.Equal(recordsBefore - recordUids.Length, vault.keeperRecords.Count);
        }

        [Fact]
        public async Task TestRemoveTeam() {
            var vault = await GetVault();
            var teamUids = vault.keeperTeams.Values.Select(x => x.TeamUid).ToArray();

            var authMock = Mock.Get(vault.Auth);
            authMock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedTeams = teamUids
                }));
            await vault.SyncDown();

            Assert.Equal(3, vault.keeperRecords.Count);
            Assert.Single(vault.keeperSharedFolders);
            Assert.Empty(vault.keeperTeams);
        }

        [Fact]
        public async Task TestRemoveSharedFolderThenTeam() {
            var vault = await GetVault();
            var authMock = Mock.Get(vault.Auth);

            var sfUids = vault.keeperSharedFolders.Values.Select(x => x.Uid).Take(1).ToArray();
            Assert.Single(sfUids);

            var links = vault.Storage.SharedFolderKeys.GetLinksForSubject(sfUids[0]).Count();
            Assert.Equal(2, links);
            authMock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedSharedFolders = sfUids
                }));

            await vault.SyncDown();
            links = vault.Storage.SharedFolderKeys.GetLinksForSubject(sfUids[0]).Count();
            Assert.Equal(1, links);
            Assert.Equal(3, vault.keeperRecords.Count);
            Assert.Single(vault.keeperSharedFolders);
            Assert.Single(vault.keeperTeams);

            var teamUids = vault.keeperTeams.Values.Select(x => x.TeamUid).ToArray();
            authMock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedTeams = teamUids
                }));
            await vault.SyncDown();
            Assert.Equal(2, vault.keeperRecords.Count);
            Assert.Empty(vault.keeperSharedFolders);
            Assert.Empty(vault.keeperTeams);
        }

        [Fact]
        public async Task TestRemoveTeamAndSharedFolder() {
            var vault = await GetVault();
            var auth_mock = Mock.Get(vault.Auth);

            var sfUids = vault.keeperSharedFolders.Values.Select(x => x.Uid).ToArray();
            var teamUids = vault.keeperTeams.Values.Select(x => x.TeamUid).ToArray();

            auth_mock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedSharedFolders = sfUids,
                    removedTeams = teamUids
                }));

            await vault.SyncDown();
            Assert.Equal(2, vault.keeperRecords.Count);
            Assert.Empty(vault.keeperSharedFolders);
            Assert.Empty(vault.keeperTeams);
        }


        [Fact]
        public async Task TestTransferRecordOwnership()
        {
            var vault = await GetVault();
            var authMock = Mock.Get(vault.Auth);

            Assert.Equal(1, vault.RootFolder.Records.Count);
            var sf = vault.Folders.Where(x => x.FolderType == FolderType.SharedFolder).First();
            var uids = sf.Records.Select(x =>
            {
                if (vault.TryGetRecord(x, out PasswordRecord r))
                {
                    return r;
                }
                return null;
            }).Where(x => x != null).Where(x => x.Owner).Select(x => x.Uid).ToArray();

            Assert.Single(uids);
            authMock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedRecords = uids
                }));

            await vault.SyncDown();
            Assert.Equal(0, vault.RootFolder.Records.Count);
            Assert.Equal(3, vault.keeperRecords.Count);
            Assert.Single(vault.keeperSharedFolders);
            Assert.Single(vault.keeperTeams);
        }

        private async Task<Vault> GetVault() {
            var auth = _vaultEnv.GetConnectedAuthContext();
            var auth_mock = Mock.Get(auth);
            auth_mock
                .Setup(x => x.ExecuteAuthCommand<SyncDownCommand, SyncDownResponse>(It.IsAny<SyncDownCommand>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, bool>((c, b) => Task.FromResult(_vaultEnv.GetSyncDownResponse()));

            var vault = new Vault(auth);
            await vault.SyncDown();
            return vault;
        }
    }
}
