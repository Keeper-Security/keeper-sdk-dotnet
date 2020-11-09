using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;
using Moq;
using Xunit;

namespace Tests
{
    public class SyncDownTest
    {
        private readonly VaultEnvironment _vaultEnv;
        public SyncDownTest()
        {
            _vaultEnv = new VaultEnvironment();
        }

        [Fact]
        public async Task TestFullSync()
        {
            var vault = await GetVault();
            Assert.NotNull(vault);
            Assert.Equal(3, vault.RecordCount);
            Assert.Equal(1, vault.SharedFolderCount);
            Assert.Equal(1, vault.TeamCount);
        }

        [Fact]
        public async Task TestRemoveOwnerRecords()
        {
            var vault = await GetVault();
            var recordsBefore = vault.RecordCount;

            var recordUids = vault.Records.Where(x => x.Owner && !x.Shared).Select(x => x.Uid).ToArray();

            var authMock = Mock.Get(vault.Auth);
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((a, c) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedRecords = recordUids
                }));

            await vault.SyncDown();
            Assert.Equal(recordsBefore - recordUids.Length, vault.RecordCount);
        }

        [Fact]
        public async Task TestRemoveTeam()
        {
            var vault = await GetVault();
            var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();

            var authMock = Mock.Get(vault.Auth);
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((c, t) => Task.FromResult((KeeperApiResponse) new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedTeams = teamUids
                }));
            await vault.SyncDown();

            Assert.Equal(3, vault.RecordCount);
            Assert.Equal(1, vault.SharedFolderCount);
            Assert.Equal(0, vault.TeamCount);
        }

        [Fact]
        public async Task TestRemoveSharedFolderThenTeam() {
            var vault = await GetVault();
            var authMock = Mock.Get(vault.Auth);

            var sfUids = vault.SharedFolders.Select(x => x.Uid).Take(1).ToArray();
            Assert.Single(sfUids);

            var links = vault.Storage.SharedFolderKeys.GetLinksForSubject(sfUids[0]).Count();
            Assert.Equal(2, links);
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((c, t) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedSharedFolders = sfUids
                }));

            await vault.SyncDown();
            links = vault.Storage.SharedFolderKeys.GetLinksForSubject(sfUids[0]).Count();
            Assert.Equal(1, links);
            Assert.Equal(3, vault.RecordCount);
            Assert.Equal(1, vault.SharedFolderCount);
            Assert.Equal(1, vault.TeamCount);

            var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((c, t) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedTeams = teamUids
                }));
            await vault.SyncDown();
            Assert.Equal(2, vault.RecordCount);
            Assert.Equal(0, vault.SharedFolderCount);
            Assert.Equal(0, vault.TeamCount);
        }

        [Fact]
        public async Task TestRemoveTeamAndSharedFolder() {
            var vault = await GetVault();
            var authMock = Mock.Get(vault.Auth);

            var sfUids = vault.SharedFolders.Select(x => x.Uid).ToArray();
            var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();

            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((c, t) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedSharedFolders = sfUids,
                    removedTeams = teamUids
                }));

            await vault.SyncDown();
            Assert.Equal(2, vault.RecordCount);
            Assert.Equal(0, vault.SharedFolderCount);
            Assert.Equal(0, vault.TeamCount);
        }

        public IAuthentication GetConnectedAuthContext()
        {
            var context = new Mock<IAuthContext>();
            context.Setup(x => x.SessionToken).Returns(_vaultEnv.SessionToken);
            context.Setup(x => x.ClientKey).Returns(_vaultEnv.ClientKey);
            context.Setup(x => x.DataKey).Returns(_vaultEnv.DataKey);
            context.Setup(x => x.PrivateKey).Returns(_vaultEnv.PrivateKey);

            var endpoint = new Mock<IKeeperEndpoint>();
            endpoint.Setup(x => x.DeviceName).Returns("C# Unit Tests");
            endpoint.Setup(x => x.ClientVersion).Returns("c15.0.0");
            endpoint.Setup(x => x.Server).Returns(DataVault.DefaultEnvironment);

            var auth = new Mock<IAuthentication>();
            auth.Setup(x => x.AuthContext).Returns(context.Object);
            auth.Setup(x => x.Endpoint).Returns(endpoint.Object);
            auth.Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((command, _) =>
                {
                    try
                    {
                        return Task.FromResult((KeeperApiResponse) _vaultEnv.GetSyncDownResponse());
                    }
                    catch (Exception e)
                    {
                        return Task.FromException<KeeperApiResponse>(e);
                    }
                });
            return auth.Object;
        }

        private async Task<VaultOnline> GetVault() {
            var auth = GetConnectedAuthContext();
            var authMock = Mock.Get(auth);
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>()))
                .Returns<SyncDownCommand, Type>((c, t) => Task.FromResult((KeeperApiResponse)_vaultEnv.GetSyncDownResponse()));

            var vault = new VaultOnline(auth);
            await vault.SyncDown();
            return vault;
        }
    }
}
