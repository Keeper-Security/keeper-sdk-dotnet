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
            Assert.Equal(2, vault.SharedFolderCount);
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
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((a, c, b) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
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
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((c, t, b) => Task.FromResult((KeeperApiResponse) new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedTeams = teamUids
                }));
            await vault.SyncDown();

            Assert.Equal(2, vault.RecordCount);
            Assert.Equal(1, vault.SharedFolderCount);
            Assert.Equal(0, vault.TeamCount);
        }

        [Fact]
        public async Task TestRemoveSharedFolderThenTeam() {
            var vault = await GetVault();
            var authMock = Mock.Get(vault.Auth);

            var sfUids = vault.SharedFolders.Where(x => x.Uid == VaultEnvironment.SharedFolder1Uid).Select(x => x.Uid).ToArray();
            Assert.Single(sfUids);
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((c, t, b) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
                {
                    result = "success",
                    fullSync = false,
                    revision = vault.Storage.Revision + 1,
                    removedSharedFolders = sfUids
                }));

            await vault.SyncDown();
            Assert.Equal(3, vault.RecordCount);
            Assert.Equal(2, vault.SharedFolderCount);
            Assert.Equal(1, vault.TeamCount);

            var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();
            Assert.Single(teamUids);
            authMock
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((c, t, b) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
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
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((c, t, b) => Task.FromResult((KeeperApiResponse)new SyncDownResponse
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
            auth.Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((command, _, __) =>
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
                .Setup(x => x.ExecuteAuthCommand(It.IsAny<SyncDownCommand>(), It.IsAny<Type>(), It.IsAny<bool>()))
                .Returns<SyncDownCommand, Type, bool>((c, t, b) => Task.FromResult((KeeperApiResponse)_vaultEnv.GetSyncDownResponse()));

            var vault = new VaultOnline(auth);
            await vault.SyncDown();
            return vault;
        }
    }
}
