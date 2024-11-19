using System;
using System.Linq;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Moq;
using Xunit;
using VaultProto = Vault;

namespace Tests;

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
        Assert.Equal(4, vault.RecordCount);
        Assert.Equal(2, vault.SharedFolderCount);
        Assert.Equal(1, vault.TeamCount);
    }

    [Fact]
    public async Task TestRemoveOwnerRecords()
    {
        var vault = await GetVault();
        var recordsBefore = vault.RecordCount;

        var recordUids = vault.KeeperRecords.Where(x => x.Owner && !x.Shared).Select(x => x.Uid).ToArray();

        var authMock = Mock.Get(vault.Auth);
        authMock.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownResponse), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, rst, apiVersion) =>
            {
                var rs = new VaultProto.SyncDownResponse 
                { 
                    HasMore = false,
                    ContinuationToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(32)),
                    CacheStatus = VaultProto.CacheStatus.Keep,
                };
                rs.RemovedRecords.AddRange(recordUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));
                return Task.FromResult((IMessage) rs);
            });

        await vault.SyncDown();
        Assert.Equal(recordsBefore - recordUids.Length, vault.RecordCount);
    }

    [Fact]
    public async Task TestRemoveTeam()
    {
        var vault = await GetVault();
        var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();

        var authMock = Mock.Get(vault.Auth);
        authMock.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownResponse), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, rst, apiVersion) =>
            {
                var rs = new VaultProto.SyncDownResponse
                {
                    HasMore = false,
                    ContinuationToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(32)),
                    CacheStatus = VaultProto.CacheStatus.Keep,
                };
                rs.RemovedTeams.AddRange(teamUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));
                return Task.FromResult((IMessage) rs);
            });

        await vault.SyncDown();

        Assert.Equal(3, vault.RecordCount);
        Assert.Equal(1, vault.SharedFolderCount);
        Assert.Equal(0, vault.TeamCount);
    }

    [Fact]
    public async Task TestRemoveSharedFolderThenTeam()
    {
        var vault = await GetVault();
        var authMock = Mock.Get(vault.Auth);

        var sfUids = vault.SharedFolders.Where(x => x.Uid == VaultEnvironment.SharedFolder1Uid).Select(x => x.Uid).ToArray();
        Assert.Single(sfUids);
        authMock.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownResponse), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, rst, apiVersion) =>
            {
                var rs = new VaultProto.SyncDownResponse
                {
                    HasMore = false,
                    ContinuationToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(32)),
                    CacheStatus = VaultProto.CacheStatus.Keep,
                };
                rs.RemovedSharedFolders.AddRange(sfUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));
                return Task.FromResult((IMessage) rs);
            });

        await vault.SyncDown();
        Assert.Equal(4, vault.RecordCount);
        Assert.Equal(2, vault.SharedFolderCount);
        Assert.Equal(1, vault.TeamCount);

        var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();
        Assert.Single(teamUids);
        authMock.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownResponse), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, rst, apiVersion) =>
            {
                var rs = new VaultProto.SyncDownResponse
                {
                    HasMore = false,
                    ContinuationToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(32)),
                    CacheStatus = VaultProto.CacheStatus.Keep,
                };
                rs.RemovedTeams.AddRange(teamUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));
                return Task.FromResult((IMessage) rs);
            });

        await vault.SyncDown();
        Assert.Equal(3, vault.RecordCount);
        Assert.Equal(0, vault.SharedFolderCount);
        Assert.Equal(0, vault.TeamCount);
    }

    [Fact]
    public async Task TestRemoveTeamAndSharedFolder()
    {
        var vault = await GetVault();

        var sfUids = vault.SharedFolders.Select(x => x.Uid).ToArray();
        var teamUids = vault.Teams.Select(x => x.TeamUid).ToArray();

        var authMock = Mock.Get(vault.Auth);
        authMock.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownResponse), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, rst, apiVersion) =>
            {
                var rs = new VaultProto.SyncDownResponse
                {
                    HasMore = false,
                    ContinuationToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(32)),
                    CacheStatus = VaultProto.CacheStatus.Keep,
                };
                rs.RemovedSharedFolders.AddRange(sfUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));
                rs.RemovedTeams.AddRange(teamUids.Select(x => ByteString.CopyFrom(x.Base64UrlDecode())));
                return Task.FromResult((IMessage) rs);
            });

        await vault.SyncDown();
        Assert.Equal(3, vault.RecordCount);
        Assert.Equal(0, vault.SharedFolderCount);
        Assert.Equal(0, vault.TeamCount);
    }

    public IAuthentication GetConnectedAuthContext()
    {
        var context = new Mock<IAuthContext>();
        context.Setup(x => x.SessionToken).Returns(_vaultEnv.SessionToken);
        context.Setup(x => x.ClientKey).Returns(_vaultEnv.ClientKey);
        context.Setup(x => x.DataKey).Returns(_vaultEnv.DataKey);
        context.Setup(x => x.PrivateRsaKey).Returns(_vaultEnv.PrivateRsaKey);
        context.Setup(x => x.Settings).Returns(new AccountSettings());

        var endpoint = new Mock<IKeeperEndpoint>();
        endpoint.Setup(x => x.DeviceName).Returns("C# Unit Tests");
        endpoint.Setup(x => x.ClientVersion).Returns("c16.0.0");
        endpoint.Setup(x => x.Server).Returns(DataVault.DefaultEnvironment);

        var auth = new Mock<IAuthentication>();
        auth.Setup(x => x.AuthContext).Returns(context.Object);
        auth.Setup(x => x.Endpoint).Returns(endpoint.Object);

        auth.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownRequest), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, _, __) =>
            {
                return Task.FromResult((IMessage) _vaultEnv.GetSyncDownResponse());
            });

        return auth.Object;
    }

    private async Task<VaultOnline> GetVault()
    {
        var auth = GetConnectedAuthContext();
        var authMock = Mock.Get(auth);

        authMock.Setup(x => x.ExecuteAuthRest("vault/sync_down", It.IsAny<VaultProto.SyncDownRequest>(), typeof(VaultProto.SyncDownResponse), It.IsAny<int>()))
            .Returns<string, VaultProto.SyncDownRequest, Type, int>((endpoint, rq, rst, apiVersion) =>
            {
                return Task.FromResult((IMessage) _vaultEnv.GetSyncDownResponse());
            });

        authMock
            .Setup(x => x.ExecuteAuthRest("vault/get_record_types", It.IsAny<Records.RecordTypesRequest>(), typeof(Records.RecordTypesResponse), It.IsAny<int>()))
            .Returns<string, Records.RecordTypesRequest, Type, int>((e, rq, rst, apiVersion) =>
            {
                var rs = new Records.RecordTypesResponse()
                {
                    StandardCounter = 1,
                };
                rs.RecordTypes.Add(new Records.RecordType
                {
                    Scope = Records.RecordTypeScope.RtStandard,
                    RecordTypeId = 1,
                    Content =
                        @"{
  ""$id"": ""login"",
  ""categories"": [""login""],
  ""description"": ""Login template"",
  ""fields"": [
    {
      ""$ref"": ""login""
    },
    {
      ""$ref"": ""password""
    },
    {
      ""$ref"": ""url""
    },
    {
      ""$ref"": ""fileRef""
    },
    {
      ""$ref"": ""oneTimeCode""
    }
  ]
}",
                });
                return Task.FromResult((Google.Protobuf.IMessage) rs);
            });

        var vault = new VaultOnline(auth);
        await vault.SyncDown();
        return vault;
    }
}