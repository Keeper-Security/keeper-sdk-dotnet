using System;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using Moq;
using Xunit;
using LoginResponse = KeeperSecurity.Sdk.LoginResponse;
using TwoFactorChannel = KeeperSecurity.Sdk.UI.TwoFactorChannel;

namespace Tests
{
    public class LoginV2Test
    {
        private readonly VaultEnvironment _vaultEnv;
        private bool HasTwoFactor { get; set; }

        public LoginV2Test()
        {
            _vaultEnv = new VaultEnvironment();
        }

        [Fact]
        public async Task TestLoginV2Success()
        {
            var auth = GetAuthV2();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.NotNull(userConfig);
            Assert.NotNull(userConfig.Username);
            Assert.NotNull(userConfig.Password);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestRefreshSessionToken()
        {
            HasTwoFactor = false;
            var auth = GetAuthV2();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            (auth.AuthContext as AuthContext).SessionToken = CryptoUtils.GetRandomBytes(32);
            await auth.RefreshSessionToken();
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
        }

        [Fact]
        public async Task TestLoginSuccessV2TwoFactorToken()
        {
            HasTwoFactor = true;
            var auth = GetAuthV2();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            var uc = new UserConfiguration(userConfig.Username)
            {
                TwoFactorToken = _vaultEnv.DeviceToken
            };
            auth.Storage.Users.Put(uc);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestLoginSuccessV2TwoFactorOneTime()
        {
            HasTwoFactor = true;
            var auth = GetAuthV2();
            var mockUi = Mock.Get(auth.Ui);
            mockUi.Setup(ui => ui.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(),
                    It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(true));
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
            userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.Equal(userConfig.TwoFactorToken, _vaultEnv.DeviceToken);
        }

        [Fact]
        public async Task TestLoginSuccessV2TwoFactorOneTimeDoNotStoreToken()
        {
            HasTwoFactor = true;
            var auth = GetAuthV2();
            var mockUi = Mock.Get(auth.Ui);
            mockUi.Setup(ui => ui.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(), 
                    It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(true));
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
            userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.Null(userConfig.TwoFactorToken);
        }

        [Fact]
        public void TestLoginSuccessV2TwoFactorCancel()
        {
            HasTwoFactor = true;
            var auth = GetAuthV2();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            var authMock = Mock.Get(auth.Ui);
            authMock.Setup(x => x.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(),
                    It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(false));
            Assert.ThrowsAsync<KeeperCanceled>(() => auth.Login(userConfig.Username, userConfig.Password));
        }

        [Fact]
        public void TestLoginV2Failed()
        {
            HasTwoFactor = false;
            var auth = GetAuthV2();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login(userConfig.Username, "123456"));
        }

        [Fact]
        public void TestLoginV2InvalidUser()
        {
            HasTwoFactor = false;
            var auth = GetAuthV2();
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login("wrong.user@company.com", "123456"));
        }

        private Auth GetAuthV2()
        {
            var storage = DataVault.GetConfigurationStorage();
            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.Setup(e => e.ClientVersion).Returns("c14.0.0");
            mEndpoint.Setup(e => e.DeviceName).Returns(".NET Unit Tests");
            mEndpoint.Setup(e => e.ExecuteRest("authentication/get_device_token", It.IsAny<ApiRequestPayload>()))
                .Returns(Task.FromResult(new DeviceResponse
                {
                    Status = DeviceStatus.DeviceOk,
                    EncryptedDeviceToken = ByteString.CopyFrom(_vaultEnv.DeviceId),
                }.ToByteArray()));

            mEndpoint.Setup(e => e.ExecuteRest("authentication/pre_login", It.IsAny<ApiRequestPayload>()))
                .Returns(Task.FromResult(new PreLoginResponse
                {
                    DeviceStatus = DeviceStatus.DeviceOk,
                    Salt = { new Salt
                    {
                        Salt_ = ByteString.CopyFrom(_vaultEnv.Salt),
                        Iterations = _vaultEnv.Iterations,
                        Name = "Master"
                    }}
                }.ToByteArray()));

            mEndpoint.Setup(e => e.ExecuteV2Command(It.IsAny<LoginCommand>(), typeof(LoginResponse)))
                .Returns((KeeperApiCommand cmd, Type _) =>
                    Task.FromResult((KeeperApiResponse) ProcessLoginCommand((LoginCommand) cmd)));

            mEndpoint.Setup(e => e.ExecuteV2Command(It.IsAny<AccountSummaryCommand>(), typeof(AccountSummaryResponse)))
                .Returns((KeeperApiCommand cmd, Type _) =>
                    Task.FromResult((KeeperApiResponse) ProcessAccountSummaryCommand(_vaultEnv, (AccountSummaryCommand) cmd)));

            var mUi = new Mock<IAuthUI>();
            var mAuth = new Mock<Auth>(mUi.Object, storage, mEndpoint.Object);
            return mAuth.Object;
        }

        private LoginResponse ProcessLoginCommand(LoginCommand command)
        {
            var rs = new KeeperSecurity.Sdk.LoginResponse();
            if (string.Compare(command.username, _vaultEnv.User, StringComparison.OrdinalIgnoreCase) == 0)
            {
                var auth1 = CryptoUtils.DeriveV1KeyHash(_vaultEnv.Password, _vaultEnv.Salt, _vaultEnv.Iterations)
                    .Base64UrlEncode();
                if (auth1 == command.authResponse)
                {
                    var method = command.twoFactorType ?? "";
                    var token = command.twoFactorToken ?? "";
                    if (HasTwoFactor && method == "one_time" && token != _vaultEnv.OneTimeToken)
                    {
                        rs.result = "fail";
                        rs.resultCode = "invalid_totp";
                        rs.channel = "two_factor_channel_google";
                    }
                    else if (HasTwoFactor && method == "device_token" && token != _vaultEnv.DeviceToken)
                    {
                        rs.result = "fail";
                        rs.resultCode = "invalid_device_token";
                        rs.channel = "two_factor_channel_google";
                    }
                    else if (HasTwoFactor && method == "")
                    {
                        rs.result = "fail";
                        rs.resultCode = "need_totp";
                        rs.channel = "two_factor_channel_google";
                    }
                    else
                    {
                        rs.result = "success";
                        rs.resultCode = "auth_success";
                        rs.sessionToken = _vaultEnv.SessionToken.Base64UrlEncode();

                        if (HasTwoFactor)
                        {
                            rs.deviceToken = _vaultEnv.DeviceToken;
                            rs.deviceTokenScope = command.deviceTokenExpiresInDays > 0 ? "expiration" : "session";
                        }

                        if (command.include != null)
                        {
                            foreach (var inc in command.include)
                            {
                                switch (inc)
                                {
                                    case "keys":
                                        rs.keys = new AccountKeys();
                                        rs.keys.encryptedPrivateKey = _vaultEnv.EncryptedPrivateKey;
                                        rs.keys.encryptionParams = _vaultEnv.EncryptionParams;

                                        break;
                                    case "client_key":
                                        rs.clientKey = CryptoUtils.EncryptAesV1(_vaultEnv.ClientKey, _vaultEnv.DataKey)
                                            .Base64UrlEncode();
                                        break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    rs.result = "fail";
                    rs.resultCode = "auth_failed";
                    rs.salt = _vaultEnv.Salt.Base64UrlEncode();
                    rs.iterations = _vaultEnv.Iterations;
                }
            }
            else
            {
                rs.result = "fail";
                rs.resultCode = "Failed_to_find_user";
            }

            return rs;
        }

        internal static AccountSummaryResponse ProcessAccountSummaryCommand(VaultEnvironment vaultEnv, AccountSummaryCommand command)
        {
            if (string.Compare(command.username, vaultEnv.User, StringComparison.OrdinalIgnoreCase) != 0)
            {
                return new AccountSummaryResponse
                {
                    result = "fail",
                    resultCode = "Failed_to_find_user",
                };
            }

            if (string.CompareOrdinal(command.sessionToken, vaultEnv.SessionToken.Base64UrlEncode()) != 0)
            {
                return new AccountSummaryResponse
                {
                    result = "fail",
                    resultCode = "auth_failed",
                };
            }

            var rs = new AccountSummaryResponse
            {
                result = "success"
            };
            if (command.include != null)
            {
                foreach (var inc in command.include)
                {
                    switch (inc)
                    {
                        case "keys":
                            rs.keys = new AccountKeys
                            {
                                encryptedPrivateKey = vaultEnv.EncryptedPrivateKey,
                                encryptionParams = vaultEnv.EncryptionParams
                            };

                            break;
                        case "client_key":
                            rs.clientKey = CryptoUtils.EncryptAesV1(vaultEnv.ClientKey, vaultEnv.DataKey)
                                .Base64UrlEncode();
                            break;
                    }
                }
            }

            return rs;
        }
    }
}