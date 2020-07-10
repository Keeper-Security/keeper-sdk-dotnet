using System;
using System.Threading.Tasks;
using Authentication;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using Moq;
using Xunit;

namespace Tests
{
    public class LoginTest
    {
        readonly VaultEnvironment _vaultEnv;
        private bool HasTwoFactor { get; set; }
        private bool DataKeyAsEncryptionParams { get; set; }

        public LoginTest()
        {
            _vaultEnv = new VaultEnvironment();
        }

        [Fact]
        public async Task TestLoginSuccess()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestRefreshSessionToken()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            auth.AuthContext.SessionToken = "BadSessionToken";
            await auth.RefreshSessionToken();
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
        }

        [Fact]
        public async Task TestLoginSuccessParams()
        {
            DataKeyAsEncryptionParams = true;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestLoginSuccessTwoFactorToken()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = true;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            var uc = new UserConfiguration(userConfig.Username)
            {
                TwoFactorToken = _vaultEnv.DeviceToken
            };
            us.PutUser(uc);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestLoginSuccessTwoFactorOneTime()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = true;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
            userConfig = us.GetUser(us.LastLogin);
            Assert.Equal(userConfig.TwoFactorToken, _vaultEnv.DeviceToken);
        }

        [Fact]
        public void TestLoginSuccessTwoFactorCancel()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = true;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            var authMock = Mock.Get(auth.Ui);
            authMock.Setup(x => x.GetTwoFactorCode(It.IsAny<TwoFactorCodeChannel>())).Throws(new Exception());
            Assert.ThrowsAsync<Exception>(() => auth.Login(userConfig.Username, userConfig.Password));
        }

        [Fact]
        public void TestLoginFailed()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            IUserStorage us = auth.Storage;
            var userConfig = us.GetUser(us.LastLogin);
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login(userConfig.Username, "123456"));
        }

        [Fact]
        public void TestLoginInvalidUser()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login("bad_user_id@company.com", "some_password_here"));
        }

        private Auth GetAuthContext()
        {
            var tfa = Task.FromResult(new TwoFactorCode(_vaultEnv.TwoFactorOneTimeToken,
                TwoFactorCodeDuration.EveryLogin));

            var uiMock = new Mock<IAuthUI>();
            uiMock.Setup(x => x.Confirmation(It.IsAny<string>()))
                .Returns(Task.FromResult(true));
            uiMock.Setup(x => x.GetNewPassword(It.IsAny<PasswordRuleMatcher>()))
                .Returns(Task.FromResult("qwerty"));
            uiMock.Setup(x => x.GetTwoFactorCode(It.IsAny<TwoFactorCodeChannel>()))
                .Returns(tfa);

            var storage = DataVault.GetConfigurationStorage();
            var endpoint = new Mock<KeeperEndpoint>(storage);
            endpoint.Setup(x => x.ExecuteV2Command<LoginCommand, KeeperSecurity.Sdk.LoginResponse>(It.IsAny<LoginCommand>()))
                .Returns<LoginCommand>(ProcessLoginCommand);
            var mAuth = new Mock<Auth>(uiMock.Object, storage, endpoint.Object);
            mAuth.Setup(x => x.GetPreLogin(It.IsAny<string>(), It.IsAny<LoginType>(), null))
                .Returns<string, LoginType, byte[]>((x, y, z) => _vaultEnv.ProcessPreLogin(x));

            return mAuth.Object;
        }

        private Task<KeeperSecurity.Sdk.LoginResponse> ProcessLoginCommand(LoginCommand command)
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
                        rs.sessionToken = _vaultEnv.SessionToken;

                        if (HasTwoFactor)
                        {
                            rs.deviceToken = _vaultEnv.DeviceToken;
                            rs.deviceTokenScope = "expiration";
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
                                        if (DataKeyAsEncryptionParams)
                                        {
                                            rs.keys.encryptionParams = _vaultEnv.EncryptionParams;
                                        }
                                        else
                                        {
                                            rs.keys.encryptedDataKey = _vaultEnv.EncryptedDataKey;
                                        }

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

            return Task.FromResult(rs);
        }
    }
}
