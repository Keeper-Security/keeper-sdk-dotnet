using System;
using System.Threading.Tasks;
using Xunit;
using Moq;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Sdk.UI;

namespace KeeperSecurity.Sdk
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
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestRefreshSessionToken() {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            auth.SessionToken = "BadSessionToken";
            await auth.RefreshSessionToken();
            Assert.Equal(auth.SessionToken, _vaultEnv.SessionToken);
        }

        [Fact]
        public async Task TestLoginSuccessParams()
        {
            DataKeyAsEncryptionParams = true;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestLoginSuccessTwoFactorToken()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = true;
            var auth = GetAuthContext();
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            var uc = new UserConfiguration(userConfig);
            uc.TwoFactorToken = _vaultEnv.DeviceToken;
            var c = new Configuration(config);
            c.MergeUserConfiguration(uc);
            auth.Storage.Put(c);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestLoginSuccessTwoFactorOneTime()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = true;
            var auth = GetAuthContext();
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.DataKey, _vaultEnv.DataKey);
            config = auth.Storage.Get();
            userConfig = config.GetUserConfiguration(config.LastLogin);
            Assert.Equal(userConfig.TwoFactorToken, _vaultEnv.DeviceToken);
        }

        [Fact]
        public void TestLoginSuccessTwoFactorCancel()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = true;
            var auth = GetAuthContext();
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            var authMock = Mock.Get(auth.Ui);
            authMock.Setup(x => x.GetTwoFactorCode(It.IsAny<TwoFactorCodeChannel>())).Throws(new Exception());
            Assert.ThrowsAsync<Exception>(() => auth.Login(userConfig.Username, userConfig.Password));
        }

        [Fact]
        public void TestLoginFailed() {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            var config = auth.Storage.Get();
            var userConfig = config.GetUserConfiguration(config.LastLogin);
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login(userConfig.Username, "123456"));
        }

        [Fact]
        public void TestLoginInvalidUser()
        {
            DataKeyAsEncryptionParams = false;
            HasTwoFactor = false;
            var auth = GetAuthContext();
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login("wrong.user@keepersecurity.com", "123456"));
        }

        private Auth GetAuthContext()
        {
            var tfa = new TaskCompletionSource<TwoFactorCode>();
            tfa.SetResult(new TwoFactorCode(_vaultEnv.TwoFactorOneTimeToken, TwoFactorCodeDuration.EveryLogin));

            var uiMock = new Mock<IAuthUI>();
            uiMock.Setup(x => x.Confirmation(It.IsAny<string>()))
                .Returns(Task.FromResult(true));
            uiMock.Setup(x => x.GetNewPassword(It.IsAny<PasswordRuleMatcher>()))
                .Returns(Task.FromResult("qwerty"));
            uiMock.Setup(x => x.GetTwoFactorCode(It.IsAny<TwoFactorCodeChannel>()))
                .Returns(tfa);

            var endpoint = new Mock<KeeperEndpoint>();
            endpoint.Setup(x => x.ExecuteV2Command<LoginCommand, LoginResponse>(It.IsAny<LoginCommand>())).Returns<LoginCommand>(c => ProcessLoginCommand(c));
            var mAuth = new Mock<Auth>(uiMock.Object, DataVault.GetConfigurationStorage(), endpoint.Object);
            mAuth.Setup(x => x.GetPreLogin(It.IsAny<string>(), null)).Returns<string, byte[]>((x, y) => _vaultEnv.ProcessPreLogin(x));

            return mAuth.Object;
        }
        /*
        private Auth GetConnectedAuthContext()
        {
            var ui_mock = new Mock<IAuthUI>();
            var endpoint = new Mock<KeeperEndpoint>();
            endpoint.Setup(x => x.ExecuteV2Command<LoginCommand, LoginResponse>(It.IsAny<LoginCommand>())).Returns<LoginCommand>(c => ProcessLoginCommand(c));
            var m_auth = new Mock<Auth>(ui_mock.Object, DataVault.GetConfigurationStorage(), endpoint.Object);
            m_auth.Setup(x => x.GetPreLogin(It.IsAny<string>(), null)).Returns<string, byte[]>((x, y) => ProcessPreLogin(x));
            var auth = m_auth.Object;
            var config = auth.Storage.Get();
            var user_conf = config.GetUserConfiguration(config.LastLogin);
            auth.Username = user_conf.Username;
            auth.TwoFactorToken = user_conf.TwoFactorToken;
            auth.ClientKey = _vaultEnv.ClientKey;
            auth.DataKey = _vaultEnv.DataKey;
            auth.privateKeyData = _vaultEnv.PrivateKeyData;
            auth.SessionToken = _vaultEnv.SessionToken;
            auth.authResponse = CryptoUtils.DeriveV1KeyHash(_vaultEnv.Password, _vaultEnv.Salt, _vaultEnv.Iterations).Base64UrlEncode();
            return auth;
        }

        private Task<PreLoginResponse> ProcessPreLogin(string username)
        {
            var rs = new PreLoginResponse
            {
                Status = DeviceStatus.Ok
            };
            rs.Salt.Add(new Salt
            {
                Iterations = _vaultEnv.Iterations,
                Salt_ = ByteString.CopyFrom(_vaultEnv.Salt),
                Algorithm = 2,
                Name = "Master password"
            });
            return Task.FromResult(rs);
        }

                    */

        private Task<LoginResponse> ProcessLoginCommand(LoginCommand command)
        {
            var rs = new LoginResponse();
            if (string.Compare(command.username, _vaultEnv.User, true) == 0)
            {
                var auth1 = CryptoUtils.DeriveV1KeyHash(_vaultEnv.Password, _vaultEnv.Salt, _vaultEnv.Iterations).Base64UrlEncode();
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
                                    case "is_enterprise_admin":
                                        rs.isEnterpriseAdmin = false;
                                        break;
                                    case "client_key":
                                        rs.clientKey = CryptoUtils.EncryptAesV1(_vaultEnv.ClientKey, _vaultEnv.DataKey).Base64UrlEncode();
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


