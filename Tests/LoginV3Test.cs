using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using Moq;
using Push;
using Xunit;

namespace Tests
{
    public class LoginTokenState
    {
        public LoginTokenState(byte[] deviceToken, string username)
        {
            LoginToken = CryptoUtils.GetRandomBytes(32);
            DeviceToken = deviceToken;
            Username = username;
        }

        public byte[] LoginToken { get; }
        public byte[] DeviceToken { get; }
        public string Username { get; }
        public LoginState LoginState { get; set; }
    }

    public class LoginV3Test
    {
        private readonly VaultEnvironment _vaultEnv;
        private bool HasTwoFactor { get; set; }
        private readonly Dictionary<string, LoginTokenState> _loginTokens = new Dictionary<string, LoginTokenState>();

        private const string TestClientVersion = "c15.0.0";
        public LoginV3Test()
        {
            _vaultEnv = new VaultEnvironment();
        }

        [Fact]
        public async Task TestRegionRedirect()
        {
            var auth = GetAuthV3();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.NotNull(userConfig);
            Assert.NotNull(userConfig.Username);
            Assert.NotNull(userConfig.Password);
            auth.Endpoint.Server = "region.keepersecurity.com";
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.Endpoint.Server, DataVault.DefaultEnvironment);
        }

        [Fact]
        public async Task TestLoginV3Success()
        {
            var auth = GetAuthV3();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.NotNull(userConfig);
            Assert.NotNull(userConfig.Username);
            Assert.NotNull(userConfig.Password);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }


        [Fact]
        public async Task TestLoginV3DeviceKeeperPush()
        {
            var auth = GetAuthV3();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.NotNull(userConfig);
            Assert.NotNull(userConfig.Username);
            Assert.NotNull(userConfig.Password);
            var mockUi = Mock.Get(auth.Ui);
            var task = new TaskCompletionSource<bool>();
            var cancelled = false;
            mockUi.Setup(x => x.WaitForDeviceApproval(It.IsAny<IDeviceApprovalChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Callback((IDeviceApprovalChannelInfo[] actions, CancellationToken token) =>
                {
                    var push = actions.Where(x => x.Channel == DeviceApprovalChannel.KeeperPush);
                    if (push != null)
                    {
                    }

                    foreach (var action in actions)
                    {
                        if (action.Channel == DeviceApprovalChannel.KeeperPush)
                        {
                            if (action is IDeviceApprovalPushInfo pi)
                            {
                                Task.Run(async () =>
                                {
                                    await pi.InvokeDeviceApprovalPushAction();
                                });
                            }
                        }
                    }
                })
                .Returns((IDeviceApprovalChannelInfo[] actions, CancellationToken token) =>
                {
                    token.Register(() => { cancelled = true; });
                    return task.Task;
                });

            var cantok = new CancellationTokenSource();
            var ee = Task.Run(async () =>
            {
                await Task.Delay(1000, cantok.Token);
                if (!task.Task.IsCompleted)
                {
                    task.SetCanceled();
                }
            }, cantok.Token);
            await auth.Login(userConfig.Username, userConfig.Password);
            task.SetCanceled();
            cantok.Cancel();
            Assert.True(cancelled);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public async Task TestLoginSuccessV3TwoFactorOneTime()
        {
            HasTwoFactor = true;
            var auth = GetAuthV3();
            var mockUi = Mock.Get(auth.Ui);
            mockUi.Setup(ui => ui.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(),It.IsAny<CancellationToken>()))
                .Callback<ITwoFactorChannelInfo[], CancellationToken>(async (channels, token) =>
                {
                    if (channels.Length > 0 && channels[0] is ITwoFactorAppCodeInfo ci)
                    {
                        if (ci is ITwoFactorDurationInfo dur)
                        {
                            dur.Duration = TwoFactorDuration.Every30Days;
                        }

                        await ci.InvokeTwoFactorCodeAction(_vaultEnv.OneTimeToken);
                    }
                })
                .Returns<ITwoFactorChannelInfo[], CancellationToken>((channels, token) =>
                {
                    var src = new TaskCompletionSource<bool>();
                    Task.Run(async () =>
                    {
                        await Task.Delay(TimeSpan.FromSeconds(1), token);
                        src.SetResult(false);
                    });
                    return src.Task;
                });

            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            await auth.Login(userConfig.Username, userConfig.Password);
            Assert.Equal(auth.AuthContext.SessionToken, _vaultEnv.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, _vaultEnv.DataKey);
        }

        [Fact]
        public void TestLoginSuccessV3TwoFactorCancel()
        {
            HasTwoFactor = true;
            var auth = GetAuthV3();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            var authMock = Mock.Get(auth.Ui);
            authMock.Setup(x => x.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(),
                    It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(false));
            Assert.ThrowsAsync<Exception>(() => auth.Login(userConfig.Username, userConfig.Password));
        }

        [Fact]
        public void TestLoginV3Failed()
        {
            HasTwoFactor = false;
            var auth = GetAuthV3();
            var userConfig = auth.Storage.Users.Get(auth.Storage.LastLogin);
            Assert.ThrowsAsync<KeeperApiException>(() => auth.Login(userConfig.Username, "123456"));
        }


        private Device ProcessRegisterDevice(IKeeperEndpoint endpoint, DeviceRegistrationRequest request)
        {
            var kInfo = new KInfoDevice
            {
                Token = CryptoUtils.GetRandomBytes(32),
                PublicKey = request.DevicePublicKey.ToByteArray()
            };
            kInfo.Environment.Add(endpoint.Server);
            _vaultEnv.KInfoDevices.Add(kInfo);
            return new Device
            {
                EncryptedDeviceToken = ByteString.CopyFrom(kInfo.Token)
            };
        }

        private KInfoDevice GetKInfoDevice(byte[] deviceToken)
        {
            return _vaultEnv.KInfoDevices.FirstOrDefault(x => x.Token.SequenceEqual(deviceToken));
        }

        private void ProcessUpdateDevice(IKeeperEndpoint endpoint, DeviceUpdateRequest request)
        {
            var kInfo = GetKInfoDevice(request.EncryptedDeviceToken.ToByteArray());

            if (kInfo == null)
            {
                if (!request.EncryptedDeviceToken.SequenceEqual(_vaultEnv.DeviceId)) throw new KeeperInvalidDeviceToken("invalid device id");
                if (request.DevicePublicKey == null || request.DevicePublicKey.Length == 0) throw new KeeperInvalidDeviceToken("missing public key");

                kInfo = new KInfoDevice
                {
                    PublicKey = request.DevicePublicKey.ToByteArray(),
                    Token = _vaultEnv.DeviceId
                };
                kInfo.Environment.Add(endpoint.Server);
            }
            else
            {
                if (request.DeviceStatus == DeviceStatus.DeviceDisabledByUser)
                {
                    _vaultEnv.KInfoDevices.Remove(kInfo);
                }
                else
                {
                    if (kInfo.Environment.Contains(endpoint.Server))
                    {
                        if (request.DevicePublicKey != null)
                        {
                            throw new KeeperInvalidDeviceToken("missing public key");
                        }
                    }
                    else
                    {
                        if (request.DevicePublicKey != null)
                        {
                            kInfo.Environment.Add(endpoint.Server);
                        }
                    }
                }
            }
        }

        private Authentication.LoginResponse ProcessStartLogin(IKeeperEndpoint endpoint, StartLoginRequest request)
        {
            KInfoDevice kInfo = null;
            string username = null;
            LoginTokenState loginToken = null;

            if (request.EncryptedLoginToken != null && request.EncryptedLoginToken.Length > 0)
            {
                loginToken = _loginTokens[request.EncryptedLoginToken.ToByteArray().Base64UrlEncode()];
                if (loginToken == null)
                {
                    throw new KeeperInvalidDeviceToken("invalid login token");
                }

                kInfo = GetKInfoDevice(loginToken.DeviceToken);
                username = loginToken.Username;
            }
            else if (request.EncryptedDeviceToken != null && request.EncryptedDeviceToken.Length > 0)
            {
                kInfo = GetKInfoDevice(request.EncryptedDeviceToken.ToByteArray());
                username = request.Username;
            }

            if (kInfo == null)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            if (!kInfo.Environment.Contains(endpoint.Server))
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }


            if (loginToken == null)
            {
                loginToken = new LoginTokenState(kInfo.Token, username)
                {
                    LoginState = LoginState.InvalidLoginstate,
                };
                _loginTokens[loginToken.LoginToken.Base64UrlEncode()] = loginToken;
            }

            var response = new Authentication.LoginResponse
            {
                EncryptedLoginToken = ByteString.CopyFrom(loginToken.LoginToken),
            };

            if (!kInfo.ApprovedUser.Contains(username))
            {
                loginToken.LoginState = LoginState.DeviceApprovalRequired;
            }

            else if (HasTwoFactor && !kInfo.TwoFactorUser.Contains(username))
            {
                loginToken.LoginState = LoginState.Requires2Fa;
                response.Channels.Add(new TwoFactorChannelInfo
                {
                    ChannelType = TwoFactorChannelType.TwoFaCtTotp,
                    ChannelName = "Google Authenticator",
                    ChannelUid = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(16))
                });
            }

            else if (kInfo.UserDataKey.ContainsKey(username))
            {
                loginToken.LoginState = LoginState.LoggedIn;

                response.AccountUid = ByteString.CopyFrom(_vaultEnv.AccountUid);
                response.PrimaryUsername = username;
                response.EncryptedDataKey = ByteString.CopyFrom(kInfo.UserDataKey[username]);
                response.EncryptedDataKeyType = EncryptedDataKeyType.ByDevicePublicKey;
                response.EncryptedSessionToken = ByteString.CopyFrom(_vaultEnv.SessionToken);
                response.SessionTokenType = SessionTokenType.NoRestriction;
                response.EncryptedLoginToken = ByteString.CopyFrom(loginToken.LoginToken);
            }
            else
            {
                loginToken.LoginState = LoginState.RequiresAuthHash;
                response.Salt.Add(new Salt
                {
                    Salt_ = ByteString.CopyFrom(_vaultEnv.Salt),
                    Iterations = _vaultEnv.Iterations,
                    Name = "Master"
                });
            }

            response.LoginState = loginToken.LoginState;
            return response;
        }

        private Authentication.LoginResponse ProcessValidateAuth(ValidateAuthHashRequest request)
        {
            var loginToken = _loginTokens[request.EncryptedLoginToken.ToByteArray().Base64UrlEncode()];
            if (loginToken == null)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            if (loginToken.LoginState != LoginState.RequiresAuthHash)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            var kInfo = GetKInfoDevice(loginToken.DeviceToken);
            if (kInfo == null)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            var username = loginToken.Username;
            if (!kInfo.ApprovedUser.Contains(username))
            {
                throw new KeeperApiException("bad_request", "It should not be bad_request");
            }

            var authHash = CryptoUtils.DeriveV1KeyHash(_vaultEnv.Password, _vaultEnv.Salt, _vaultEnv.Iterations);
            if (!authHash.SequenceEqual(request.AuthResponse))
            {
                throw new KeeperAuthFailed();
            }

            return new Authentication.LoginResponse
            {
                PrimaryUsername = username,
                EncryptedDataKey = ByteString.CopyFrom(_vaultEnv.EncryptionParams.Base64UrlDecode()),
                EncryptedDataKeyType = EncryptedDataKeyType.ByPassword,
                EncryptedSessionToken = ByteString.CopyFrom(_vaultEnv.SessionToken),
                SessionTokenType = SessionTokenType.NoRestriction,
                EncryptedLoginToken = ByteString.CopyFrom(loginToken.LoginToken),
            };
        }

        void Process2faValidate(TwoFactorValidateRequest request)
        {
            var loginToken = _loginTokens[request.EncryptedLoginToken.ToByteArray().Base64UrlEncode()];
            if (loginToken == null)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            if (loginToken.LoginState != LoginState.Requires2Fa)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            var kInfo = GetKInfoDevice(loginToken.DeviceToken);
            if (kInfo == null)
            {
                throw new KeeperInvalidDeviceToken("invalid device token");
            }

            var username = loginToken.Username;
            if (!kInfo.ApprovedUser.Contains(username))
            {
                throw new KeeperApiException("bad_request", "It should not be bad_request");
            }

            if (request.Value != _vaultEnv.OneTimeToken)
            {
                throw new KeeperAuthFailed();
            }

            kInfo.TwoFactorUser.Add(username);
            loginToken.LoginState = LoginState.RequiresAuthHash;
        }

        void AcceptDeviceVerificationRequest(string username, byte[] deviceToken)
        {
            var kInfo = GetKInfoDevice(deviceToken);
            kInfo?.ApprovedUser.Add(username);
        }

        private Auth GetAuthV3()
        {
            var storage = DataVault.GetConfigurationStorage();
            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.Setup(e => e.ClientVersion).Returns(TestClientVersion);
            mEndpoint.Setup(e => e.DeviceName).Returns(".NET Unit Tests");
            var server = DataVault.DefaultEnvironment;
            mEndpoint.SetupGet(e => e.Server).Returns(server);
            mEndpoint.SetupSet(e => e.Server = It.IsAny<string>()).Callback((string value) => { server = value; });

            var mUi = new Mock<IAuthUI>();

            var mAuth = new Mock<Auth>(mUi.Object, storage, mEndpoint.Object);
            var auth = mAuth.Object;

            var webSocket = new TestWebSocket();
            mAuth.Setup(x => x.ConnectToPushServer(It.IsAny<WssConnectionRequest>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<IFanOut<NotificationEvent>>(webSocket));


            mUi.Setup(x => x.WaitForDeviceApproval(It.IsAny<IDeviceApprovalChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Callback((IDeviceApprovalChannelInfo[] x, CancellationToken y) =>
                {
                    AcceptDeviceVerificationRequest(auth.Username, auth.DeviceToken);
                })
                .Returns((IDeviceApprovalChannelInfo[] x, CancellationToken y) => Task.FromResult(true));
            var passwordReturned = false;
            mUi.Setup(x => x.WaitForUserPassword(It.IsAny<IPasswordInfo>(), It.IsAny<CancellationToken>()))
                .Callback(async (IPasswordInfo info, CancellationToken token) =>
                {
                    if (passwordReturned) return;
                    passwordReturned = true;
                    await info.InvokePasswordActionDelegate(_vaultEnv.Password);
                })
                .Returns((IPasswordInfo info, CancellationToken token) =>
                {
                    var src = new TaskCompletionSource<bool>();
                    Task.Run(async () =>
                    {
                        await Task.Delay(TimeSpan.FromSeconds(1), token);
                        src.SetResult(false);
                    });
                    return src.Task;
                });
            var tfaCodeReturned = false;
            mUi.Setup(x => x.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Callback(async (ITwoFactorChannelInfo[] info, CancellationToken token) =>
                {
                    if (tfaCodeReturned) return;
                    tfaCodeReturned = true;
                    if (info?.Length > 0 && info[0] is ITwoFactorAppCodeInfo ci)
                    {
                        await ci.InvokeTwoFactorCodeAction(_vaultEnv.OneTimeToken);
                    }
                })
                .Returns((ITwoFactorChannelInfo[] info, CancellationToken token) =>
                {
                    var src = new TaskCompletionSource<bool>();
                    Task.Run(async () =>
                    {
                        await Task.Delay(TimeSpan.FromSeconds(1), token);
                        src.SetResult(false);
                    });
                    return src.Task;
                });

            mEndpoint.Setup(e => e.ExecuteRest(It.IsAny<string>(), It.IsAny<ApiRequestPayload>()))
                .Returns((string endpoint, ApiRequestPayload payload) =>
                {
                    if (mEndpoint.Object.Server != DataVault.DefaultEnvironment)
                    {
                        throw new KeeperRegionRedirect(DataVault.DefaultEnvironment);
                    }

                    try
                    {
                        switch (endpoint)
                        {
                            case "authentication/register_device":
                            {
                                var rq = DeviceRegistrationRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                var rs = ProcessRegisterDevice(mEndpoint.Object, rq);
                                return Task.FromResult(rs.ToByteArray());
                            }
                            case "authentication/update_device":
                            {
                                var rq = DeviceUpdateRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                ProcessUpdateDevice(mEndpoint.Object, rq);
                                return Task.FromResult(new byte[0]);
                            }
                            case "authentication/start_login":
                            {
                                var rq = StartLoginRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                var rs = ProcessStartLogin(mEndpoint.Object, rq);
                                return Task.FromResult(rs.ToByteArray());
                            }
                            case "authentication/validate_auth_hash":
                            {
                                var rq = ValidateAuthHashRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                var rs = ProcessValidateAuth(rq);
                                return Task.FromResult(rs.ToByteArray());
                            }
                            case "authentication/request_device_verification":
                            {
                                var rq = DeviceVerificationRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                AcceptDeviceVerificationRequest(rq.Username, rq.EncryptedDeviceToken.ToByteArray());
                                return Task.FromResult(new byte[0]);
                            }
                            case "authentication/2fa_validate":
                            {
                                var rq = TwoFactorValidateRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                Process2faValidate(rq);
                                return Task.FromResult(new byte[0]);
                            }
                            case "authentication/2fa_send_push":
                            {
                                var rq = TwoFactorSendPushRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                var loginToken = _loginTokens[rq.EncryptedLoginToken.ToByteArray().Base64UrlEncode()];
                                if (loginToken.LoginState == LoginState.DeviceApprovalRequired)
                                {
                                    AcceptDeviceVerificationRequest(loginToken.Username, loginToken.DeviceToken);
                                    webSocket.Push(new NotificationEvent
                                    {
                                        Approved = true,
                                        Message = "device_approved"
                                    });
                                }

                                return Task.FromResult(new byte[0]);
                            }
                            case "login/account_summary":
                            {
                                var rq = AccountSummaryRequest.Parser.ParseFrom(payload.Payload.ToByteArray());
                                var rs = ProcessAccountSummary(auth);
                                return Task.FromResult(rs.ToByteArray());
                            }
                        }

                        throw new KeeperApiException("invalid_command", endpoint);
                    }
                    catch (Exception e)
                    {
                        return Task.FromException<byte[]>(e);
                    }
                });
            return auth;
        }

        private AccountSummaryElements ProcessAccountSummary(IAuth auth)
        {
            var device = _vaultEnv.KInfoDevices.First(x => auth.DeviceToken.SequenceEqual(x.Token));
            return new AccountSummaryElements
            {
                ClientKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(_vaultEnv.ClientKey, _vaultEnv.DataKey)),
                IsEnterpriseAdmin = false,
                KeysInfo = new KeysInfo
                {
                    EncryptionParams = ByteString.CopyFrom(_vaultEnv.EncryptionParams.Base64UrlDecode()),
                    EncryptedPrivateKey = ByteString.CopyFrom(_vaultEnv.EncryptedPrivateKey.Base64UrlDecode()),
                },
                Devices =
                {
                    new DeviceInfo
                    {
                        ClientVersion = TestClientVersion,
                        DeviceName = "Test Device",
                        DeviceStatus = DeviceStatus.DeviceOk,
                        EncryptedDeviceToken = ByteString.CopyFrom(device.Token),
                        DevicePublicKey = ByteString.CopyFrom(device.PublicKey),
                    }
                },
                Settings = new Settings
                {
                    
                },
                License = new AccountSummary.License
                {
                    
                }
            };
        }
    }

    public class TestWebSocket : FanOut<NotificationEvent>, IPushNotificationChannel
    {
        public Task SendToWebSocket(byte[] payload, bool encrypted)
        {
            return Task.CompletedTask;
        }
    }
}
