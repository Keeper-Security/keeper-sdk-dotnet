using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using Moq;
using Push;
using Xunit;

namespace Tests
{
    public class OnceAuthSyncCallback : IAuthSyncCallback
    {
        private Action _onNextStep;
        public void OnNextStep()
        {
            _onNextStep?.Invoke();
            _onNextStep = null;
        }

        public void SetOnNextStep(Action doOnNext)
        {
            _onNextStep = doOnNext;
        }
    }

    public class AuthFlowTest
    {
        private bool StopAtDeviceApproval { get; set; }
        private bool StopAtTwoFactor { get; set; }
        private bool StopAtPassword { get; set; }
        private static byte[] encryptedLoginToken = CryptoUtils.GetRandomBytes(64);

        private Task<byte[]> MockExecuteRest(string endpoint, ApiRequestPayload payload, IAuth auth)
        {
            byte[] response = null;
            switch (endpoint)
            {
                case "authentication/register_device":
                {
                    var device = new Device()
                    {
                        EncryptedDeviceToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(64)),
                    };
                    response = device.ToByteArray();
                }
                    break;
                case "authentication/start_login":
                {
                    var lrs = new LoginResponse
                    {
                        EncryptedLoginToken = ByteString.CopyFrom(encryptedLoginToken),

                    };
                    if (StopAtDeviceApproval)
                    {
                        lrs.LoginState = LoginState.DeviceApprovalRequired;
                    }
                    else if (StopAtTwoFactor)
                    {
                        lrs.LoginState = LoginState.Requires2Fa;
                        lrs.Channels.Add(new TwoFactorChannelInfo
                        {
                            ChannelType = TwoFactorChannelType.TwoFaCtTotp,
                            ChannelUid = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8)),
                            ChannelName = "Mock",
                        });
                    }
                    else if (StopAtPassword)
                    {
                        lrs.LoginState = LoginState.RequiresAuthHash;
                        lrs.Salt.Add(new Salt
                        {
                            Iterations = DataVault.UserIterations,
                            Salt_ = ByteString.CopyFrom(DataVault.UserSalt),
                            Name = "Mock",
                            Uid = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8)),
                        });
                    }
                    else
                    {
                        lrs.LoginState = LoginState.LoggedIn;
                        lrs.AccountUid = ByteString.CopyFrom(DataVault.AccountUid);
                        lrs.PrimaryUsername = DataVault.UserName;
                        lrs.CloneCode = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8));
                        lrs.EncryptedSessionToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(64));
                        var device = auth.Storage.Devices.List.FirstOrDefault();
                        var devicePrivateKey = CryptoUtils.LoadPrivateEcKey(device.DeviceKey);
                        var devicePublicKey = CryptoUtils.GetPublicEcKey(devicePrivateKey);
                        lrs.EncryptedDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(DataVault.UserDataKey, devicePublicKey));
                        lrs.EncryptedDataKeyType = EncryptedDataKeyType.ByDevicePublicKey;
                    }

                    response = lrs.ToByteArray();
                }
                    break;

                case "authentication/validate_auth_hash":
                {
                    var lrs = new LoginResponse
                    {
                        LoginState = LoginState.LoggedIn,
                        EncryptedLoginToken = ByteString.CopyFrom(encryptedLoginToken),
                        AccountUid = ByteString.CopyFrom(DataVault.AccountUid),
                        PrimaryUsername = DataVault.UserName,
                        CloneCode = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(8)),
                        EncryptedSessionToken = ByteString.CopyFrom(CryptoUtils.GetRandomBytes(64)),
                        EncryptedDataKey = ByteString.CopyFrom(DataVault.EncryptionParams),
                        EncryptedDataKeyType = EncryptedDataKeyType.ByPassword,
                    };
                    response = lrs.ToByteArray();
                }
                break;

                case "authentication/request_device_verification":
                    StopAtDeviceApproval = false;
                    response = new byte[0];
                    break;

                case "authentication/2fa_send_push":
                    if (StopAtDeviceApproval)
                    {
                        StopAtDeviceApproval = false;
                    }

                    response = new byte[0];
                    break;

                case "authentication/2fa_validate":
                    var tfvr = TwoFactorValidateRequest.Parser.ParseFrom(payload.Payload);
                    if (tfvr.Value == DataVault.TwoFactorOneTimeToken)
                    {
                        StopAtTwoFactor = false;
                        var tfars = new TwoFactorValidateResponse
                        {
                            EncryptedLoginToken = tfvr.EncryptedLoginToken
                        };
                        response = tfars.ToByteArray();
                    }
                    else
                    {
                        return Task.FromException<byte[]>(new KeeperAuthFailed());
                    }
                    break;

                case "vault/execute_v2_command":
                    break;

                case "authentication/validate_device_verification_code":
                    var vdvcr = ValidateDeviceVerificationCodeRequest.Parser.ParseFrom(payload.Payload);
                    if (vdvcr.VerificationCode == DataVault.DeviceVerificationEmailCode)
                    {
                        StopAtDeviceApproval = false;
                        response = new byte[0];
                    }
                    else
                    {
                        return Task.FromException<byte[]>(new KeeperAuthFailed());
                    }

                    break;
                case "login/account_summary":
                {
                    var device = auth.Storage.Devices.List.FirstOrDefault();
                    var asrs = new AccountSummaryElements
                    {
                        ClientKey = ByteString.CopyFrom(
                            CryptoUtils.EncryptAesV1(
                                CryptoUtils.GetRandomBytes(16), 
                                DataVault.UserDataKey)),
                        IsEnterpriseAdmin = false,
                        KeysInfo = new KeysInfo
                        {
                            EncryptionParams = ByteString.CopyFrom(DataVault.EncryptionParams),
                            EncryptedPrivateKey = ByteString.CopyFrom(DataVault.EncryptedPrivateKey),
                        },
                        Devices =
                        {
                            new DeviceInfo
                            {
                                ClientVersion = LoginV3Test.TestClientVersion,
                                DeviceName = "Test Device",
                                DeviceStatus = DeviceStatus.DeviceOk,
                                EncryptedDeviceToken = ByteString.CopyFrom(device.DeviceToken.Base64UrlDecode()),
                                DevicePublicKey = ByteString.CopyFrom(device.DeviceKey),
                            }
                        },
                        Settings = new Settings
                        {

                        },
                        License = new AccountSummary.License
                        {

                        }
                    };
                    response = asrs.ToByteArray();
                }
                    break;
            }

            if (response != null)
            {
                return Task.FromResult(response);
            }

            return Task.FromException<byte[]>(new KeeperCanceled());
        }

        private AuthSync getAuthFlow()
        {
            var storage = DataVault.GetConfigurationStorage();
            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.SetupGet(e => e.ClientVersion)
                .Returns(LoginV3Test.TestClientVersion);
            mEndpoint.SetupGet(e => e.DeviceName)
                .Returns(".NET Unit Tests");
            mEndpoint.SetupGet(e => e.ServerKeyId)
                .Returns(1);
            var server = DataVault.DefaultEnvironment;
            mEndpoint.SetupGet(e => e.Server)
                .Returns(server);
            mEndpoint.SetupSet(e => e.Server = It.IsAny<string>())
                .Callback((string value) => { server = value; });

            var webSocket = new TestWebSocket();
            mEndpoint.Setup(x => x.ConnectToPushServer(It.IsAny<WssConnectionRequest>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult<IFanOut<NotificationEvent>>(webSocket));

            var flow = new AuthSync(storage, mEndpoint.Object);

            mEndpoint.Setup(e => e.ExecuteRest(
                    It.IsAny<string>(), It.IsAny<ApiRequestPayload>()))
                .Returns((string endpoint, ApiRequestPayload payload) => MockExecuteRest(endpoint, payload, flow));

            flow.UiCallback = new OnceAuthSyncCallback();
            return flow;
        }

        [Fact]
        public async Task TestSuccessFlow()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = false;
            StopAtTwoFactor = false;
            StopAtPassword = false;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestPasswordFlow()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = false;
            StopAtTwoFactor = false;
            StopAtPassword = true;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);
            Assert.Equal(typeof(PasswordStep), flow.Step.GetType());
            await ((PasswordStep) flow.Step).VerifyPassword(DataVault.UserPassword);
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestDeviceApproveEmailCode()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = true;
            StopAtTwoFactor = false;
            StopAtPassword = false;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);

            Assert.Equal(typeof(DeviceApprovalStep), flow.Step.GetType());
            var das = (DeviceApprovalStep) flow.Step;

            await Assert.ThrowsAsync<KeeperAuthFailed>(async () =>
            {
                await das.SendCode(DeviceApprovalChannel.Email, "wrong code");
            });
            Assert.Equal(typeof(DeviceApprovalStep), flow.Step.GetType());

            await das.SendCode(DeviceApprovalChannel.Email,  DataVault.DeviceVerificationEmailCode);
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestDeviceApproveEmailPush()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = true;
            StopAtTwoFactor = false;
            StopAtPassword = false;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);

            Assert.Equal(typeof(DeviceApprovalStep), flow.Step.GetType());
            var das = (DeviceApprovalStep) flow.Step;

            var evt = new AutoResetEvent(false);
            ((OnceAuthSyncCallback) flow.UiCallback).SetOnNextStep(() =>
            {
                evt.Set();
            });
            await das.SendPush(DeviceApprovalChannel.Email);
            _ = Task.Run(() =>
            {
                StopAtDeviceApproval = false;
                flow.PushNotifications.Push(new NotificationEvent
                {
                    Command = "device_verified",
                });
            });

            evt.WaitOne(TimeSpan.FromSeconds(1));

            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestDeviceApproveKeeperPush()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = true;
            StopAtTwoFactor = false;
            StopAtPassword = false;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);

            Assert.Equal(typeof(DeviceApprovalStep), flow.Step.GetType());
            var das = (DeviceApprovalStep) flow.Step;

            var evt = new AutoResetEvent(false);
            ((OnceAuthSyncCallback) flow.UiCallback).SetOnNextStep(() =>
            {
                evt.Set();
            });
            await das.SendPush(DeviceApprovalChannel.KeeperPush);
            _ = Task.Run(() =>
            {
                flow.PushNotifications.Push(new NotificationEvent
                {
                    Message = "device_approved",
                    Approved = true,
                });
            });

            evt.WaitOne(TimeSpan.FromSeconds(1));

            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestTwoFactorCode()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = false;
            StopAtTwoFactor = true;
            StopAtPassword = false;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);

            Assert.Equal(typeof(TwoFactorStep), flow.Step.GetType());
            var tfs = (TwoFactorStep) flow.Step;

            tfs.Duration = TwoFactorDuration.EveryLogin;
            await Assert.ThrowsAsync<KeeperAuthFailed>(async () =>
            {
                await tfs.OnSendCode(tfs.DefaultChannel, "wrong code");
            });
            Assert.Equal(typeof(TwoFactorStep), flow.Step.GetType());

            await tfs.OnSendCode(tfs.DefaultChannel, DataVault.TwoFactorOneTimeToken);
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestInterruptAtPasswordFlow()
        {
            var flow = getAuthFlow();
            flow.Cancel();
            StopAtDeviceApproval = false;
            StopAtTwoFactor = false;
            StopAtPassword = true;

            Assert.Equal(typeof(LoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);
            Assert.Equal(typeof(PasswordStep), flow.Step.GetType());

            flow.Cancel();
            await flow.Login(DataVault.UserName);
            Assert.Equal(typeof(PasswordStep), flow.Step.GetType());
            await ((PasswordStep) flow.Step).VerifyPassword(DataVault.UserPassword);
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }
    }
}
