using System;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using Moq;
using Xunit;

namespace Tests
{
    public class AuthSyncCallback : IAuthSyncCallback
    {
        private Action _onNextStep;

        public void OnNextStep()
        {
            _onNextStep?.Invoke();
        }

        public void SetOnNextStep(Action doOnNext)
        {
            _onNextStep = doOnNext;
        }
    }

    public class AuthSyncTest : AuthMockParameters
    {
        private AuthSync GetAuthSync()
        {
            var storage = DataVault.GetConfigurationStorage();
            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.SetupGet(e => e.ClientVersion)
                .Returns(DataVault.TestClientVersion);
            mEndpoint.SetupGet(e => e.DeviceName)
                .Returns(".NET Unit Tests");
            mEndpoint.SetupGet(e => e.ServerKeyId)
                .Returns(1);
            mEndpoint.SetupProperty(e => e.Server);
            mEndpoint.Object.Server = DataVault.DefaultEnvironment;

            var mFlow = new Mock<AuthSync>(storage, mEndpoint.Object) {CallBase = true};
            var flow = mFlow.Object;

            mEndpoint.Setup(e => e.ExecuteRest(
                    It.IsAny<string>(),
                    It.IsAny<ApiRequestPayload>()))
                .Returns((string endpoint, ApiRequestPayload payload) => MockExecuteRest(endpoint, payload, flow));

            flow.UiCallback = new AuthSyncCallback();
            return flow;
        }

        [Fact]
        public async Task TestSuccessFlow()
        {
            ResetStops();

            var auth = GetAuthSync();
            auth.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), auth.Step.GetType());
            await auth.Login(DataVault.UserName);
            Assert.Equal(typeof(ConnectedStep), auth.Step.GetType());

            Assert.Equal(auth.AuthContext.SessionToken, DataVault.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, DataVault.UserDataKey);
        }

        [Fact]
        public async Task TestRegionRedirect()
        {
            ResetStops();

            var auth = GetAuthSync();
            auth.Endpoint.Server = "region.keepersecurity.com";
            await auth.Login(DataVault.UserName);
            Assert.Equal(DataVault.DefaultEnvironment, auth.Endpoint.Server);
            Assert.True(auth.IsAuthenticated());
        }

        [Fact]
        public async Task TestPasswordFlow()
        {
            ResetStops();
            StopAtPassword = true;

            var flow = GetAuthSync();
            flow.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);
            Assert.Equal(typeof(PasswordStep), flow.Step.GetType());
            await ((PasswordStep) flow.Step).VerifyPassword(DataVault.UserPassword);
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestDeviceApproveEmailCode()
        {
            ResetStops();
            StopAtDeviceApproval = true;

            var flow = GetAuthSync();
            flow.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), flow.Step.GetType());
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
            ResetStops();
            StopAtDeviceApproval = true;

            var flow = GetAuthSync();
            flow.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);

            Assert.Equal(typeof(DeviceApprovalStep), flow.Step.GetType());
            var das = (DeviceApprovalStep) flow.Step;

            var evt = new ManualResetEventSlim();
            ((AuthSyncCallback) flow.UiCallback).SetOnNextStep(() =>
            {
                if (flow.Step.State == AuthState.Connected)
                {
                    evt.Set();
                }
            });
            await das.SendPush(DeviceApprovalChannel.Email);
            StopAtDeviceApproval = false;
            flow.PushNotifications.Push(new NotificationEvent
            {
                Command = "device_verified",
            });

            Assert.True(evt.Wait(TimeSpan.FromMilliseconds(100)));

            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestDeviceApproveKeeperPush()
        {
            ResetStops();
            StopAtDeviceApproval = true;

            var flow = GetAuthSync();
            flow.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), flow.Step.GetType());
            await flow.Login(DataVault.UserName);

            Assert.Equal(typeof(DeviceApprovalStep), flow.Step.GetType());
            var das = (DeviceApprovalStep) flow.Step;

            var evt = new ManualResetEventSlim();
            ((AuthSyncCallback) flow.UiCallback).SetOnNextStep(() =>
            {
                if (flow.Step.State == AuthState.Connected)
                {
                    evt.Set();
                }
            });
            await das.SendPush(DeviceApprovalChannel.KeeperPush);
                StopAtDeviceApproval = false;
                flow.PushNotifications.Push(new NotificationEvent
                {
                    Message = "device_approved",
                    Approved = true,
                });

            Assert.True(evt.Wait(TimeSpan.FromMilliseconds(100)));

            var sss = flow.Step.State;
            Assert.Equal(typeof(ConnectedStep), flow.Step.GetType());
        }

        [Fact]
        public async Task TestTwoFactorCode()
        {
            ResetStops();
            StopAtTwoFactor = true;

            var flow = GetAuthSync();
            flow.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), flow.Step.GetType());
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
        public async Task TestSuccessWithPassword()
        {
            ResetStops();
            StopAtPassword = true;

            var flow = GetAuthSync();
            flow.Cancel();

            Assert.Equal(typeof(ReadyToLoginStep), flow.Step.GetType());
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
