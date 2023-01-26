using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;
using KeeperSecurity.Utils;
using Moq;
using Push;
using Xunit;

namespace Tests
{
    public class AuthAsyncTest : AuthMockParameters
    {
        [Fact]
        public async Task TestLoginV3Success()
        {
            ResetStops();

            var auth = GetAuthAsync();
            await auth.Login(DataVault.UserName);
            Assert.Equal(auth.AuthContext.SessionToken, DataVault.SessionToken);
            Assert.Equal(auth.AuthContext.DataKey, DataVault.UserDataKey);
        }

        [Fact]
        public async Task TestRegionRedirect()
        {
            ResetStops();

            var auth = GetAuthAsync();
            auth.Endpoint.Server = "region.keepersecurity.com";
            await auth.Login(DataVault.UserName);
            Assert.Equal(DataVault.DefaultEnvironment, auth.Endpoint.Server);
            Assert.True(auth.IsAuthenticated());
        }

        [Fact]
        public async Task TestDeviceApproveEmailCode()
        {
            ResetStops();
            StopAtDeviceApproval = true;

            var auth = GetAuthAsync();
            var mockUi = Mock.Get(auth.Ui);

            var task = new TaskCompletionSource<bool>();
            var cancelled = false;
            mockUi.Setup(x => x.WaitForDeviceApproval(It.IsAny<IDeviceApprovalChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Returns((IDeviceApprovalChannelInfo[] actions, CancellationToken token) =>
                {
                    token.Register(() => { cancelled = true; });
                    _ = Task.Run(async () =>
                    {
                        var email = actions
                            .OfType<IDeviceApprovalPushInfo>()
                            .First(x => x.Channel == DeviceApprovalChannel.Email);
                        await email.InvokeDeviceApprovalPushAction();
                        _ = Task.Run(() =>
                        {

                            StopAtDeviceApproval = false;
                            auth.PushNotifications.Push(new NotificationEvent
                            {
                                Message = "device_approved",
                                Approved = true,
                            });
                        });
                    });

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
                },
                cantok.Token);
            await auth.Login(DataVault.UserName);
            task.SetCanceled();
            cantok.Cancel();
            Assert.True(cancelled);
            Assert.True(auth.IsAuthenticated());
        }

        [Fact]
        public async Task TestDeviceApproveKeeperPush()
        {
            ResetStops();
            StopAtDeviceApproval = true;

            var auth = GetAuthAsync();
            var mockUi = Mock.Get(auth.Ui);

            var task = new TaskCompletionSource<bool>();
            var cancelled = false;
            mockUi.Setup(x => x.WaitForDeviceApproval(It.IsAny<IDeviceApprovalChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Returns((IDeviceApprovalChannelInfo[] actions, CancellationToken token) =>
                {
                    token.Register(() => { cancelled = true; });
                    _ = Task.Run(async () =>
                    {
                        var push = actions
                            .OfType<IDeviceApprovalPushInfo>()
                            .First(x => x.Channel == DeviceApprovalChannel.KeeperPush);
                        await push.InvokeDeviceApprovalPushAction();
                        _ = Task.Run(() =>
                        {
                            StopAtDeviceApproval = false;
                            auth.PushNotifications.Push(new NotificationEvent
                            {
                                Message = "device_approved",
                                Approved = true,
                            });
                        });
                    });

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
                },
                cantok.Token);
            await auth.Login(DataVault.UserName);
            task.SetCanceled();
            cantok.Cancel();
            Assert.True(cancelled);
            Assert.True(auth.IsAuthenticated());
        }

        [Fact]
        public async Task TestTwoFactorCode()
        {
            ResetStops();
            StopAtTwoFactor = true;

            var auth = GetAuthAsync();
            var mockUi = Mock.Get(auth.Ui);
            mockUi.Setup(ui => ui.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Returns<ITwoFactorChannelInfo[], CancellationToken>((channels, token) =>
                {
                    var src = new TaskCompletionSource<bool>();
                    _ = Task.Run(async () =>
                    {
                        var channel = channels
                            .OfType<ITwoFactorAppCodeInfo>()
                            .First();
                        await channel.InvokeTwoFactorCodeAction(DataVault.TwoFactorOneTimeToken);
                    });
                    return src.Task;
                });

            await auth.Login(DataVault.UserName);
            Assert.True(auth.IsAuthenticated());

        }

        [Fact]
        public void TestLoginSuccessV3TwoFactorCancel()
        {
            ResetStops();
            StopAtTwoFactor = true;

            var auth = GetAuthAsync();
            var authMock = Mock.Get(auth.Ui);
            authMock.Setup(x => x.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(),
                    It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(false));
            Assert.ThrowsAsync<KeeperCanceled>(() => auth.Login(DataVault.UserName));
        }

        [Fact]
        public async Task TestSuccessWithPassword()
        {
            ResetStops();
            StopAtPassword = true;

            var auth = GetAuthAsync();

            var mUi = Mock.Get(auth.Ui);
            mUi.Setup(x => x.WaitForUserPassword(It.IsAny<IPasswordInfo>(), It.IsAny<CancellationToken>()))
                .Returns((IPasswordInfo info, CancellationToken token) =>
                {
                    var src = new TaskCompletionSource<bool>();
                    _ = Task.Run(async () => { await info.InvokePasswordActionDelegate(DataVault.UserPassword); });
                    return src.Task;
                });

            await auth.Login(DataVault.UserName);
        }

        [Fact]
        public void TestFailedWithPassword()
        {
            ResetStops();
            StopAtPassword = true;

            var auth = GetAuthAsync();

            var mUi = Mock.Get(auth.Ui);
            mUi.Setup(x => x.WaitForUserPassword(It.IsAny<IPasswordInfo>(), It.IsAny<CancellationToken>()))
                .Returns((IPasswordInfo info, CancellationToken token) =>
                {
                    var src = new TaskCompletionSource<bool>();
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await Assert.ThrowsAsync<KeeperAuthFailed>(async () =>
                            {
                                await info.InvokePasswordActionDelegate("123456");
                            });
                        }
                        finally
                        {
                            src.TrySetResult(false);
                        }
                    });
                    return src.Task;
                });
            Assert.ThrowsAsync<KeeperCanceled>(() => auth.Login(DataVault.UserPassword));
        }

        internal Auth GetAuthAsync()
        {
            var storage = DataVault.GetConfigurationStorage();
            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.SetupGet(e => e.ClientVersion)
                .Returns(DataVault.TestClientVersion);
            mEndpoint.SetupGet(e => e.DeviceName)
                .Returns(".NET Unit Tests");
            mEndpoint.SetupProperty(e => e.Server);
            mEndpoint.Object.Server = DataVault.DefaultEnvironment;

            var mUi = new Mock<IAuthUI>();

            var mAuth = new Mock<Auth>(mUi.Object, storage, mEndpoint.Object) {CallBase = true};
            var auth = mAuth.Object;

            mEndpoint.Setup(e => e.ExecuteRest(
                    It.IsAny<string>(),
                    It.IsAny<ApiRequestPayload>()))
                .Returns((string endpoint, ApiRequestPayload payload) => MockExecuteRest(endpoint, payload, auth));

            mUi.Setup(x => x.WaitForDeviceApproval(It.IsAny<IDeviceApprovalChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Returns((IDeviceApprovalChannelInfo[] x, CancellationToken y) => Task.FromResult(false));

            mUi.Setup(x => x.WaitForUserPassword(It.IsAny<IPasswordInfo>(), It.IsAny<CancellationToken>()))
                .Returns((IPasswordInfo info, CancellationToken token) => Task.FromResult(false));

            mUi.Setup(x => x.WaitForTwoFactorCode(It.IsAny<ITwoFactorChannelInfo[]>(), It.IsAny<CancellationToken>()))
                .Callback((ITwoFactorChannelInfo[] info, CancellationToken token) => Task.FromResult(false));
            return auth;
        }
    }
}
