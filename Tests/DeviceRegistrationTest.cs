using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using Moq;
using Xunit;

namespace Tests
{
    public class DeviceRegistrationTest : AuthMockParameters
    {
        // A device registered with a Keeper server the test server is not a region of:
        // it has a key pair but no server info for DataVault.DefaultEnvironment.
        private static string AddForeignDevice(IConfigurationStorage storage)
        {
            CryptoUtils.GenerateEcKey(out var privateKey, out _);
            var token = CryptoUtils.GetRandomBytes(34).Base64UrlEncode();
            var configuration = storage.Get();
            configuration.Devices.Put(new DeviceConfiguration(token)
            {
                DeviceKey = CryptoUtils.UnloadEcPrivateKey(privateKey),
            });
            storage.Put(configuration);
            return token;
        }

        private AuthSync GetAuthSync(IConfigurationStorage storage, List<string> calls)
        {
            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.SetupGet(e => e.ClientVersion).Returns(DataVault.TestClientVersion);
            mEndpoint.SetupGet(e => e.DeviceName).Returns(".NET Unit Tests");
            mEndpoint.SetupGet(e => e.ServerKeyId).Returns(1);
            mEndpoint.SetupProperty(e => e.Server);
            mEndpoint.Object.Server = DataVault.DefaultEnvironment;

            var mFlow = new Mock<AuthSync>(storage, mEndpoint.Object) { CallBase = true };
            var flow = mFlow.Object;
            flow.SetPushNotifications(new FanOut<NotificationEvent>());
            mEndpoint.Setup(e => e.ExecuteRest(It.IsAny<string>(), It.IsAny<ApiRequestPayload>()))
                .Returns((string endpoint, ApiRequestPayload payload) =>
                {
                    calls.Add(endpoint);
                    if (endpoint == "authentication/register_device_in_region")
                    {
                        // What a server answers for a device token it did not issue.
                        return Task.FromException<byte[]>(new KeeperInvalidDeviceToken("device_not_registered"));
                    }

                    return MockExecuteRest(endpoint, payload, flow);
                });
            flow.UiCallback = new AuthSyncCallback();
            return flow;
        }

        [Fact]
        public async Task RegistersNewDeviceWhenRegionRejectsForeignDevice()
        {
            ResetStops();
            var storage = DataVault.GetConfigurationStorage();
            var foreignToken = AddForeignDevice(storage);
            var calls = new List<string>();

            var auth = GetAuthSync(storage, calls);
            await auth.Login(DataVault.UserName);

            Assert.True(auth.IsAuthenticated());
            Assert.Equal(
                new[] { "authentication/register_device_in_region", "authentication/register_device" },
                calls.Where(c => c.StartsWith("authentication/register_device")).ToArray());

            var configuration = storage.Get();
            // The foreign device is kept for the server that issued it.
            Assert.NotNull(configuration.Devices.Get(foreignToken));
            // The new device is the one logged in with, and is bound to this server.
            var current = configuration.Devices.Get(auth.DeviceToken.Base64UrlEncode());
            Assert.NotEqual(foreignToken, current.DeviceToken);
            Assert.NotNull(current.ServerInfo.Get(DataVault.DefaultEnvironment));
        }

        [Fact]
        public async Task OtherRegionErrorsAreNotTreatedAsUnknownDevice()
        {
            ResetStops();
            var storage = DataVault.GetConfigurationStorage();
            AddForeignDevice(storage);

            var mEndpoint = new Mock<IKeeperEndpoint>();
            mEndpoint.SetupGet(e => e.ClientVersion).Returns(DataVault.TestClientVersion);
            mEndpoint.SetupGet(e => e.DeviceName).Returns(".NET Unit Tests");
            mEndpoint.SetupGet(e => e.ServerKeyId).Returns(1);
            mEndpoint.SetupProperty(e => e.Server);
            mEndpoint.Object.Server = DataVault.DefaultEnvironment;
            var flow = new Mock<AuthSync>(storage, mEndpoint.Object) { CallBase = true }.Object;
            flow.SetPushNotifications(new FanOut<NotificationEvent>());
            var registered = false;
            mEndpoint.Setup(e => e.ExecuteRest(It.IsAny<string>(), It.IsAny<ApiRequestPayload>()))
                .Returns((string endpoint, ApiRequestPayload payload) =>
                {
                    if (endpoint == "authentication/register_device_in_region")
                        return Task.FromException<byte[]>(new KeeperApiException("throttled", "try again later"));
                    if (endpoint == "authentication/register_device") registered = true;
                    return MockExecuteRest(endpoint, payload, flow);
                });
            flow.UiCallback = new AuthSyncCallback();

            await flow.Login(DataVault.UserName);

            // The error ends the login; it does not trigger a new device registration.
            Assert.False(flow.IsAuthenticated());
            var error = Assert.IsType<ErrorStep>(flow.Step);
            Assert.Equal("throttled", error.Code);
            Assert.False(registered);
        }
    }
}
