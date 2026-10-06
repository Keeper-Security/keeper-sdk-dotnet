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
        // Adds a device to the configuration. When "server" is null the device has a key pair but
        // no server info, as if it had been registered with another Keeper server.
        private static string AddDevice(IConfigurationStorage storage, string server)
        {
            CryptoUtils.GenerateEcKey(out var privateKey, out _);
            var token = CryptoUtils.GetRandomBytes(34).Base64UrlEncode();
            var device = new DeviceConfiguration(token)
            {
                DeviceKey = CryptoUtils.UnloadEcPrivateKey(privateKey),
            };
            if (server != null)
            {
                device.ServerInfo.Put(new DeviceServerConfiguration(server));
            }

            var configuration = storage.Get();
            configuration.Devices.Put(device);
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
                    return MockExecuteRest(endpoint, payload, flow);
                });
            flow.UiCallback = new AuthSyncCallback();
            return flow;
        }

        [Fact]
        public async Task RegistersNewDeviceWhenConfiguredDeviceBelongsToAnotherServer()
        {
            ResetStops();
            var storage = DataVault.GetConfigurationStorage();
            var foreignToken = AddDevice(storage, null);
            var calls = new List<string>();

            var auth = GetAuthSync(storage, calls);
            await auth.Login(DataVault.UserName);

            Assert.True(auth.IsAuthenticated());
            // The device is never offered to a server it was not registered with.
            Assert.Equal(
                new[] { "authentication/register_device" },
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
        public async Task ReusesDeviceRegisteredWithServer()
        {
            ResetStops();
            var storage = DataVault.GetConfigurationStorage();
            var foreignToken = AddDevice(storage, null);
            var ownToken = AddDevice(storage, DataVault.DefaultEnvironment);
            var calls = new List<string>();

            var auth = GetAuthSync(storage, calls);
            await auth.Login(DataVault.UserName);

            Assert.True(auth.IsAuthenticated());
            // The device registered with this server is reused, so nothing is registered.
            Assert.DoesNotContain(calls, c => c.StartsWith("authentication/register_device"));
            Assert.Equal(ownToken, auth.DeviceToken.Base64UrlEncode());
            Assert.NotEqual(foreignToken, auth.DeviceToken.Base64UrlEncode());
        }
    }
}
