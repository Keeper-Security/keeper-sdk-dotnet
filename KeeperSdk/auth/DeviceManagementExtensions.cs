using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DeviceManagement;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Provides a set of static methods for the personal (non-enterprise) device management REST endpoints.
    /// </summary>
    public static class DeviceManagementExtensions
    {
        /// <summary>
        /// Lists all devices registered for the currently logged in user.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <returns>A list of device groups, each containing the devices in that group.</returns>
        public static async Task<IEnumerable<Device>> GetUserDevices(this IAuthentication auth)
        {
            var rs = await auth.ExecuteAuthRest<Empty, DeviceUserResponse>("dm/device_user_list", new Empty());
            return rs.DeviceGroups.SelectMany(x => x.Devices);
        }

        /// <summary>
        /// Performs an action (logout, remove, lock, unlock, account-lock, account-unlock, link, unlink)
        /// on one or more of the current user's devices.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="actionType">The device action to perform.</param>
        /// <param name="encryptedDeviceTokens">The encrypted device tokens of the devices to act on.</param>
        /// <returns>The per-device action results.</returns>
        public static async Task<IEnumerable<DeviceActionResult>> ExecuteDeviceAction(this IAuthentication auth,
            DeviceActionType actionType, IEnumerable<ByteString> encryptedDeviceTokens)
        {
            var request = new DeviceActionRequest();
            var action = new DeviceAction
            {
                DeviceActionType = actionType,
            };
            action.EncryptedDeviceToken.AddRange(encryptedDeviceTokens);
            request.DeviceAction.Add(action);

            var rs = await auth.ExecuteAuthRest<DeviceActionRequest, DeviceActionResponse>("dm/device_user_action", request);
            return rs.DeviceActionResult;
        }

        /// <summary>
        /// Renames one of the current user's devices.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="encryptedDeviceToken">The encrypted device token of the device to rename.</param>
        /// <param name="newName">The new device name.</param>
        /// <returns>The rename result.</returns>
        public static async Task<DeviceRenameResult> RenameUserDevice(this IAuthentication auth,
            ByteString encryptedDeviceToken, string newName)
        {
            var request = new DeviceRenameRequest();
            request.DeviceRename.Add(new DeviceRename
            {
                EncryptedDeviceToken = encryptedDeviceToken,
                DeviceNewName = newName,
            });

            var rs = await auth.ExecuteAuthRest<DeviceRenameRequest, DeviceRenameResponse>("dm/device_user_rename", request);
            return rs.DeviceRenameResult.FirstOrDefault();
        }
    }
}
