using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DeviceManagement;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Provides SDK methods for the personal (non-enterprise) device-management REST endpoints.
    /// </summary>
    public static class DeviceManagementExtensions
    {
        private static readonly IDictionary<string, DeviceActionType> DeviceActionNames =
            new Dictionary<string, DeviceActionType>(StringComparer.OrdinalIgnoreCase)
            {
                ["logout"] = DeviceActionType.DaLogout,
                ["remove"] = DeviceActionType.DaRemove,
                ["lock"] = DeviceActionType.DaLock,
                ["unlock"] = DeviceActionType.DaUnlock,
                ["account-lock"] = DeviceActionType.DaDeviceAccountLock,
                ["account-unlock"] = DeviceActionType.DaDeviceAccountUnlock,
                ["link"] = DeviceActionType.DaLink,
                ["unlink"] = DeviceActionType.DaUnlink,
            };

        /// <summary>
        /// Resolves a supported user-facing device action name to its protocol value.
        /// </summary>
        public static bool TryParseDeviceAction(string action, out DeviceActionType actionType)
        {
            return DeviceActionNames.TryGetValue(action ?? string.Empty, out actionType);
        }

        /// <summary>
        /// Lists the devices registered to the currently authenticated user.
        /// </summary>
        public static async Task<IEnumerable<Device>> GetUserDevices(this IAuthentication auth)
        {
            if (auth == null)
                throw new ArgumentNullException(nameof(auth));

            var response = await auth.ExecuteAuthRest<Empty, DeviceUserResponse>(
                "dm/device_user_list", new Empty());
            return response.DeviceGroups.SelectMany(x => x.Devices);
        }

        /// <summary>
        /// Performs an action on one or more devices registered to the currently authenticated user.
        /// </summary>
        public static async Task<IEnumerable<DeviceActionResult>> ExecuteDeviceAction(this IAuthentication auth,
            DeviceActionType actionType, IEnumerable<ByteString> encryptedDeviceTokens)
        {
            if (auth == null)
                throw new ArgumentNullException(nameof(auth));

            if (!System.Enum.IsDefined(typeof(DeviceActionType), actionType) || actionType == DeviceActionType.DaInvalid)
                throw new ArgumentOutOfRangeException(nameof(actionType), actionType, "Unrecognized device action type");

            var tokens = ValidateTokens(encryptedDeviceTokens, nameof(encryptedDeviceTokens));
            var request = new DeviceActionRequest();
            var action = new DeviceAction { DeviceActionType = actionType };
            action.EncryptedDeviceToken.AddRange(tokens);
            request.DeviceAction.Add(action);

            var response = await auth.ExecuteAuthRest<DeviceActionRequest, DeviceActionResponse>(
                "dm/device_user_action", request);
            return response.DeviceActionResult;
        }

        /// <summary>
        /// Renames one device registered to the currently authenticated user.
        /// </summary>
        public static async Task<DeviceRenameResult> RenameUserDevice(this IAuthentication auth,
            ByteString encryptedDeviceToken, string newName)
        {
            if (auth == null)
                throw new ArgumentNullException(nameof(auth));

            if (encryptedDeviceToken == null || encryptedDeviceToken.Length == 0)
                throw new ArgumentException("A device token must be specified", nameof(encryptedDeviceToken));

            if (string.IsNullOrWhiteSpace(newName))
                throw new ArgumentException("A new device name must be specified", nameof(newName));

            var request = new DeviceRenameRequest();
            request.DeviceRename.Add(new DeviceRename
            {
                EncryptedDeviceToken = encryptedDeviceToken,
                DeviceNewName = newName,
            });

            var response = await auth.ExecuteAuthRest<DeviceRenameRequest, DeviceRenameResponse>(
                "dm/device_user_rename", request);
            return response.DeviceRenameResult.FirstOrDefault();
        }

        private static ByteString[] ValidateTokens(IEnumerable<ByteString> encryptedDeviceTokens, string parameterName)
        {
            if (encryptedDeviceTokens == null)
                throw new ArgumentNullException(parameterName);

            var tokens = encryptedDeviceTokens.ToArray();
            if (tokens.Length == 0)
                throw new ArgumentException("At least one device token must be specified", parameterName);

            if (tokens.Any(x => x == null || x.Length == 0))
                throw new ArgumentException("Device tokens must not be empty", parameterName);

            return tokens;
        }
    }
}
