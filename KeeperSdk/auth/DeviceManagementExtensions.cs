using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
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
        private const int MaxDeviceNameLength = 255;
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
        /// Normalizes and validates a device name before it is sent to the service.
        /// </summary>
        public static string NormalizeDeviceName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("A new device name must be specified", nameof(name));

            if (!HasValidSurrogatePairs(name))
                throw new ArgumentException("The device name contains invalid Unicode text", nameof(name));

            string normalizedName;
            try
            {
                normalizedName = name.Normalize(NormalizationForm.FormKC).Trim();
            }
            catch (ArgumentException e)
            {
                throw new ArgumentException("The device name is not valid Unicode text", nameof(name), e);
            }

            if (normalizedName.Length == 0)
                throw new ArgumentException("A new device name must be specified", nameof(name));
            if (normalizedName.Length > MaxDeviceNameLength)
                throw new ArgumentException($"Device name cannot exceed {MaxDeviceNameLength} characters", nameof(name));
            if (normalizedName.Any(x => x == '<' || x == '>' || x == '"' || x == '\'' ||
                                        char.IsControl(x) || char.GetUnicodeCategory(x) == UnicodeCategory.Format))
                throw new ArgumentException("Device name contains invalid characters", nameof(name));

            return normalizedName;
        }

        /// <summary>
        /// Compares two device names after applying the same normalization and validation rules.
        /// </summary>
        public static bool DeviceNamesEqual(string firstName, string secondName)
        {
            return string.Equals(NormalizeDeviceName(firstName), NormalizeDeviceName(secondName),
                StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasValidSurrogatePairs(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                if (char.IsHighSurrogate(value[index]))
                {
                    if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                        return false;
                    index++;
                }
                else if (char.IsLowSurrogate(value[index]))
                {
                    return false;
                }
            }
            return true;
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

            var normalizedName = NormalizeDeviceName(newName);

            var request = new DeviceRenameRequest();
            request.DeviceRename.Add(new DeviceRename
            {
                EncryptedDeviceToken = encryptedDeviceToken,
                DeviceNewName = normalizedName,
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
