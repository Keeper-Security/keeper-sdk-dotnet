using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DeviceManagement;
using Google.Protobuf;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Provides a set of static methods for the enterprise-admin device management REST endpoints.
    /// </summary>
    /// <summary>
    /// The outcome of <see cref="DeviceManagementExtensions.ResolveDevicesByIdentifiers"/>.
    /// </summary>
    public sealed class DeviceResolveResult
    {
        /// <summary>
        /// The matched devices, de-duplicated and in first-matched order, even if identifiers overlap.
        /// </summary>
        public IReadOnlyList<Device> Matched { get; }

        /// <summary>
        /// Identifiers that matched no device.
        /// </summary>
        public IReadOnlyList<string> NotFound { get; }

        /// <summary>
        /// Identifiers that matched more than one device and were not acted on.
        /// </summary>
        public IReadOnlyList<string> Ambiguous { get; }

        public DeviceResolveResult(IReadOnlyList<Device> matched, IReadOnlyList<string> notFound, IReadOnlyList<string> ambiguous)
        {
            Matched = matched;
            NotFound = notFound;
            Ambiguous = ambiguous;
        }
    }

    public static class DeviceManagementExtensions
    {
        /// <summary>
        /// Determines a human-readable UI category label for a device, matching the labels shown
        /// by the Keeper Vault / Admin Console UI.
        /// </summary>
        /// <param name="device">The device to classify.</param>
        /// <returns>The UI category label.</returns>
        public static string GetUiCategory(Device device)
        {
            if (device == null)
                throw new ArgumentNullException(nameof(device));

            switch (device.ClientTypeCategory)
            {
                case ClientTypeCategory.CatExtension:
                    return "Browser Extension";
                case ClientTypeCategory.CatDesktop:
                    return "Desktop";
                case ClientTypeCategory.CatWebVault:
                    return "Web Vault";
                case ClientTypeCategory.CatAdmin when device.ClientType == ClientType.EnterpriseManagementConsole:
                    return "Admin Console";
                case ClientTypeCategory.CatAdmin when device.ClientType == ClientType.Commander:
                    return "Commander CLI";
                case ClientTypeCategory.CatMobile when device.ClientType == ClientType.Ios:
                    return "iOS App";
                case ClientTypeCategory.CatMobile when device.ClientType == ClientType.Android:
                    return "Android App";
                case ClientTypeCategory.CatMobile when device.ClientFormFactor == global::Authentication.ClientFormFactor.FfPhone:
                    return "Mobile";
                case ClientTypeCategory.CatMobile when device.ClientFormFactor == global::Authentication.ClientFormFactor.FfTablet:
                    return "Tablet";
                case ClientTypeCategory.CatMobile when device.ClientFormFactor == global::Authentication.ClientFormFactor.FfWatch:
                    return "Wear OS";
                default:
                    return "Unknown Device";
            }
        }

        /// <summary>
        /// Resolves user-provided identifiers to devices. Supports "all", "#n" for a row number,
        /// "id:<prefix>" for a device ID, and "name:<text>" for a device name.
        /// Ambiguous matches are rejected to prevent accidental actions on multiple devices.
        /// </summary>
        /// <param name="devices">The candidate devices, in the same order shown to the user (e.g. table row order).</param>
        /// <param name="identifiers">The identifiers to resolve.</param>
        /// <param name="deviceIdSelector">Formats a device's token into the display ID string the caller matches/shows to the user.</param>
        /// <returns>The matched, not-found, and ambiguous identifiers.</returns>
        public static DeviceResolveResult ResolveDevicesByIdentifiers(
            IReadOnlyList<Device> devices,
            IEnumerable<string> identifiers,
            Func<byte[], string> deviceIdSelector)
        {
            if (devices == null)
                throw new ArgumentNullException(nameof(devices));

            if (identifiers == null)
                throw new ArgumentNullException(nameof(identifiers));

            if (deviceIdSelector == null)
                throw new ArgumentNullException(nameof(deviceIdSelector));

            var result = new List<Device>();
            var seenTokens = new HashSet<ByteString>();
            var notFound = new List<string>();
            var ambiguous = new List<string>();

            foreach (var raw in identifiers)
            {
                var identifier = raw?.Trim();
                if (string.IsNullOrEmpty(identifier))
                {
                    continue;
                }

                var isAll = identifier.Equals("all", StringComparison.OrdinalIgnoreCase);

                Device[] matches;
                if (isAll)
                {
                    matches = devices.ToArray();
                }
                else if (identifier.StartsWith("#") &&
                         int.TryParse(identifier.Substring(1), out var explicitRowNo) &&
                         explicitRowNo >= 1 && explicitRowNo <= devices.Count)
                {
                    matches = new[] { devices[explicitRowNo - 1] };
                }
                else if (identifier.StartsWith("id:", StringComparison.OrdinalIgnoreCase))
                {
                    var idPrefix = identifier.Substring(3);
                    matches = devices
                        .Where(x => deviceIdSelector(x.EncryptedDeviceToken.ToByteArray()).StartsWith(idPrefix, StringComparison.OrdinalIgnoreCase))
                        .ToArray();
                }
                else if (identifier.StartsWith("name:", StringComparison.OrdinalIgnoreCase))
                {
                    var namePart = identifier.Substring(5);
                    matches = devices
                        .Where(x => !string.IsNullOrEmpty(x.DeviceName) && x.DeviceName.IndexOf(namePart, StringComparison.OrdinalIgnoreCase) >= 0)
                        .ToArray();
                }
                else if (int.TryParse(identifier, out var rowNo) && rowNo >= 1 && rowNo <= devices.Count)
                {
                    matches = new[] { devices[rowNo - 1] };
                }
                else
                {
                    matches = devices
                        .Where(x => deviceIdSelector(x.EncryptedDeviceToken.ToByteArray()).StartsWith(identifier, StringComparison.OrdinalIgnoreCase) ||
                                    (!string.IsNullOrEmpty(x.DeviceName) && x.DeviceName.IndexOf(identifier, StringComparison.OrdinalIgnoreCase) >= 0))
                        .ToArray();
                }

                if (matches.Length == 0)
                {
                    notFound.Add(identifier);
                    continue;
                }

                if (matches.Length > 1 && !isAll)
                {
                    ambiguous.Add(identifier);
                    continue;
                }

                foreach (var match in matches)
                {
                    if (seenTokens.Add(match.EncryptedDeviceToken))
                    {
                        result.Add(match);
                    }
                }
            }

            return new DeviceResolveResult(result, notFound, ambiguous);
        }

        /// <summary>
        /// Maps the user-facing action name (as used by Commander/PowerCommander) to the protocol
        /// <see cref="DeviceActionType"/> value, shared so both front-ends use identical action names.
        /// </summary>
        /// <param name="action">The action name, e.g. "logout", "remove", "lock", "unlock", "account-lock", "account-unlock".</param>
        /// <param name="actionType">The resolved action type, if <paramref name="action"/> is recognized.</param>
        /// <returns><c>true</c> if the action name was recognized.</returns>
        public static bool TryParseDeviceAction(string action, out DeviceActionType actionType)
        {
            return DeviceActionNames.TryGetValue(action ?? "", out actionType);
        }

        /// <summary>
        /// The action names recognized by <see cref="TryParseDeviceAction"/>, in display order.
        /// </summary>
        public static IEnumerable<string> DeviceActionNameList => DeviceActionNames.Keys;

        private static readonly IDictionary<string, DeviceActionType> DeviceActionNames =
            new Dictionary<string, DeviceActionType>(StringComparer.OrdinalIgnoreCase)
            {
                ["logout"] = DeviceActionType.DaLogout,
                ["remove"] = DeviceActionType.DaRemove,
                ["lock"] = DeviceActionType.DaLock,
                ["unlock"] = DeviceActionType.DaUnlock,
                ["account-lock"] = DeviceActionType.DaDeviceAccountLock,
                ["account-unlock"] = DeviceActionType.DaDeviceAccountUnlock,
            };

        /// <summary>
        /// Lists all devices registered to the given enterprise users. Requires enterprise administrator privileges.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="enterpriseUserIds">The enterprise user IDs to list devices for.</param>
        /// <returns>A list of per-user device lists.</returns>
        public static async Task<IEnumerable<DeviceUserList>> GetAdminUserDevices(this IAuthentication auth,
            IEnumerable<long> enterpriseUserIds)
        {
            if (auth == null)
                throw new ArgumentNullException(nameof(auth));

            if (enterpriseUserIds == null)
                throw new ArgumentNullException(nameof(enterpriseUserIds));

            var userIds = enterpriseUserIds.ToArray();
            if (userIds.Length == 0)
                return Enumerable.Empty<DeviceUserList>();

            var request = new DeviceAdminRequest();
            request.EnterpriseUserIds.AddRange(userIds);

            var rs = await auth.ExecuteAuthRest<DeviceAdminRequest, DeviceAdminResponse>("dm/device_admin_list", request);
            return rs.DeviceUserList;
        }

        /// <summary>
        /// Performs an action (logout, remove, lock, unlock, account-lock, account-unlock)
        /// on one or more devices of the given enterprise user. Requires enterprise administrator privileges.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="actionType">The device action to perform.</param>
        /// <param name="enterpriseUserId">The enterprise user ID that owns the devices.</param>
        /// <param name="encryptedDeviceTokens">The encrypted device tokens of the devices to act on.</param>
        /// <returns>The per-device action results.</returns>
        public static async Task<IEnumerable<DeviceAdminActionResult>> ExecuteAdminDeviceAction(this IAuthentication auth,
            DeviceActionType actionType, long enterpriseUserId, IEnumerable<ByteString> encryptedDeviceTokens)
        {
            if (auth == null)
                throw new ArgumentNullException(nameof(auth));

            if (!Enum.IsDefined(typeof(DeviceActionType), actionType))
                throw new ArgumentOutOfRangeException(nameof(actionType), actionType, "Unrecognized device action type");

            if (enterpriseUserId <= 0)
                throw new ArgumentOutOfRangeException(nameof(enterpriseUserId), enterpriseUserId, "Enterprise user ID must be positive");

            if (encryptedDeviceTokens == null)
                throw new ArgumentNullException(nameof(encryptedDeviceTokens));

            var tokens = encryptedDeviceTokens.ToArray();
            if (tokens.Length == 0)
                throw new ArgumentException("At least one device token must be specified", nameof(encryptedDeviceTokens));

            var request = new DeviceAdminActionRequest();
            var action = new DeviceAdminAction
            {
                DeviceActionType = actionType,
                EnterpriseUserId = enterpriseUserId,
            };
            action.EncryptedDeviceToken.AddRange(tokens);
            request.DeviceAdminAction.Add(action);

            var rs = await auth.ExecuteAuthRest<DeviceAdminActionRequest, DeviceAdminActionResponse>("dm/device_admin_action", request);
            return rs.DeviceAdminActionResults;
        }
    }
}
