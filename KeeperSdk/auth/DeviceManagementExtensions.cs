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
        /// Resolves a set of user-supplied identifiers (1-based row numbers, device ID prefixes,
        /// device name substrings, or "all") against a list of devices. Used to share identical
        /// matching semantics between CLI front-ends (Commander, PowerCommander).
        /// </summary>
        /// <param name="devices">The candidate devices, in the same order shown to the user (e.g. table row order).</param>
        /// <param name="identifiers">The identifiers to resolve.</param>
        /// <param name="deviceIdSelector">Formats a device's token into the display ID string the caller matches/shows to the user.</param>
        /// <param name="notFound">Identifiers that matched no device.</param>
        /// <returns>The matched devices, in identifier order. May contain duplicates if identifiers overlap.</returns>
        public static List<Device> ResolveDevicesByIdentifiers(
            IReadOnlyList<Device> devices,
            IEnumerable<string> identifiers,
            Func<byte[], string> deviceIdSelector,
            out List<string> notFound)
        {
            var result = new List<Device>();
            notFound = new List<string>();

            foreach (var identifier in identifiers)
            {
                Device[] matches;
                if (identifier.Equals("all", StringComparison.OrdinalIgnoreCase))
                {
                    matches = devices.ToArray();
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

                result.AddRange(matches);
            }

            return result;
        }

        /// <summary>
        /// Lists all devices registered to the given enterprise users. Requires enterprise administrator privileges.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="enterpriseUserIds">The enterprise user IDs to list devices for.</param>
        /// <returns>A list of per-user device lists.</returns>
        public static async Task<IEnumerable<DeviceUserList>> GetAdminUserDevices(this IAuthentication auth,
            IEnumerable<long> enterpriseUserIds)
        {
            var request = new DeviceAdminRequest();
            request.EnterpriseUserIds.AddRange(enterpriseUserIds);

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
            var request = new DeviceAdminActionRequest();
            var action = new DeviceAdminAction
            {
                DeviceActionType = actionType,
                EnterpriseUserId = enterpriseUserId,
            };
            action.EncryptedDeviceToken.AddRange(encryptedDeviceTokens);
            request.DeviceAdminAction.Add(action);

            var rs = await auth.ExecuteAuthRest<DeviceAdminActionRequest, DeviceAdminActionResponse>("dm/device_admin_action", request);
            return rs.DeviceAdminActionResults;
        }
    }
}
