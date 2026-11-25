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
    public sealed class DeviceResolveResult
    {
        public IReadOnlyList<Device> Matched { get; }
        public IReadOnlyList<string> NotFound { get; }
        public IReadOnlyList<string> Ambiguous { get; }
        public DeviceResolveResult(IReadOnlyList<Device> matched, IReadOnlyList<string> notFound, IReadOnlyList<string> ambiguous)
        { Matched = matched; NotFound = notFound; Ambiguous = ambiguous; }
    }

    public static class DeviceManagementExtensions
    {
        private const int MaxDeviceNameLength = 255;
        private static readonly IDictionary<string, DeviceActionType> DeviceActionNames =
            new Dictionary<string, DeviceActionType>(StringComparer.OrdinalIgnoreCase)
            {
                ["logout"] = DeviceActionType.DaLogout, ["remove"] = DeviceActionType.DaRemove,
                ["lock"] = DeviceActionType.DaLock, ["unlock"] = DeviceActionType.DaUnlock,
                ["account-lock"] = DeviceActionType.DaDeviceAccountLock, ["account-unlock"] = DeviceActionType.DaDeviceAccountUnlock,
                ["link"] = DeviceActionType.DaLink, ["unlink"] = DeviceActionType.DaUnlink,
            };

        public static string GetUiCategory(Device device)
        {
            if (device == null) throw new ArgumentNullException(nameof(device));
            switch (device.ClientTypeCategory)
            {
                case ClientTypeCategory.CatExtension: return "Browser Extension";
                case ClientTypeCategory.CatDesktop: return "Desktop";
                case ClientTypeCategory.CatWebVault: return "Web Vault";
                case ClientTypeCategory.CatAdmin when device.ClientType == ClientType.EnterpriseManagementConsole: return "Admin Console";
                case ClientTypeCategory.CatAdmin when device.ClientType == ClientType.Commander: return "Commander CLI";
                case ClientTypeCategory.CatMobile when device.ClientType == ClientType.Ios: return "iOS App";
                case ClientTypeCategory.CatMobile when device.ClientType == ClientType.Android: return "Android App";
                case ClientTypeCategory.CatMobile when device.ClientFormFactor == global::Authentication.ClientFormFactor.FfPhone: return "Mobile";
                case ClientTypeCategory.CatMobile when device.ClientFormFactor == global::Authentication.ClientFormFactor.FfTablet: return "Tablet";
                case ClientTypeCategory.CatMobile when device.ClientFormFactor == global::Authentication.ClientFormFactor.FfWatch: return "Wear OS";
                default: return "Unknown Device";
            }
        }

        public static DeviceResolveResult ResolveDevicesByIdentifiers(IReadOnlyList<Device> devices, IEnumerable<string> identifiers, Func<byte[], string> deviceIdSelector)
        {
            if (devices == null) throw new ArgumentNullException(nameof(devices));
            if (identifiers == null) throw new ArgumentNullException(nameof(identifiers));
            if (deviceIdSelector == null) throw new ArgumentNullException(nameof(deviceIdSelector));
            var result = new List<Device>(); var seenTokens = new HashSet<ByteString>(); var notFound = new List<string>(); var ambiguous = new List<string>();
            foreach (var raw in identifiers)
            {
                var identifier = raw?.Trim(); if (string.IsNullOrEmpty(identifier)) continue;
                var isAll = identifier.Equals("all", StringComparison.OrdinalIgnoreCase); Device[] matches;
                if (isAll) matches = devices.ToArray();
                else if (identifier.StartsWith("#") && int.TryParse(identifier.Substring(1), out var explicitRowNo) && explicitRowNo >= 1 && explicitRowNo <= devices.Count) matches = new[] { devices[explicitRowNo - 1] };
                else if (identifier.StartsWith("id:", StringComparison.OrdinalIgnoreCase)) matches = devices.Where(x => deviceIdSelector(x.EncryptedDeviceToken.ToByteArray()).StartsWith(identifier.Substring(3), StringComparison.OrdinalIgnoreCase)).ToArray();
                else if (identifier.StartsWith("name:", StringComparison.OrdinalIgnoreCase)) matches = devices.Where(x => !string.IsNullOrEmpty(x.DeviceName) && x.DeviceName.IndexOf(identifier.Substring(5), StringComparison.OrdinalIgnoreCase) >= 0).ToArray();
                else if (int.TryParse(identifier, out var rowNo) && rowNo >= 1 && rowNo <= devices.Count) matches = new[] { devices[rowNo - 1] };
                else matches = devices.Where(x => deviceIdSelector(x.EncryptedDeviceToken.ToByteArray()).StartsWith(identifier, StringComparison.OrdinalIgnoreCase) || (!string.IsNullOrEmpty(x.DeviceName) && x.DeviceName.IndexOf(identifier, StringComparison.OrdinalIgnoreCase) >= 0)).ToArray();
                if (matches.Length == 0) { notFound.Add(identifier); continue; }
                if (matches.Length > 1 && !isAll) { ambiguous.Add(identifier); continue; }
                foreach (var match in matches) if (seenTokens.Add(match.EncryptedDeviceToken)) result.Add(match);
            }
            return new DeviceResolveResult(result, notFound, ambiguous);
        }

        public static bool TryParseDeviceAction(string action, out DeviceActionType actionType) => DeviceActionNames.TryGetValue(action ?? string.Empty, out actionType);
        public static IEnumerable<string> DeviceActionNameList => DeviceActionNames.Keys;

        public static async Task<IEnumerable<DeviceUserList>> GetAdminUserDevices(this IAuthentication auth, IEnumerable<long> enterpriseUserIds)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth)); if (enterpriseUserIds == null) throw new ArgumentNullException(nameof(enterpriseUserIds));
            var userIds = enterpriseUserIds.ToArray(); if (userIds.Length == 0) return Enumerable.Empty<DeviceUserList>();
            var request = new DeviceAdminRequest(); request.EnterpriseUserIds.AddRange(userIds);
            var response = await auth.ExecuteAuthRest<DeviceAdminRequest, DeviceAdminResponse>("dm/device_admin_list", request); return response.DeviceUserList;
        }

        public static async Task<IEnumerable<DeviceAdminActionResult>> ExecuteAdminDeviceAction(this IAuthentication auth, DeviceActionType actionType, long enterpriseUserId, IEnumerable<ByteString> encryptedDeviceTokens)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth));
            if (!System.Enum.IsDefined(typeof(DeviceActionType), actionType)) throw new ArgumentOutOfRangeException(nameof(actionType), actionType, "Unrecognized device action type");
            if (enterpriseUserId <= 0) throw new ArgumentOutOfRangeException(nameof(enterpriseUserId), enterpriseUserId, "Enterprise user ID must be positive");
            if (encryptedDeviceTokens == null) throw new ArgumentNullException(nameof(encryptedDeviceTokens)); var tokens = encryptedDeviceTokens.ToArray();
            if (tokens.Length == 0) throw new ArgumentException("At least one device token must be specified", nameof(encryptedDeviceTokens));
            var request = new DeviceAdminActionRequest(); var action = new DeviceAdminAction { DeviceActionType = actionType, EnterpriseUserId = enterpriseUserId }; action.EncryptedDeviceToken.AddRange(tokens); request.DeviceAdminAction.Add(action);
            var response = await auth.ExecuteAuthRest<DeviceAdminActionRequest, DeviceAdminActionResponse>("dm/device_admin_action", request); return response.DeviceAdminActionResults;
        }

        public static string NormalizeDeviceName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("A new device name must be specified", nameof(name));
            if (!HasValidSurrogatePairs(name)) throw new ArgumentException("The device name contains invalid Unicode text", nameof(name));
            string normalizedName; try { normalizedName = name.Normalize(NormalizationForm.FormKC).Trim(); } catch (ArgumentException e) { throw new ArgumentException("The device name is not valid Unicode text", nameof(name), e); }
            if (normalizedName.Length == 0) throw new ArgumentException("A new device name must be specified", nameof(name));
            if (normalizedName.Length > MaxDeviceNameLength) throw new ArgumentException($"Device name cannot exceed {MaxDeviceNameLength} characters", nameof(name));
            if (normalizedName.Any(x => x == '<' || x == '>' || x == '\"' || x == '\'' || char.IsControl(x) || char.GetUnicodeCategory(x) == UnicodeCategory.Format)) throw new ArgumentException("Device name contains invalid characters", nameof(name));
            return normalizedName;
        }
        public static bool DeviceNamesEqual(string firstName, string secondName) => string.Equals(NormalizeDeviceName(firstName), NormalizeDeviceName(secondName), StringComparison.OrdinalIgnoreCase);

        public static async Task<IEnumerable<Device>> GetUserDevices(this IAuthentication auth)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth)); var response = await auth.ExecuteAuthRest<Empty, DeviceUserResponse>("dm/device_user_list", new Empty()); return response.DeviceGroups.SelectMany(x => x.Devices);
        }
        public static async Task<IEnumerable<DeviceActionResult>> ExecuteDeviceAction(this IAuthentication auth, DeviceActionType actionType, IEnumerable<ByteString> encryptedDeviceTokens)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth)); if (!System.Enum.IsDefined(typeof(DeviceActionType), actionType) || actionType == DeviceActionType.DaInvalid) throw new ArgumentOutOfRangeException(nameof(actionType), actionType, "Unrecognized device action type");
            var tokens = ValidateTokens(encryptedDeviceTokens, nameof(encryptedDeviceTokens)); var request = new DeviceActionRequest(); var action = new DeviceAction { DeviceActionType = actionType }; action.EncryptedDeviceToken.AddRange(tokens); request.DeviceAction.Add(action);
            var response = await auth.ExecuteAuthRest<DeviceActionRequest, DeviceActionResponse>("dm/device_user_action", request); return response.DeviceActionResult;
        }
        public static async Task<DeviceRenameResult> RenameUserDevice(this IAuthentication auth, ByteString encryptedDeviceToken, string newName)
        {
            if (auth == null) throw new ArgumentNullException(nameof(auth)); if (encryptedDeviceToken == null || encryptedDeviceToken.Length == 0) throw new ArgumentException("A device token must be specified", nameof(encryptedDeviceToken));
            var request = new DeviceRenameRequest(); request.DeviceRename.Add(new DeviceRename { EncryptedDeviceToken = encryptedDeviceToken, DeviceNewName = NormalizeDeviceName(newName) });
            var response = await auth.ExecuteAuthRest<DeviceRenameRequest, DeviceRenameResponse>("dm/device_user_rename", request); return response.DeviceRenameResult.FirstOrDefault();
        }
        private static bool HasValidSurrogatePairs(string value)
        {
            for (var index = 0; index < value.Length; index++) { if (char.IsHighSurrogate(value[index])) { if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return false; index++; } else if (char.IsLowSurrogate(value[index])) return false; } return true;
        }
        private static ByteString[] ValidateTokens(IEnumerable<ByteString> encryptedDeviceTokens, string parameterName)
        {
            if (encryptedDeviceTokens == null) throw new ArgumentNullException(parameterName); var tokens = encryptedDeviceTokens.ToArray(); if (tokens.Length == 0) throw new ArgumentException("At least one device token must be specified", parameterName); if (tokens.Any(x => x == null || x.Length == 0)) throw new ArgumentException("Device tokens must not be empty", parameterName); return tokens;
        }
    }
}
