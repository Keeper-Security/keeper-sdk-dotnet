using System;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using Google.Protobuf;

namespace KeeperSecurity.Sdk
{
    public static class AuthUtils
    {
        public static bool IsAuthenticated(this IAuthentication auth)
        {
            return auth.AuthContext?.SessionToken != null;
        }

        public static async Task<KeeperApiResponse> ExecuteAuthCommand(this IAuthentication auth, AuthenticatedCommand command, Type responseType)
        {
            var context = auth.AuthContext;
            command.username = context.Username;
            command.sessionToken = context.SessionToken.Base64UrlEncode();

            return await auth.Endpoint.ExecuteV2Command(command, responseType);
        }

        public static async Task<TR> ExecuteAuthCommand<TC, TR>(this IAuthentication auth, TC command, bool throwOnError = true)
            where TC : AuthenticatedCommand
            where TR : KeeperApiResponse
        {
            var response = (TR) await auth.ExecuteAuthCommand(command, typeof(TR));
            if (!response.IsSuccess && throwOnError)
            {
                throw new KeeperApiException(response.resultCode, response.message);
            }

            return response;
        }

        public static Task ExecuteAuthCommand<TC>(this IAuthentication auth, TC command)
            where TC : AuthenticatedCommand
        {
            return auth.ExecuteAuthCommand<TC, KeeperApiResponse>(command);
        }

        public static async Task<TR> ExecuteAuthRest<TC, TR>(this IAuthentication auth, string endpoint, TC request)
            where TC : IMessage
            where TR : IMessage
        {
            return (TR) await auth.ExecuteAuthRest(endpoint, request, typeof(TR));
        }

        public static async Task<bool> RegisterDataKeyForDevice(this IAuthentication auth, DeviceInfo device)
        {
            if (!(auth.AuthContext is AuthContextV3)) return false;

            var publicKeyBytes = device.DevicePublicKey.ToByteArray();
            var publicKey = CryptoUtils.LoadPublicEcKey(publicKeyBytes);
            var encryptedDataKey = CryptoUtils.EncryptEc(auth.AuthContext.DataKey, publicKey);
            var request = new RegisterDeviceDataKeyRequest
            {
                EncryptedDeviceToken = device.EncryptedDeviceToken,
                EncryptedDeviceDataKey = ByteString.CopyFrom(encryptedDataKey),
            };
            try
            {
                await auth.ExecuteAuthRest("authentication/register_encrypted_data_key_for_device", request);
                return true;
            }
            catch (KeeperApiException kae)
            {
                if (kae.Code == "device_data_key_exists") return false;
                throw;
            }
        }

        private static async Task SetSessionParameter(this IAuthentication auth, string name, string value)
        {
            if (!(auth.AuthContext is AuthContextV3)) return;
            await auth.ExecuteAuthRest("setting/set_user_setting",
                new UserSettingRequest
                {
                    Setting = name,
                    Value = value
                });
        }

        public static Task SetSessionInactivityTimeout(this IAuthentication auth, int timeoutInMinutes)
        {
            return auth.SetSessionParameter("logout_timer", $"{timeoutInMinutes}");
        }

        public static Task SetSessionPersistentLogin(this IAuthentication auth, bool enabled)
        {
            return auth.SetSessionParameter("persistent_login", enabled ? "1" : "0");
        }

        public static async Task<AccountSummaryElements> LoadAccountSummary(this IAuthentication auth)
        {
            if (!(auth.AuthContext is AuthContextV3)) return null;
            var rq = new AccountSummaryRequest
            {
                SummaryVersion = 1
            };
            return await auth.ExecuteAuthRest<AccountSummaryRequest, AccountSummaryElements>("login/account_summary", rq);
        }


    }
}
