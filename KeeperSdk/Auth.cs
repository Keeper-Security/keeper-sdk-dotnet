//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2020 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Sdk.UI;
using System.Diagnostics;
using System.Reflection;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Google.Protobuf;
using Type = System.Type;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Tests")]

namespace KeeperSecurity.Sdk
{
    public interface IAuthentication
    {
        IKeeperEndpoint Endpoint { get; }
        IAuthContext AuthContext { get; }
        Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType);
        Task<IMessage> ExecuteAuthRest(string endpoint, IMessage request, Type responseType = null);
        Task Logout();
    }

    public interface IAuth
    {
        string Username { get; }
        IKeeperEndpoint Endpoint { get; }
        byte[] DeviceToken { get; set; }
        IAuthUI Ui { get; }
        IConfigurationStorage Storage { get; }
        bool ResumeSession { get; set; }
    }

    public interface IAuthContext : IDisposable
    {
        string Username { get; }
        byte[] DataKey { get; }
        byte[] SessionToken { get; }
        byte[] DeviceToken { get; }
        byte[] ClientKey { get; }
        RsaPrivateCrtKeyParameters PrivateKey { get; }
        IFanOut<NotificationEvent> PushNotifications { get; }
        bool CheckPasswordValid(string password);
        AccountLicense License { get; }
        AccountSettings Settings { get; }
        IDictionary<string, object> Enforcements { get; }
        bool IsEnterpriseAdmin { get; }
    }

    [Flags]
    public enum SessionTokenRestriction
    {
        AccountRecovery = 1 << 0,
        ShareAccount = 1 << 1,
        AcceptInvite = 1 << 2,
        AccountExpired = 1 << 3,
    }

    public class AuthContext : IAuthContext
    {
        public string Username { get; internal set; }
        public byte[] DataKey { get; internal set; }
        public byte[] ClientKey { get; internal set; }
        public RsaPrivateCrtKeyParameters PrivateKey { get; internal set; }
        public IFanOut<NotificationEvent> PushNotifications { get; } = new FanOut<NotificationEvent>();
        public byte[] SessionToken { get; internal set; }
        public SessionTokenRestriction SessionTokenRestriction { get; set; }
        public byte[] DeviceToken { get; internal set; }
        public AccountLicense License { get; internal set; }
        public AccountSettings Settings { get; internal set; }
        public IDictionary<string, object> Enforcements { get; internal set; }
        public bool IsEnterpriseAdmin { get; internal set; }

        internal byte[] PasswordValidator { get; set; }

        public bool CheckPasswordValid(string password)
        {
            if (PasswordValidator == null) return false;
            try
            {
                var rnd = CryptoUtils.DecryptEncryptionParams(password, PasswordValidator);
                return rnd?.Length == 32;
            }
            catch
            {
                return false;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            PushNotifications.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~AuthContext()
        {
            Dispose(false);
        }
    }

    public class Auth : IAuth, IAuthentication
    {
        private static readonly Regex VersionPattern;
        static Auth() {
            VersionPattern = new Regex(@"^[a-z]+(\d{2})\.\d{1,2}\.\d{1,2}$");
        }

        public Auth(IAuthUI authUi, IConfigurationStorage storage, IKeeperEndpoint endpoint = null)
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage.LastServer, Storage.Servers);

            Ui = authUi;
            if (Endpoint is KeeperEndpoint ep && Ui is IHttpProxyCredentialUI proxyUi)
            {
                ep.ProxyUi = proxyUi;
            }
        }

        public string Username { get; set; }
        internal string Password { get; set; }

        public IKeeperEndpoint Endpoint { get; }
        public byte[] DeviceToken { get; set; }
        public bool ResumeSession { get; set; }

        public IAuthUI Ui { get; }
        public IConfigurationStorage Storage { get; }

        internal AuthContext authContext;
        public IAuthContext AuthContext => authContext;
        public Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType = null)
        {
            return ExecuteAuthCommand(command, responseType, true);
        }

        public async Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType, bool throwOnError = true)
        {
            var attempt = 0;
            while (attempt < 2)
            {
                attempt++;
                if (!this.IsAuthenticated()) break;

                command.username = authContext.Username;
                command.sessionToken = authContext.SessionToken.Base64UrlEncode();
                try
                {
                    var response = await Endpoint.ExecuteV2Command(command, responseType);
                    if (response.IsSuccess) return response;

                    if (response.resultCode == "auth_failed")
                    {
                        throw new KeeperAuthFailed();
                    }

                    if (throwOnError)
                    {
                        throw new KeeperApiException(response.resultCode, response.message);
                    }

                    return response;
                }
                catch (KeeperAuthFailed)
                {
                    Debug.WriteLine("Refresh Session Token");
                    authContext.SessionToken = null;
                    await RefreshSessionToken();
                    if (this.IsAuthenticated())
                    {
                        continue;
                    }
                    await Logout();
                }

                break;
            }

            throw new KeeperAuthFailed();
        }

        internal static bool IsV3Api(string clientVersion)
        {
            var match = VersionPattern.Match(clientVersion);
            if (match.Groups.Count == 2)
            {
                if (int.TryParse(match.Groups[1].Value, out var version))
                {
                    return version >= 15;
                }
            }

            return false;
        }

        public async Task LoginSso(string providerName)
        {
            var isV3Api = IsV3Api(Endpoint.ClientVersion);
            if (isV3Api)
            {
                var authV3 = new AuthV3(this);
                AuthContextV3 contextV3;
                try
                {
                    contextV3 = await authV3.LoginSsoV3(providerName);
                }
                catch (KeeperRegionRedirect krr)
                {
                    Endpoint.Server = krr.RegionHost;
                    contextV3 = await authV3.LoginSsoV3(providerName);
                }

                this.StoreConfigurationIfChangedV3(contextV3);
                authContext = contextV3;
            }
            else
            {
                var authV2 = new AuthV2(this);

                AuthContextV2 contextV2;
                try
                {
                    contextV2 = await authV2.LoginSsoV2(providerName);
                }
                catch (KeeperRegionRedirect krr)
                {
                    Endpoint.Server = krr.RegionHost;
                    contextV2 = await authV2.LoginSsoV2(providerName);
                }

                this.StoreConfigurationIfChangedV2(contextV2);
                authContext = contextV2;
            }

            await PostLogin(isV3Api);
        }

        public async Task Login(string username, params string[] passwords)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
            }

            Username = username.ToLowerInvariant();
            Password = null;
            var isV3Api = IsV3Api(Endpoint.ClientVersion);
            if (isV3Api)
            {
                var authV3 = new AuthV3(this);
                AuthContextV3 contextV3;
                try
                {
                    contextV3 = await authV3.LoginV3(passwords);
                }
                catch (KeeperRegionRedirect krr)
                {
                    Endpoint.Server = krr.RegionHost;
                    contextV3 = await authV3.LoginV3(passwords);
                }

                this.StoreConfigurationIfChangedV3(contextV3);
                authContext = contextV3;
            }
            else
            {
                var authV2 = new AuthV2(this);
                AuthContextV2 contextV2;
                try
                {
                    contextV2 = await authV2.LoginV2(passwords);
                }
                catch (KeeperRegionRedirect krr)
                {
                    Endpoint.Server = krr.RegionHost;
                    contextV2 = await authV2.LoginV2(passwords);
                }

                this.StoreConfigurationIfChangedV2(contextV2);
                authContext = contextV2;
            }

            await PostLogin(isV3Api);
        }

        private async Task PostLogin(bool isV3Api)
        {
            AccountLicense license;
            AccountSettings settings;
            AccountKeys keys;
            IDictionary<string, object> enforcements;
            string clientKey = null;
            bool isEnterpriseAdmin = false;
            if (isV3Api)
            {
                var accountSummaryResponse = await this.LoadAccountSummary();
                license = AccountLicense.LoadFromProtobuf(accountSummaryResponse.License);
                settings = AccountSettings.LoadFromProtobuf(accountSummaryResponse.Settings);
                keys = AccountKeys.LoadFromProtobuf(accountSummaryResponse.KeysInfo);
                if (accountSummaryResponse.ClientKey?.Length > 0)
                {
                    clientKey = accountSummaryResponse.ClientKey.ToByteArray().Base64UrlEncode();
                }
                enforcements = new Dictionary<string, object>();
                if (accountSummaryResponse.Enforcements?.Booleans != null)
                {
                    foreach (var kvp in accountSummaryResponse.Enforcements.Booleans)
                    {
                        enforcements[kvp.Key] = kvp.Value;
                    }
                }

                if (accountSummaryResponse.Enforcements?.Strings != null)
                {
                    foreach (var kvp in accountSummaryResponse.Enforcements.Strings)
                    {
                        enforcements[kvp.Key] = kvp.Value;
                    }
                }

                if (accountSummaryResponse.Enforcements?.Longs != null)
                {
                    foreach (var kvp in accountSummaryResponse.Enforcements.Longs)
                    {
                        enforcements[kvp.Key] = kvp.Value;
                    }
                }

                if (accountSummaryResponse.Enforcements?.Jsons != null)
                {
                    foreach (var kvp in accountSummaryResponse.Enforcements.Jsons)
                    {
                        try
                        {
                            switch (kvp.Key)
                            {
                                case "password_rules":
                                    var rules = JsonUtils.ParseJson<PasswordRule[]>(Encoding.UTF8.GetBytes(kvp.Value));
                                    enforcements[kvp.Key] = rules;
                                    break;
                                case "master_password_reentry":
                                    var mpr = JsonUtils.ParseJson<MasterPasswordReentry>(Encoding.UTF8.GetBytes(kvp.Value));
                                    enforcements[kvp.Key] = mpr;
                                    break;
                            }
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message);
                        }
                    }
                }

                isEnterpriseAdmin = accountSummaryResponse.IsEnterpriseAdmin;
            }
            else
            {
                var cmd = new AccountSummaryCommand
                {
                    include = new[] { "settings", "license", "keys", "client_key", "enforcements", "is_enterprise_admin"}
                };
                var accountSummaryResponse = await this.ExecuteAuthCommand<AccountSummaryCommand, AccountSummaryResponse>(cmd);
                license = accountSummaryResponse.License;
                settings = accountSummaryResponse.Settings;
                keys = accountSummaryResponse.keys;
                clientKey = accountSummaryResponse.clientKey;
                enforcements = accountSummaryResponse.Enforcements;
                if (accountSummaryResponse.IsEnterpriseAdmin.HasValue)
                {
                    isEnterpriseAdmin = accountSummaryResponse.IsEnterpriseAdmin.Value;
                }
            }

            if (authContext.SessionTokenRestriction != 0 && Ui is IPostLoginTaskUI postUi)
            {

                if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountExpired) != 0)
                {
                    const string accountExpiredDescription = "Your Keeper account has expired. Please open the Keeper app to renew " +
                        "or visit the Web Vault at https://keepersecurity.com/vault";
                    await postUi.Confirmation(accountExpiredDescription);
                }
                else
                {
                    if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountRecovery) != 0)
                    {
                        const string passwordExpiredDescription =
                            "Your Master Password has expired, you are required to change it before you can login.";
                        if (await postUi.Confirmation(passwordExpiredDescription))
                        {
                            Password = await this.ChangeMasterPassword();
                            authContext.SessionTokenRestriction &= ~SessionTokenRestriction.AccountRecovery;
                        }
                    }
                    if ((authContext.SessionTokenRestriction & SessionTokenRestriction.ShareAccount) != 0)
                    {
                        //expired_account_transfer_description
                        const string accountTransferDescription =
                            "Your Keeper administrator has changed your account settings to enable the ability to transfer your vault records at a later date, " +
                            "in accordance with company operating procedures and or policies." +
                            "\nPlease acknowledge this change in account settings by clicking 'Accept' or contact your administrator to request an extension." +
                            "\nDo you accept Account Transfer policy?";
                        if (await postUi.Confirmation(accountTransferDescription))
                        {
                            await this.ShareAccount(settings?.shareAccountTo);
                            authContext.SessionTokenRestriction &= ~SessionTokenRestriction.ShareAccount;
                        }
                    }
                }

                if (authContext.SessionTokenRestriction == 0)
                {
                    await Login(Username, Password);
                }
                else
                {
                    if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountExpired) != 0)
                    {
                        if (license?.AccountType == 0 && license?.ProductTypeId == 1)
                        {
                            throw new KeeperPostLoginErrors("free_trial_expired_please_purchase",
                                "Your free trial has expired. Please purchase a subscription.");
                        }
                        throw new KeeperPostLoginErrors("expired_please_purchase", 
                            "Your subscription has expired. Please purchase a subscription now.");
                    }
                    if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountRecovery) != 0)
                    {
                        throw new KeeperPostLoginErrors("expired_master_password_description", "Your Master Password has expired, you are required to change it before you can login.");
                    }
                    throw new KeeperPostLoginErrors("need_vault_settings_update", "Please log into the web Vault to update your account settings.");
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(Password))
                {
                    var password = Password;
                    _ = Task.Run(() =>
                    {

                        var salt = CryptoUtils.GetRandomBytes(16);
                        authContext.PasswordValidator = 
                            CryptoUtils.CreateEncryptionParams(password, salt, 100000, CryptoUtils.GetRandomBytes(32));
                    });
                    Password = null;
                }

                if (keys.encryptedPrivateKey != null)
                {
                    var privateKeyData =
                        CryptoUtils.DecryptAesV1(keys.encryptedPrivateKey.Base64UrlDecode(),
                            authContext.DataKey);
                    authContext.PrivateKey = CryptoUtils.LoadPrivateKey(privateKeyData);
                }

                if (!string.IsNullOrEmpty(clientKey))
                {
                    authContext.ClientKey = CryptoUtils.DecryptAesV1(clientKey.Base64UrlDecode(), authContext.DataKey);
                }

                authContext.License = license;
                authContext.Settings = settings;
                authContext.Enforcements = enforcements;
                authContext.IsEnterpriseAdmin = isEnterpriseAdmin;
            }
        }

        internal async Task RefreshSessionToken()
        {
            if (AuthContext is AuthContextV2 contextV2)
            {
                await LoginV2Extensions.RefreshSessionTokenV2(Endpoint, contextV2);
            }
        }

        public async Task<IMessage> ExecuteAuthRest(string endpoint, IMessage request, Type responseType = null)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"{endpoint}\": {request}");
#endif
            var rq = new ApiRequestPayload
            {
                EncryptedSessionToken = ByteString.CopyFrom(authContext.SessionToken),
                ApiVersion = 3,
            };
            if (request != null)
            {
                rq.Payload = request.ToByteString();
            }

            var rsBytes = await Endpoint.ExecuteRest(endpoint, rq);
            if (responseType == null) return null;

            var responseParser = responseType.GetProperty("Parser", BindingFlags.Static | BindingFlags.Public);
            if (responseParser == null) throw new KeeperInvalidParameter("ExecuteAuthRest", "responseType", responseType.Name, "Google Protobuf class expected");
            var mp = (MessageParser) (responseParser.GetMethod.Invoke(null, null));

            var response = mp.ParseFrom(rsBytes);
#if DEBUG
            Debug.WriteLine($"REST response: endpoint \"{endpoint}\": {response}");
#endif
            return response;
        }

        public async Task Logout()
        {
            if (authContext == null) return;
            try
            {
                if (this.IsAuthenticated())
                {
                    if (authContext is AuthContextV3)
                    {
                        await ExecuteAuthRest("vault/logout_v3", null);
                    }
                }
            }
            finally
            {
                authContext?.Dispose();
                authContext = null;
            }
        }
    }

#pragma warning disable 0649
    [DataContract]
    public class NotificationEvent
    {
        [DataMember(Name = "command")]
        public string Command { get; set; }

        [DataMember(Name = "event")]
        public string Event
        {
            get => Command;
            set => Command = value;
        }

        [DataMember(Name = "message")]
        public string Message
        {
            get => Command;
            set => Command = value;
        }

        [DataMember(Name = "email")]
        public string Email { get; set; }

        [DataMember(Name = "username")]
        public string Username
        {
            get => Email;
            set => Email = value;
        }

        [DataMember(Name = "approved")]
        public bool Approved { get; set; }

        [DataMember(Name = "sync")]
        public bool Sync
        {
            get => Approved;
            set => Approved = value;
        }

        [DataMember(Name = "passcode")]
        public string Passcode { get; set; }

        [DataMember(Name = "deviceName")]
        public string DeviceName
        {
            get => Passcode;
            set => Passcode = value;
        }

        [DataMember(Name = "encryptedLoginToken")]
        public string EncryptedLoginToken { get; set; }

        [DataMember(Name = "encryptedDeviceToken")]
        public string EncryptedDeviceToken
        {
            get => EncryptedLoginToken;
            set => EncryptedLoginToken = value;
        }

        [DataMember(Name = "ipAddress")]
        public string IPAddress { get; set; }

    }
#pragma warning restore 0649
}