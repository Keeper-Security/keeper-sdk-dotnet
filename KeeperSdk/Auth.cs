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
using System.Net.WebSockets;
using System.Reflection;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using Google.Protobuf;
using Push;
using Type = System.Type;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Tests")]

namespace KeeperSecurity.Sdk
{
    public class SsoLoginInfo
    {
        public string SsoProvider { get; set; }
        public string SpBaseUrl { get; set; }
        internal string IdpSessionId { get; set; }
    }

    public interface IAuth
    {
        IKeeperEndpoint Endpoint { get; }
        IAuthUI Ui { get; }
        IConfigurationStorage Storage { get; }
        IFanOut<NotificationEvent> PushNotifications { get; }
        string Username { get; }
        bool ResumeSession { get; set; }
        byte[] DeviceToken { get; set; }
    }

    public interface IAuthentication : IAuth
    {
        IAuthContext AuthContext { get; }
        Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType);
        Task<IMessage> ExecuteAuthRest(string endpoint, IMessage request, Type responseType = null);
        Task Logout();
    }

    public interface IAuthContext
    {
        byte[] DataKey { get; }
        byte[] SessionToken { get; }
        byte[] ClientKey { get; }
        RsaPrivateCrtKeyParameters PrivateKey { get; }
        bool CheckPasswordValid(string password);
        AccountLicense License { get; }
        AccountSettings Settings { get; }
        IDictionary<string, object> Enforcements { get; }
        bool IsEnterpriseAdmin { get; }
        SsoLoginInfo SsoLoginInfo { get; set; }
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
        public byte[] DataKey { get; internal set; }
        public byte[] ClientKey { get; internal set; }
        public RsaPrivateCrtKeyParameters PrivateKey { get; internal set; }
        public byte[] SessionToken { get; internal set; }
        public SessionTokenRestriction SessionTokenRestriction { get; set; }
        public AccountLicense License { get; internal set; }
        public AccountSettings Settings { get; internal set; }
        public IDictionary<string, object> Enforcements { get; internal set; }
        public bool IsEnterpriseAdmin { get; internal set; }
        internal AccountAuthType AccountAuthType { get; set; }
        public SsoLoginInfo SsoLoginInfo { get; set; }
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
    }

    public class Auth : IAuthentication, IDisposable
    {
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
        public IKeeperEndpoint Endpoint { get; }
        public byte[] DeviceToken { get; set; }
        public bool ResumeSession { get; set; }
        public bool AlternatePassword { get; set; }

        public IAuthUI Ui { get; }
        public IConfigurationStorage Storage { get; }

        internal AuthContext authContext;
        public IAuthContext AuthContext => authContext;

        public IFanOut<NotificationEvent> PushNotifications { get;  set; }

        public Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType = null)
        {
            return ExecuteAuthCommand(command, responseType, true);
        }

        public async Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType, bool throwOnError = true)
        {
            command.username = Username;
            command.sessionToken = authContext.SessionToken.Base64UrlEncode();
            var response = await Endpoint.ExecuteV2Command(command, responseType);
            if (response.IsSuccess)
            {
                this.ResetKeepAliveTimer();
                return response;
            }

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

        public async Task LoginSso(string providerName, bool forceLogin = false)
        {
            var authV3 = new AuthV3Wrapper(this);
            var attempt = 0;
            while (attempt < 3)
            {
                attempt++;
                try
                {
                    var contextV3 = await authV3.LoginSsoV3(providerName, forceLogin);
                    this.StoreConfigurationIfChangedV3(authV3.CloneCode);
                    authContext = contextV3;
                    await PostLogin();
                }
                catch (KeeperRegionRedirect krr)
                {
                    await this.RedirectToRegionV3(krr.RegionHost);
                    if (string.IsNullOrEmpty(krr.Username)) continue;

                    Username = krr.Username;
                    await authV3.LoginV3();
                }
                return;
            }
            throw new KeeperAuthFailed();
        }

        public async Task Login(string username, params string[] passwords)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
            }

            Username = username.ToLowerInvariant();
            var authV3 = new AuthV3Wrapper(this);
            try
            {
                authContext = await authV3.LoginV3(passwords);
            }
            catch (KeeperRegionRedirect krr)
            {
                await this.RedirectToRegionV3(krr.RegionHost);
                authContext = await authV3.LoginV3(passwords);
            }

            this.StoreConfigurationIfChangedV3(authV3.CloneCode);

            await PostLogin();
        }

        private async Task PostLogin()
        {
            AccountLicense license;
            AccountSettings settings;
            AccountKeys keys;
            IDictionary<string, object> enforcements;
            string clientKey = null;
            bool isEnterpriseAdmin = false;
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

            if (authContext.SessionTokenRestriction != 0)
            {
                if (Ui is IPostLoginTaskUI postUi)
                {
                    if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountExpired) != 0)
                    {
                        var accountExpiredDescription = "Your Keeper account has expired. Please open the Keeper app to renew " +
                            $"or visit the Web Vault at https://{Endpoint.Server}/vault";
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
                                var newPassword = await this.ChangeMasterPassword();

                                var validatorSalt = CryptoUtils.GetRandomBytes(16);
                                authContext.PasswordValidator =
                                    CryptoUtils.CreateEncryptionParams(newPassword, validatorSalt, 100000, CryptoUtils.GetRandomBytes(32));

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
                }

                if (authContext.SessionTokenRestriction == 0)
                {
                    // ???? relogin
                    await Login(Username);
                }
                else
                {
                    try
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
                    finally
                    {
                        await Logout();
                    }
                }
            }
            else
            {
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

                if (authContext.Settings.logoutTimerInSec.HasValue)
                {
                    if (authContext.Settings.logoutTimerInSec > TimeSpan.FromMinutes(10).TotalSeconds && authContext.Settings.logoutTimerInSec < TimeSpan.FromHours(12).TotalSeconds)
                    {
                        SetKeepAliveTimer((int) TimeSpan.FromSeconds(authContext.Settings.logoutTimerInSec.Value).TotalMinutes, this);
                    }
                }
            }
        }

        internal async Task<IFanOut<NotificationEvent>> ConnectToPushServer(WssConnectionRequest connectionRequest, CancellationToken token)
        {
            var transmissionKey = CryptoUtils.GenerateEncryptionKey();
            var apiRequest = Endpoint.PrepareApiRequest(connectionRequest, transmissionKey);
            var builder = new UriBuilder
            {
                Scheme = "wss",
                Host = Endpoint.PushServer(),
                Path = "wss_open_connection/" + apiRequest.ToByteArray().Base64UrlEncode()
            };
            var ws = new ClientWebSocket();
            await ws.ConnectAsync(builder.Uri, token);

            return new WebSocketChannel(ws, transmissionKey, token);
        }

        private Timer _timer;
        private long _lastRequestTime;

        internal void SetKeepAliveTimer(int timeoutInMinutes, IAuthentication auth)
        {
            _timer?.Dispose();
            _timer = null;
            if (auth == null) return;

            ResetKeepAliveTimer();
            var timeout = TimeSpan.FromMinutes(timeoutInMinutes - (timeoutInMinutes > 1 ? 1 : 0));
            _timer = new Timer(async (_) =>
                {
                    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000;
                    if (_lastRequestTime + timeout.TotalSeconds / 2 > now) return;
                    try
                    {
                        await auth.ExecuteAuthRest("keep_alive", null);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                        _timer.Dispose();
                        _timer = null;
                    }

                    _lastRequestTime = now;
                },
                null,
                (long) timeout.TotalMilliseconds / 2,
                (long) timeout.TotalMilliseconds / 2);
        }

        internal void ResetKeepAliveTimer()
        {
            _lastRequestTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000;
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
            this.ResetKeepAliveTimer();
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
                    await ExecuteAuthRest("vault/logout_v3", null);
                    this.SsoLogout();
                }
            }
            finally
            {
                authContext = null;
                _timer?.Dispose();
                _timer = null;
            }
        }

        public void Dispose()
        {
            authContext = null;
            PushNotifications?.Dispose();
            _timer?.Dispose();
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