﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Commands;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using PasswordRule = KeeperSecurity.Commands.PasswordRule;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Specifies login type
    /// </summary>
    public enum AccountAuthType
    {
        /// <summary>
        /// Regular account
        /// </summary>
        Regular = 1,
        /// <summary>
        /// Cloud SSO account
        /// </summary>
        CloudSso = 2,
        /// <summary>
        /// On-Premises SSO account
        /// </summary>
        OnsiteSso = 3,
        /// <summary>
        /// MSP logged in to MC
        /// </summary>
        ManagedCompany = 4
    }

    /// <exclude/>
    public interface IAuthCallback
    {
    }

    /// <summary>
    /// Defines the basic properties of Keeper endpoint object.
    /// </summary>
    public interface IAuthEndpoint
    {
        /// <exclude/>
        IAuthCallback AuthCallback { get; }

        /// <summary>
        /// Gets a keeper server endpoint
        /// </summary>
        IKeeperEndpoint Endpoint { get; }
        /// <exclude/>
        IFanOut<NotificationEvent> PushNotifications { get; }

        /// <summary>
        /// Gets user email address.
        /// </summary>
        /// <remarks>
        /// This property is set by <c>Login</c> method
        /// </remarks>
        string Username { get; }

        /// <summary>
        /// Gets device token
        /// </summary>
        byte[] DeviceToken { get; }
    }

    /// <summary>
    /// Defines the properties and methods of not connected Keeper authentication object.
    /// </summary>
    public interface IAuth: IAuthEndpoint
    {
        /// <summary>
        /// Gets or sets username.
        /// </summary>
        new string Username { get; set; }

        /// <exclude />
        void SetPushNotifications(IFanOut<NotificationEvent> pushNotifications);

        /// <summary>
        /// Gets or sets device token
        /// </summary>
        new byte[] DeviceToken { get; set; }

        /// <summary>
        /// Gets configuration storage 
        /// </summary>
        IConfigurationStorage Storage { get; }

        /// <summary>
        /// Gets or sets session resumption flag
        /// </summary>
        bool ResumeSession { get; set; }

        /// <summary>
        /// Forces master password login for SSO accounts.
        /// </summary>
        bool AlternatePassword { get; set; }

        /// <summary>
        /// Login to Keeper account with email.
        /// </summary>
        /// <param name="username">Keeper account email address.</param>
        /// <param name="passwords">Master password(s)</param>
        /// <returns>Awaitable task</returns>
        /// <seealso cref="LoginSso(string, bool)"/>
        /// <exception cref="KeeperStartLoginException">Unrecoverable login error.</exception>
        /// <exception cref="KeeperCanceled">Login cancelled.</exception>
        /// <exception cref="Exception">Other exceptions.</exception>
        Task Login(string username, params string[] passwords);

        /// <summary>
        /// Login to Keeper account with SSO Provider.
        /// </summary>
        /// <param name="providerName">SSO provider name.</param>
        /// <param name="forceLogin">Force new login with SSO IdP.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="KeeperStartLoginException">Unrecoverable login error.</exception>
        /// <exception cref="KeeperCanceled">Login cancelled.</exception>
        /// <exception cref="Exception">Other exceptions.</exception>
        /// <seealso cref="Login(string, string[])" />
        Task LoginSso(string providerName, bool forceLogin = false);
    }

    /// <summary>
    /// Defines properties and methods of connected Keeper authentication object.
    /// </summary>
    public interface IAuthentication : IAuthEndpoint
    {
        /// <summary>
        /// Gets authentication context
        /// </summary>
        IAuthContext AuthContext { get; }

        /// <summary>
        /// Executes Keeper JSON command.
        /// </summary>
        /// <param name="command">Keeper JSON command.</param>
        /// <param name="responseType">Type of response.</param>
        /// <param name="throwOnError">throws exception on error.</param>
        /// <returns>Task returning JSON response.</returns>
        /// <seealso cref="AuthExtensions.ExecuteAuthCommand"/>
        Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType, bool throwOnError);

        /// <summary>
        /// Executes Keeper Protobuf request.
        /// </summary>
        /// <param name="endpoint">Request endpoint.</param>
        /// <param name="request">Protobuf request.</param>
        /// <param name="responseType">Expected response type</param>
        /// <param name="apiVersion">Request version</param>
        /// <returns>Task returning Protobuf response.</returns>
        /// <seealso cref="AuthExtensions.ExecuteAuthRest"/>
        Task<IMessage> ExecuteAuthRest(string endpoint, IMessage request, Type responseType = null, int apiVersion=0);

        /// <summary>
        /// Logout from Keeper server.
        /// </summary>
        /// <returns>Awaitable Task</returns>
        Task Logout();

        /// <exclude/>
        Task AuditEventLogging(string eventType, AuditEventInput input = null);
        /// <exclude/>
        void ScheduleAuditEventLogging(string eventType, AuditEventInput input = null);
        /// <exclude/>
        Task FlushAuditEvents();
    }

    /// <summary>
    /// Defines properties of connected user.
    /// </summary>
    public interface IAuthContext
    {
        /// <summary>
        /// User's Data Key.
        /// </summary>
        byte[] DataKey { get; }

        /// <summary>
        /// Connection Token.
        /// </summary>
        byte[] SessionToken { get; }

        /// <summary>
        /// User's Client Key.
        /// </summary>
        byte[] ClientKey { get; }

        /// <summary>
        /// User's RSA Private Key.
        /// </summary>
        RsaPrivateCrtKeyParameters PrivateRsaKey { get; }

        /// <summary>
        /// User's EC Private key
        /// </summary>
        ECPrivateKeyParameters PrivateEcKey { get; }

        /// <summary>
        /// Enterprise EC Public key
        /// </summary>
        ECPublicKeyParameters EnterprisePublicEcKey { get; }

        /// <exclude/>
        [Obsolete("Use PrivateRsaKey")]
        RsaPrivateCrtKeyParameters PrivateKey { get; }

        /// <summary>
        /// Gets user's account license.
        /// </summary>
        AccountLicense License { get; }

        /// <summary>
        /// Gets user's account settings.
        /// </summary>
        AccountSettings Settings { get; }

        /// <summary>
        /// Gets user's enterprise enforcements.
        /// </summary>
        IDictionary<string, object> Enforcements { get; }

        /// <summary>
        /// Gets enterprise administrator flag.
        /// </summary>
        bool IsEnterpriseAdmin { get; }

        /// <summary>
        /// Gets account login type
        /// </summary>
        AccountAuthType AccountAuthType { get; }

        /// <summary>
        /// Gets SSO provider information
        /// </summary>
        SsoLoginInfo SsoLoginInfo { get; }

        /// <exclude/>
        bool CheckPasswordValid(string password);
    }

    [Flags]
    internal enum SessionTokenRestriction
    {
        AccountRecovery = 1 << 0,
        ShareAccount = 1 << 1,
        AcceptInvite = 1 << 2,
        AccountExpired = 1 << 3,
    }

    /// <summary>
    /// Describes SSO Provider connection parameters
    /// </summary>
    public class SsoLoginInfo
    {
        /// <summary>
        /// Gets SSO Provider name
        /// </summary>
        public string SsoProvider { get; internal set; }
        /// <summary>
        /// Gets SSO Provider base URL
        /// </summary>
        public string SpBaseUrl { get; internal set; }
        internal string IdpSessionId { get; set; }
    }

    internal class AuthContext : IAuthContext
    {
        public byte[] DataKey { get; internal set; }
        public byte[] ClientKey { get; internal set; }
        public RsaPrivateCrtKeyParameters PrivateRsaKey { get; internal set; }
        public ECPrivateKeyParameters PrivateEcKey { get; internal set; }
        public ECPublicKeyParameters EnterprisePublicEcKey { get; internal set; }
        public byte[] SessionToken { get; internal set; }
        public SessionTokenRestriction SessionTokenRestriction { get; set; }
        public AccountLicense License { get; internal set; }
        public AccountSettings Settings { get; internal set; }
        public DeviceInfo DeviceInfo { get; internal set; }
        public IDictionary<string, object> Enforcements { get; internal set; }
        public bool IsEnterpriseAdmin { get; internal set; }
        public AccountAuthType AccountAuthType { get; set; }
        public SsoLoginInfo SsoLoginInfo { get; internal set; }
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
        public RsaPrivateCrtKeyParameters PrivateKey => PrivateRsaKey;
    }

    /// <summary>
    /// Represents base authentication class
    /// </summary>
    /// <seealso cref="Sync.AuthSync"/>
    public abstract class AuthCommon : IAuthentication, IDisposable
    {
        /// <inheritdoc/>

        public IKeeperEndpoint Endpoint { get; protected set; }

        /// <inheritdoc/>
        public string Username { get; protected set; }

        /// <inheritdoc/>
        public byte[] DeviceToken { get; protected set; }

        internal AuthContext authContext;

        /// <inheritdoc/>
        public IAuthContext AuthContext => authContext;

        /// <exclude/>
        public IFanOut<NotificationEvent> PushNotifications { get; internal set; }

        /// <exclude/>
        public abstract IAuthCallback AuthCallback { get; }

        internal void ResetKeepAliveTimer()
        {
            _lastRequestTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000;
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

        /// <inheritdoc/>
        public async Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType, bool throwOnError)
        {
            command.username = Username;
            command.sessionToken = authContext.SessionToken.Base64UrlEncode();
            var response = await Endpoint.ExecuteV2Command(command, responseType);
            if (response.IsSuccess)
            {
                ResetKeepAliveTimer();
                return response;
            }

            if (response.resultCode == "auth_failed")
            {
                throw new KeeperAuthFailed(response.message);
            }

            if (throwOnError)
            {
                throw new KeeperApiException(response.resultCode, response.message);
            }

            return response;
        }

        /// <inheritdoc/>
        public async Task<IMessage> ExecuteAuthRest(string endpoint, IMessage request, Type responseType = null, int apiVersion=0)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"{endpoint}\": {request}");
#endif
            var rq = new ApiRequestPayload
            {
                EncryptedSessionToken = ByteString.CopyFrom(authContext.SessionToken),
                ApiVersion = apiVersion,
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

        /// <exclude/>
        public void SetPushNotifications(IFanOut<NotificationEvent> pushNotifications)
        {
            if (!ReferenceEquals(PushNotifications, pushNotifications))
            {
                PushNotifications?.Dispose();
                PushNotifications = pushNotifications;
            }
        }

        protected virtual IWebProxy GetStoredProxy(Uri proxyUri, string[] proxyAuth)
        {
#if NET452_OR_GREATER
            if (CredentialManager.GetCredentials(proxyUri.DnsSafeHost, out var username, out var password))
            {
                return AuthUIExtensions.GetWebProxyForCredentials(proxyUri, proxyAuth, username, password);
            }
#endif
            return null;
        }

        /// <exclude />
        public async Task<bool> DetectProxy(Action<Uri, string[]> onProxyDetected)
        {
            var keeperUri = new Uri($"https://{Endpoint.Server}/api/rest/ping");
            string authHeader = "";
            try
            {
                await PingKeeperServer(keeperUri, Endpoint.WebProxy);
                return true;
            }
            catch (WebException e)
            {
                var response = (HttpWebResponse) e.Response;
                if (response?.StatusCode != HttpStatusCode.ProxyAuthenticationRequired) throw e;

                authHeader = response.Headers.AllKeys
                    .Where(x => string.Compare(x, "Proxy-Authenticate", StringComparison.OrdinalIgnoreCase) == 0)
                    .Select(x => response.Headers[x])
                    .FirstOrDefault();
            }
            var systemProxy = WebRequest.GetSystemWebProxy();
            var directUri = systemProxy.GetProxy(keeperUri);
            var proxyAuthenticate = KeeperSettings.ParseProxyAuthentication(authHeader).ToArray();

            var proxy = GetStoredProxy(directUri, proxyAuthenticate);
            if (proxy != null && !ReferenceEquals(proxy, Endpoint.WebProxy))
            {
                try
                {
                    await PingKeeperServer(keeperUri, proxy);
                    Endpoint.WebProxy = proxy;
                    return true;
                }
                catch (WebException e)
                {
                    var response = (HttpWebResponse) e.Response;
                    if (response?.StatusCode != HttpStatusCode.ProxyAuthenticationRequired) throw e;
                }
            }
            onProxyDetected?.Invoke(directUri, proxyAuthenticate);
            return false;
        }

        internal virtual async Task<bool> PingKeeperServer(Uri keeperUri, IWebProxy proxy)
        {
            var request = (HttpWebRequest) WebRequest.Create(keeperUri);
            if (proxy != null)
            {
                request.Proxy = proxy;
            }
            using (var response = (HttpWebResponse) await request.GetResponseAsync())
            {
                if (response.StatusCode != HttpStatusCode.OK) return false;
                var rs = response.GetResponseStream();
                if (rs == null) return false;
                using (var sr = new StreamReader(rs, Encoding.UTF8))
                {
                    var status = await sr.ReadLineAsync();
                    return status == "alive";
                }
            }
        }

        /// <exclude/>
        public bool SupportRestrictedSession { get; set; }

        protected async Task PostLogin()
        {
            string clientKey = null;
            var accountSummaryResponse = await this.LoadAccountSummary();
            var license = AccountLicense.LoadFromProtobuf(accountSummaryResponse.License);
            var settings = AccountSettings.LoadFromProtobuf(accountSummaryResponse.Settings);
            var keys = AccountKeys.LoadFromProtobuf(accountSummaryResponse.KeysInfo);

            if (accountSummaryResponse.ClientKey?.Length > 0)
            {
                clientKey = accountSummaryResponse.ClientKey.ToByteArray().Base64UrlEncode();
            }

            IDictionary<string, object> enforcements = new Dictionary<string, object>();
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

            var isEnterpriseAdmin = accountSummaryResponse.IsEnterpriseAdmin;
            if (keys.EncryptedPrivateKey != null)
            {
                var privateKeyData =
                    CryptoUtils.DecryptAesV1(keys.EncryptedPrivateKey.Base64UrlDecode(),
                        authContext.DataKey);
                authContext.PrivateRsaKey = CryptoUtils.LoadPrivateKey(privateKeyData);
            }
            if (keys.EncryptedEcPrivateKey != null) {
                var privateKeyData =
                    CryptoUtils.DecryptAesV2(keys.EncryptedEcPrivateKey.Base64UrlDecode(),
                        authContext.DataKey);
                authContext.PrivateEcKey = CryptoUtils.LoadPrivateEcKey(privateKeyData);
            }

            if (!string.IsNullOrEmpty(clientKey))
            {
                authContext.ClientKey = CryptoUtils.DecryptAesV1(clientKey.Base64UrlDecode(), authContext.DataKey);
            }

            authContext.License = license;
            authContext.Settings = settings;
            authContext.Enforcements = enforcements;
            authContext.IsEnterpriseAdmin = isEnterpriseAdmin;

            if (authContext.SessionTokenRestriction != 0)
            {
                if (AuthCallback is IPostLoginTaskUI postUi)
                {
                    if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountExpired) != 0)
                    {
                        var accountExpiredDescription =
                            "Your Keeper account has expired. Please open the Keeper app to renew " +
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
                                    CryptoUtils.CreateEncryptionParams(newPassword, validatorSalt, 100000,
                                        CryptoUtils.GetRandomBytes(32));

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
                                await this.ShareAccount(settings?.ShareAccountTo);
                                authContext.SessionTokenRestriction &= ~SessionTokenRestriction.ShareAccount;
                            }
                        }
                    }
                }

                if (authContext.SessionTokenRestriction == 0)
                {
                    // ???? relogin
                }
                else
                {
                    if (!SupportRestrictedSession)
                    {
                        if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountExpired) != 0)
                        {
                            if (authContext.License?.AccountType == 0 && authContext.License?.ProductTypeId == 1)
                            {
                                throw new KeeperPostLoginErrors("free_trial_expired_please_purchase",
                                    "Your free trial has expired. Please purchase a subscription.");
                            }

                            throw new KeeperPostLoginErrors("expired_please_purchase",
                                "Your subscription has expired. Please purchase a subscription now.");
                        }

                        if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountRecovery) != 0)
                        {
                            throw new KeeperPostLoginErrors("expired_master_password_description",
                                "Your Master Password has expired, you are required to change it before you can login.");
                        }

                        throw new KeeperPostLoginErrors("need_vault_settings_update",
                            "Please log into the web Vault to update your account settings.");
                    }
                }
            }
            else
            {
                if (authContext.Settings.LogoutTimerInSec.HasValue)
                {
                    if (authContext.Settings.LogoutTimerInSec > TimeSpan.FromMinutes(10).TotalSeconds &&
                        authContext.Settings.LogoutTimerInSec < TimeSpan.FromHours(12).TotalSeconds)
                    {
                        SetKeepAliveTimer(
                            (int) TimeSpan.FromSeconds(authContext.Settings.LogoutTimerInSec.Value).TotalMinutes, this);
                    }
                }

                if (authContext.License.AccountType == 2)
                {
                    try
                    {
                        var rs = (BreachWatch.EnterprisePublicKeyResponse) await ExecuteAuthRest(
                            "enterprise/get_enterprise_public_key", null,
                            typeof(BreachWatch.EnterprisePublicKeyResponse));
                        authContext.EnterprisePublicEcKey =
                            CryptoUtils.LoadPublicEcKey(rs.EnterpriseECCPublicKey.ToByteArray());
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }
            }
        }

        private readonly List<AuditEventItem> _auditEventQueue = new List<AuditEventItem>();

        /// <exclude/>
        public void ScheduleAuditEventLogging(string eventType, AuditEventInput input = null)
        {
            if (AuthContext.EnterprisePublicEcKey != null)
            {
                _auditEventQueue.Add(new AuditEventItem
                {
                    AuditEventType = eventType,
                    Inputs = input
                });
            }
        }

        /// <exclude/>
        public async Task FlushAuditEvents()
        {
            if (AuthContext.EnterprisePublicEcKey != null)
            {
                List<AuditEventItem> events = null;
                lock (_auditEventQueue)
                {
                    events = new List<AuditEventItem>(_auditEventQueue);
                    _auditEventQueue.Clear();
                }
                while (events.Count > 0)
                {
                    var chunk = events.Take(99).ToArray();
                    events.RemoveRange(0, chunk.Length);

                    var rq = new AuditEventLoggingCommand
                    {
                        ItemLogs = chunk
                    };
                    _ = await AuthExtensions.ExecuteAuthCommand<AuditEventLoggingCommand, AuditEventLoggingResponse>(this, rq);
                }
            }
        }

        /// <exclude/>
        public async Task AuditEventLogging(string eventType, AuditEventInput input = null)
        {
            if (AuthContext.EnterprisePublicEcKey != null)
            {
                ScheduleAuditEventLogging(eventType, input);
                await FlushAuditEvents();
            }
        }

        private async Task DoLogout()
        {
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

        /// <inheritdoc/>
        public virtual async Task Logout()
        {
            await DoLogout();
        }

        /// <inheritdoc/>
        public virtual void Dispose()
        {
            authContext = null;
            PushNotifications?.Dispose();
            _timer?.Dispose();
        }
    }
#pragma warning disable 0649
    /// <exclude/>
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

    /// <exclude/>
    [DataContract]
    public class MasterPasswordReentry
    {
        [DataMember(Name = "operations")]
        public string[] operations;

        [DataMember(Name = "timeout")]
        internal string _timeout;

        public int Timeout
        {
            get
            {
                if (!string.IsNullOrEmpty(_timeout))
                {
                    if (int.TryParse(_timeout, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i))
                    {
                        return i;
                    }
                }

                return 1;
            }
        }
    }

}
