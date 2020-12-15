using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
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
using SsoCloud;
using PasswordRule = KeeperSecurity.Commands.PasswordRule;

namespace KeeperSecurity.Authentication
{

    public interface IAuthUi
    {
    }

    /// <summary>
    /// Defines the basic properties of Keeper authentication object.
    /// </summary>
    /// <remarks>
    /// Keeper authentication object ....
    /// </remarks>
    public interface IAuth
    {
        /// <summary>
        /// Gets User interaction interface.
        /// </summary>
        IAuthUi AuthUi { get; }

        /// <summary>
        /// Gets a keeper server endpoint
        /// </summary>
        IKeeperEndpoint Endpoint { get; }

        /// <summary>
        /// Gets configuration storage 
        /// </summary>
        IConfigurationStorage Storage { get; }

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

        /// <summary>
        /// Gets or sets session resumption flag
        /// </summary>
        bool ResumeSession { get; set; }

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
    public interface IAuthentication : IAuth
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
        /// <seealso cref="Auth.ExecuteAuthCommand(AuthenticatedCommand,System.Type)"/>
        Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType, bool throwOnError);

        /// <summary>
        /// Executes Keeper Protobuf request.
        /// </summary>
        /// <param name="endpoint">Request endpoint.</param>
        /// <param name="request">Protobuf request.</param>
        /// <param name="responseType">Expected response type</param>
        /// <returns>Task returning Protobuf response.</returns>
        /// <seealso cref="Auth.ExecuteAuthRest"/>
        Task<IMessage> ExecuteAuthRest(string endpoint, IMessage request, Type responseType = null);

        /// <summary>
        /// Logout from Keeper server.
        /// </summary>
        /// <returns>Awaitable Task</returns>
        Task Logout();
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
        /// Gets device information.
        /// </summary>
        DeviceInfo DeviceInfo { get; }

        /// <summary>
        /// Gets user's enterprise enforcements.
        /// </summary>
        IDictionary<string, object> Enforcements { get; }

        /// <summary>
        /// Gets enterprise administrator flag.
        /// </summary>
        bool IsEnterpriseAdmin { get; }

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
        public RsaPrivateCrtKeyParameters PrivateKey { get; internal set; }
        public byte[] SessionToken { get; internal set; }
        public SessionTokenRestriction SessionTokenRestriction { get; set; }
        public AccountLicense License { get; internal set; }
        public AccountSettings Settings { get; internal set; }
        public DeviceInfo DeviceInfo { get; internal set; }
        public IDictionary<string, object> Enforcements { get; internal set; }
        public bool IsEnterpriseAdmin { get; internal set; }
        internal AccountAuthType AccountAuthType { get; set; }
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
    }

    public abstract class AuthCommon : IAuthentication, IDisposable
    {
        protected AuthCommon(IConfigurationStorage storage, IKeeperEndpoint endpoint = null)
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage.LastServer, Storage.Servers);
        }

        /// <summary>
        /// Gets configuration storage.
        /// </summary>
        public IConfigurationStorage Storage { get; protected set; }

        /// <summary>
        /// Gets Keeper endpoint.
        /// </summary>
        
        public IKeeperEndpoint Endpoint { get; protected set; }
        /// <summary>
        /// Gets device token
        /// </summary>
        public byte[] DeviceToken { get; internal set; }

        /// <summary>
        /// Gets user email address.
        /// </summary>
        public string Username { get; internal set; }

        internal AuthContext authContext;
        /// <summary>
        /// Gets connected user context.
        /// </summary>
        public IAuthContext AuthContext => authContext;

        /// <summary>
        /// Gets or sets session resumption flag.
        /// </summary>
        public bool ResumeSession { get; set; }
        /// <summary>
        /// Forces master password login for SSO accounts.
        /// </summary>
        public bool AlternatePassword { get; set; }

        /// <exclude/>
        public IFanOut<NotificationEvent> PushNotifications { get; set; }

        public abstract IAuthUi AuthUi { get; }

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

        /// <summary>
        /// Executes Keeper JSON command.
        /// </summary>
        /// <param name="command">JSON command.</param>
        /// <param name="responseType">Type of response.</param>
        /// <param name="throwOnError">if <c>True</c> throw exception on Keeper error.</param>
        /// <returns>JSON response.</returns>
        /// <exception cref="KeeperApiException">Keeper JSON API Exception</exception>
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
                throw new KeeperAuthFailed();
            }

            if (throwOnError)
            {
                throw new KeeperApiException(response.resultCode, response.message);
            }

            return response;
        }

        /// <summary>
        /// Executes Keeper Protobuf request.
        /// </summary>
        /// <param name="endpoint">Request endpoint.</param>
        /// <param name="request">Protobuf request.</param>
        /// <param name="responseType">Expected response type</param>
        /// <returns>Task returning Protobuf response.</returns>
        /// <seealso cref="IKeeperEndpoint.ExecuteRest"/>
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

        public abstract Task Login(string username, params string[] passwords);
        public abstract Task LoginSso(string providerName, bool forceLogin = false);

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

            if (authContext.SessionTokenRestriction != 0)
            {
                if (AuthUi is IPostLoginTaskUI postUi)
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
                                await this.ShareAccount(settings?.ShareAccountTo);
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
                if (keys.EncryptedPrivateKey != null)
                {
                    var privateKeyData =
                        CryptoUtils.DecryptAesV1(keys.EncryptedPrivateKey.Base64UrlDecode(),
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
                foreach (var device in accountSummaryResponse.Devices)
                {
                    if (DeviceToken.SequenceEqual(device.EncryptedDeviceToken))
                    {
                        authContext.DeviceInfo = device;
                        break;
                    }
                }

                if (authContext.Settings.LogoutTimerInSec.HasValue)
                {
                    if (authContext.Settings.LogoutTimerInSec > TimeSpan.FromMinutes(10).TotalSeconds && authContext.Settings.LogoutTimerInSec < TimeSpan.FromHours(12).TotalSeconds)
                    {
                        SetKeepAliveTimer((int) TimeSpan.FromSeconds(authContext.Settings.LogoutTimerInSec.Value).TotalMinutes, this);
                    }
                }
            }
        }


        /// <summary>
        /// Logout from Keeper server.
        /// </summary>
        /// <returns>Awaitable Task</returns>
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

        public virtual void Dispose()
        {
            authContext = null;
            PushNotifications?.Dispose();
            _timer?.Dispose();
        }
    }
}
