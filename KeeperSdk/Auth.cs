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
using System.Threading.Tasks;
using KeeperSecurity.Sdk.UI;
using System.Diagnostics;
using System.Reflection;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using AccountSummary;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using SsoCloud;
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

    public interface IAuthContext: IDisposable
    {
        string Username { get; }
        byte[] DataKey { get; }
        byte[] SessionToken { get; }
        byte[] DeviceToken { get; }
        byte[] ClientKey { get; }
        RsaPrivateCrtKeyParameters PrivateKey { get; }
        IFanOut<NotificationEvent> PushNotifications { get; }
    }

    [Flags]
    public enum SessionTokenRestriction
    {
        AccountRecovery = 1 << 0,
        ShareAccount = 1 << 1,
        AcceptInvite = 1 << 2,
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

        private static bool IsV3Api(string clientVersion)
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
            if (authContext.SessionTokenRestriction != 0 && Ui is IPostLoginTaskUI postUi)
            {
                if ((authContext.SessionTokenRestriction & SessionTokenRestriction.AccountRecovery) != 0)
                {
                    Password = await this.ChangeMasterPassword();
                    authContext.SessionTokenRestriction &= ~SessionTokenRestriction.AccountRecovery;
                }

                if ((authContext.SessionTokenRestriction & SessionTokenRestriction.ShareAccount) != 0)
                {
                    //expired_account_transfer_description
                    var description =
                        "Your Keeper administrator has changed your account settings to enable the ability to transfer your vault records at a later date, " +
                        "in accordance with company operating procedures and or policies." +
                        "\nPlease acknowledge this change in account settings by clicking 'Accept' or contact your administrator to request an extension." +
                        "\nDo you accept Account Transfer policy?";
                    if (await postUi.Confirmation(description))
                    {
                        var cmd = new AccountSummaryCommand
                        {
                            include = new[] { "settings" }
                        };
                        var summaryRs = await this.ExecuteAuthCommand<AccountSummaryCommand, AccountSummaryResponse>(cmd);
                        await this.ShareAccount(summaryRs.Settings.shareAccountTo);
                        authContext.SessionTokenRestriction &= ~SessionTokenRestriction.ShareAccount;
                    }
                }


                if (authContext.SessionTokenRestriction == 0)
                {
                    await Login(Username, Password);
                }
                else
                {
                    //need_vault_settings_update
                    throw new KeeperPostLoginErrors("Please log into the web Vault to update your account settings.");
                }
            }
            else
            {
                Username = null;
                Password = null;

                if (isV3Api)
                {
                    var rq = new AccountSummaryRequest
                    {
                        SummaryVersion = 1
                    };
                    var rs = await this.ExecuteAuthRest<AccountSummaryRequest, AccountSummaryElements>("login/account_summary", rq);
                    if (rs.ClientKey?.Length > 0)
                    {
                        authContext.ClientKey = CryptoUtils.DecryptAesV1(rs.ClientKey.ToByteArray(), authContext.DataKey);
                    }

                    if (rs.KeysInfo?.EncryptedPrivateKey?.Length > 0)
                    {
                        var privateKeyData =
                            CryptoUtils.DecryptAesV1(rs.KeysInfo.EncryptedPrivateKey.ToByteArray(), authContext.DataKey);
                        authContext.PrivateKey = CryptoUtils.LoadPrivateKey(privateKeyData);
                    }
                }
                else
                {
                    var accountSummaryRq = new AccountSummaryCommand
                    {
                        include = new[] { "keys", "client_key" },
                    };
                    var accountSummaryRs = await this.ExecuteAuthCommand<AccountSummaryCommand, AccountSummaryResponse>(accountSummaryRq);
                    if (accountSummaryRs.keys.encryptedPrivateKey != null)
                    {
                        var privateKeyData =
                            CryptoUtils.DecryptAesV1(accountSummaryRs.keys.encryptedPrivateKey.Base64UrlDecode(),
                                authContext.DataKey);
                        authContext.PrivateKey = CryptoUtils.LoadPrivateKey(privateKeyData);
                    }

                    if (!string.IsNullOrEmpty(accountSummaryRs.clientKey))
                    {
                        authContext.ClientKey = CryptoUtils.DecryptAesV1(accountSummaryRs.clientKey.Base64UrlDecode(), authContext.DataKey);
                    }
                }
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