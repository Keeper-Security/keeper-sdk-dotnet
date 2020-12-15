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
using System.Diagnostics;
using System.Threading.Tasks;
using System.Globalization;
using System.Runtime.CompilerServices;
using Authentication;
using System.Runtime.Serialization;
using System.Threading;
using Google.Protobuf;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;

[assembly: InternalsVisibleTo("Tests")]
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2")]

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Represents Keeper authentication.
    /// </summary>
    /// <seealso cref="IAuth"/>
    /// <seealso cref="IAuthentication"/>
    public class Auth : AuthCommon
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="authUi">User Interface.</param>
        /// <param name="storage">Configuration storage.</param>
        /// <param name="endpoint">Keeper Endpoint.</param>
        public Auth(IAuthUI authUi, IConfigurationStorage storage, IKeeperEndpoint endpoint = null) : base(storage, endpoint)
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage.LastServer, Storage.Servers);

            Ui = authUi;
            if (Endpoint is KeeperEndpoint ep && Ui is IHttpProxyCredentialUi proxyUi)
            {
                ep.ProxyUi = proxyUi;
            }
        }

        /// <summary>
        /// Gets User interaction interface.
        /// </summary>
        public IAuthUI Ui { get; private set; }

        public override IAuthUi AuthUi => Ui;

        /// <summary>
        /// Login to Keeper account with SSO provider.
        /// </summary>
        /// <param name="providerName">SSO provider name.</param>
        /// <param name="forceLogin">Force new login with SSO IdP.</param>
        /// <returns>Awaitable task.</returns>
        /// <seealso cref="Login(string, string[])"/>
        /// <exception cref="KeeperCanceled">Login is cancelled.</exception>
        /// <exception cref="KeeperStartLoginException">Unrecoverable login exception.</exception>
        /// <exception cref="Exception">Generic exception.</exception>
        public override async Task LoginSso(string providerName, bool forceLogin = false)
        {
            var v3 = new V3LoginContext();
            var attempt = 0;
            while (attempt < 3)
            {
                attempt++;
                try
                {
                    var contextV3 = await LoginSsoV3(v3, providerName, forceLogin);
                    this.StoreConfigurationIfChangedV3(v3.CloneCode);
                    authContext = contextV3;
                    await PostLogin();
                }
                catch (KeeperRegionRedirect krr)
                {
                    await this.RedirectToRegionV3(krr.RegionHost);
                    if (string.IsNullOrEmpty(krr.Username)) continue;

                    Username = krr.Username;
                    await this.LoginV3(v3);
                }

                return;
            }

            throw new KeeperAuthFailed();
        }

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
        public override async Task Login(string username, params string[] passwords)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
            }

            Username = username.ToLowerInvariant();
            var v3 = new V3LoginContext();
            foreach (var p in passwords)
            {
                if (string.IsNullOrEmpty(p)) continue;
                v3.PasswordQueue.Enqueue(p);
            }

            try
            {
                authContext = await LoginV3(v3, passwords);
            }
            catch (KeeperRegionRedirect krr)
            {
                await this.RedirectToRegionV3(krr.RegionHost);
                authContext = await LoginV3(v3, passwords);
            }

            this.StoreConfigurationIfChangedV3(v3.CloneCode);
            await PostLogin();
        }

        private async Task<AuthContext> LoginSsoV3(V3LoginContext v3, string providerName, bool forceLogin)
        {
            if (Ui != null && Ui is IAuthSsoUI)
            {
                var payload = new ApiRequestPayload
                {
                    ApiVersion = 3,
                    Payload = new SsoServiceProviderRequest
                    {
                        ClientVersion = Endpoint.ClientVersion,
                        Locale = Endpoint.Locale,
                        Name = providerName
                    }.ToByteString()
                };

                var rsBytes = await Endpoint.ExecuteRest("enterprise/get_sso_service_provider", payload);
                if (rsBytes?.Length > 0)
                {
                    var rs = SsoServiceProviderResponse.Parser.ParseFrom(rsBytes);

                    v3.AccountAuthType = rs.IsCloud ? AccountAuthType.CloudSso : AccountAuthType.OnsiteSso;
                    if (rs.IsCloud)
                    {
                        return await this.AuthorizeUsingCloudSso(v3, rs.SpUrl, forceLogin);
                    }

                    return await this.AuthorizeUsingOnsiteSso(v3, rs.SpUrl, forceLogin);
                }

                throw new KeeperInvalidParameter("enterprise/get_sso_service_provider", "provider_name", providerName, "SSO provider not found");
            }

            throw new KeeperAuthFailed();
        }


        private async Task<AuthContext> LoginV3(V3LoginContext v3, params string[] passwords)
        {
            try
            {
                var loginMethod = v3.AccountAuthType == AccountAuthType.Regular || v3.PasswordQueue.Count == 0
                    ? LoginMethod.ExistingAccount
                    : LoginMethod.AfterSso;
                return await this.StartLogin(v3, false, loginMethod);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                throw;
            }
        }

        private async Task<AuthContext> ExecuteStartLogin(V3LoginContext v3, StartLoginRequest request)
        {
#if DEBUG
            Debug.WriteLine($"REST Request: endpoint \"start_login\": {request}");
#endif

            var rs = await Endpoint.ExecuteRest("authentication/start_login", new ApiRequestPayload {Payload = request.ToByteString()});
            var response = LoginResponse.Parser.ParseFrom(rs);
#if DEBUG
            Debug.WriteLine($"REST Response: endpoint \"start_login\": {response}");
#endif
            switch (response.LoginState)
            {
                case LoginState.LoggedIn:
                    Username = response.PrimaryUsername;
                    v3.CloneCode = response.CloneCode.ToByteArray();
                    var context = new AuthContext
                    {
                        SessionToken = response.EncryptedSessionToken.ToByteArray(),
                        SessionTokenRestriction = LoginV3Extensions.GetSessionTokenScope(response.SessionTokenType),
                        SsoLoginInfo = v3.SsoLoginInfo,
                    };
                    var encryptedDataKey = response.EncryptedDataKey.ToByteArray();
                    switch (response.EncryptedDataKeyType)
                    {
                        case EncryptedDataKeyType.ByDevicePublicKey:
                            context.DataKey = CryptoUtils.DecryptEc(encryptedDataKey, v3.DeviceKey);
                            break;
                    }

                    return context;

                case LoginState.RequiresUsername:
                    return await ResumeLogin(v3, response.EncryptedLoginToken);

                case LoginState.Requires2Fa:
                    if (Ui != null)
                    {
                        return await TwoFactorValidate(v3, response.EncryptedLoginToken, response.Channels);
                    }

                    break;
                case LoginState.RequiresAuthHash:
                    if (Ui != null)
                    {
                        return await ValidateAuthHash(v3, response.EncryptedLoginToken, response.Salt);
                    }

                    break;

                case LoginState.DeviceApprovalRequired:
                    if (Ui != null)
                    {
                        return await ApproveDevice(v3, response.EncryptedLoginToken);
                    }

                    break;

                case LoginState.RedirectCloudSso:
                    v3.AccountAuthType = AccountAuthType.CloudSso;
                    return await AuthorizeUsingCloudSso(v3, response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

                case LoginState.RedirectOnsiteSso:
                    v3.AccountAuthType = AccountAuthType.OnsiteSso;
                    return await AuthorizeUsingOnsiteSso(v3, response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

                case LoginState.RequiresDeviceEncryptedDataKey:
                {
                    if (Ui != null)
                    {
                        v3.CloneCode = null;
                        if (v3.AccountAuthType == AccountAuthType.CloudSso)
                        {
                            return await RequestDataKey(v3, response.EncryptedLoginToken);
                        }

                        ResumeSession = false;
                        var newRequest = new StartLoginRequest
                        {
                            Username = Username,
                            ClientVersion = Endpoint.ClientVersion,
                            EncryptedDeviceToken = ByteString.CopyFrom(DeviceToken),
                            LoginType = LoginType.Normal,
                            LoginMethod = LoginMethod.ExistingAccount,
                            MessageSessionUid = ByteString.CopyFrom(v3.MessageSessionUid),
                        };
                        return await ExecuteStartLogin(v3, newRequest);
                    }

                    break;
                }

                case LoginState.RequiresAccountCreation:
                    if (v3.AccountAuthType == AccountAuthType.CloudSso)
                    {
                        await this.CreateSsoUser(v3, response.EncryptedLoginToken);
                        return await ResumeLogin(v3, response.EncryptedLoginToken);
                    }

                    break;

                case LoginState.RegionRedirect:
                    throw new KeeperRegionRedirect(response.StateSpecificValue)
                    {
                        Username = request.Username
                    };

                case LoginState.DeviceAccountLocked:
                case LoginState.DeviceLocked:
                    throw new KeeperInvalidDeviceToken(response.Message);

                case LoginState.AccountLocked:
                case LoginState.LicenseExpired:
                case LoginState.Upgrade:
                    break;
            }

            throw new KeeperStartLoginException(response.LoginState, response.Message);
        }


        private async Task<AuthContext> StartLogin(
            V3LoginContext v3,
            bool forceNewLogin = false,
            LoginMethod loginMethod = LoginMethod.ExistingAccount)
        {
            return await this.StartLogin(v3,
                async (request) =>
                {
                    var context = await ExecuteStartLogin(v3, request);
                    if (context.SessionTokenRestriction == 0 && PushNotifications is IPushNotificationChannel push)
                    {
                        await push.SendToWebSocket(context.SessionToken, false);
                    }

                    return context;
                },
                forceNewLogin,
                loginMethod);
        }


        private Task<AuthContext> ResumeLogin(
            V3LoginContext v3,
            ByteString loginToken,
            LoginMethod method = LoginMethod.ExistingAccount)
        {
            return this.ResumeLogin(
                v3,
                (request) => ExecuteStartLogin(v3, request),
                loginToken,
                method);
        }

        private async Task<AuthContext> AuthorizeUsingCloudSso(V3LoginContext v3, string ssoBaseUrl, bool forceLogin, ByteString loginToken = null)
        {
            if (Ui != null && Ui is IAuthSsoUI ssoUi)
            {
                var loginTokenSource = new TaskCompletionSource<ByteString>();
                var ssoAction = this.AuthorizeUsingCloudSsoPrepare(v3,
                    (token) => { loginTokenSource.SetResult(token); },
                    ssoBaseUrl,
                    forceLogin,
                    loginToken);

                using (var cancellationSource = new CancellationTokenSource())
                {
                    var uiTask = ssoUi.WaitForSsoToken(ssoAction, cancellationSource.Token);
                    var index = Task.WaitAny(uiTask, loginTokenSource.Task);
                    if (index == 0)
                    {
                        var result = await uiTask;
                        if (result && loginToken != null)
                        {
                            return await ResumeLogin(v3, loginToken);
                        }

                        throw new KeeperCanceled();
                    }

                    loginToken = await loginTokenSource.Task;
                    cancellationSource.Cancel();
                    await this.EnsureDeviceTokenIsRegistered(v3, Username);
                    return await ResumeLogin(v3, loginToken, LoginMethod.AfterSso);
                }
            }

            throw new KeeperAuthFailed();
        }

        private async Task<AuthContext> TwoFactorValidate(
            V3LoginContext v3,
            ByteString loginToken,
            IEnumerable<TwoFactorChannelInfo> channels)
        {

            var loginTokenSource = new TaskCompletionSource<ByteString>();
            var t = this.TwoFactorValidatePrepare(
                token => loginTokenSource.SetResult(token),
                loginToken,
                channels);
            var channelInfo = t.Item1;
            var onDone = t.Item2;

            var resumeWithToken = loginToken;
            using (var tokenSource = new CancellationTokenSource())
            {
                var userTask = Ui.WaitForTwoFactorCode(channelInfo, tokenSource.Token);
                int index = Task.WaitAny(userTask, loginTokenSource.Task);
                onDone?.Invoke();
                if (index == 0)
                {
                    if (!await userTask) throw new KeeperCanceled();
                }
                else
                {
                    tokenSource.Cancel();
                    resumeWithToken = await loginTokenSource.Task;
                }
            }

            return await ResumeLogin(v3, resumeWithToken);
        }

        private async Task<AuthContext> ValidateAuthHash(V3LoginContext v3, ByteString loginToken, IEnumerable<Salt> salts)
        {
            var contextTask = new TaskCompletionSource<AuthContext>();
            var passwordInfo = this.ValidateAuthHashPrepare(v3,
                (context) => contextTask.SetResult(context),
                loginToken,
                salts);

            while (v3.PasswordQueue.Count > 0)
            {
                var password = v3.PasswordQueue.Dequeue();
                try
                {
                    await passwordInfo.InvokePasswordActionDelegate.Invoke(password);
                    if (contextTask.Task.IsCompleted)
                    {
                        return await contextTask.Task;
                    }
                }
                catch (KeeperAuthFailed)
                {
                }
                catch
                {
                    v3.PasswordQueue.Enqueue(password);
                    throw;
                }
            }

            using (var cancellationToken = new CancellationTokenSource())
            {
                var uiTask = Ui.WaitForUserPassword(passwordInfo, cancellationToken.Token);
                var index = Task.WaitAny(uiTask, contextTask.Task);
                if (index == 1)
                {
                    cancellationToken.Cancel();
                    return await contextTask.Task;
                }

                var result = await uiTask;
                if (result)
                {
                    return await ResumeLogin(v3, loginToken);
                }

                throw new KeeperCanceled();
            }
        }

        private async Task<AuthContext> ApproveDevice(V3LoginContext v3, ByteString loginToken)
        {
            var loginTokenTask = new TaskCompletionSource<ByteString>();
            var t = this.ApproveDevicePrepare(v3,
                (token) => { loginTokenTask.SetResult(token); },
                loginToken);
            var channelInfo = t.Item1;
            var onDone = t.Item2;

            var resumeLoginToken = loginToken;
            using (var sdkCancellation = new CancellationTokenSource())
            {
                var uiTask = Ui.WaitForDeviceApproval(channelInfo, sdkCancellation.Token);
                var index = Task.WaitAny(uiTask, loginTokenTask.Task);
                if (index == 0)
                {
                    onDone?.Invoke();
                    var resume = await uiTask;
                    if (!resume) throw new KeeperCanceled();
                }
                else
                {
                    sdkCancellation.Cancel();
                    resumeLoginToken = await loginTokenTask.Task;
                }

                return await ResumeLogin(v3, resumeLoginToken);
            }
        }

        private async Task<AuthContext> AuthorizeUsingOnsiteSso(
            V3LoginContext v3,
            string ssoBaseUrl,
            bool forceLogin,
            ByteString loginToken = null)
        {
            var tokenSource = new TaskCompletionSource<bool>();
            var ssoAction = this.AuthorizeUsingOnsiteSsoPrepare(v3,
                () => { tokenSource.SetResult(true); },
                ssoBaseUrl,
                forceLogin,
                loginToken
            );
            if (Ui != null && Ui is IAuthSsoUI ssoUi)
            {
                using (var cancellationSource = new CancellationTokenSource())
                {
                    var userTask = ssoUi.WaitForSsoToken(ssoAction, cancellationSource.Token);
                    var index = Task.WaitAny(userTask, tokenSource.Task);
                    if (index == 0)
                    {
                        var result = await userTask;
                        if (result && loginToken != null)
                        {
                            return await ResumeLogin(v3, loginToken);
                        }

                        throw new KeeperCanceled();
                    }

                    await tokenSource.Task;
                    cancellationSource.Cancel();
                    if (loginToken != null)
                    {
                        return await ResumeLogin(v3, loginToken, LoginMethod.AfterSso);
                    }

                    await this.EnsureDeviceTokenIsRegistered(v3, Username);
                    return await StartLogin(v3, false, LoginMethod.AfterSso);
                }
            }

            throw new KeeperAuthFailed();
        }

        private async Task<AuthContext> RequestDataKey(V3LoginContext v3, ByteString loginToken)
        {
            if (!(Ui is IAuthSsoUI ssoUi)) throw new KeeperCanceled();

            var completeTask = new TaskCompletionSource<bool>();
            var t = this.RequestDataKeyPrepare(
                v3,
                (approved) => { completeTask.SetResult(approved); },
                loginToken);
            var channels = t.Item1;
            var onApproved = t.Item2;

            using (var completeToken = new CancellationTokenSource())
            {
                var uiTask = ssoUi.WaitForDataKey(channels, completeToken.Token);
                var index = Task.WaitAny(uiTask, completeTask.Task);
                onApproved.Invoke();
                if (index == 0)
                {
                    var result = await uiTask;
                    if (!result) throw new KeeperCanceled();
                }
                else
                {
                    await completeTask.Task;
                    completeToken.Cancel();
                }
            }

            return await ResumeLogin(v3, loginToken);
        }

        public override void Dispose()
        {
            Ui = null;
            base.Dispose();
        }
    }

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
}