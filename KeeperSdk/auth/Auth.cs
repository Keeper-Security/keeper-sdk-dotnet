using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;
using Authentication;
using System.Threading;
using Google.Protobuf;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;

[assembly: InternalsVisibleTo("Tests")]
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2")]

namespace KeeperSecurity.Authentication.Async
{
    /// <summary>
    /// Defines the user interface methods required for authentication with Keeper.
    /// </summary>
    /// <seealso cref="IAuthSsoUI"/>
    /// <seealso cref="IHttpProxyCredentialUi"/>
    /// <seealso cref="IAuthSecurityKeyUI"/>
    /// <seealso cref="IPostLoginTaskUI"/>
    public interface IAuthUI : IAuthCallback
    {
        /// <summary>
        /// Device Approval is required.
        /// </summary>
        /// <param name="channels">List of available device approval channels.</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client when device is successfully approved.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// Clients to display the list of available device approval channels.
        /// When user picks one clients to check if channel implements <see cref="IDeviceApprovalPushInfo">push interface</see>
        /// then invoke <see cref="IDeviceApprovalPushInfo.InvokeDeviceApprovalPushAction">push action</see>
        /// If channel implements <see cref="ITwoFactorDurationInfo">2FA duration interface</see> clients may show 2FA expiration picker.
        /// </remarks>
        Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token);

        /// <summary>
        /// Two Factor Authentication is required.
        /// </summary>
        /// <param name="channels">List of available 2FA channels.</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client passed 2FA.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// Clients to display the list of available 2FA channels.
        /// When user picks one clients to check
        /// <list type="number">
        /// <item><description>
        /// if channel implements <see cref="ITwoFactorPushInfo">push interface</see> clients displays an button for each <see cref="ITwoFactorPushInfo.SupportedActions">push action</see>
        /// </description></item>
        /// <item><description>
        /// If channel implements <see cref="ITwoFactorDurationInfo">2FA duration interface</see> clients may show 2FA expiration picker.
        /// </description></item>
        /// <item><description>
        /// If channel implements <see cref="ITwoFactorAppCodeInfo">2FA code interface</see> clients displays 2FA code input.
        /// </description></item>
        /// </list>
        /// When customer enters the code and click Next clients returns the code to <see cref="ITwoFactorAppCodeInfo.InvokeTwoFactorCodeAction">the SDK</see>.
        /// </remarks>
        Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token);

        /// <summary>
        /// Master Password is required.
        /// </summary>
        /// <param name="passwordInfo">Enter Password interface</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client successfully authorized. Can be ignored.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resumes login, <c>False</c> cancels.</returns>
        /// <remarks>
        /// Client displays Enter password dialog.
        /// When customer clicks Next client returns the password to <see cref="IPasswordInfo.InvokePasswordActionDelegate">the SDK</see>.
        /// </remarks>
        Task<bool> WaitForUserPassword(IPasswordInfo passwordInfo, CancellationToken token);
    }

    /// <summary>
    /// Defines the methods required completing SSO Login. Optional.
    /// </summary>
    /// <remarks>If client supports SSO Login this interface needs to be implemented
    /// along with <see cref="IAuthUI">Auth UI</see>
    /// </remarks>
    /// <seealso cref="IAuthUI"/>
    /// <remarks>
    /// Client implements this interface to support SSO login. This interface will be called in response
    /// of <see cref="IAuth.Login"/> if username is SSO user or <see cref="IAuth.LoginSso"/>
    /// </remarks>
    public interface IAuthSsoUI : ISsoLogoutCallback
    {
        /// <summary>
        /// SSO Login is required.
        /// </summary>
        /// <param name="actionInfo"></param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client successfully logged in with SSO.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// When this method is called client opens embedded web browser and navigates to URL specified in
        /// <see cref="ISsoTokenActionInfo.SsoLoginUrl">actionInfo.SsoLoginUrl</see>
        /// then monitors embedded web browser navigation.
        /// When it finds the page that contains <c>window.token</c> object it passes this object to
        /// <see cref="ISsoTokenActionInfo.InvokeSsoTokenAction">actionInfo.InvokeSsoTokenAction</see>
        /// </remarks>
        Task<bool> WaitForSsoToken(ISsoTokenActionInfo actionInfo, CancellationToken token);

        /// <summary>
        /// Data Key needs to be shared. 
        /// </summary>
        /// <param name="channels">List of available data key sharing channels.</param>
        /// <param name="token">Cancellation token. Keeper SDK notifies the client that data key is shared.</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        /// <remarks>
        /// Cloud SSO login may require user data key to be shared if the device is used for the first time.
        /// Client displays the list of available data key sharing channels.
        /// When user picks a channel, client invokes channel's action <see cref="IDataKeyChannelInfo.InvokeGetDataKeyAction">channels.InvokeGetDataKeyAction</see>
        /// </remarks>
        Task<bool> WaitForDataKey(IDataKeyChannelInfo[] channels, CancellationToken token);
    }

    /// <summary>
    /// Defines a method that returns HTTP Web proxy credentials. Optional.
    /// </summary>
    /// <remarks>
    /// Keeper SDK calls this interface if it detects that access to the Internet is protected with HTTP Proxy.
    /// Clients requests HTTP proxy credentials from the user and return them to the library.
    /// </remarks>
    /// <seealso cref="IAuthUI"/>
    public interface IHttpProxyCredentialUi
    {
        /// <summary>
        /// Requests HTTP Proxy credentials.
        /// </summary>
        /// <param name="proxyInfo">HTTP Proxy information</param>
        /// <returns>Awaitable boolean result. <c>True</c>True resume login, <c>False</c> cancel.</returns>
        Task<bool> WaitForHttpProxyCredentials(IHttpProxyInfo proxyInfo);
    }




    /// <summary>
    /// Represents Keeper authentication. (async)
    /// </summary>
    /// <seealso cref="AuthSync"/>
    /// <seealso cref="IAuth"/>
    /// <seealso cref="IAuthentication"/>
    public class Auth : AuthCommon, IAuth
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="authUi">User Interface.</param>
        /// <param name="storage">Configuration storage.</param>
        /// <param name="endpoint">Keeper Endpoint.</param>
        public Auth(IAuthUI authUi, IConfigurationStorage storage, IKeeperEndpoint endpoint = null) 
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage.LastServer, Storage.Servers);
            Ui = authUi;
        }

        /// <summary>
        /// Gets configuration storage.
        /// </summary>
        public IConfigurationStorage Storage { get; }

        /// <summary>
        /// Gets User interaction interface.
        /// </summary>
        public IAuthUI Ui { get; private set; }

        /// <exclude/>
        public override IAuthCallback AuthCallback => Ui;

        /// <summary>
        /// Gets or sets session resumption flag
        /// </summary>
        public bool ResumeSession { get; set; }

        /// <summary>
        /// Forces master password login for SSO accounts.
        /// </summary>
        public bool AlternatePassword { get; set; }

        /// <summary>
        /// Gets or sets username.
        /// </summary>
        public new string Username
        {
            get => base.Username;
            set => base.Username = value;
        }

        /// <exclude />
        public void SetPushNotifications(IFanOut<NotificationEvent> pushNotifications)
        {
            PushNotifications = pushNotifications;
        }

        /// <summary>
        /// Gets or sets device token
        /// </summary>
        public new byte[] DeviceToken
        {
            get => base.DeviceToken;
            set => base.DeviceToken = value;
        }

        private async Task DetectProxyAsync(Func<Task> resumeWhenDone)
        {
            var keeperUri = new Uri($"https://{Endpoint.Server}/api/rest/ping");
            TaskCompletionSource<bool> credentialsTask = null;
            var proxyInfo = await DetectProxy(keeperUri, (proxyUri, proxyAuth) =>
            {
                return new HttpProxyInfo
                {
                    ProxyUri = proxyUri,
                    ProxyAuthenticationMethods = proxyAuth,
                    InvokeHttpProxyCredentialsDelegate = async (proxyUsername, proxyPassword) =>
                    {
                        var webProxy = AuthUIExtensions.GetWebProxyForCredentials(proxyUri, proxyAuth, proxyUsername, proxyPassword);
                        await PingKeeperServer(keeperUri, webProxy);
                        Endpoint.WebProxy = webProxy;
                        credentialsTask?.SetResult(true);
                    },
                };
            });

            if (proxyInfo != null)
            {
                if (Ui is IHttpProxyCredentialUi proxyUi)
                {
                    credentialsTask = new TaskCompletionSource<bool>();
                    var uiTask = proxyUi.WaitForHttpProxyCredentials(proxyInfo);
                    var index = Task.WaitAny(uiTask, credentialsTask.Task);
                    var result = await(index == 0 ? uiTask : credentialsTask.Task);
                    if (!result) throw new KeeperCanceled();
                    await resumeWhenDone.Invoke();
                }
                else
                {
                    throw new KeeperCanceled();
                }
            }
            else
            {
                await resumeWhenDone.Invoke();
            }
        }

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
        public async Task LoginSso(string providerName, bool forceLogin = false)
        {
            var v3 = new LoginContext();
            var attempt = 0;
            while (attempt < 3)
            {
                attempt++;
                try
                {
                    var contextV3 = await LoginSsoV3(v3, providerName, forceLogin);
                    this.StoreConfigurationIfChangedV3(v3);
                    authContext = contextV3;
                    await PostLogin();
                }
                catch (KeeperRegionRedirect krr)
                {
                    await this.RedirectToRegionV3(krr.RegionHost);
                    if (string.IsNullOrEmpty(krr.Username)) continue;

                    Username = krr.Username;
                    await LoginV3(v3);
                }

                return;
            }

            throw new KeeperCanceled();
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
        public async Task Login(string username, params string[] passwords)
        {
            await DetectProxyAsync(async () =>
            {
                if (string.IsNullOrEmpty(username))
                {
                    throw new KeeperStartLoginException(LoginState.RequiresUsername, "Username is required.");
                }

                Username = username.ToLowerInvariant();
                var v3 = new LoginContext();
                foreach (var p in passwords)
                {
                    if (string.IsNullOrEmpty(p)) continue;
                    v3.PasswordQueue.Enqueue(p);
                }

                try
                {
                    authContext = await LoginV3(v3);
                }
                catch (KeeperRegionRedirect krr)
                {
                    await this.RedirectToRegionV3(krr.RegionHost);
                    authContext = await LoginV3(v3);
                }

                this.StoreConfigurationIfChangedV3(v3);
                await PostLogin();
            });
        }

        private async Task<AuthContext> LoginSsoV3(LoginContext v3, string providerName, bool forceLogin)
        {
            if (Ui != null && Ui is IAuthSsoUI)
            {
                var rs = await this.GetSsoServiceProvider(v3, providerName);

                v3.AccountAuthType = rs.IsCloud ? AccountAuthType.CloudSso : AccountAuthType.OnsiteSso;
                return await AuthorizeUsingSso(v3, rs.IsCloud, rs.SpUrl, forceLogin);
            }

            throw new KeeperCanceled();
        }

        private async Task<AuthContext> LoginV3(LoginContext v3)
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

        private async Task<AuthContext> ExecuteStartLogin(LoginContext v3, StartLoginRequest request)
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
                    return await AuthorizeUsingSso(v3, true, response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

                case LoginState.RedirectOnsiteSso:
                    v3.AccountAuthType = AccountAuthType.OnsiteSso;
                    return await AuthorizeUsingSso(v3, false, response.Url, request.ForceNewLogin, response.EncryptedLoginToken);

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
                    switch (v3.AccountAuthType)
                    {
                        case AccountAuthType.CloudSso:
                            await this.CreateSsoUser(v3, response.EncryptedLoginToken);
                            return await ResumeLogin(v3, response.EncryptedLoginToken);
                        case AccountAuthType.OnsiteSso:
                            if (v3.PasswordQueue.Count > 0)
                            {
                                await this.RequestCreateUser(v3, v3.PasswordQueue.Peek());
                                return await ResumeLogin(v3, response.EncryptedLoginToken);
                            }
                            break;
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
            LoginContext v3,
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
            LoginContext v3,
            ByteString loginToken,
            LoginMethod method = LoginMethod.ExistingAccount)
        {
            return this.ResumeLogin(
                v3,
                (request) => ExecuteStartLogin(v3, request),
                loginToken,
                method);
        }

        private async Task<AuthContext> TwoFactorValidate(
            LoginContext v3,
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

        private async Task<AuthContext> ValidateAuthHash(LoginContext v3, ByteString loginToken, IEnumerable<Salt> salts)
        {
            var contextTask = new TaskCompletionSource<AuthContext>();
            var passwordInfo = this.ValidateAuthHashPrepare(v3,
                (context) =>
                {
                    contextTask.SetResult(context);
                    return Task.FromResult(true);
                },
                loginToken,
                salts);

            while (v3.PasswordQueue.Count > 0)
            {
                var password = v3.PasswordQueue.Dequeue();
                try
                {
                    await passwordInfo.InvokePasswordActionDelegate.Invoke(password);
                    var index = Task.WaitAny(Task.Delay(TimeSpan.FromSeconds(1)), contextTask.Task);
                    if (index == 1)
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

        private async Task<AuthContext> ApproveDevice(LoginContext v3, ByteString loginToken)
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


        private async Task<AuthContext> AuthorizeUsingSso(
            LoginContext v3,
            bool isCloudSso,
            string ssoBaseUrl,
            bool forceLogin,
            ByteString loginToken = null)
        {
            var tokenSource = new TaskCompletionSource<ByteString>();
            var ssoAction = isCloudSso
                ? this.AuthorizeUsingCloudSsoPrepare(v3,
                    (token) => { tokenSource.SetResult(token); },
                    ssoBaseUrl,
                    forceLogin)
                : this.AuthorizeUsingOnsiteSsoPrepare(v3,
                    () => { tokenSource.SetResult(loginToken); },
                    ssoBaseUrl,
                    forceLogin);


            if (Ui != null && Ui is IAuthSsoUI ssoUi)
            {
                using (var cancellationSource = new CancellationTokenSource())
                {
                    var uiTask = ssoUi.WaitForSsoToken(ssoAction, cancellationSource.Token);
                    var index = Task.WaitAny(uiTask, tokenSource.Task);
                    var loginMethod = index == 1 ? LoginMethod.AfterSso : LoginMethod.ExistingAccount;
                    if (index == 0)
                    {
                        var result = await uiTask;
                        if (!result) throw new KeeperCanceled();
                    }
                    else
                    {
                        cancellationSource.Cancel();
                        loginToken = await tokenSource.Task;
                    }

                    if (loginToken != null)
                    {
                        return await ResumeLogin(v3, loginToken, loginMethod);
                    }

                    return await StartLogin(v3, false, loginMethod);
                }
            }

            throw new KeeperCanceled();
        }

        private async Task<AuthContext> RequestDataKey(LoginContext v3, ByteString loginToken)
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

        /// <exclude/>
        public override void Dispose()
        {
            Ui = null;
            base.Dispose();
        }
    }
}