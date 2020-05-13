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
using System.Linq;
using System.Diagnostics;
using Authentication;
using Org.BouncyCastle.Crypto.Parameters;
using System.Runtime.Serialization;
using Google.Protobuf;
using System.Collections.Generic;
using System.Threading;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Tests")]

namespace KeeperSecurity.Sdk
{
    public class PrimaryCredentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public byte[] Salt { get; set; }
        public int Iterations { get; set; }
    }

    public class SecondaryCredentials
    {
        public string SecondFactorType { get; set; }
        public string SecondFactorToken { get; set; }
        public string SecondFactorMode { get; set; }
        public TwoFactorCodeDuration? SecondFactorDuration { get; set; }
    }

    public interface IAuth
    {
        KeeperEndpoint Endpoint { get; }
        byte[] EncryptedDeviceToken { get; }
        IAuthUI Ui { get; }
        IConfigurationStorage Storage { get; }
        bool IsAuthenticated { get; }
        AuthContext AuthContext { get; }

        Task Login(string username, string password);
        void Logout();

        Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType = null,
            bool throwOnError = true);
    }

    public class AuthContext
    {
        public string Username { get; internal set; }
        public byte[] DataKey { get; internal set; }
        public byte[] ClientKey { get; internal set; }

        public RsaPrivateCrtKeyParameters PrivateKey { get; internal set; }
        public string SessionToken { get; internal set; }
        public string TwoFactorToken { get; set; }
        public string AuthResponse { get; internal set; }
        public byte[] AuthSalt { get; internal set; }
        public int AuthIterations { get; internal set; }
    }

    public static class AuthExtensions
    {
        public static async Task<LoginResponse> ExecuteLoginCommand(this KeeperEndpoint endpoint,
            PrimaryCredentials primary, SecondaryCredentials secondary = null)
        {
            var authHash = CryptoUtils.DeriveV1KeyHash(primary.Password, primary.Salt, primary.Iterations)
                .Base64UrlEncode();
            var command = new LoginCommand
            {
                username = primary.Username.ToLowerInvariant(),
                authResponse = authHash,
                include = new[] {"keys", "client_key"},
            };

            if (secondary != null)
            {
                command.twoFactorType = secondary.SecondFactorType;
                command.twoFactorToken = secondary.SecondFactorToken;
                command.twoFactorMode = secondary.SecondFactorMode;
                if (secondary.SecondFactorDuration != null)
                {
                    command.deviceTokenExpiresInDays = (int) secondary.SecondFactorDuration;
                }
            }

            return await endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
        }

        public static void ParseLoginResponse(this Auth auth, PrimaryCredentials primary,
            SecondaryCredentials secondary, LoginResponse loginResponse)
        {
            var authContext = new AuthContext
            {
                Username = primary.Username,
                SessionToken = loginResponse.sessionToken,
            };

            if (loginResponse.keys != null)
            {
                if (loginResponse.keys.encryptedDataKey != null)
                {
                    var key = CryptoUtils.DeriveKeyV2("data_key", primary.Password, primary.Salt, primary.Iterations);
                    authContext.DataKey =
                        CryptoUtils.DecryptAesV2(loginResponse.keys.encryptedDataKey.Base64UrlDecode(), key);
                }
                else if (loginResponse.keys.encryptionParams != null)
                {
                    authContext.DataKey = CryptoUtils.DecryptEncryptionParams(primary.Password,
                        loginResponse.keys.encryptionParams.Base64UrlDecode());
                }
                else
                {
                    throw new Exception("Missing data key");
                }

                if (loginResponse.keys.encryptedPrivateKey != null)
                {
                    var privateKeyData =
                        CryptoUtils.DecryptAesV1(loginResponse.keys.encryptedPrivateKey.Base64UrlDecode(),
                            authContext.DataKey);
                    authContext.PrivateKey = CryptoUtils.LoadPrivateKey(privateKeyData);
                }
            }
            else
            {
                throw new Exception("Missing data key");
            }

            if (!string.IsNullOrEmpty(loginResponse.deviceToken))
            {
                authContext.TwoFactorToken = loginResponse.deviceToken;
            }
            else if (secondary != null)
            {
                if (string.Equals(secondary.SecondFactorType, "device_token"))
                {
                    authContext.TwoFactorToken = secondary.SecondFactorToken;
                }
            }

            authContext.AuthResponse = CryptoUtils.DeriveV1KeyHash(primary.Password, primary.Salt, primary.Iterations)
                .Base64UrlEncode();
            authContext.AuthSalt = primary.Salt;
            authContext.AuthIterations = primary.Iterations;

            if (!string.IsNullOrEmpty(loginResponse.clientKey))
            {
                authContext.ClientKey =
                    CryptoUtils.DecryptAesV1(loginResponse.clientKey.Base64UrlDecode(), authContext.DataKey);
            }

            auth.authContext = authContext;

            if (!string.IsNullOrEmpty(loginResponse.deviceToken) && loginResponse.deviceTokenScope == "expiration")
            {
                IUserStorage us = auth.Storage;
                var uc = us.GetUser(auth.authContext.Username);
                var storedToken = uc?.TwoFactorToken;
                if (string.IsNullOrEmpty(storedToken) || !loginResponse.deviceToken.SequenceEqual(storedToken))
                {
                    var userConfig = uc != null
                        ? new UserConfiguration(uc)
                        : new UserConfiguration(auth.authContext.Username);
                    userConfig.TwoFactorToken = loginResponse.deviceToken;
                    us.PutUser(userConfig);
                }
            }
        }

        public static async Task<TR> ExecuteAuthCommand<TC, TR>(this IAuth auth, TC command, bool throwOnError = true)
            where TC : AuthenticatedCommand
            where TR : KeeperApiResponse
        {
            return (TR) await auth.ExecuteAuthCommand(command, typeof(TR), throwOnError);
        }

        public static Task ExecuteAuthCommand<TC>(this IAuth auth, TC command)
            where TC : AuthenticatedCommand
        {
            return auth.ExecuteAuthCommand<TC, KeeperApiResponse>(command, true);
        }

        public static async Task<string> GetNotificationUrl(this IAuth auth)
        {
            if (!auth.IsAuthenticated)
            {
                throw new KeeperApiException("auth_failed", "Not authenticated");
            }

            var command = new GetPushInfoCommand();
            var rs = await auth.ExecuteAuthCommand<GetPushInfoCommand, GetPushInfoResponse>(command);
            return rs.url;
        }
    }

    public class Auth : IAuth
    {
        public static readonly ISet<string> SecondFactorErrorCodes =
            new HashSet<string>(new[] {"need_totp", "invalid_device_token", "invalid_totp"});

        public static readonly ISet<string> PostLoginErrorCodes =
            new HashSet<string>(new[] {"auth_expired", "auth_expired_transfer"});

        public Auth(IAuthUI authUi, IConfigurationStorage storage, KeeperEndpoint endpoint = null)
        {
            Storage = storage ?? new InMemoryConfigurationStorage();
            Endpoint = endpoint ?? new KeeperEndpoint(Storage);
            var conf = (storage as IServerStorage)?.GetServer(Endpoint.Server);
            if (conf != null)
            {
                EncryptedDeviceToken = conf.DeviceId;
            }

            Ui = authUi;
        }

        internal AuthContext authContext;
        public AuthContext AuthContext => authContext;
        public bool IsAuthenticated => authContext != null && !string.IsNullOrEmpty(authContext.SessionToken);

        private async Task<byte[]> GetDeviceToken()
        {
            var deviceRequest = new DeviceRequest
            {
                ClientVersion = Endpoint.ClientVersion,
                DeviceName = Endpoint.DeviceName
            };

            var apiPayload = new ApiRequestPayload()
            {
                Payload = deviceRequest.ToByteString()
            };
            var rs = await Endpoint.ExecuteRest("authentication/get_device_token", apiPayload);
            var deviceRs = DeviceResponse.Parser.ParseFrom(rs);
            if (deviceRs.Status == DeviceStatus.Ok)
            {
                return deviceRs.EncryptedDeviceToken.ToByteArray();
            }

            throw new KeeperApiException("device_token_rejected", "Device is rejected");
        }

        public virtual async Task<PreLoginResponse> GetPreLogin(string username,
            LoginType loginType = LoginType.Normal, byte[] twoFactorToken = null)
        {
            var attempt = 0;
            var encryptedDeviceToken = EncryptedDeviceToken;
            while (attempt < 5)
            {
                attempt++;

                if (encryptedDeviceToken == null)
                {
                    encryptedDeviceToken = await GetDeviceToken();
                }

                var preLogin = new PreLoginRequest()
                {
                    AuthRequest = new AuthRequest
                    {
                        ClientVersion = Endpoint.ClientVersion,
                        Username = username.ToLowerInvariant(),
                        EncryptedDeviceToken = ByteString.CopyFrom(encryptedDeviceToken)
                    },
                    LoginType = loginType
                };

                if (twoFactorToken != null)
                {
                    preLogin.TwoFactorToken = ByteString.CopyFrom(twoFactorToken);
                }

                var apiPayload = new ApiRequestPayload()
                {
                    Payload = preLogin.ToByteString()
                };
                try
                {
                    var response = await Endpoint.ExecuteRest("authentication/pre_login", apiPayload);
                    if (EncryptedDeviceToken == null || !EncryptedDeviceToken.SequenceEqual(encryptedDeviceToken))
                    {
                        EncryptedDeviceToken = encryptedDeviceToken;
                        IServerStorage ss = Storage;
                        var sc = ss.GetServer(Endpoint.Server);
                        var conf = sc != null ? new ServerConfiguration(sc) : new ServerConfiguration(Endpoint.Server);
                        conf.DeviceId = EncryptedDeviceToken;
                        ss.PutServer(conf);
                    }

                    return PreLoginResponse.Parser.ParseFrom(response);
                }
                catch (KeeperInvalidDeviceToken)
                {
                    encryptedDeviceToken = null;
                    continue;
                }
                catch (KeeperRegionRedirect redirect)
                {
                    Endpoint.Server = redirect.RegionHost;
                    var conf = ((IServerStorage) Storage).GetServer(Endpoint.Server);
                    encryptedDeviceToken = conf?.DeviceId;
                    continue;
                }
            }

            throw new KeeperTooManyAttempts();
        }

        public async Task<KeeperApiResponse> ExecuteAuthCommand(AuthenticatedCommand command, Type responseType = null,
            bool throwOnError = true)
        {
            if (!IsAuthenticated)
            {
                throw new KeeperApiException("auth_failed", "auth_failed");
            }

            command.username = authContext.Username;
            command.sessionToken = authContext.SessionToken;

            var response = await Endpoint.ExecuteV2Command(command, responseType);
            if (!response.IsSuccess && response.resultCode == "auth_failed")
            {
                Debug.WriteLine("Refresh Session Token");
                authContext.SessionToken = null;
                await RefreshSessionToken();
                if (IsAuthenticated)
                {
                    command.sessionToken = authContext.SessionToken;
                    response = await Endpoint.ExecuteV2Command(command, responseType);
                }
                else
                {
                    Logout();
                }
            }

            if (response != null && !response.IsSuccess && throwOnError)
            {
                throw new KeeperApiException(response.resultCode, response.message);
            }

            return response;
        }

        public async Task Login(string username, string password)
        {
            var primaryCredentials = new PrimaryCredentials
            {
                Username = username.ToLower(),
                Password = password,
            };

            SecondaryCredentials secondaryCredentials = null;
            {
                IUserStorage us = Storage;
                var userConf = us.GetUser(username);
                var storedToken = userConf?.TwoFactorToken;
                if (!string.IsNullOrEmpty(storedToken))
                {
                    secondaryCredentials = new SecondaryCredentials
                    {
                        SecondFactorType = "device_token",
                        SecondFactorToken = storedToken,
                    };
                }
            }

            PreLoginResponse preLogin = null;
            CancellationTokenSource cancellationToken = null;
            var attempt = 0;
            try
            {
                while (true)
                {
                    attempt++;
                    if (attempt >= 5)
                    {
                        throw new KeeperApiException("auth_failed", "Invalid username or password");
                    }

                    if (preLogin == null)
                    {
                        preLogin = await GetPreLogin(username);
                        var authParams = preLogin.Salt[0];
                        primaryCredentials.Salt = authParams.Salt_.ToByteArray();
                        primaryCredentials.Iterations = authParams.Iterations;
                    }

                    var loginRs = await Endpoint.ExecuteLoginCommand(primaryCredentials, secondaryCredentials);
                    if (!loginRs.IsSuccess && (Ui == null || !PostLoginErrorCodes.Contains(loginRs.resultCode)))
                    {
                        if (SecondFactorErrorCodes.Contains(loginRs.resultCode) && Ui != null)
                        {
                            var channel = AuthUIExtensions.GetTwoFactorChannel(loginRs.channel);
                            if (channel == TwoFactorCodeChannel.DuoSecurity && Ui is IDuoTwoFactorUI duoUi)
                            {
                                if (string.IsNullOrEmpty(loginRs.enrollUrl))
                                {
                                    var account = new DuoAccount
                                    {
                                        Phone = loginRs.phone,
                                        PushNotificationUrl = loginRs.url,
                                    };
                                    if (loginRs.capabilities != null)
                                    {
                                        account.Capabilities = loginRs.capabilities
                                            .Select<string, DuoAction?>(x =>
                                            {
                                                if (AuthUIExtensions.TryParseDuoAction(x, out var action))
                                                {
                                                    return action;
                                                }

                                                return null;
                                            })
                                            .Where(x => x != null).Select(x => x.Value).ToArray();
                                    }

                                    if (cancellationToken == null)
                                    {
                                        cancellationToken = new CancellationTokenSource();
                                    }

                                    var code = await duoUi.GetDuoTwoFactorResult(account, cancellationToken.Token);
                                    if (code != null && !string.IsNullOrEmpty(code.Code))
                                    {
                                        secondaryCredentials = new SecondaryCredentials
                                        {
                                            SecondFactorType = "one_time",
                                            SecondFactorDuration = code.Duration,
                                        };
                                        if (AuthUIExtensions.DuoActions.Values.Any(x => x == code.Code))
                                        {
                                            secondaryCredentials.SecondFactorMode = code.Code;
                                        }
                                        else
                                        {
                                            secondaryCredentials.SecondFactorToken = code.Code;
                                        }

                                        continue;
                                    }
                                }
                                else
                                {
                                    duoUi.DuoRequireEnrollment(loginRs.enrollUrl);
                                }
                            }
                            else
                            {
                                var code = await Ui.GetTwoFactorCode(channel);
                                if (code != null && !string.IsNullOrEmpty(code.Code))
                                {
                                    secondaryCredentials = new SecondaryCredentials
                                    {
                                        SecondFactorType = "one_time",
                                        SecondFactorToken = code.Code,
                                        SecondFactorDuration = code.Duration,
                                    };
                                    continue;
                                }
                            }
                        }

                        var message = loginRs.resultCode == "auth_failed"
                            ? "Invalid username or password"
                            : loginRs.message;
                        throw new KeeperApiException(loginRs.resultCode, message);
                    }

                    this.ParseLoginResponse(primaryCredentials, secondaryCredentials, loginRs);

                    if (loginRs.IsSuccess)
                    {
                        break;
                    }

                    switch (loginRs.resultCode)
                    {
                        case "auth_expired":
                            var newPassword = await this.ChangeMasterPassword(new PasswordRequirements
                            {
                                PasswordRulesIntro = loginRs.passwordRulesIntro,
                                PasswordRules = loginRs.passwordRules
                            });
                            if (!string.IsNullOrEmpty(newPassword))
                            {
                                primaryCredentials.Password = newPassword;
                                preLogin = null;
                                continue;
                            }

                            break;

                        case "auth_expired_transfer":
                            if (await Ui.Confirmation("Do you accept Account Transfer policy?"))
                            {
                                var cmd = new AccountSummaryCommand
                                {
                                    include = new[] {"settings"}
                                };
                                var summaryRs = await this.ExecuteAuthCommand<AccountSummaryCommand, AccountSummaryResponse>(cmd);
                                await this.ShareAccount(summaryRs.Settings.shareAccountTo);
                                continue;
                            }

                            break;
                    }

                    throw new KeeperApiException(loginRs.resultCode, loginRs.message);
                }
            }
            finally
            {
                if (cancellationToken != null)
                {
                    if (!cancellationToken.IsCancellationRequested)
                    {
                        cancellationToken.Cancel();
                    }

                    cancellationToken.Dispose();
                }
            }
        }

        public void Logout()
        {
            authContext = null;
        }

        public async Task RefreshSessionToken()
        {
            var command = new LoginCommand
            {
                username = authContext.Username,
                authResponse = authContext.AuthResponse,
                twoFactorToken = authContext.TwoFactorToken,
                twoFactorType = !string.IsNullOrEmpty(authContext.TwoFactorToken) ? "device_token" : null
            };

            var loginRs = await Endpoint.ExecuteV2Command<LoginCommand, LoginResponse>(command);
            if (loginRs.IsSuccess)
            {
                authContext.SessionToken = loginRs.sessionToken;
            }
            else
            {
                throw new KeeperApiException(loginRs.resultCode, loginRs.message);
            }
        }

        public KeeperEndpoint Endpoint { get; }
        public byte[] EncryptedDeviceToken { get; private set; }

        public IAuthUI Ui { get; }
        public IConfigurationStorage Storage { get; }
    }

#pragma warning disable 0649
    [DataContract]
    internal class NotificationEvent
    {
        [DataMember(Name = "pt")] public string pt;
        [DataMember(Name = "event")] public string notificationEvent;
        [DataMember(Name = "sync")] public bool sync;
        [DataMember(Name = "passcode")] public string passcode;
    }
#pragma warning restore 0649
}