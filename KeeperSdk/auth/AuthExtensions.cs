using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using Google.Protobuf;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Provides a set of static methods for IAuthentication interface.
    /// </summary>
    public static class AuthExtensions
    {
        /// <summary>
        /// Gets authenticated flag.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <returns><c>True</c> if logged in.</returns>
        public static bool IsAuthenticated(this IAuthentication auth)
        {
            return auth.AuthContext?.SessionToken != null;
        }

        /// <summary>
        /// Executes JSON authenticated command that does not return data.
        /// </summary>
        /// <param name="auth">The authenticated connection</param>
        /// <param name="command">JSON authenticated command</param>
        /// <returns>A JSON response</returns>
        /// <seealso cref="KeeperEndpointExtensions.ExecuteV2Command"/>
        public static async Task<KeeperApiResponse> ExecuteAuthCommand(this IAuthentication auth, AuthenticatedCommand command)
        {
            return await auth.ExecuteAuthCommand(command, typeof(KeeperApiResponse), true);
        }

        /// <summary>
        /// Execute JSON authenticated command in a batch
        /// </summary>
        /// <param name="auth">The authenticated connection</param>
        /// <param name="commands">JSON authenticated commands</param>
        /// <returns>A list of JSON responses</returns>
        public static async Task<IList<KeeperApiResponse>> ExecuteBatch(this IAuthentication auth, IList<KeeperApiCommand> commands)
        {
            var responses = new List<KeeperApiResponse>();
            int pos = 0;
            int delayInSec = 0;
            while (pos < commands.Count)
            {
                if (delayInSec > 0)
                {
                    await Task.Delay(TimeSpan.FromSeconds(delayInSec));
                }

                var rq = new ExecuteCommand()
                {
                    Requests = commands.Skip(pos).Take(100).ToList(),
                };
                var execRs = await auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(rq);
                pos += execRs.Results.Count;

                if (execRs.Results.Count == rq.Requests.Count)
                {
                    responses.AddRange(execRs.Results);
                    delayInSec = 5;
                }
                else if (execRs.Results.Count > 0)
                {
                    delayInSec = 0;
                    if (execRs.Results.Count > 50)
                    {
                        delayInSec = 5;
                    }
                    if (execRs.Results.Count > 1)
                    {
                        responses.AddRange(execRs.Results.Take(execRs.Results.Count - 1));
                    }
                    var lastStatus = responses.Last();
                    if (lastStatus.resultCode == "throttled")
                    {
                        pos -= 1;
                        delayInSec = 10;
                    }
                    else
                    {
                        responses.Add(lastStatus);
                    }
                }
                else
                {
                    break;
                }

            }

            return responses;
        }

        /// <summary>
        /// Executes JSON authenticated command.
        /// </summary>
        /// <typeparam name="TC">JSON authenticated command type.</typeparam>
        /// <typeparam name="TR">JSON response type.</typeparam>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="command">JSON authenticated command.</param>
        /// <param name="throwOnError">if <c>True</c> throw exception on Keeper error.</param>
        /// <returns>A Task returning JSON response.</returns>
        /// <exception cref="KeeperApiException">Keeper API Exception.</exception>
        /// <seealso cref="KeeperEndpointExtensions.ExecuteV2Command"/>
        public static async Task<TR> ExecuteAuthCommand<TC, TR>(this IAuthentication auth, TC command, bool throwOnError = true)
            where TC : AuthenticatedCommand
            where TR : KeeperApiResponse
        {
            return (TR) await auth.ExecuteAuthCommand(command, typeof(TR), throwOnError);
        }

        /// <summary>
        /// Executes JSON authenticated command.
        /// </summary>
        /// <typeparam name="TC">JSON authenticated command type.</typeparam>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="command">SON authenticated command.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="KeeperApiException">Keeper API Exception.</exception>
        /// <seealso cref="KeeperEndpointExtensions.ExecuteV2Command"/>
        public static Task ExecuteAuthCommand<TC>(this IAuthentication auth, TC command)
            where TC : AuthenticatedCommand
        {
            return auth.ExecuteAuthCommand<TC, KeeperApiResponse>(command);
        }

        /// <summary>
        /// Executes Protobuf authenticated request.
        /// </summary>
        /// <typeparam name="TC">Protobuf authenticated request type.</typeparam>
        /// <typeparam name="TR">Protobuf response type.</typeparam>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="endpoint">URL path for request.</param>
        /// <param name="request"></param>
        /// <param name="apiVersion">request version</param>
        /// <returns>Task returning Protobuf response.</returns>
        /// <seealso cref="IAuthentication.ExecuteAuthRest"/>
        /// <seealso cref="IKeeperEndpoint.ExecuteRest"/>
        public static async Task<TR> ExecuteAuthRest<TC, TR>(this IAuthentication auth, string endpoint, TC request, int apiVersion=0)
            where TC : IMessage
            where TR : IMessage
        {
            return (TR) await auth.ExecuteAuthRest(endpoint, request, typeof(TR), apiVersion);
        }

        /// <exclude/>
        public static async Task RegisterDataKeyForDevice(this IAuthentication auth, DeviceInfo device)
        {
            var publicKeyBytes = device.DevicePublicKey.ToByteArray();
            var publicKey = CryptoUtils.LoadEcPublicKey(publicKeyBytes);
            var encryptedDataKey = CryptoUtils.EncryptEc(auth.AuthContext.DataKey, publicKey);
            var request = new RegisterDeviceDataKeyRequest
            {
                EncryptedDeviceToken = device.EncryptedDeviceToken,
                EncryptedDeviceDataKey = ByteString.CopyFrom(encryptedDataKey),
            };
            try
            {
                await auth.ExecuteAuthRest("authentication/register_encrypted_data_key_for_device", request);
            }
            catch (KeeperApiException kae)
            {
                if (kae.Code == "device_data_key_exists") return;
                throw;
            }
        }

        /// <exclude/>
        public static async Task SetSessionParameter(this IAuthentication auth, string name, string value)
        {
            await auth.ExecuteAuthRest("setting/set_user_setting",
                new UserSettingRequest
                {
                    Setting = name,
                    Value = value
                });
        }

        /// <exclude/>
        public static Task SetSessionInactivityTimeout(this IAuthentication auth, int timeoutInMinutes)
        {
            return auth.SetSessionParameter("logout_timer", $"{timeoutInMinutes}");
        }

        /// <exclude/>
        public static string GetBiUrl(this IAuthentication auth, string endpoint)
        {
            var builder = new UriBuilder(auth.Endpoint.Server)
            {
                Path = "/bi_api/v2/enterprise_console/",
                Scheme = "https",
                Port = 443
            };
            return new Uri(builder.Uri, endpoint).AbsoluteUri;
        }

        // <exclude/>
        public static async Task<AccountSummaryElements> LoadAccountSummary(this IAuthentication auth)
        {
            var rq = new AccountSummaryRequest
            {
                SummaryVersion = 1
            };
            return await auth.ExecuteAuthRest<AccountSummaryRequest, AccountSummaryElements>("login/account_summary", rq);
        }

        /// <summary>
        /// Executes Router REST API request with Protobuf message.
        /// </summary>
        /// <typeparam name="TRQ">Protobuf request message type.</typeparam>
        /// <typeparam name="TRS">Protobuf response message type.</typeparam>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="path">Router endpoint path.</param>
        /// <param name="request">Optional Protobuf request message.</param>
        /// <param name="responseType">Optional Protobuf response message type. If null, returns null.</param>
        /// <returns>Task returning Protobuf response message, or null if responseType is null.</returns>
        public static async Task<TRS> ExecuteRouter<TRQ, TRS>(this IAuthentication auth, string path, TRQ request = null, Type responseType = null)
            where TRQ : class, IMessage
            where TRS : class, IMessage
        {
            byte[] payload = null;
            if (request != null)
            {
                payload = request.ToByteArray();
            }

            if (auth.Endpoint is not KeeperEndpoint keeperEndpoint)
            {
                throw new InvalidOperationException("Endpoint must be KeeperEndpoint to use ExecuteRouter");
            }

            var rsBytes = await keeperEndpoint.ExecuteRouterRest(path, auth.AuthContext.SessionToken, payload);

            if (responseType == null) return null;

            var parserProperty = responseType.GetProperty("Parser", BindingFlags.Public | BindingFlags.Static);
            if (parserProperty == null)
                throw new InvalidOperationException($"Type {responseType.Name} does not have a static Parser property");

            var parser = (MessageParser)parserProperty.GetValue(null);
            var response = (TRS)parser.ParseFrom(rsBytes ?? Array.Empty<byte>());

            return response;
        }

        /// <summary>
        /// Executes Router REST API request with Protobuf message (generic version with type inference).
        /// </summary>
        /// <typeparam name="TRS">Protobuf response message type.</typeparam>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="path">Router endpoint path.</param>
        /// <param name="request">Optional Protobuf request message.</param>
        /// <returns>Task returning Protobuf response message.</returns>
        public static async Task<TRS> ExecuteRouter<TRS>(this IAuthentication auth, string path, IMessage request = null)
            where TRS : class, IMessage
        {
            return await auth.ExecuteRouter<IMessage, TRS>(path, request, typeof(TRS));
        }

        /// <summary>
        /// Executes Router REST API request with JSON payload.
        /// </summary>
        /// <param name="auth">The authenticated connection.</param>
        /// <param name="path">Router endpoint path.</param>
        /// <param name="request">Optional JSON request as dictionary.</param>
        /// <returns>Task returning JSON response as dictionary, or null if response is empty.</returns>
        public static async Task<Dictionary<string, object>> ExecuteRouterJson(this IAuthentication auth, string path, Dictionary<string, object> request = null)
        {
            byte[] payload = null;
           
            payload = JsonUtils.DumpJson(request, indent: false);
            

            if (auth.Endpoint is not KeeperEndpoint keeperEndpoint)
            {
                throw new InvalidOperationException("Endpoint must be KeeperEndpoint to use ExecuteRouterJson");
            }

            var rsBytes = await keeperEndpoint.ExecuteRouterRest(path, auth.AuthContext.SessionToken, payload);

            try
            {
                var response = JsonUtils.ParseJson<Dictionary<string, object>>(rsBytes);
                return response;
            }
            catch
            {
                return null;
            }
        }
    }
}
