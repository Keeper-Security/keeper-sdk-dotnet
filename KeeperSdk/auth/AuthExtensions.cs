using System;
using System.Collections.Generic;
using System.Linq;
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
    }
}
