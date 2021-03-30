using System.Linq;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;

namespace KeeperSecurity
{
    namespace Commands
    {
        [DataContract]
        public class ChangeMasterPasswordCommand : AuthenticatedCommand
        {
            [DataMember(Name = "auth_verifier")]
            public string AuthVerifier;

            [DataMember(Name = "encryption_params")]
            public string EncryptionParams;

            public ChangeMasterPasswordCommand() : base("change_master_password")
            {
            }
        }


        [DataContract]
        public class ShareAccountCommand : AuthenticatedCommand
        {
            [DataMember(Name = "to_role_id")]
            public long ToRoleId;

            [DataMember(Name = "transfer_key")]
            public string TransferKey;

            public ShareAccountCommand() : base("share_account")
            {
            }
        }
    }

    namespace Utils
    {
        /// <summary>
        ///     Represents a password complexity rule matcher.
        /// </summary>
        public class PasswordRuleMatcher
        {
            public PasswordRuleMatcher(PasswordRule[] rules)
            {
                Rules = rules;
            }

            /// <summary>
            /// Gets the password rule list.
            /// </summary>
            /// <seealso cref="PasswordRule"/>
            public PasswordRule[] Rules { get; }

            /// <summary>
            ///     Matches password.
            /// </summary>
            /// <param name="password">Master Password.</param>
            /// <returns>A list of failed password rules.</returns>
            public string[] MatchFailedRules(string password)
            {
                return Rules?
                    .Where(x =>
                    {
                        var match = Regex.IsMatch(password, x.pattern);
                        if (!x.match) match = !match;

                        return !match;
                    })
                    .Select(x => x.description).ToArray();
            }

            public static PasswordRuleMatcher FromNewUserParams(NewUserMinimumParams userParams)
            {
                var rules = userParams.PasswordMatchDescription
                    .Zip(userParams.PasswordMatchRegex,
                        (description, pattern) => new PasswordRule
                        {
                            description = description,
                            match = true,
                            pattern = pattern
                        })
                    .ToArray();
                return new PasswordRuleMatcher(rules);
            }
        }

        /// <exclude />
        public static class ManageAccountExtension
        {
            internal static async Task ShareAccount(this IAuthentication auth, AccountShareTo[] shareAccountTo)
            {
                if (shareAccountTo != null)
                    foreach (var shareTo in shareAccountTo)
                    {
                        var key = CryptoUtils.LoadPublicKey(shareTo.PublicKey.Base64UrlDecode());
                        var command = new ShareAccountCommand
                        {
                            ToRoleId = shareTo.RoleId,
                            TransferKey = CryptoUtils.EncryptRsa(auth.AuthContext.DataKey, key).Base64UrlEncode()
                        };
                        await auth.ExecuteAuthCommand(command);
                    }
            }

            public static async Task<NewUserMinimumParams> GetNewUserParams(this IKeeperEndpoint endpoint, string username)
            {
                var authRequest = new DomainPasswordRulesRequest
                {
                    Username = username
                };
                var payload = new ApiRequestPayload
                {
                    Payload = ByteString.CopyFrom(authRequest.ToByteArray())
                };
                var rs = await endpoint.ExecuteRest("authentication/get_domain_password_rules", payload);
                return NewUserMinimumParams.Parser.ParseFrom(rs);
            }

            public static async Task<string> ChangeMasterPassword(this IAuthentication auth)
            {
                if (auth.AuthCallback is IPostLoginTaskUI postUi)
                {
                    var userParams = await auth.Endpoint.GetNewUserParams(auth.Username);

                    var rules = userParams.PasswordMatchDescription
                        .Zip(userParams.PasswordMatchRegex,
                            (description, pattern) => new PasswordRule
                            {
                                description = description,
                                match = true,
                                pattern = pattern
                            })
                        .ToArray();
                    var ruleMatcher = new PasswordRuleMatcher(rules);

                    var newPassword = await postUi.GetNewPassword(ruleMatcher);

                    var failedRules = ruleMatcher.MatchFailedRules(newPassword);
                    if (failedRules.Length != 0) throw new KeeperApiException("password_rule_failed", failedRules[0]);

                    var iterations = 100000;
                    var authSalt = CryptoUtils.GetRandomBytes(16);
                    var authVerifier = CryptoUtils.CreateAuthVerifier(newPassword, authSalt, iterations);
                    var keySalt = CryptoUtils.GetRandomBytes(16);
                    var encryptionParameters = CryptoUtils.CreateEncryptionParams(newPassword, keySalt, iterations, auth.AuthContext.DataKey);

                    var command = new ChangeMasterPasswordCommand
                    {
                        AuthVerifier = authVerifier.Base64UrlEncode(),
                        EncryptionParams = encryptionParameters.Base64UrlEncode()
                    };

                    await auth.ExecuteAuthCommand(command);
                    return newPassword;
                }

                return null;
            }
        }
    }
}
