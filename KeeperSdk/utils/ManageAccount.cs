using System.Linq;
using System;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

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
        /// Calculates the Commander master-password strength score using zxcvbn.
        /// </summary>
        public static class MasterPasswordStrength
        {
            /// <summary>
            /// Gets the Commander strength score: 25 (weak), 50 (fair), 75 (medium), or 100 (strong).
            /// Returns 0 if the score cannot be calculated.
            /// </summary>
            public static int GetScore(string password)
            {
                if (string.IsNullOrEmpty(password))
                {
                    return 0;
                }

                try
                {
                    var result = Zxcvbn.Core.EvaluatePassword(password, null);
                    switch (result.Score)
                    {
                        case 0:
                        case 1:
                            return 25;
                        case 2:
                            return 50;
                        case 3:
                            return 75;
                        case 4:
                            return 100;
                        default:
                            return 0;
                    }
                }
                catch (Exception e)
                {
                    // Keep password-change behavior available if the estimator fails, but don't
                    // misreport the password as weak.
                    Trace.TraceWarning("Master password strength evaluation failed: {0}", e.GetType().Name);
                    return 0;
                }
            }

            /// <summary>
            /// Gets the display category corresponding to a Commander strength score.
            /// Returns UNKNOWN for scores that cannot be mapped to a known category.
            /// </summary>
            public static string GetCategory(int score)
            {
                switch (score)
                {
                    case 25:
                        return "WEAK";
                    case 50:
                        return "FAIR";
                    case 75:
                        return "MEDIUM";
                    case 100:
                        return "STRONG";
                    default:
                        return "UNKNOWN";
                }
            }
        }

        /// <summary>
        /// Optional callback for hosts that want to display the estimated master-password strength.
        /// </summary>
        public interface IMasterPasswordStrengthUI
        {
            Task ReportMasterPasswordStrength(int score, string category);
        }

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
                        var command = new ShareAccountCommand
                        {
                            ToRoleId = shareTo.RoleId,
                        };
                        if (!auth.AuthContext.ForbidKeyType2)
                        {
                            var key = CryptoUtils.LoadRsaPublicKey(shareTo.PublicKey.Base64UrlDecode());
                            command.TransferKey = CryptoUtils.EncryptRsa(auth.AuthContext.DataKey, key).Base64UrlEncode();
                        }
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
                var postUi = auth.AuthCallback as IPostLoginTaskUI
                    ?? (auth as AuthCommon)?.PostLoginTaskUI;
                if (postUi != null)
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
                    if (string.IsNullOrEmpty(newPassword))
                    {
                        throw new KeeperApiException("invalid_password", "Master Password cannot be empty.");
                    }

                    var failedRules = ruleMatcher.MatchFailedRules(newPassword);
                    if (failedRules.Length != 0) throw new KeeperApiException("password_rule_failed", failedRules[0]);

                    var strengthScore = MasterPasswordStrength.GetScore(newPassword);
                    if (postUi is IMasterPasswordStrengthUI strengthUi)
                    {
                        await strengthUi.ReportMasterPasswordStrength(
                            strengthScore,
                            MasterPasswordStrength.GetCategory(strengthScore));
                    }

                    const int iterations = 1_000_000;
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
