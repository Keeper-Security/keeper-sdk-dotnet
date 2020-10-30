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
using System.Linq;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Sdk.UI;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    public class ChangeMasterPasswordCommand : AuthenticatedCommand
    {
        public ChangeMasterPasswordCommand() : base("change_master_password")
        {
        }

        [DataMember(Name = "auth_verifier")] public string AuthVerifier;

        [DataMember(Name = "encryption_params")]
        public string EncryptionParams;
    }


    [DataContract]
    public class ShareAccountCommand : AuthenticatedCommand
    {
        public ShareAccountCommand() : base("share_account")
        {
        }

        [DataMember(Name = "to_role_id")] public long ToRoleId;

        [DataMember(Name = "transfer_key")] public string TransferTey;
    }

    public class PasswordRuleMatcher
    {
        public PasswordRule[] Rules { get; }

        public PasswordRuleMatcher(PasswordRule[] rules)
        {
            Rules = rules;
        }

        public string[] MatchFailedRules(string password)
        {
            return Rules?
                .Where(x =>
                {
                    var match = Regex.IsMatch(password, x.pattern);
                    if (!x.match)
                    {
                        match = !match;
                    }

                    return !match;
                })
                .Select(x => x.description).ToArray();
        }
    }

    public static class ManageAccountExtension
    {

        public static async Task<NewUserMinimumParams> GetNewUserParams(this IAuth auth, string userName)
        {
            var authRequest = new AuthRequest()
            {
                ClientVersion = auth.Endpoint.ClientVersion,
                Username = userName.ToLowerInvariant(),
                EncryptedDeviceToken = ByteString.CopyFrom(auth.DeviceToken)
            };

            var payload = new ApiRequestPayload
            {
                Payload = ByteString.CopyFrom(authRequest.ToByteArray()),
            };

            var rs = await auth.Endpoint.ExecuteRest("authentication/get_new_user_params", payload);
            return NewUserMinimumParams.Parser.ParseFrom(rs);
        }

        public static async Task ShareAccount(this Auth auth, AccountShareTo[] shareAccountTo)
        {
            if (shareAccountTo != null)
            {
                foreach (var shareTo in shareAccountTo)
                {
                    var key = CryptoUtils.LoadPublicKey(shareTo.publicKey.Base64UrlDecode());
                    var command = new ShareAccountCommand
                    {
                        ToRoleId = shareTo.roleId,
                        TransferTey = CryptoUtils.EncryptRsa(auth.AuthContext.DataKey, key).Base64UrlEncode()
                    };
                    await auth.ExecuteAuthCommand(command);
                }
            }
        }

        public static async Task<NewUserMinimumParams> GetNewUserParams(this Auth auth)
        {
            var authRequest = new DomainPasswordRulesRequest
            {
                Username = auth.Username
            };
            var payload = new ApiRequestPayload
            {
                Payload = ByteString.CopyFrom(authRequest.ToByteArray()),
            };
            var rs = await auth.Endpoint.ExecuteRest("authentication/get_domain_password_rules", payload);
            return NewUserMinimumParams.Parser.ParseFrom(rs);
        }

        public static async Task<string> ChangeMasterPassword(this Auth auth)
        {
            if (auth.Ui is IPostLoginTaskUI postUi )
            {
                var userParams = await auth.GetNewUserParams();

                var rules = userParams.PasswordMatchDescription
                    .Zip(userParams.PasswordMatchRegex, (description, pattern) => new PasswordRule
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