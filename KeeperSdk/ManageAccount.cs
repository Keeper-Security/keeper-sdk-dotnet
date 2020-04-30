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
        public string RuleIntro { get; }
        public PasswordRule[] Rules { get; }

        public PasswordRuleMatcher(PasswordRequirements requirements)
        {
            RuleIntro = requirements.PasswordRulesIntro;
            Rules = requirements.PasswordRules;
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

        public static async Task<string> ChangeMasterPassword(this Auth auth, PasswordRequirements requirements)
        {
            var ruleMatcher = new PasswordRuleMatcher(requirements);
            var password = await auth.Ui.GetNewPassword(ruleMatcher);
            var failedRules = ruleMatcher.MatchFailedRules(password);
            if (failedRules.Length != 0) throw new KeeperApiException("password_rule_failed", failedRules[0]);

            var authSalt = CryptoUtils.GetRandomBytes(16);
            var authVerifier = CryptoUtils.CreateAuthVerifier(password, authSalt, auth.authContext.AuthIterations);
            var keySalt = CryptoUtils.GetRandomBytes(16);
            var encryptionParameters = CryptoUtils.CreateEncryptionParams(password, keySalt,
                auth.authContext.AuthIterations, auth.AuthContext.DataKey);

            var command = new ChangeMasterPasswordCommand
            {
                AuthVerifier = authVerifier.Base64UrlEncode(),
                EncryptionParams = encryptionParameters.Base64UrlEncode()
            };

            await auth.ExecuteAuthCommand(command);
            return password;
        }
    }
}