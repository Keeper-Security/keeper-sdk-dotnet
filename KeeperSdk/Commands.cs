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

using System.Collections.Generic;
using System.Runtime.Serialization;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    public class KeeperApiCommand
    {
        public KeeperApiCommand(string command)
        {
            this.command = command;
        }
        [DataMember(Name = "command", EmitDefaultValue = false)]
        public string command;
        [DataMember(Name = "locale", EmitDefaultValue = false)]
        public string locale = "en_US";
        [DataMember(Name = "client_version", EmitDefaultValue = false)]
        public string clientVersion;
    }

    public interface IBatchCommand
    {
    }

    [DataContract]
    public class KeeperApiResponse
    {
        [DataMember(Name = "result", EmitDefaultValue = false)]
        public string result;
        [DataMember(Name = "result_code", EmitDefaultValue = false)]
        public string resultCode;
        [DataMember(Name = "message", EmitDefaultValue = false)]
        public string message;
        [DataMember(Name = "command", EmitDefaultValue = false)]
        public string command;

        public bool IsSuccess => result == "success";
    }

    [DataContract]
    public class KeeperApiErrorResponse : KeeperApiResponse
    {
        [DataMember(Name = "error", EmitDefaultValue = false)]
        public string Error { get; set; }
        [DataMember(Name = "key_id")]
        public int KeyId { get; set; }
        [DataMember(Name = "region_host")]
        public string RegionHost { get; set; }
    }

    [DataContract]
    public class LoginCommand : KeeperApiCommand
    {
        public LoginCommand() : base("login")
        {
        }
        [DataMember(Name = "version")]
        public int version = 2;
        [DataMember(Name = "include")]
        public string[] include;
        [DataMember(Name = "auth_response")]
        public string authResponse;
        [DataMember(Name = "username")]
        public string username;
        [DataMember(Name = "2fa_type", EmitDefaultValue = false)]
        public string twoFactorType;
        [DataMember(Name = "2fa_token", EmitDefaultValue = false)]
        public string twoFactorToken;
        [DataMember(Name = "2fa_mode", EmitDefaultValue = false)]
        public string twoFactorMode;
        [DataMember(Name = "device_token_expire_days", EmitDefaultValue = false)]
        public int? deviceTokenExpiresInDays;
    }

    [DataContract]
    public class AccountKeys
    {
        [DataMember(Name = "encryption_params")]
        public string encryptionParams;
        [DataMember(Name = "encrypted_data_key")]
        public string encryptedDataKey;
        [DataMember(Name = "encrypted_private_key")]
        public string encryptedPrivateKey;
        [DataMember(Name = "data_key_backup_date")]
        public long? dataKeyBackupDate;
    }

    [DataContract]
    public class PasswordRequirements
    {
        [DataMember(Name = "password_rules_intro", EmitDefaultValue = false)]
        public string PasswordRulesIntro { get; set; }

        [DataMember(Name = "password_rules", EmitDefaultValue = false)]
        public PasswordRule[] PasswordRules;
    }

    [DataContract]
    public class PasswordRule
    {
        [DataMember(Name = "match")]
        public bool match;

        [DataMember(Name = "pattern")]
        public string pattern;

        [DataMember(Name = "description")]
        public string description;
    }


    [DataContract]
    public class LoginResponse : KeeperApiResponse
    {
        [DataMember(Name = "session_token")]
        public string sessionToken;
        [DataMember(Name = "device_token")]
        public string deviceToken;
        [DataMember(Name = "dt_scope")]
        public string deviceTokenScope;
        /*
        "two_factor_channel_sms" - Users receive a TOTP code via text message.
        "two_factor_channel_voice" - Users receive a TOTP code via phone call.
        "two_factor_channel_google" - Users look up TOTP codes on their Google Authenticator app.
        "two_factor_channel_rsa" - Users authenticate against an RSA server, using either a generated passcode or a pin.
        "two_factor_channel_duo" - Users authenticate through Duo Security.
        "two_factor_channel_push" - Users authenticate through Keeper DNA.
        "two_factor_channel_u2f" - Users authenticate with a U2F Security Key, using challenge-response.
        */
        [DataMember(Name = "channel")]
        public string channel;
        [DataMember(Name = "capabilities")]
        public string[] capabilities;
        /*  DUO account capabilities
         *  "push"    
         *  "sms"
         *  "phone"
         *  "mobile_otp"   ????
         */
        [DataMember(Name = "phone")]
        public string phone;    // Phone number associated with Two Factor Method
        [DataMember(Name = "url")]
        public string url;      // websocket URL associated with Two Factor Method
        [DataMember(Name = "enroll_url")]
        public string enrollUrl;      // requires 2FA enrollment

        [DataMember(Name = "client_key")]
        public string clientKey;

        [DataMember(Name = "keys")]
        public AccountKeys keys;

        [DataMember(Name = "enforcements")]
        public IDictionary<string, object> Enforcements { get; set; }

        [DataMember(Name = "password_rules_intro", EmitDefaultValue = false)]
        public string passwordRulesIntro;
        [DataMember(Name = "password_rules", EmitDefaultValue = false)]
        public PasswordRule[] passwordRules;

        [DataMember(Name = "iterations")]
        public int? iterations;
        [DataMember(Name = "salt")]
        public string salt;
    }

    [DataContract]
    public class AuthenticatedCommand : KeeperApiCommand
    {
        public AuthenticatedCommand(string command) : base(command) { }

        [DataMember(Name = "device_id", EmitDefaultValue = false)]
        public string deviceId;

        [DataMember(Name = "session_token", EmitDefaultValue = false)]
        public string sessionToken;

        [DataMember(Name = "username", EmitDefaultValue = false)]
        public string username;
    }

    [DataContract]
    public class SetClientKeyCommand : AuthenticatedCommand
    {
        public SetClientKeyCommand() : base("set_client_key") { }

        [DataMember(Name = "client_key")]
        public string clientKey;
    }

    [DataContract]
    public class SetClientKeyResponse : KeeperApiResponse
    {
        [DataMember(Name = "client_key")]
        public string clientKey;
    }

    [DataContract]
    public class GetPushInfoCommand : AuthenticatedCommand
    {
        public GetPushInfoCommand() : base("get_push_info") { }

        [DataMember(Name = "type", EmitDefaultValue = false)]
        public string type;
    }

    [DataContract]
    public class GetPushInfoResponse : KeeperApiResponse
    {
        [DataMember(Name = "url")]
        public string url;
    }

}
