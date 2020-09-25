using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization;
using System.Threading;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    public class AccountSummaryCommand : AuthenticatedCommand
    {
        public const string IsEnterpriseAdmin = "is_enterprise_admin";
        public const string License = "license";
        public const string Settings = "settings";
        public const string Enforcements = "enforcements";

        public AccountSummaryCommand() : base("account_summary") { }

        [DataMember(Name = "include")]
        public string[] include;
    }

    [DataContract]
    public class AccountLicense
    {
        [DataMember(Name = "account_type")]
        public int AccountType { get; set; }

        [DataMember(Name = "product_type_id")]
        public int ProductTypeId { get; set; }

        [DataMember(Name = "product_type_name")]
        public string ProductTypeName { get; set; }

        [DataMember(Name = "expiration_date")]
        public string ExpirationDate { get; set; }

        [DataMember(Name = "seconds_until_expiration")]
        public float SecondsUntilExpiration { get; set; }

        [DataMember(Name = "file_plan_type")]
        public int FilePlanType { get; set; }

        [DataMember(Name = "storage_expiration_date")]
        public string StorageExpirationDate { get; set; }

        [DataMember(Name = "seconds_until_storage_expiration")]
        public float SecondsUntilStorageExpiration { get; set; }

        internal static AccountLicense LoadFromProtobuf(AccountSummary.License license)
        {
            return new AccountLicense
            {
                AccountType = license.AccountType,
                ProductTypeId = license.ProductTypeId,
                ProductTypeName = license.ProductTypeName,
                ExpirationDate = license.ExpirationDate,
                SecondsUntilExpiration = license.SecondsUntilExpiration,
                FilePlanType = license.FilePlanType,
                StorageExpirationDate = license.StorageExpirationDate,
                SecondsUntilStorageExpiration = license.SecondsUntilStorageExpiration
            };
        }
    }

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

    [DataContract]
    public class AccountShareTo
    {
        [DataMember(Name = "role_id")]
        public long roleId;
        [DataMember(Name = "public_key")]
        public string publicKey;
    }

    [DataContract]
    public class AccountSettings : PasswordRequirements
    {
        [DataMember(Name = "twoFactorRequired")]
        public bool? twoFactorRequired;

        [DataMember(Name = "channel")]
        public string channel;

        [DataMember(Name = "channel_value")]
        public string channelValue;

        [DataMember(Name = "email_verified")]
        public bool emailVerified;

        [DataMember(Name = "account_folder_key")]
        public string accountFolderKey;

        [DataMember(Name = "must_perform_account_share_by")]
        public double? mustPerformAccountShareBy;

        [DataMember(Name = "share_account_to")]
        public AccountShareTo[] shareAccountTo;

        [DataMember(Name = "master_password_last_modified")]
        public double? masterPasswordLastModified;

        [DataMember(Name = "theme")]
        public string theme;

        [DataMember(Name = "sso_user")]
        public bool? ssoUser;

        public bool? shareDatakeyWithEccPublicKey;


        internal static AccountSettings LoadFromProtobuf(AccountSummary.Settings settings)
        {
            return new AccountSettings
            {
                twoFactorRequired = settings.TwoFactorRequired,
                channel = settings.Channel,
                channelValue = settings.ChannelValue,
                emailVerified = settings.EmailVerified,
                accountFolderKey = settings.AccountFolderKey.ToByteArray().Base64UrlEncode(),
                mustPerformAccountShareBy = settings.MustPerformAccountShareBy > 0 ? (double?) settings.MustPerformAccountShareBy : null,
                shareAccountTo = settings.ShareAccountTo.Select(x => new AccountShareTo
                {
                    publicKey = x.PublicKey.ToByteArray().Base64UrlEncode(),
                    roleId = x.RoleId
                }).ToArray(),
                masterPasswordLastModified = settings.MasterPasswordLastModified > 1 ? (double?) settings.MasterPasswordLastModified : null,
                theme = settings.Theme,
                ssoUser = settings.SsoUser,
                shareDatakeyWithEccPublicKey = settings.ShareDataKeyWithEccPublicKey,
            };
        }
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
        public double? dataKeyBackupDate;

        internal static AccountKeys LoadFromProtobuf(AccountSummary.KeysInfo keyInfo)
        {
            return new AccountKeys
            {
                encryptionParams = keyInfo.EncryptionParams.ToByteArray().Base64UrlEncode(),
                encryptedPrivateKey = keyInfo.EncryptedPrivateKey.ToByteArray().Base64UrlEncode(),
                encryptedDataKey = keyInfo.EncryptedDataKey.ToByteArray().Base64UrlEncode(),
                dataKeyBackupDate = keyInfo.DataKeyBackupDate > 1 ? keyInfo.DataKeyBackupDate : (double?) null
            };
        }
    }

    [DataContract]
    public class AccountSummaryResponse : KeeperApiResponse
    {
        [DataMember(Name = "is_enterprise_admin")]
        public bool? IsEnterpriseAdmin { get; set; }

        [DataMember(Name = "license")]
        public AccountLicense License { get; set; }

        [DataMember(Name = "enforcements")]
        public IDictionary<string, object> Enforcements { get; set; }

        [DataMember(Name = "settings")]
        public AccountSettings Settings { get; set; }

        [DataMember(Name = "client_key")]
        public string clientKey;

        [DataMember(Name = "keys")]
        public AccountKeys keys;
    }
}
