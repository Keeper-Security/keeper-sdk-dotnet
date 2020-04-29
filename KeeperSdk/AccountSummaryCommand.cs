using System.Collections.Generic;
using System.Runtime.Serialization;

namespace KeeperSecurity.Sdk
{
    [DataContract]
    public class AccountSummaryCommand : AuthenticatedCommand
    {
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
        public long SecondsUntilExpiration { get; set; }

        [DataMember(Name = "file_plan_type")]
        public int FilePlanType { get; set; }

        [DataMember(Name = "storage_expiration_date")]
        public string StorageExpirationDate { get; set; }

        [DataMember(Name = "seconds_until_storage_expiration")]
        public long SecondsUntilStorageExpiration { get; set; }
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
        public string emailVerified;

        [DataMember(Name = "account_folder_key")]
        public string accountFolderKey;

        [DataMember(Name = "must_perform_account_share_by")]
        public long? mustPerformAccountShareBy;

        [DataMember(Name = "share_account_to")]
        public AccountShareTo[] shareAccountTo;

        [DataMember(Name = "master_password_last_modified")]
        public long? masterPasswordLastModified;

        [DataMember(Name = "theme")]
        public string theme;

        [DataMember(Name = "sso_user")]
        public bool? ssoUser;
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

    }
}
