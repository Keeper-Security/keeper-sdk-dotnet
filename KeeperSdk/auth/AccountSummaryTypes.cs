using System.Linq;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    /// Represents user's account license information.
    /// </summary>
    public class AccountLicense
    {
        /// <summary>
        /// Account Type ID.
        /// <list type="bullet">
        /// <item>
        /// <term>0</term>
        /// <description>Consumer</description>
        /// </item>
        /// <item>
        /// <term>1</term>
        /// <description>Family</description>
        /// </item>
        /// <item>
        /// <term>2</term>
        /// <description>Enterprise</description>
        /// </item>
        /// </list>
        /// </summary>
        public int AccountType { get; internal set; }

        /// <summary>
        /// Product Type ID.
        /// <list type="bullet">
        /// <item>
        /// <term>1</term>
        /// <description>Trial</description>
        /// </item>
        /// <item>
        /// <term>2</term>
        /// <description>Backup</description>
        /// </item>
        /// <item>
        /// <term>3</term>
        /// <description>Groups</description>
        /// </item>
        /// <item>
        /// <term>4</term>
        /// <description>Backup unlimited</description>
        /// </item>
        /// </list>
        /// </summary>
        public int ProductTypeId { get; internal set; }

        /// <summary>
        /// Product Type name.
        /// </summary>
        public string ProductTypeName { get; internal set; }

        /// <summary>
        /// The date that the license will expire.
        /// </summary>
        public string ExpirationDate { get; internal set; }

        /// <summary>
        /// The number of seconds until this user’s subscription expires. Unix time.
        /// </summary>
        public float SecondsUntilExpiration { get; internal set; }

        /// <summary>
        /// The type of file plan the user has.
        /// </summary>
        public int FilePlanType { get; internal set; }

        /// <summary>
        /// The date that the file plan license will expire.
        /// </summary>
        public string StorageExpirationDate { get; internal set; }

        /// <summary>
        /// The number of seconds until this user’s file plan subscription expires. Unix time.
        /// </summary>
        public float SecondsUntilStorageExpiration { get; internal set; }

        /// <summary>
        /// File storage plan. Total bytes
        /// </summary>
        public long BytesTotal { get; internal set; }

        /// <summary>
        /// File storage plan. Used bytes
        /// </summary>
        public long BytesUsed { get; set; }

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
                SecondsUntilStorageExpiration = license.SecondsUntilStorageExpiration,
                BytesTotal = license.BytesTotal,
                BytesUsed = license.BytesUsed,
            };
        }
    }

    internal class AccountShareTo
    {
        public long RoleId { get; internal set; }
        public string PublicKey { get; internal set; }
    }

    /// <summary>
    /// Represents user's account settings.
    /// </summary>
    public class AccountSettings : PasswordRequirements
    {
        /// <summary>
        /// 2FA is required.
        /// </summary>
        public bool? TwoFactorRequired { get; internal set; }

        /// <summary>
        /// 2FA channel.
        /// <list type="bullet">
        /// <item>
        /// <term>two_factor_disabled</term>
        /// <description>two factor is not enabled for this user</description>
        /// </item>
        /// <item>
        /// <term>two_factor_channel_sms</term>
        /// <description>TOTP codes are sent through SMS</description>
        /// </item>
        /// <item>
        /// <term>two_factor_channel_voice</term>
        /// <description>TOTP codes are sent through voice calls</description>
        /// </item>
        /// <item>
        /// <term>two_factor_channel_google</term>
        /// <description>Google/Microsoft Authenticator</description>
        /// </item>
        /// </list>
        /// </summary>
        public string Channel { get; internal set; }
        /// <summary>
        /// Parameter value for <see cref="Channel"/>
        /// </summary>
        public string ChannelValue { get; internal set; }
        /// <summary>
        /// Is email verified?
        /// </summary>
        public bool? EmailVerified { get; internal set; }
        /// <summary>
        /// Deadline to accept Account Transfer Consent. Unix timestamp.
        /// </summary>
        public double? MustPerformAccountShareBy { get; internal set; }
        /// <summary>
        /// Time of last change of master password. Unix timestamp.
        /// </summary>
        public double? MasterPasswordLastModified { get; internal set; }
        /// <summary>
        /// Theme.
        /// </summary>
        public string Theme { get; internal set; }
        /// <summary>
        /// Is SSO user?
        /// </summary>
        public bool? SsoUser { get; internal set; }
        /// <summary>
        /// Logout timeout in seconds.
        /// </summary>
        public long? LogoutTimerInSec { get; internal set; }
        /// <summary>
        /// Enterprise administrator requested data key sharing.
        /// </summary>
        public bool? ShareDatakeyWithEnterprise { get; internal set; }
        /// <summary>
        /// Persistent login.
        /// </summary>
        public bool PersistentLogin { get; internal set; }
        /// <summary>
        /// Record types enabled flag.
        /// </summary>

        public bool RecordTypesEnabled { get; internal set; }

        internal string AccountFolderKey { get; set; }
        internal AccountShareTo[] ShareAccountTo { get; set; }

        internal static AccountSettings LoadFromProtobuf(AccountSummary.Settings settings)
        {
            return new AccountSettings
            {
                TwoFactorRequired = settings.TwoFactorRequired,
                Channel = settings.Channel,
                ChannelValue = settings.ChannelValue,
                EmailVerified = settings.EmailVerified,
                AccountFolderKey = settings.AccountFolderKey.ToByteArray().Base64UrlEncode(),
                MustPerformAccountShareBy = settings.MustPerformAccountShareBy > 0 ? (double?) settings.MustPerformAccountShareBy : null,
                ShareAccountTo = settings.ShareAccountTo.Select(x => new AccountShareTo
                {
                    PublicKey = x.PublicKey.ToByteArray().Base64UrlEncode(),
                    RoleId = x.RoleId
                }).ToArray(),
                MasterPasswordLastModified = settings.MasterPasswordLastModified > 1 ? (double?) settings.MasterPasswordLastModified : null,
                Theme = settings.Theme,
                SsoUser = settings.SsoUser,
                ShareDatakeyWithEnterprise = settings.ShareDataKeyWithEccPublicKey,
                LogoutTimerInSec = settings.LogoutTimer > 1000 ? settings.LogoutTimer / 1000 : (long?) null,
                PersistentLogin = settings.PersistentLogin,
                RecordTypesEnabled = settings.RecordTypesEnabled,
            };
        }
    }

    internal class AccountKeys
    {
        public string EncryptionParams { get; internal set; }

        public string EncryptedDataKey { get; internal set; }

        public string EncryptedPrivateKey { get; internal set; }

        public string EncryptedEcPrivateKey { get; internal set; }

        public double? DataKeyBackupDate { get; internal set; }

        internal static AccountKeys LoadFromProtobuf(AccountSummary.KeysInfo keyInfo)
        {
            return new AccountKeys
            {
                EncryptionParams = keyInfo.EncryptionParams.ToByteArray().Base64UrlEncode(),
                EncryptedPrivateKey = keyInfo.EncryptedPrivateKey.ToByteArray().Base64UrlEncode(),
                EncryptedEcPrivateKey = keyInfo.EncryptedEccPrivateKey?.Length > 0 ? keyInfo.EncryptedEccPrivateKey.ToByteArray().Base64UrlEncode() : null,
                EncryptedDataKey = keyInfo.EncryptedDataKey.ToByteArray().Base64UrlEncode(),
                DataKeyBackupDate = keyInfo.DataKeyBackupDate > 1 ? keyInfo.DataKeyBackupDate : (double?) null
            };
        }
    }
}
