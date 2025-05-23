using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Collections;
using System.Runtime.Serialization;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Defines properties and methods of decrypted Vault data.
    /// </summary>
    /// <seealso cref="VaultData"/>
    public interface IVaultData
    {
        /// <summary>
        /// Gets encrypted vault storage.
        /// </summary>
        IKeeperStorage Storage { get; }

        /// <summary>
        /// Gets client key. AES encryption key that encrypts data in the local storage <see cref="Storage"/>
        /// </summary>
        byte[] ClientKey { get; }

        /// <summary>
        /// Gets vault root folder. <c>My Vault</c>
        /// </summary>
        FolderNode RootFolder { get; }

        /// <summary>
        /// Get the list of all folders in the vault. Both user and shared folders.
        /// </summary>
        IEnumerable<FolderNode> Folders { get; }

        /// <summary>
        /// Gets the folder associated with the specified folder UID.
        /// </summary>
        /// <param name="folderUid">Folder UID</param>
        /// <param name="node">When this method returns <c>true</c>, contains requested folder; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the vault contains a folder with specified UID; otherwise, <c>false</c></returns>
        bool TryGetFolder(string folderUid, out FolderNode node);

        /// <summary>
        /// Gets the number of all records in the vault.
        /// </summary>
        int RecordCount { get; }

        /// <summary>
        /// Get the list of all records in the vault.
        /// </summary>
        IEnumerable<KeeperRecord> KeeperRecords { get; }

        /// <summary>
        /// Gets the Keeper record associated with the specified record UID from a record cache.
        /// </summary>
        /// <param name="recordUid">Record UID</param>
        /// <param name="record">When this method returns <c>true</c>, contains requested record; otherwise <c>null</c></param>
        /// <returns><c>true</c> in the vault contains a record with specified UID; otherwise, <c>false</c></returns>
        /// <seealso cref="TryLoadKeeperRecord"/>
        bool TryGetKeeperRecord(string recordUid, out KeeperRecord record);

        /// <summary>
        /// Tries to load a Keeper from storage. 
        /// The loaded record can be modified and discarded without changing a record cache.
        /// </summary>
        /// <param name="recordUid">Record UID</param>
        /// <param name="record">When this method returns <c>true</c>, contains requested record; otherwise <c>null</c></param>
        /// <returns><c>true</c> in the vault contains a record with specified UID; otherwise, <c>false</c></returns>
        /// <seealso cref="TryGetKeeperRecord"/>
        bool TryLoadKeeperRecord(string recordUid, out KeeperRecord record);

        /// <summary>
        /// Get the list of all legacy records in the vault.
        /// </summary>
        [Obsolete("Use KeeperRecords")]
        IEnumerable<PasswordRecord> Records { get; }

        /// <summary>
        /// Gets the legacy record associated with the specified record UID.
        /// </summary>
        /// <param name="recordUid">Record UID.</param>
        /// <param name="record">When this method returns <c>true</c>, contains requested record; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the vault contains a record with specified UID; otherwise, <c>false</c></returns>
        [Obsolete("Use TryGetKeeperRecord")]
        bool TryGetRecord(string recordUid, out PasswordRecord record);

        /// <summary>
        /// Gets  number of all shared folders in the vault.
        /// </summary>
        int SharedFolderCount { get; }

        /// <summary>
        /// Get the list of all shared folders in the vault.
        /// </summary>
        IEnumerable<SharedFolder> SharedFolders { get; }

        /// <summary>
        /// Gets shared folder associated with a specified record UID.
        /// </summary>
        /// <param name="sharedFolderUid">Shared Folder UID</param>
        /// <param name="sharedFolder">When this method returns <c>true</c>, contains requested shared folder; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the vault contains a shared folder with specified UID; otherwise, <c>false</c>.</returns>
        bool TryGetSharedFolder(string sharedFolderUid, out SharedFolder sharedFolder);

        /// <summary>
        /// Gets the number of all teams user is member of.
        /// </summary>
        int TeamCount { get; }

        /// <summary>
        /// Get list of all teams user is member of.
        /// </summary>
        IEnumerable<Team> Teams { get; }

        /// <summary>
        /// Gets a team associated with a specified team UID.
        /// </summary>
        /// <param name="teamUid">Team UID.</param>
        /// <param name="team">When this method returns <c>true</c>, contains requested team; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the vault contains a team with specified UID; otherwise, <c>false</c>.</returns>
        bool TryGetTeam(string teamUid, out Team team);

        /// <summary>
        /// Loads non shared (or per user) data associated with the record.
        /// </summary>
        /// <typeparam name="T">App specific per-user data type</typeparam>
        /// <param name="recordUid">Record UID</param>
        /// <returns>Non shared data associated with the record</returns>
        T LoadNonSharedData<T>(string recordUid) where T : RecordNonSharedData, new();

        /// <summary>
        /// Gets list of all registered record types.
        /// </summary>
        IEnumerable<RecordType> RecordTypes { get; }

        /// <summary>
        /// Gets record type meta data associated with the record type name.
        /// </summary>
        /// <param name="name">Record type name.</param>
        /// <param name="recordType">When this method returns <c>true</c>, contains requested record type; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if record type exists; otherwise, <c>false</c>.</returns>
        bool TryGetRecordTypeByName(string name, out RecordType recordType);

        /// <summary>
        /// Gets user email by user account Uid
        /// </summary>
        /// <param name="accountUid">User Account Uid</param>
        /// <param name="username">Username / Email</param>
        /// <returns><c>true</c> if accountUid exists; otherwise, <c>false</c>.</returns>
        bool TryGetUsername(string accountUid, out string username);

        /// <summary>
        /// Gets user email by user account Uid
        /// </summary>
        /// <param name="username">Username / Email</param>
        /// <param name="accountUid">User Account Uid</param>
        /// <returns><c>true</c> if email exists; otherwise, <c>false</c>.</returns>
        bool TryGetAccountUid(string username, out string accountUid);
    }

    /// <summary>
    /// Represents a record in folder.
    /// </summary>
    public class RecordPath
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        public string RecordUid { get; set; }

        /// <summary>
        /// Folder UID.
        /// </summary>
        public string FolderUid { get; set; }
    }

    /// <summary>
    /// Defines shared folder record permissions.
    /// </summary>
    public interface IRecordShareOptions
    {
        /// <summary>
        /// Record can be edited.
        /// </summary>
        bool? CanEdit { get; }

        /// <summary>
        /// Record can be re-shared.
        /// </summary>
        bool? CanShare { get; }

        /// <summary>
        /// Share expiration time.
        /// </summary>
        DateTimeOffset? Expiration { get; }
    }

    /// <summary>
    /// Defines shared folder user permissions.
    /// </summary>
    public interface IUserShareOptions
    {
        /// <summary>
        /// User can manage other users.
        /// </summary>
        bool? ManageUsers { get; }

        /// <summary>
        /// User can manage records.
        /// </summary>
        bool? ManageRecords { get; }

        /// <summary>
        /// Share expiration time.
        /// </summary>
        DateTimeOffset? Expiration { get; }
    }

    /// <summary>
    /// Defines methods for interaction between Vault API and user.
    /// </summary>
    public interface IVaultUi
    {
        /// <summary>
        /// Ask confirmation from user.
        /// </summary>
        /// <param name="information">text to be displayed in the dialog.</param>
        /// <returns>Task returning <c>bool</c>; <c>true</c> means Yes/Accept; <c>false</c> No/Decline</returns>
        /// <seealso cref="IVault.DeleteRecords"/>
        /// <seealso cref="IVault.DeleteFolder"/>
        Task<bool> Confirmation(string information);
    }

    /// <summary>
    /// Represents an exception that occurs when current user requests other user's public for the first time.
    /// </summary>
    public class NoActiveShareWithUserException : Authentication.KeeperApiException
    {
        /// <exclude />
        public NoActiveShareWithUserException(string username, string code, string message) : base(code, message)
        {
            Username = username;
        }

        /// <summary>
        /// Gets user email to send share invite
        /// </summary>
        public string Username { get; }
    }

    [Flags]
    public enum RecordChange
    {
        RecordType = 1 << 0,
        Title = 1 << 1,
        Login = 1 << 2,
        Password = 1 << 3,
        Url = 1 << 4,
        Totp = 1 << 5,
        Hostname = 1 << 6,
        Address = 1 << 7,
        PaymentCard = 1 << 8,
        Notes = 1 << 9,
        File = 1 << 10,
        CustomField = 1 << 11,
    }

    /// <summary>
    /// Represents a record history
    /// </summary>
    public class RecordHistory
    {
        /// <summary>
        /// Keeper record
        /// </summary>
        public KeeperRecord KeeperRecord { get; internal set; }

        /// <summary>
        /// User modified the record
        /// </summary>
        public string Username { get; internal set; }

        /// <summary>
        /// Summary of changes
        /// </summary>
        public RecordChange RecordChange { get; internal set; }
    }


    /// <summary>
    /// Defines methods for modifying the vault records and folders. 
    /// </summary>
    /// <seealso cref="VaultOnline"/>
    public interface IVault : IVaultData
    {
        /// <summary>
        /// Gets Vault user interaction interface.
        /// </summary>
        IVaultUi VaultUi { get; }

        /// <summary>
        /// Gets or Sets automatic sync down flag.
        /// </summary>
        bool AutoSync { get; set; }

        /// <summary>
        /// Records "open_record" audit event for enterprise accounts
        /// </summary>
        /// <param name="recordUid"></param>
        void AuditLogRecordOpen(string recordUid);

        /// <summary>
        /// Records "copy_password" audit event for enterprise accounts
        /// </summary>
        /// <param name="recordUid"></param>
        void AuditLogRecordCopyPassword(string recordUid);

        /// <summary>
        /// Creates a password record.
        /// </summary>
        /// <param name="record">Keeper Record.</param>
        /// <param name="folderUid">Folder UID where the record to be created. Optional.</param>
        /// <returns>A task returning created password record.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<KeeperRecord> CreateRecord(KeeperRecord record, string folderUid = null);

        /// <summary>
        /// Modifies a password record.
        /// </summary>
        /// <param name="record">Keeper Record.</param>
        /// <param name="skipExtra">Do not update file attachment information on the record.</param>
        /// <returns>A task returning updated password record.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<KeeperRecord> UpdateRecord(KeeperRecord record, bool skipExtra = true);

        /// <summary>
        /// Modifies multiple password records.
        /// </summary>
        /// <param name="records">Keeper Records.</param>
        /// <returns>A task returning record update statuses.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<IList<RecordUpdateStatus>> UpdateRecords(IEnumerable<KeeperRecord> records);

        /// <summary>
        /// Deletes records.
        /// </summary>
        /// <param name="records">an array of record paths.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task DeleteRecords(RecordPath[] records);

        /// <summary>
        /// Moves records to a folder.
        /// </summary>
        /// <param name="records">an array of record paths.</param>
        /// <param name="dstFolderUid">Destination folder UID.</param>
        /// <param name="link"><c>true</c>creates a link. The source record in not deleted; otherwise record will be removed from the source.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task MoveRecords(RecordPath[] records, string dstFolderUid, bool link = false);

        /// <summary>
        /// Stores non shared (or per user) data associated with the record.
        /// </summary>
        /// <typeparam name="T">App specific per-user data type</typeparam>
        /// <param name="recordUid">Record UID</param>
        /// <param name="nonSharedData">Non shared data</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException">Keeper API error</exception>
        Task StoreNonSharedData<T>(string recordUid, T nonSharedData) where T : RecordNonSharedData, new();

        /// <summary>
        /// Creates a folder.
        /// </summary>
        /// <param name="name">Folder Name.</param>
        /// <param name="parentFolderUid">Parent Folder UID.</param>
        /// <param name="sharedFolderOptions">Shared Folder creation options. Optional.</param>
        /// <returns>A task returning created folder.</returns>
        /// <remarks>Pass sharedFolderOptions parameter to create a Shared Folder.</remarks>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        /// <seealso cref="SharedFolderOptions"/>
        Task<FolderNode> CreateFolder(string name, string parentFolderUid = null,
            SharedFolderOptions sharedFolderOptions = null);

        /// <summary>
        /// Renames a folder.
        /// </summary>
        /// <param name="folderUid">Folder UID.</param>
        /// <param name="newName">New folder name.</param>
        /// <returns>A task returning renamed folder.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<FolderNode> RenameFolder(string folderUid, string newName);

        /// <summary>
        /// Renames a folder.
        /// </summary>
        /// <param name="folderUid">Folder UID.</param>
        /// <param name="newName">New folder name.</param>
        /// <param name="sharedFolderOptions">Shared Folder creation options. Optional.</param>
        /// <returns>A task returning renamed folder.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<FolderNode> UpdateFolder(string folderUid, string newName, SharedFolderOptions sharedFolderOptions = null);

        /// <summary>
        /// Moves a folder to the another folder.
        /// </summary>
        /// <param name="srcFolderUid">Source Folder UID.</param>
        /// <param name="dstFolderUid">Destination Folder UID.</param>
        /// <param name="link"><c>true</c>creates a link. The source folder in not deleted; otherwise source folder will be removed.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task MoveFolder(string srcFolderUid, string dstFolderUid, bool link = false);

        /// <summary>
        /// Delete folder.
        /// </summary>
        /// <param name="folderUid">Folder UID.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task DeleteFolder(string folderUid);

        /// <summary>
        /// Retrieves all enterprise team descriptions.
        /// </summary>
        /// <returns>A list of all enterprise teams. (awaitable)</returns>
        Task<IEnumerable<TeamInfo>> GetTeamsForShare();

        /// <summary>
        /// Retrieves all known users for sharing
        /// </summary>
        /// <returns></returns>
        Task<ShareWithUsers> GetUsersForShare();

        /// <summary>
        /// Sends share invitation request to the user.
        /// </summary>
        /// <param name="username">User email</param>
        /// <returns>Awaitable task</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task SendShareInvitationRequest(string username);

        /// <summary>
        /// Retrieves record sharing information. 
        /// </summary>
        /// <param name="recordUids">List of record UIDs</param>
        /// <returns>Awaitable task returning record share details</returns>
        Task<IEnumerable<RecordSharePermissions>> GetSharesForRecords(IEnumerable<string> recordUids);

        /// <summary>
        /// Cancels all shares with a user.
        /// </summary>
        /// <param name="username">User account email.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task CancelSharesWithUser(string username);

        /// <summary>
        /// Shares a record with a user
        /// </summary>
        /// <param name="recordUid">Record UID.</param>
        /// <param name="username">User account email</param>
        /// <param name="options">Record share options</param>
        /// <exception cref="NoActiveShareWithUserException"/>
        /// <returns>Awaitable task.</returns>
        Task ShareRecordWithUser(string recordUid, string username, IRecordShareOptions options);

        /// <summary>
        /// Transfers a record to user
        /// </summary>
        /// <param name="recordUid">Record UID.</param>
        /// <param name="username">User account email</param>
        /// <returns>Awaitable task.</returns>
        Task TransferRecordToUser(string recordUid, string username);

        /// <summary>
        /// Removes a record share from a user
        /// </summary>
        /// <param name="recordUid">Record UID.</param>
        /// <param name="username">User account email</param>
        /// <returns>Awaitable task.</returns>
        Task RevokeShareFromUser(string recordUid, string username);

        Task<RecordHistory[]> GetRecordHistory(string recordUid);
    }

    /// <summary>
    /// Defines properties of Secrets Manager configuration
    /// </summary>
    public interface ISecretManagerConfiguration
    {
        /// <summary>
        /// Keeper Hostname
        /// </summary>
        string Hostname { get; }

        /// <summary>
        /// Client or Device ID
        /// </summary>
        string ClientId { get; }

        /// <summary>
        /// Device Private Key
        /// </summary>
        string PrivateKey { get; }

        /// <summary>
        /// Application Key
        /// </summary>
        string AppKey { get; }

        /// <exclude />
        string ServerPublicKeyId { get; }

        /// <summary>
        /// Public Key for record creation
        /// </summary>
        string AppOwnerPublicKey { get; }
    }

    /// <summary>
    /// Define methods for Keeper Secret Maneger (KSM)
    /// </summary>
    public interface ISecretManager
    {
        /// <summary>
        /// Gets Keeper Secret Manager Application Details
        /// </summary>
        /// <param name="applicationUid">Application UID.</param>
        /// <param name="force">Force reloading</param>
        /// <returns>Secret Manager Application Info</returns>
        Task<SecretsManagerApplication> GetSecretManagerApplication(string applicationUid, bool force = true);

        /// <summary>
        /// Creates Secret Manager Application
        /// </summary>
        /// <param name="title">Application Title</param>
        /// <returns>Application Record</returns>
        Task<ApplicationRecord> CreateSecretManagerApplication(string title);

        /// <summary>
        /// Deletes Secret Manager Application
        /// </summary>
        /// <param name="applicationId"></param>
        /// <returns>Awaitable Task</returns>
        Task DeleteSecretManagerApplication(string applicationId);


        /// <summary>
        /// Grants Shared Folder or Record Access to Secret Manager Application
        /// </summary>
        /// <param name="applicationId">Application ID</param>
        /// <param name="sharedFolderOrRecordUid">Shared Folder or Record UID</param>
        /// <param name="canEdit">permission to edit</param>
        /// <returns>Secret Manager Application</returns>
        Task<SecretsManagerApplication> ShareToSecretManagerApplication(string applicationId,
            string sharedFolderOrRecordUid, bool canEdit);

        /// <summary>
        /// Revokes Shared Folder or Record access from Secret Manager Application
        /// </summary>
        /// <param name="applicationId">Application ID</param>
        /// <param name="sharedFolderOrRecordUid">Shared Folder or Record UID</param>
        /// <returns>Secret Manager Application</returns>
        Task<SecretsManagerApplication> UnshareFromSecretManagerApplication(string applicationId,
            string sharedFolderOrRecordUid);

        /// <summary>
        /// Adds a client/device to Secret Manager Application
        /// </summary>
        /// <param name="applicationId">Application ID</param>
        /// <param name="unlockIp">Optional. If false the first call from the client locks IP. If true no IP locking</param>
        /// <param name="firstAccessExpireInMinutes">Optional. First access duration in minutes. Default: an hour (60). Maximum: a day (1440) </param>
        /// <param name="accessExpiresInMinutes">Optional. Access Expiration duration in minutes.</param>
        /// <param name="name">Optional. Client/Device name</param>
        /// <returns>Tuple: Client Device, Client Key</returns>
        Task<Tuple<SecretsManagerDevice, string>> AddSecretManagerClient(
            string applicationId, bool? unlockIp = null, int? firstAccessExpireInMinutes = null,
            int? accessExpiresInMinutes = null, string name = null);

        /// <summary>
        /// Creates SecretsManager Configuration Storage
        /// </summary>
        /// <param name="oneTimeToken">One time token</param>
        /// <returns>Configuration Storage</returns>
        Task<ISecretManagerConfiguration> GetConfiguration(string oneTimeToken);

        /// <summary>
        /// Deletes a client/device from Secret Manager Application
        /// </summary>
        /// <param name="applicationId">Application ID</param>
        /// <param name="deviceId">Device ID or Name</param>
        /// <returns>Awaitable Task</returns>
        Task DeleteSecretManagerClient(string applicationId, string deviceId);

    }

    /// <summary>
    /// Defines methods to manipulate Shared Folders.
    /// </summary>
    /// <seealso cref="VaultOnline"/>
    public interface IVaultSharedFolder
    {
        /// <summary>
        /// Adds (if needed) user or team to the shared folder and set user access permissions.
        /// </summary>
        /// <param name="sharedFolderUid">Shared Folder UID.</param>
        /// <param name="userId">User email or Team UID.</param>
        /// <param name="userType">Type of userId parameter.</param>
        /// <param name="options">Shared Folder User Permissions.</param>
        /// <returns>Awaitable task.</returns>
        /// <remarks>
        /// If <c>options</c>c> parameter is <c>null</c> then user gets default user permissions when added./>
        /// </remarks>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        /// <exception cref="NoActiveShareWithUserException" />
        /// <seealso cref="SharedFolderUserOptions"/>
        Task PutUserToSharedFolder(string sharedFolderUid, string userId, UserType userType,
            IUserShareOptions options = null);

        /// <summary>
        /// Removes user or team from shared folder.
        /// </summary>
        /// <param name="sharedFolderUid">Shared Folder UID.</param>
        /// <param name="userId">User email or Team UID.</param>
        /// <param name="userType">Type of userId parameter.</param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task RemoveUserFromSharedFolder(string sharedFolderUid, string userId, UserType userType);

        /// <summary>
        /// Changes record permissions in shared folder.
        /// </summary>
        /// <param name="sharedFolderUid">Shared Folder UID.</param>
        /// <param name="recordUid">Record UID.</param>
        /// <param name="options">Record permissions.</param>
        /// <returns></returns>
        /// <remarks>
        /// This method does not add a record to shared folder.
        /// Use <see cref="IVault.CreateRecord"/> or <see cref="IVault.MoveRecords"/>.
        /// </remarks>
        /// <seealso cref="SharedFolderRecordOptions"/>
        Task ChangeRecordInSharedFolder(string sharedFolderUid, string recordUid, IRecordShareOptions options);
    }

    /// <summary>
    /// Defines properties of thumbnail upload task.
    /// </summary>
    public interface IThumbnailUploadTask
    {
        /// <summary>
        /// Thumbnail MIME type.
        /// </summary>
        string MimeType { get; }

        /// <summary>
        /// Thumbnail size in pixels.
        /// </summary>
        int Size { get; }

        /// <summary>
        /// Thumbnail read stream.
        /// </summary>
        Stream Stream { get; }
    }

    /// <summary>
    /// Defines properties of file upload task.
    /// </summary>
    public interface IAttachmentUploadTask
    {
        /// <summary>
        /// Attachment name.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Attachment title.
        /// </summary>
        string Title { get; }

        /// <summary>
        /// Attachment MIME type.
        /// </summary>
        string MimeType { get; }

        /// <summary>
        /// Attachment read stream.
        /// </summary>
        Stream Stream { get; }

        /// <summary>
        /// Thumbnail upload task. Optional.
        /// </summary>
        IThumbnailUploadTask Thumbnail { get; }
    }

    /// <summary>
    /// Defines methods to manipulate file attachments.
    /// </summary>
    public interface IVaultFileAttachment
    {
        /// <summary>
        /// Returns Record attachments
        /// </summary>
        /// <param name="record">Keeper record</param>
        /// <returns>List od attachments</returns>
        IEnumerable<IAttachment> RecordAttachments(KeeperRecord record);

        /// <summary>
        /// Downloads and decrypts file attachment.
        /// </summary>
        /// <param name="record">Keeper record.</param>
        /// <param name="attachment">Attachment name, title, or ID.</param>
        /// <param name="destination">Writable stream.</param>
        /// <returns>Awaitable task.</returns>
        Task DownloadAttachment(KeeperRecord record, string attachment, Stream destination);

        /// <summary>
        /// Encrypts and uploads file attachment.
        /// </summary>
        /// <param name="record">Keeper record</param>
        /// <param name="uploadTask">Upload task</param>
        /// <returns>Awaitable task.</returns>
        Task UploadAttachment(KeeperRecord record, IAttachmentUploadTask uploadTask);

        /// <summary>
        /// Deletes file attachment.
        /// </summary>
        /// <param name="record">Keeper record.</param>
        /// <param name="attachmentId">Attachment ID</param>
        /// <returns>Awaitable task.</returns>
        Task<bool> DeleteAttachment(KeeperRecord record, string attachmentId);
    }

    /// <summary>
    /// The exception that is thrown by the Vault module.
    /// </summary>
    public class VaultException : Exception
    {
        /// <exclude/>
        public VaultException(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// Represents generic Keeper Record
    /// </summary>
    public abstract class KeeperRecord
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        public string Uid { get; set; }

        /// <summary>
        /// Record version
        /// </summary>
        public int Version { get; set; }

        /// <summary>
        /// Record revision
        /// </summary>
        public long Revision { get; set; }

        /// <summary>
        /// Title.
        /// </summary>
        public string Title { get; set; }

        /// <summary>
        /// Last modification time.
        /// </summary>
        public DateTimeOffset ClientModified { get; internal set; }

        /// <summary>
        /// Is user Owner?
        /// </summary>
        public bool Owner { get; set; }

        /// <summary>
        /// Is record Shared?
        /// </summary>
        public bool Shared { get; set; }

        /// <summary>
        /// Record key.
        /// </summary>
        public byte[] RecordKey { get; set; }
    }

    /// <exclude />
    public interface ICustomField
    {
        string Type { get; }
        string Name { get; }
        string Value { get; set; }
    }

    /// <summary>
    /// Defines properties for typed record field
    /// </summary>
    public interface ITypedField : IRecordTypeField
    {
        /// <summary>
        /// Gets or sets the first field value
        /// </summary>
        object ObjectValue { get; set; }

        /// <summary>
        /// Gets default field value.
        /// </summary>
        /// <returns></returns>
        object AppendValue();

        /// <summary>
        /// Deletes value at index.
        /// </summary>
        /// <param name="index">Index</param>
        void DeleteValueAt(int index);

        /// <summary>
        /// Gets value at index
        /// </summary>
        /// <param name="index">Index</param>
        /// <returns></returns>
        object GetValueAt(int index);

        /// <summary>
        /// Sets value at index.
        /// </summary>
        /// <param name="index">Index</param>
        /// <param name="value">Value</param>
        void SetValueAt(int index, object value);

        /// <summary>
        /// Gets the number of values
        /// </summary>
        int Count { get; }

        /// <summary>
        /// Gets required flag
        /// </summary>
        bool Required { get; set; }
    }

    /// <summary>
    /// Represents a Typed Record 
    /// </summary>
    /// <seealso cref="ITypedField"/>
    public class TypedRecord : KeeperRecord
    {
        /// <summary>
        /// Record notes
        /// </summary>
        public string Notes { get; set; }

        /// <summary>
        /// Record type name.
        /// </summary>
        public string TypeName { get; set; }

        /// <exclude/>
        public TypedRecord(string typeName)
        {
            TypeName = typeName;
        }

        /// <summary>
        /// Record mandatory fields.
        /// </summary>
        public List<ITypedField> Fields { get; } = new();

        /// <summary>
        /// Record custom data.
        /// </summary>
        public List<ITypedField> Custom { get; } = new();

        internal Dictionary<string, byte[]> LinkedKeys;
    }

    internal interface IToRecordTypeDataField
    {
        RecordTypeDataFieldBase ToRecordTypeDataField();
    }

    /// <exclude />
    public class UnsupportedField : ITypedField, IToRecordTypeDataField
    {
        private readonly RecordTypeDataFieldBase _dataField;

        internal UnsupportedField(RecordTypeDataFieldBase dataField)
        {
            _dataField = dataField;
            Required = dataField.Required;
        }

        RecordTypeDataFieldBase IToRecordTypeDataField.ToRecordTypeDataField()
        {
            return _dataField;
        }

        object ITypedField.ObjectValue
        {
            get => null;
            set { }
        }

        object ITypedField.AppendValue()
        {
            return null;
        }

        object ITypedField.GetValueAt(int index)
        {
            return null;
        }

        void ITypedField.SetValueAt(int index, object value)
        {
        }

        void ITypedField.DeleteValueAt(int index)
        {
        }

        int ITypedField.Count => 0;

        string IRecordTypeField.FieldName => _dataField.Type;
        string IRecordTypeField.FieldLabel => _dataField.Label;

        public bool Required { get; set; }
    }

    /// <summary>
    /// Defines methods for typed field serialization
    /// </summary>
    public interface ISerializeTypedField
    {
        /// <summary>
        /// Imports the content of typed field from text
        /// </summary>
        /// <param name="text">external field representation</param>
        void ImportTypedField(string text);

        /// <summary>
        /// Exports typed field to text
        /// </summary>
        /// <returns>external field representation</returns>
        string ExportTypedField();
    }



    /// <summary>
    /// Represents a typed field.
    /// </summary>
    /// <typeparam name="T">Field Data Type</typeparam>
    public class TypedField<T> : ITypedField, IToRecordTypeDataField, ISerializeTypedField
    {
        internal TypedField(RecordTypeDataField<T> dataField)
        {
            FieldName = dataField.Type;
            FieldLabel = dataField.Label;
            if (dataField.Value != null)
            {
                Values.AddRange(dataField.Value);
            }
        }

        /// <exclude/>
        public TypedField() : this("")
        {
        }

        /// <exclude/>
        public TypedField(string fieldType, string fieldLabel = null)
        {
            FieldName = string.IsNullOrEmpty(fieldType) ? "text" : fieldType;
            FieldLabel = fieldLabel ?? "";
        }

        /// <summary>
        /// Field type name.
        /// </summary>
        public string FieldName { get; }

        /// <summary>
        /// Field Label.
        /// </summary>
        public string FieldLabel { get; set; }

        /// <summary>
        /// Field values.
        /// </summary>
        public List<T> Values { get; } = new();

        /// <inheritdoc />
        public bool Required { get; set; }

        public T AppendTypedValue()
        {
            switch (Values)
            {
                case List<string> ls:
                    ls.Add("");
                    break;
                case List<long> ll:
                    ll.Add(0);
                    break;
                case List<bool> lf:
                    lf.Add(false);
                    break;
                default:
                    Values.Add((T) Activator.CreateInstance(typeof(T)));
                    break;
            }

            return Values.Last();
        }

        /// <summary>
        /// Default field value.
        /// </summary>
        public T TypedValue
        {
            get
            {
                if (Values.Count == 0)
                {
                    return AppendTypedValue();
                }

                return Values[0];
            }
            set
            {
                if (Values.Count == 0)
                {
                    Values.Add(value);
                }
                else
                {
                    Values[0] = value;
                }
            }
        }

        /// <exclude />
        public object ObjectValue
        {
            get => TypedValue;
            set
            {
                if (value is T tv)
                {
                    TypedValue = tv;
                }
                else if (value is string sv)
                {
                    var o = (object) TypedValue;
                    if (o is IFieldTypeSerialize fts)
                    {
                        fts.SetValueAsString(sv);
                    }
                    else
                    {
                        if (o is long)
                        {
                            if (sv.All(char.IsDigit))
                            {
                                o = long.Parse(sv);
                            }
                            else if (FieldName == "date")
                            {
                                var dt = DateTimeOffset.Parse(sv);
                                o = dt.ToUnixTimeMilliseconds();
                            }
                        }
                        else if (o is bool)
                        {
                            o = new[] { "1", "on", "true" }.Any(y =>
                                string.Equals(y, sv, StringComparison.InvariantCultureIgnoreCase));
                        }

                        TypedValue = (T) o;
                    }
                }
                else if (value is IDictionary dv)
                {
                    var o = TypedValue;
                    if (o is IFieldTypeSerialize fts)
                    {
                        foreach (var key in dv.Keys)
                        {
                            var fv = dv[key];
                            if (key is string skey && fv is string sfv)
                            {
                                fts.SetElementValue(skey, sfv);
                            }
                        }
                    }

                    TypedValue = o;
                }
                else
                {
                    TypedValue = (T) value;
                }
            }
        }

        /// <summary>
        /// Gets field value at index
        /// </summary>
        /// <param name="index">value index</param>
        /// <returns></returns>
        public object GetValueAt(int index)
        {
            if (index >= 0 && index < Values.Count)
            {
                return Values[index];
            }

            return default(T);
        }

        /// <summary>
        /// Deletes field value at index
        /// </summary>
        /// <param name="index">Value index</param>
        public void DeleteValueAt(int index)
        {
            if (index >= 0 && index < Values.Count)
            {
                Values.RemoveAt(index);
            }
        }

        /// <summary>
        /// Sets field value at index
        /// </summary>
        /// <param name="index">Value index</param>
        /// <param name="value">Value</param>
        public void SetValueAt(int index, object value)
        {
            if (index >= 0 && index < Values.Count)
            {
                if (value is T tv)
                {
                    Values[index] = tv;
                }
            }
        }

        /// <summary>
        /// Value Count
        /// </summary>
        public int Count => Values.Count;

        RecordTypeDataFieldBase IToRecordTypeDataField.ToRecordTypeDataField()
        {
            return new RecordTypeDataField<T>(this);
        }

        /// <summary>
        /// Appends a value.
        /// </summary>
        /// <returns>Default value</returns>
        object ITypedField.AppendValue()
        {
            return AppendTypedValue();
        }

        void ISerializeTypedField.ImportTypedField(string text)
        {
            Values.Clear();
            if (string.IsNullOrEmpty(text))
            {
                return;
            }

            switch (Values)
            {
                case List<string> ls:
                    ls.AddRange(text.Split('\n').Select(x => x.Replace("\\n", "\n").Trim()));
                    break;
                case List<long> ll:
                {
                    ll.AddRange(text.Split('\n').Select(x => x.Trim()).Select(x =>
                    {
                        if (x.All(char.IsDigit))
                        {
                            return long.Parse(x);
                        }
                        else if (FieldName == "date")
                        {
                            var dt = DateTimeOffset.Parse(x);
                            return dt.ToUnixTimeMilliseconds();
                        }

                        return 0;
                    }).Where(x => x > 0));
                }
                break;
                case List<bool> lb:
                    lb.AddRange(text.Split('\n').Select(x =>
                    {
                        return (new[] { "1", "on", "true" }).Any(y =>
                            string.Equals(y, "on", StringComparison.InvariantCultureIgnoreCase));
                    }));
                    break;

                default:
                    if (typeof(IFieldTypeSerialize).IsAssignableFrom(typeof(T)))
                    {
                        Values.AddRange(text.Split('\n').Select(x =>
                        {
                            var v = Activator.CreateInstance<T>();
                            ((IFieldTypeSerialize) v).SetValueAsString(x);
                            return v;
                        }));
                    }
                    else
                    {
                        throw new Exception($"Field type {typeof(T).Name} does not support serialization.");
                    }

                    break;
            }
        }

        string ISerializeTypedField.ExportTypedField()
        {
            if (Values.Count == 0)
            {
                return "";
            }

            switch (Values)
            {
                case List<string> ls:
                    return string.Join("\n",
                        ls.Where(x => !string.IsNullOrEmpty(x)).Select(x => x.Replace("\n", "\\n")));

                case List<long> ll:
                {
                    return string.Join("\n", ll.Where(x => x > 0).Select(x =>
                    {
                        if (FieldName == "date")
                        {
                            var dt = DateTimeOffsetExtensions.FromUnixTimeMilliseconds(x).Date;
                            return dt.ToString("yyyy-MM-dd");
                        }
                        else
                        {
                            return x.ToString();
                        }
                    }));
                }
                case List<bool> lb:
                    return string.Join("\n", lb.Select(x => x ? "1" : "0"));

                default:
                    if (typeof(IFieldTypeSerialize).IsAssignableFrom(typeof(T)))
                    {
                        return string.Join("\n",
                            Values.OfType<IFieldTypeSerialize>().Select(x => x.GetValueAsString())
                                .Where(x => !string.IsNullOrEmpty(x)));
                    }
                    else
                    {
                        throw new Exception($"Field type {typeof(T).Name} does not support serialization.");
                    }
            }
        }
    }

    /// <summary>
    /// Represents a Legacy Keeper Record.
    /// </summary>
    public class PasswordRecord : KeeperRecord
    {
        /// <summary>
        /// Notes.
        /// </summary>
        public string Notes { get; set; }

        /// <summary>
        /// Login or Username.
        /// </summary>
        public string Login { get; set; }

        /// <summary>
        /// Password.
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Web URL.
        /// </summary>
        public string Link { get; set; }

        /// <summary>
        /// TOTP URL.
        /// </summary>
        public string Totp { get; set; }

        /// <summary>
        /// A list of Custom Fields.
        /// </summary>
        public IList<CustomField> Custom { get; } = new List<CustomField>();

        /// <summary>
        /// A list of Attachments.
        /// </summary>
        public IList<AttachmentFile> Attachments { get; } = new List<AttachmentFile>();

        /// <summary>
        /// Gets a custom field.
        /// </summary>
        /// <param name="name">Custom field Name.</param>
        /// <returns>Returns custom field or <c>null</c> is it was not found.</returns>
        public ICustomField GetCustomField(string name)
        {
            return Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
        }

        /// <summary>
        /// Deletes a custom field.
        /// </summary>
        /// <param name="name">Custom field Name.</param>
        /// <returns>Deleted custom field or <c>null</c> is it was not found.</returns>
        public ICustomField DeleteCustomField(string name)
        {
            var cf = Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
            if (cf != null)
            {
                if (Custom.Remove(cf))
                {
                    return cf;
                }
            }

            return null;
        }

        /// <summary>
        /// Adds or Changes custom field.
        /// </summary>
        /// <param name="name">Name.</param>
        /// <param name="value">Value.</param>
        /// <returns>Added or modified custom field.</returns>
        public ICustomField SetCustomField(string name, string value)
        {
            var cf = Custom.FirstOrDefault(x => string.Equals(name, x.Name, StringComparison.CurrentCultureIgnoreCase));
            if (cf == null)
            {
                cf = new CustomField
                {
                    Name = name
                };
                Custom.Add(cf);
            }

            cf.Value = value ?? "";
            return cf;
        }
    }

    /// <summary>
    /// Represents a custom field.
    /// </summary>
    public class CustomField : ICustomField
    {
        /// <summary>
        /// Custom field name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Custom field value.
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Custom field type.
        /// </summary>
        public string Type { get; set; }
    }

    /// <summary>
    /// Represents an extra field.
    /// </summary>
    public class ExtraField
    {
        /// <summary>
        /// Extra field ID.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Extra field type.
        /// </summary>
        public string FieldType { get; set; }

        /// <summary>
        /// Extra field title.
        /// </summary>
        public string FieldTitle { get; set; }

        /// <summary>
        /// Additional extra field values.
        /// </summary>
        public Dictionary<string, object> Custom { get; } = new();
    }

    /// <summary>
    /// Represents a thumbnail of attachment.
    /// </summary>
    /// <remarks>It usually is used for large image thumbnails.</remarks>
    public class AttachmentFileThumb
    {
        /// <summary>
        /// Thumbnail ID.
        /// </summary>
        public string Id { get; internal set; }

        /// <summary>
        /// Thumbnail MIME type.
        /// </summary>
        public string Type { get; internal set; }

        /// <summary>
        /// Thumbnail size. pixels.
        /// </summary>
        public int Size { get; internal set; }
    }

    /// <summary>
    /// Defines property for file attachment
    /// </summary>
    public interface IAttachment
    {
        /// <summary>
        /// Attachment ID.
        /// </summary>
        string Id { get; }

        /// <summary>
        /// Attachment name.
        /// </summary>
        /// <remarks>Usually it is an original file name.</remarks>
        string Name { get; }

        /// <summary>
        /// Attachment title.
        /// </summary>
        string Title { get; }

        /// <summary>
        /// Attachment MIME type.
        /// </summary>
        string MimeType { get; }

        /// <summary>
        /// Attachment size in bytes.
        /// </summary>
        long Size { get; }

        /// <summary>
        /// Last time modified.
        /// </summary>
        DateTimeOffset LastModified { get; }

        /// <summary>
        /// Attachment encryption key.
        /// </summary>
        byte[] AttachmentKey { get; }
    }

    /// <summary>
    /// Represents attachment file.
    /// </summary>
    public class AttachmentFile : IAttachment
    {
        /// <summary>
        /// Attachment ID.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Attachment encryption key.
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Attachment name.
        /// </summary>
        /// <remarks>Usually it is an original file name.</remarks>
        public string Name { get; set; }

        /// <summary>
        /// Attachment title.
        /// </summary>
        public string Title { get; set; }

        /// <summary>
        /// Attachment MIME type.
        /// </summary>
        public string MimeType { get; set; }

        /// <summary>
        /// Attachment size in bytes.
        /// </summary>
        public long Size { get; set; }

        /// <summary>
        /// Last time modified.
        /// </summary>
        public DateTimeOffset LastModified { get; set; }

        /// <summary>
        /// A list of thumbnails.
        /// </summary>
        public AttachmentFileThumb[] Thumbnails { get; internal set; }

        byte[] IAttachment.AttachmentKey => string.IsNullOrEmpty(Key) ? null : Key.Base64UrlDecode();
    }

    /// <summary>
    /// Represents a Keeper File Record.
    /// </summary>
    public class FileRecord : KeeperRecord, IAttachment
    {
        /// <summary>
        /// File Name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// File MIME type.
        /// </summary>
        public string MimeType { get; set; }

        /// <summary>
        /// File size in bytes.
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// File size in bytes.
        /// </summary>
        public long ThumbnailSize { get; set; }

        /// <summary>
        /// Last time modified.
        /// </summary>
        public DateTimeOffset LastModified { get; set; }

        /// <summary>
        /// On storage file size in bytes.
        /// </summary>
        public long? StorageFileSize { get; internal set; }

        /// <summary>
        /// On storage thumbnail size in bytes.
        /// </summary>
        public long? StorageThumbnailSize { get; internal set; }

        string IAttachment.Id => Uid;
        long IAttachment.Size => FileSize;
        byte[] IAttachment.AttachmentKey => RecordKey;
    }

    /// <summary>
    /// Represents a Keeper Secret Manager Application Record.
    /// </summary>
    public class ApplicationRecord : KeeperRecord
    {
        /// <summary>
        /// Application Type.
        /// </summary>
        public string Type { get; set; }
    }

    /// <exclude/>
    public class SecretsManagerDevice
    {
        public string Name { get; internal set; }
        public string DeviceId { get; internal set; }
        public DateTimeOffset CreatedOn { get; internal set; }
        public DateTimeOffset? FirstAccess { get; internal set; }
        public DateTimeOffset? LastAccess { get; internal set; }
        public byte[] PublicKey { get; internal set; }
        public bool LockIp { get; internal set; }
        public string IpAddress { get; internal set; }
        public DateTimeOffset? FirstAccessExpireOn { get; internal set; }
        public DateTimeOffset? AccessExpireOn { get; internal set; }
    }

    /// <exclude/>
    public enum SecretManagerSecretType
    {
        Record = 0,
        Folder = 1,
    }

    /// <exclude/>
    public class SecretManagerShare
    {
        public string SecretUid { get; internal set; }
        public SecretManagerSecretType SecretType { get; internal set; }
        public bool Editable { get; internal set; }
        public DateTimeOffset CreatedOn { get; internal set; }
    }

    /// <exclude/>
    public class SecretsManagerApplication : ApplicationRecord
    {
        public SecretsManagerDevice[] Devices { get; internal set; }
        public SecretManagerShare[] Shares { get; internal set; }
        public bool IsExternalShare { get; internal set; }
    }

    /// <summary>
    /// Represents record permissions for user.
    /// </summary>
    public class UserRecordPermissions
    {
        /// <summary>
        /// Keeper username.
        /// </summary>
        public string Username { get; internal set; }

        /// <summary>
        /// Flag indicating if the user has share permissions.
        /// </summary>
        public bool CanShare { get; internal set; }

        /// <summary>
        /// Flag indicating if the user has rights to edit the record
        /// </summary>
        public bool CanEdit { get; internal set; }

        /// <summary>
        /// Flag indicating if the user is record owner.
        /// </summary>
        public bool Owner { get; internal set; }

        /// <summary>
        /// Flag indicating if the user has pending invitation.
        /// </summary>
        public bool AwaitingApproval { get; internal set; }

        /// <summary>
        /// Share expiration time.
        /// </summary>
        public DateTimeOffset? Expiration { get; internal set; }
    }

    /// <summary>
    /// Represents record permissions in shared folder.
    /// </summary>
    public class SharedFolderRecordPermissions
    {
        /// <summary>
        /// Shared Folder UID.
        /// </summary>
        public string SharedFolderUid { get; internal set; }

        /// <summary>
        /// Flag indicating if the shared folder has share permissions.
        /// </summary>
        public bool CanShare { get; internal set; }

        /// <summary>
        /// Flag indicating if the shared folder has rights to edit the record
        /// </summary>
        public bool CanEdit { get; internal set; }

        /// <summary>
        /// Share expiration time.
        /// </summary>
        public DateTimeOffset? Expiration { get; internal set; }
    }

    /// <summary>
    /// Represent record sharing information
    /// </summary>
    public class RecordSharePermissions
    {
        /// <summary>
        /// Record UID
        /// </summary>
        public string RecordUid { get; internal set; }

        /// <summary>
        /// List of direct record share permissions
        /// </summary>
        public UserRecordPermissions[] UserPermissions { get; internal set; }

        /// <summary>
        /// List of shared folder permissions
        /// </summary>
        public SharedFolderRecordPermissions[] SharedFolderPermissions { get; internal set; }
    }

    /// <summary>
    /// Represent user list available for sharing
    /// </summary>
    public class ShareWithUsers
    {
        /// <summary>
        /// Array of users shared from
        /// </summary>
        public string[] SharesFrom { get; internal set; }

        /// <summary>
        /// Array of users shared to
        /// </summary>
        public string[] SharesWith { get; internal set; }

        /// <summary>
        /// Array of users in the enterprise
        /// </summary>
        public string[] GroupUsers { get; internal set; }
    }

    /// <summary>
    /// Specifies shared folder user type.
    /// </summary>
    public enum UserType
    {
        /// <summary>
        /// Regular user.
        /// </summary>
        User = 1,

        /// <summary>
        /// Enterprise Team.
        /// </summary>
        Team = 2
    }

    /// <summary>
    /// Represents shared folder user permissions.
    /// </summary>
    public class SharedFolderPermission
    {
        /// <summary>
        /// AccountUid or TeamUid.
        /// </summary>
        public string Uid { get; internal set; }

        /// <summary>
        /// Email or Team Name.
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// The type of <see cref="Uid"/> property.
        /// </summary>
        public UserType UserType { get; internal set; }

        /// <summary>
        /// Can Manage Records?
        /// </summary>
        public bool ManageRecords { get; internal set; }

        /// <summary>
        /// Can Manage Users?
        /// </summary>
        public bool ManageUsers { get; internal set; }

        /// <summary>
        /// Share expiration time.
        /// </summary>
        public DateTimeOffset? Expiration { get; internal set; }
    }

    /// <summary>
    /// Represents shared folder record permissions.
    /// </summary>
    public class SharedFolderRecord
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        public string RecordUid { get; internal set; }

        /// <summary>
        /// Can be re-shared?
        /// </summary>
        public bool CanShare { get; internal set; }

        /// <summary>
        /// Can be edited?
        /// </summary>
        public bool CanEdit { get; internal set; }

        /// <summary>
        /// Share expiration time.
        /// </summary>
        public DateTimeOffset? Expiration { get; internal set; }
    }

    /// <summary>
    /// Represents Shared Folder.
    /// </summary>
    public class SharedFolder
    {
        /// <summary>
        /// Shared folder UID.
        /// </summary>
        public string Uid { get; set; }

        /// <summary>
        /// Shared folder name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Default manage records permission.
        /// </summary>
        public bool DefaultManageRecords { get; set; }

        /// <summary>
        /// Default manage users permission.
        /// </summary>
        public bool DefaultManageUsers { get; set; }

        /// <summary>
        /// Default record can be re-shared permission.
        /// </summary>
        public bool DefaultCanEdit { get; set; }

        /// <summary>
        /// Default record can be edited permission.
        /// </summary>
        public bool DefaultCanShare { get; set; }

        /// <summary>
        /// A list of user permissions.
        /// </summary>
        public List<SharedFolderPermission> UsersPermissions { get; } = new();

        /// <summary>
        /// A list of record permissions.
        /// </summary>
        public List<SharedFolderRecord> RecordPermissions { get; } = new();

        /// <summary>
        /// Shared Folder key.
        /// </summary>
        public byte[] SharedFolderKey { get; set; }
    }

    /// <summary>
    /// Represents basic team properties.
    /// </summary>
    public class TeamInfo
    {
        /// <summary>
        /// Team UID.
        /// </summary>
        public string TeamUid { get; set; }

        /// <summary>
        /// Team Name.
        /// </summary>
        public string Name { get; set; }
    }

    /// <summary>
    /// Represents team properties that user is member of.
    /// </summary>
    public class Team : TeamInfo
    {
        /// <summary>
        /// Team restricts record edit.
        /// </summary>
        public bool RestrictEdit { get; set; }

        /// <summary>
        /// Team restricts record re-share.
        /// </summary>
        public bool RestrictShare { get; set; }

        /// <summary>
        /// Team restricts record view.
        /// </summary>
        public bool RestrictView { get; set; }

        /// <summary>
        /// Team key.
        /// </summary>
        public byte[] TeamKey { get; set; }

        /// <summary>
        /// Team RSA private key.
        /// </summary>
        public RsaPrivateKey TeamRsaPrivateKey { get; internal set; }

        /// <summary>
        /// Team EC private key.
        /// </summary>
        public EcPrivateKey TeamEcPrivateKey { get; internal set; }
    }

    /// <summary>
    /// Specifies folder types.
    /// </summary>
    public enum FolderType
    {
        /// <summary>
        /// User folder.
        /// </summary>
        UserFolder,

        /// <summary>
        /// Shared folder.
        /// </summary>
        SharedFolder,

        /// <summary>
        /// Subfolder of shared folder.
        /// </summary>
        /// <remarks><see cref="SharedFolderFolder"/> inherits user and record permissions from the parent shared folder.</remarks>
        SharedFolderFolder
    }

    /// <summary>
    /// Represents folder.
    /// </summary>
    public class FolderNode
    {
        /// <summary>
        /// Folder UID.
        /// </summary>
        public string FolderUid { get; internal set; }

        /// <summary>
        /// Parent folder UID.
        /// </summary>
        public string ParentUid { get; internal set; }

        /// <summary>
        /// Shared Folder UID. 
        /// </summary>
        /// <remarks>Populated for <c>SharedFolderFolder</c> <see cref="FolderType"/></remarks>
        public string SharedFolderUid { get; internal set; }

        /// <summary>
        /// Folder type.
        /// </summary>
        public FolderType FolderType { get; internal set; } = FolderType.UserFolder;

        /// <summary>
        /// Folder name.
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        /// A UID list of subfolders
        /// </summary>
        public IList<string> Subfolders { get; } = new List<string>();

        /// <summary>
        /// A UID list of records.
        /// </summary>
        public IList<string> Records { get; } = new List<string>();

        /// <summary>
        /// Folder key
        /// </summary>
        public byte[] FolderKey { get; internal set; }
    }

    /// <summary>
    /// Defines record access path properties.
    /// </summary>
    /// <remarks>
    /// Access to the record can be granted through:
    /// <list type="number">
    /// <item><description>Record is owned by user.</description></item>
    /// <item><description>Record is directly shared with user.</description></item>
    /// <item><description>Record is added to shared folder and user is a member of that shared folder.</description></item>
    /// <item><description>Record is added to shared folder and user is a member of team that is added that shared folder.</description></item>
    /// </list>
    /// </remarks>
    public interface IRecordAccessPath
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        string RecordUid { get; }

        /// <summary>
        /// Shared Folder UID.
        /// </summary>
        string SharedFolderUid { get; set; }

        /// <summary>
        /// Team UID.
        /// </summary>
        string TeamUid { get; set; }
    }

    /// <summary>
    /// Defines shared folder access path properties.
    /// </summary>
    /// <remarks>
    /// Access to the shared folder can be granted through:
    /// <list type="number">
    /// <item><description>User is member of shared folder.</description></item>
    /// <item><description>User is member of team that is member of shared folder.</description></item>
    /// </list>
    /// </remarks>
    public interface ISharedFolderAccessPath
    {
        /// <summary>
        /// Shared Folder UID.
        /// </summary>
        string SharedFolderUid { get; set; }

        /// <summary>
        /// Team UID.
        /// </summary>
        string TeamUid { get; set; }
    }

    internal static class VaultTypeExtensions
    {
        private static readonly IDictionary<FolderType, string> FolderTypes = new Dictionary<FolderType, string>
        {
            { FolderType.UserFolder, "user_folder" },
            { FolderType.SharedFolder, "shared_folder" },
            { FolderType.SharedFolderFolder, "shared_folder_folder" },
        };

        public static string GetFolderTypeText(this FolderType folderType)
        {
            return FolderTypes[folderType];
        }
    }

    [DataContract]
    public class FolderData
    {
        [DataMember(Name = "name")] public string name;
    }
    
    public class RecordShareOptions : IRecordShareOptions
    {
        public bool CanEdit { get; set; }
        public bool CanShare { get; set; }
        public DateTimeOffset? Expiration { get; set; }

        bool? IRecordShareOptions.CanEdit => CanEdit;

        bool? IRecordShareOptions.CanShare => CanShare;

        DateTimeOffset? IRecordShareOptions.Expiration => Expiration;

        public RecordShareOptions(bool canEdit, bool canShare, DateTimeOffset? expiration)
        {
            CanEdit = canEdit;
            CanShare = canShare;
            Expiration = expiration;
        }
    }
}
