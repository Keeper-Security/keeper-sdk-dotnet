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

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

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
        IEnumerable<PasswordRecord> Records { get; }
        /// <summary>
        /// Gets the record associated with the specified record UID.
        /// </summary>
        /// <param name="recordUid">Record UID.</param>
        /// <param name="record">When this method returns <c>true</c>, contains requested record; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the vault contains a record with specified UID; otherwise, <c>false</c></returns>
        bool TryGetRecord(string recordUid, out PasswordRecord record);

        /// <summary>
        /// Gets the number of all shared folders in the vault.
        /// </summary>
        int SharedFolderCount { get; }
        /// <summary>
        /// Get the list of all shared folders in the vault.
        /// </summary>
        IEnumerable<SharedFolder> SharedFolders { get; }
        /// <summary>
        /// Gets the shared folder associated with the specified record UID.
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
        /// Get the list of all teams user is member of.
        /// </summary>
        IEnumerable<Team> Teams { get; }
        /// <summary>
        /// Gets the team associated with the specified team UID.
        /// </summary>
        /// <param name="teamUid">Team UID.</param>
        /// <param name="team">When this method returns <c>true</c>, contains requested team; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the vault contains a team with specified UID; otherwise, <c>false</c>.</returns>
        bool TryGetTeam(string teamUid, out Team team);
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
    public interface ISharedFolderRecordOptions
    {
        /// <summary>
        /// Record can be edited.
        /// </summary>
        bool? CanEdit { get; }
        /// <summary>
        /// Record can be re-shared.
        /// </summary>
        bool? CanShare { get; }
    }

    /// <summary>
    /// Defines shared folder user permissions.
    /// </summary>
    public interface ISharedFolderUserOptions
    {
        /// <summary>
        /// User can manage other users.
        /// </summary>
        bool? ManageUsers { get; }
        /// <summary>
        /// User can manage records.
        /// </summary>
        bool? ManageRecords { get; }
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
        /// Creates a password record.
        /// </summary>
        /// <param name="record">Password Record.</param>
        /// <param name="folderUid">Folder UID where the record to be created. Optional.</param>
        /// <returns>A task returning created password record.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<PasswordRecord> CreateRecord(PasswordRecord record, string folderUid = null);

        /// <summary>
        /// Modifies a password record.
        /// </summary>
        /// <param name="record">Password Record.</param>
        /// <returns>A task returning created password record.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<PasswordRecord> UpdateRecord(PasswordRecord record);

        /// <summary>
        /// Deletes password records.
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
        /// <typeparam name="T"></typeparam>
        /// <param name="recordUid"></param>
        /// <param name="nonSharedData"></param>
        /// <returns>Awaitable task.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task StoreNonSharedData<T>(string recordUid, T nonSharedData) where T : RecordNonSharedDataData;

        /// <summary>
        /// Creates a folder.
        /// </summary>
        /// <typeparam name="T">Shared Folder Options type.</typeparam>
        /// <param name="name">Folder Name.</param>
        /// <param name="parentFolderUid">Parent Folder UID.</param>
        /// <param name="sharedFolderOptions">Shared Folder creation options. Optional.</param>
        /// <returns>A task returning created folder.</returns>
        /// <remarks>Pass <see cref="sharedFolderOptions"/> parameter to create a Shared Folder.</remarks>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        /// <seealso cref="SharedFolderOptions"/>
        Task<FolderNode> CreateFolder<T>(string name, string parentFolderUid = null, T sharedFolderOptions = null) 
            where T: class, ISharedFolderUserOptions, ISharedFolderRecordOptions;
        /// <summary>
        /// Renames a folder.
        /// </summary>
        /// <param name="folderUid">Folder UID.</param>
        /// <param name="newName">New folder name.</param>
        /// <returns>A task returning renamed folder.</returns>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        Task<FolderNode> RenameFolder(string folderUid, string newName);
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
        /// <param name="userType">Type of <see cref="userId"/> parameter.</param>
        /// <param name="options">Shared Folder User Permissions.</param>
        /// <returns>Awaitable task.</returns>
        /// <remarks>
        /// If <seealso cref="options"/> parameter is <c>null</c> then user gets default user permissions when added./>
        /// </remarks>
        /// <exception cref="Authentication.KeeperApiException"></exception>
        /// <seealso cref="SharedFolderUserOptions"/>
        Task PutUserToSharedFolder(string sharedFolderUid, string userId, UserType userType, ISharedFolderUserOptions options = null);
        /// <summary>
        /// Removes user or team from shared folder.
        /// </summary>
        /// <param name="sharedFolderUid">Shared Folder UID.</param>
        /// <param name="userId">User email or Team UID.</param>
        /// <param name="userType">Type of <see cref="userId"/> parameter.</param>
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
        Task ChangeRecordInSharedFolder(string sharedFolderUid, string recordUid, ISharedFolderRecordOptions options);
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
        /// Downloads and decrypts file attachment.
        /// </summary>
        /// <param name="record">Keeper record.</param>
        /// <param name="attachment">Attachment name, title, or ID.</param>
        /// <param name="destination">Writable stream.</param>
        /// <returns>Awaitable task.</returns>
        Task DownloadAttachment(PasswordRecord record, string attachment, Stream destination);
        /// <summary>
        /// Encrypts and uploads file attachment.
        /// </summary>
        /// <param name="record">Keeper record.</param>
        /// <param name="uploadTask">Upload task</param>
        /// <returns>Awaitable task.</returns>
        Task UploadAttachment(PasswordRecord record, IAttachmentUploadTask uploadTask);
    }

    /// <summary>
    /// The exception that is thrown by the Vault module.
    /// </summary>
    public class VaultException : Exception
    {
        public VaultException(string message) : base(message)
        {
        }
        public VaultException(string translationKey, string message) : base(message)
        {
            TranslationKey = translationKey;
        }

        /// <exclude />
        public string TranslationKey { get; }
    }

    /// <summary>
    /// Represents a decrypted Keeper Password Record.
    /// </summary>
    public class PasswordRecord
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        public string Uid { get; set; }
        /// <summary>
        /// Is user Owner?
        /// </summary>
        public bool Owner { get; set; }
        /// <summary>
        /// Is record Shared?
        /// </summary>
        public bool Shared { get; set; }

        /// <summary>
        /// Title.
        /// </summary>
        public string Title { get; set; }
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
        /// Notes.
        /// </summary>
        public string Notes { get; set; }
        /// <summary>
        /// Last modification time.
        /// </summary>
        public DateTimeOffset ClientModified { get; internal set; }
        /// <summary>
        /// A list of Custom Fields.
        /// </summary>
        public IList<CustomField> Custom { get; } = new List<CustomField>();
        /// <summary>
        /// A list of Attachments.
        /// </summary>
        public IList<AttachmentFile> Attachments { get; } = new List<AttachmentFile>();
        /// <summary>
        /// A list of Extra Fields.
        /// </summary>
        public IList<ExtraField> ExtraFields { get; } = new List<ExtraField>();
        /// <summary>
        /// Record key.
        /// </summary>
        public byte[] RecordKey { get; set; }

        /// <summary>
        /// Deletes a custom field.
        /// </summary>
        /// <param name="name">Custom field name.</param>
        /// <returns>Deleted custom field or <c>null</c> is it was not found.</returns>
        public CustomField DeleteCustomField(string name)
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
        public CustomField SetCustomField(string name, string value)
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
    public class CustomField
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
        public Dictionary<string, object> Custom { get; } = new Dictionary<string, object>();
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
    /// Represents attachment file.
    /// </summary>
    public class AttachmentFile
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
        public string Type { get; set; }
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
        /// User email or team UID.
        /// </summary>
        public string UserId { get; internal set; }
        /// <summary>
        /// The type of <see cref="UserId"/> property.
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
        public List<SharedFolderPermission> UsersPermissions { get; } = new List<SharedFolderPermission>();
        /// <summary>
        /// A list of record permissions.
        /// </summary>
        public List<SharedFolderRecord> RecordPermissions { get; } = new List<SharedFolderRecord>();

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
    public class Team: TeamInfo
    {
        internal Team()
        {
        }

        internal Team(IEnterpriseTeam et, byte[] teamKey)
        {
            TeamKey = teamKey;
            var pk = et.TeamPrivateKey.Base64UrlDecode();
            TeamPrivateKey = CryptoUtils.LoadPrivateKey(CryptoUtils.DecryptAesV1(pk, teamKey));
            TeamUid = et.TeamUid;
            Name = et.Name;
            RestrictEdit = et.RestrictEdit;
            RestrictShare = et.RestrictShare;
            RestrictView = et.RestrictView;
        }

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
        public RsaPrivateCrtKeyParameters TeamPrivateKey { get; internal set; }
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
            {FolderType.UserFolder, "user_folder"},
            {FolderType.SharedFolder, "shared_folder"},
            {FolderType.SharedFolderFolder, "shared_folder_folder"},
        };
        
        public static string GetFolderTypeText(this FolderType folderType)
        {
            return FolderTypes[folderType];
        }
    }
}