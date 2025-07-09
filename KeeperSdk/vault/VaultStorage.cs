using KeeperSecurity.Storage;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Specifies key used for entity encryption.
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// AES GCM encryption with the user's client key.
        /// </summary>
        ClientKeyAesGcm = 1,

        /*
        /// <summary>
        /// RSA excryption with the user's RSA key.
        /// </summary>
        UserPrivateKey_RSA = 2,
        */

        /*
        /// <summary>
        /// RSA excryption with the user's RSA key.
        /// </summary>
        UserPrivateKey_EC = 3,
        */

        /// <summary>
        /// AES CBC/GCM with shared folder key.
        /// </summary>
        SharedFolderKeyAesAny = 4,

        /// <summary>
        /// AES encryption with team key.
        /// </summary>
        TeamKeyAesGcm = 5,

        /*
        /// <summary>
        /// Key is encrypted with team RSA key.
        /// </summary>
        TeamRsaPrivateKey = 6,
        */
        /// <summary>
        /// Key is encrypted with record key.
        /// </summary>
        RecordKeyAesGcm = 7,
    }

    /// <summary>
    /// Defines vault settings properties
    /// </summary>
    public interface IVaultSettings
    {
        /// <summary>
        /// Last Vault sync down token
        /// </summary>
        byte[] SyncDownToken { get; }
    }

    /// <summary>
    /// Defines Record storage properties.
    /// </summary>
    public interface IStorageRecord : IUid
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        string RecordUid { get; }

        /// <summary>
        /// Last Revision.
        /// </summary>
        long Revision { get; }

        /// <summary>
        /// Record Version.
        /// 2 - Legacy
        /// 3 - Typed
        /// 4 - File
        /// 5 - Application
        /// </summary>
        int Version { get; }

        /// <summary>
        /// Last modification time. Unix epoch in seconds.
        /// </summary>
        long ClientModifiedTime { get; }

        /// <summary>
        /// Encrypted record data 
        /// </summary>
        string Data { get; }

        /// <summary>
        /// Encrypted record extra data.
        /// </summary>
        string Extra { get; }

        /// <summary>
        /// Unencrypted record data
        /// </summary>
        string Udata { get; }

        /// <summary>
        /// Is record shared?
        /// </summary>
        bool Shared { get; set; }
    }

    /// <summary>
    /// Defines properties for shared folder storage.
    /// </summary>
    public interface IStorageSharedFolder : IUid
    {
        /// <summary>
        /// Shared folder UID.
        /// </summary>
        string SharedFolderUid { get; }

        /// <exclude/>
        long Revision { get; }

        /// <summary>
        /// Shared folder name. Encrypted with the shared folder key.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Shared folder encrypted data
        /// </summary>
        string Data { get; }

        /// <summary>
        /// Can manage records by default?
        /// </summary>
        bool DefaultManageRecords { get; }

        /// <summary>
        /// Can manage users by default?
        /// </summary>
        bool DefaultManageUsers { get; }

        /// <summary>
        /// Can edit records by default?
        /// </summary>
        bool DefaultCanEdit { get; }

        /// <summary>
        /// Can re-share records by default.
        /// </summary>
        bool DefaultCanShare { get; }

        /// <summary>
        /// Owner Account UID
        /// </summary>
        string OwnerAccountUid { get; }
    }

    /// <summary>
    /// Defines properties for team storage.
    /// </summary>
    public interface IStorageTeam : IUid
    {
        /// <summary>
        /// Team UID.
        /// </summary>
        string TeamUid { get; }

        /// <summary>
        /// Team name. Plain text.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Team key. Encrypted with the <see cref="KeyType"/>
        /// </summary>
        string TeamKey { get; }

        /// <summary>
        /// Encryption key type.
        /// </summary>
        /// <see cref="Vault.KeyType"/>
        int KeyType { get; }

        /// <summary>
        /// Team RSA private key.
        /// </summary>
        string TeamRsaPrivateKey { get; }

        /// <summary>
        /// Team ECC private key.
        /// </summary>
        string TeamEcPrivateKey { get; }

        /// <summary>
        /// Does team restrict record edit?
        /// </summary>
        bool RestrictEdit { get; }

        /// <summary>
        /// Does team restrict record re-share?
        /// </summary>
        bool RestrictShare { get; }

        /// <summary>
        /// Does team restrict record view?
        /// </summary>
        bool RestrictView { get; }
    }

    /// <summary>
    /// Defines non-shared data storage.
    /// </summary>
    public interface IStorageNonSharedData : IUid
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        string RecordUid { get; }

        /// <summary>
        /// Encrypted record data.
        /// </summary>
        string Data { get; set; }
    }

    /// <summary>
    /// Defines Record Key Metadata storage.
    /// </summary>
    public interface IStorageRecordKey : IUidLink
    {
        /// <summary>
        /// Record UID.
        /// </summary>
        string RecordUid { get; }

        /// <summary>
        /// Shared Folder UID if record key is encrypted with shared folder key.
        /// </summary>
        string SharedFolderUid { get; }

        /// <summary>
        /// Encrypted record key.
        /// </summary>
        string RecordKey { get; }

        /// <summary>
        /// Record key encryption key type.
        /// </summary>
        /// <seealso cref="KeyType"/>
        int RecordKeyType { get; }

        /// <summary>
        /// Can user re-share record?
        /// </summary>
        bool CanShare { get; }

        /// <summary>
        /// Can user edit record?
        /// </summary>
        bool CanEdit { get; }

        /// <summary>
        /// Is record owner?
        /// </summary>
        bool Owner { get; }

        /// <summary>
        /// Owner Account UID
        /// </summary>
        string OwnerAccountUid { get; }

        /// <summary>
        /// Share expiration
        /// </summary>
        long Expiration { get; }
    }

    /// <summary>
    /// Defines shared folder key storage.
    /// </summary>
    public interface IStorageSharedFolderKey : IUidLink
    {
        /// <summary>
        /// Shared Folder UID.
        /// </summary>
        string SharedFolderUid { get; }

        /// <summary>
        /// Team Uid if shared folder UID is encrypted with team key.
        /// </summary>
        string TeamUid { get; }

        /// <summary>
        /// Shared folder key encryption key type.
        /// </summary>
        int KeyType { get; }

        /// <summary>
        /// Encrypted shared folder key.
        /// </summary>
        string SharedFolderKey { get; }
    }

    /// <summary>
    /// Defines properties for shared folder user permissions.
    /// </summary>
    public interface ISharedFolderPermission : IUidLink
    {
        /// <summary>
        /// Shared folder UID.
        /// </summary>
        string SharedFolderUid { get; }

        /// <summary>
        /// User Account UID or Team UID.
        /// </summary>
        string UserId { get; }

        /// <summary>
        /// User type.
        /// </summary>
        /// <seealso cref="Vault.UserType"/>
        int UserType { get; }

        /// <summary>
        /// Can manage records?
        /// </summary>
        bool ManageRecords { get; }

        /// <summary>
        /// Can manage users?
        /// </summary>
        bool ManageUsers { get; }

        /// <summary>
        /// Share expiration
        /// </summary>
        long Expiration { get; }
    }

    /// <summary>
    /// Defines properties for folder storage.
    /// </summary>
    public interface IStorageFolder : IUid
    {
        /// <summary>
        /// Parent folder UID.
        /// </summary>
        string ParentUid { get; }

        /// <summary>
        /// Folder UID.
        /// </summary>
        string FolderUid { get; }

        /// <summary>
        /// Folder type.
        /// </summary>
        string FolderType { get; }

        /// <summary>
        /// Folder key. Encrypted with data key for <c>user_folder</c> or <c>shared folder key</c> for <c>shared_folder_folder</c>
        /// </summary>
        string FolderKey { get; }

        /// <summary>
        /// Shared Folder UID.
        /// </summary>
        string SharedFolderUid { get; }

        /// <summary>
        /// Revision.
        /// </summary>
        long Revision { get; }

        /// <summary>
        /// Shared folder data. Encrypted with the shared folder key.
        /// </summary>
        string Data { get; }
    }

    /// <summary>
    /// Defines user's email storage properties
    /// </summary>
    public interface IStorageUserEmail : IUidLink
    {
        /// <summary>
        /// User account UID
        /// </summary>
        string AccountUid { get; }

        /// <summary>
        /// User email
        /// </summary>
        string Email { get; }
    }

    /// <summary>
    /// Defines properties record-folder link.
    /// </summary>
    public interface IStorageFolderRecord : IUidLink
    {
        /// <summary>
        /// Folder UID.
        /// </summary>
        string FolderUid { get; }

        /// <summary>
        /// Record UID.
        /// </summary>
        string RecordUid { get; }
    }

    /// <summary>
    /// Defines properties for offline Keeper vault storage.
    /// </summary>
    public interface IKeeperStorage
    {
        /// <summary>
        /// ID for logged in user. 
        /// </summary>
        string PersonalScopeUid { get; }

        /// <summary>
        /// Gets or sets settings.
        /// </summary>
        IRecordStorage<IVaultSettings> VaultSettings { get; }

        /// <summary>
        /// Gets record entity storage.
        /// </summary>
        IEntityStorage<IStorageRecord> Records { get; }

        /// <summary>
        /// Gets shared folder entity storage.
        /// </summary>
        IEntityStorage<IStorageSharedFolder> SharedFolders { get; }

        /// <summary>
        /// Gets team entity storage.
        /// </summary>
        IEntityStorage<IStorageTeam> Teams { get; }

        /// <summary>
        /// Gets non-shared record data entity storage.
        /// </summary>
        IEntityStorage<IStorageNonSharedData> NonSharedData { get; }

        /// <summary>
        /// Gets record key entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Record UID</description></item>
        /// <item><term>Object UID</term><description><c>PersonalScopeUid</c> or Shared Folder UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<IStorageRecordKey> RecordKeys { get; } // RecordUid / "" or SharedFolderUid

        /// <summary>
        /// Gets shared folder key entity link storage
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Shared Folder UID</description></item>
        /// <item><term>Object UID</term><description><c>PersonalScopeUid</c> or Team UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<IStorageSharedFolderKey> SharedFolderKeys { get; }

        /// <summary>
        /// Gets shared folder user permission entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Shared Folder UID</description></item>
        /// <item><term>Object UID</term><description>User Email or Team UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<ISharedFolderPermission> SharedFolderPermissions { get; }

        /// <summary>
        /// Gets folder entity storage.
        /// </summary>
        IEntityStorage<IStorageFolder> Folders { get; }

        /// <summary>
        /// Gets folder's record entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Folder UID</description></item>
        /// <item><term>Object UID</term><description>Record UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<IStorageFolderRecord> FolderRecords { get; } // FolderUid / RecordUid

        /// <summary>
        /// Gets record type's entity storage
        /// </summary>
        IEntityStorage<IStorageRecordType> RecordTypes { get; }

        /// <summary>
        /// Gets user email storage
        /// </summary>
        ILinkStorage<IStorageUserEmail> UserEmails { get; }

        /// <summary>
        /// Gets breachwatch records storage
        /// </summary>
        IEntityStorage<IStorageBreachWatchRecord> BreachWatchRecords { get; }


        /// <summary>
        /// Clear offline Keeper vault storage.
        /// </summary>
        void Clear();
    }

    /// <summary>
    /// Specifies Record Type Scope
    /// </summary>
    public enum RecordTypeScope
    {
        /// <summary>
        /// Pre-Defined 
        /// </summary>
        Standard = 0,

        /// <summary>
        /// User-Defined
        /// </summary>
        User = 1,

        /// <summary>
        /// Enterprise-Defined
        /// </summary>
        Enterprise = 2,
    }

    /// <summary>
    /// Defines Record Types storage properties.
    /// </summary>
    public interface IStorageRecordType : IUid
    {
        /// <summary>
        /// Record type name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Record Type ID
        /// </summary>
        int RecordTypeId { get; }

        /// <summary>
        /// Record Type Scope
        /// </summary>
        int Scope { get; }

        /// <summary>
        /// Record Type Content (JSON).
        /// </summary>
        string Content { get; }
    }
    
    public interface IStorageBreachWatchRecord : IUid
    {
        /// <summary>
        /// BreachWatch Record UID.
        /// </summary>
        string RecordUid { get; }

        /// <summary>
        /// Last Revision.
        /// </summary>
        long Revision { get; }

        /// <summary>
        /// Type of breach watch record
        /// </summary>
        int Type { get; }

        /// <summary>
        /// Encrypted record data 
        /// </summary>
        string Data { get; }
    }
}