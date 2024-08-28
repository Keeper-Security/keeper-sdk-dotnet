using System;
using System.Collections.Generic;
using System.Linq;

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
        ClientKey_AES_GCM = 1,

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
        SharedFolderKey_AES_Any = 4,
        /// <summary>
        /// AES encryption with team key.
        /// </summary>
        TeamKey_AES_GCM = 5,
        /*
        /// <summary>
        /// Key is encrypted with team RSA key.
        /// </summary>
        TeamRsaPrivateKey = 6,
        */
        /// <summary>
        /// Key is encrypted with record key.
        /// </summary>
        RecordKey_AES_GCM = 7,
    }

    /// <exclude/>
    public interface IUid
    {
        string Uid { get; }
    }

    /// <exclude/>
    public interface IUidLink
    {
        string SubjectUid { get; }
        string ObjectUid { get; }
    }

    public class EqualityComparerIUidLink : EqualityComparer<IUidLink>
    {
        private EqualityComparerIUidLink() { }
        private static EqualityComparerIUidLink _instance = new EqualityComparerIUidLink();

        public static EqualityComparerIUidLink Instance => _instance;

        public override bool Equals(IUidLink x, IUidLink y)
        {
            if (x != null && y != null) 
            {
                return string.Equals(x.SubjectUid, y.SubjectUid) && string.Equals(x.ObjectUid, y.ObjectUid);
            }
            if (x == null && y == null)
            {
                return true;
            }
            return false;
        }

        public override int GetHashCode(IUidLink obj)
        {
            if (obj != null) 
            {
                return Tuple.Create(obj.SubjectUid ?? "", obj.ObjectUid ?? "").GetHashCode();
            }
            return 0;
        }
    }

    public interface IVaultSettings
    {
        long Revision { get; }
        string SyncDownToken { get; }
    }

    /// <summary>
    /// Defines Record Key Metadata properties.
    /// </summary>
    public interface IRecordMetadata : IUidLink
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
    /// Defines Password Record properties.
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
        bool Shared { get; set;  }
    }

    /// <summary>
    /// Defines non-shared data properties.
    /// </summary>
    public interface INonSharedData : IUid
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
    /// Defines shared folder key properties.
    /// </summary>
    public interface ISharedFolderKey : IUidLink
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
    /// Defines properties for shared folder.
    /// </summary>
    public interface ISharedFolder : IUid
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
    /// Defines properties for Enterprise Team.
    /// </summary>
    public interface IEnterpriseTeam : IUid
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
    /// Defines properties for folder.
    /// </summary>
    public interface IFolder : IUid
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
    /// Defines properties for user's emails
    /// </summary>
    public interface IUserEmail: IUid 
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
    public interface IFolderRecordLink : IUidLink
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
    /// Defines entity storage methods.
    /// </summary>
    /// <typeparam name="T">Type of entity.</typeparam>
    public interface IEntityStorage<T> where T : IUid
    {
        /// <summary>
        /// Gets entity by entity UID.
        /// </summary>
        /// <param name="uid">Entity UID.</param>
        /// <returns>Entity instance.</returns>
        T GetEntity(string uid);
        /// <summary>
        /// Stores entities.
        /// </summary>
        /// <param name="entities">List of entities.</param>
        void PutEntities(IEnumerable<T> entities);
        /// <summary>
        /// Deletes entity by entity UID.
        /// </summary>
        /// <param name="uids">List of Entity UIDs to delete.</param>
        void DeleteUids(IEnumerable<string> uids);
        /// <summary>
        /// Gets all entities in the storage.
        /// </summary>
        /// <returns></returns>
        IEnumerable<T> GetAll();
    }

    /// <summary>
    /// Defines entity link storage methods.
    /// </summary>
    /// <typeparam name="T">Type of entity link.</typeparam>
    public interface ILinkStorage<T> where T : IUidLink
    {
        /// <summary>
        /// Stores entity links
        /// </summary>
        /// <param name="entities">List of entity links.</param>
        void PutLinks(IEnumerable<T> entities);
        /// <summary>
        /// Deletes entity link.
        /// </summary>
        /// <param name="links">List links to delete.</param>
        void DeleteLinks(IEnumerable<IUidLink> links);
        /// <summary>
        /// Delete all links for subject entity UIDs
        /// </summary>
        /// <param name="subjectUids">List of Subject UIDs to delete.</param>
        void DeleteLinksForSubjects(IEnumerable<string> subjectUids);
        /// <summary>
        /// Delete all links for object entity UID
        /// </summary>
        /// <param name="objectUids">List of Object UIDs to delete.</param>
        void DeleteLinksForObjects(IEnumerable<string> objectUids);
        /// <summary>
        /// Gets all entity links for subject entity UID.
        /// </summary>
        /// <param name="subjectUid">Subject UID.</param>
        /// <returns>A list of entity links.</returns>
        IEnumerable<T> GetLinksForSubject(string subjectUid);
        /// <summary>
        /// Gets all entity links for object entity UID.
        /// </summary>
        /// <param name="objectUid">Object UID.</param>
        /// <returns>A list of entity links.</returns>
        IEnumerable<T> GetLinksForObject(string objectUid);
        /// <summary>
        /// Gets all entity links in the storage.
        /// </summary>
        /// <returns>A list of entity links.</returns>
        IEnumerable<T> GetAllLinks();

        T GetLink(IUidLink link);
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
        IVaultSettings VaultSettings { get; set; }

        /// <summary>
        /// Gets record entity storage.
        /// </summary>
        IEntityStorage<IStorageRecord> Records { get; }

        /// <summary>
        /// Gets shared folder entity storage.
        /// </summary>
        IEntityStorage<ISharedFolder> SharedFolders { get; }

        /// <summary>
        /// Gets team entity storage.
        /// </summary>
        IEntityStorage<IEnterpriseTeam> Teams { get; }

        /// <summary>
        /// Gets non-shared record data entity storage.
        /// </summary>
        IEntityStorage<INonSharedData> NonSharedData { get; }

        /// <summary>
        /// Gets record key entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Record UID</description></item>
        /// <item><term>Object UID</term><description><c>PersonalScopeUid</c> or Shared Folder UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<IRecordMetadata> RecordKeys { get; } // RecordUid / "" or SharedFolderUid

        /// <summary>
        /// Gets shared folder key entity link storage
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Shared Folder UID</description></item>
        /// <item><term>Object UID</term><description><c>PersonalScopeUid</c> or Team UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<ISharedFolderKey> SharedFolderKeys { get; }

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
        IEntityStorage<IFolder> Folders { get; }

        /// <summary>
        /// Gets folder's record entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Subject UID</term><description>Folder UID</description></item>
        /// <item><term>Object UID</term><description>Record UID</description></item>
        /// </list>
        /// </remarks>
        ILinkStorage<IFolderRecordLink> FolderRecords { get; } // FolderUid / RecordUid

        /// <summary>
        /// Gets record type's entity storage
        /// </summary>
        IEntityStorage<IRecordType> RecordTypes { get; }

        /// <summary>
        /// Gets user email storage
        /// </summary>
        IEntityStorage<IUserEmail> UserEmails { get; }

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
    /// Defines properties for Record Types.
    /// </summary>
    public interface IRecordType : IUid
    {
        /// <summary>
        /// Record Type ID
        /// </summary>
        int Id { get; }
        /// <summary>
        /// Record Type Scope
        /// </summary>
        RecordTypeScope Scope { get; }
        /// <summary>
        /// Record Type Content (JSON).
        /// </summary>
        string Content { get; }
    }

    internal class InMemoryItemStorage<T> : IEntityStorage<T> where T : IUid
    {
        private readonly Dictionary<string, T> _items = new Dictionary<string, T>();

        public void DeleteUids(IEnumerable<string> uids)
        {
            foreach (var uid in uids)
            {
                _items.Remove(uid);
            }
        }

        public T GetEntity(string uid)
        {
            if (_items.TryGetValue(uid, out T item))
            {
                return item;
            }

            return default;
        }

        public IEnumerable<T> GetAll()
        {
            return _items.Values;
        }

        public void PutEntities(IEnumerable<T> data)
        {
            foreach (var entity in data)
            {
                if (entity != null)
                {
                    _items[entity.Uid] = entity;
                }
            }
        }
    }

    internal class InMemoryLinkStorage<T> : ILinkStorage<T> where T : IUidLink
    {
        private readonly Dictionary<string, IDictionary<string, T>> _links =
            new Dictionary<string, IDictionary<string, T>>();

        public void DeleteLinks(IEnumerable<IUidLink> links)
        {
            foreach (var link in links)
            {
                if (_links.TryGetValue(link.SubjectUid, out IDictionary<string, T> dict))
                {
                    dict.Remove(link.ObjectUid ?? "");
                }
            }
        }

        public void DeleteLinksForSubjects(IEnumerable<string> subjectUids)
        {
            foreach (var subjectUid in subjectUids)
            {
                _links.Remove(subjectUid ?? "");
            }
        }

        public void DeleteLinksForObjects(IEnumerable<string> objectUids)
        {
            foreach (var objectUid in objectUids)
            {
                foreach (var pair in _links)
                {
                    pair.Value?.Remove(objectUid ?? "");
                }
            }
        }

        public IEnumerable<T> GetAllLinks()
        {
            foreach (var dict in _links.Values)
            {
                foreach (var link in dict.Values)
                {
                    yield return link;
                }
            }
        }

        public T GetLink(IUidLink link) {
            if (_links.ContainsKey(link.SubjectUid)) {
                var subjects = _links[link.SubjectUid];
                if (subjects.ContainsKey(link.ObjectUid)) { 
                    return subjects[link.ObjectUid];
                }
            }
            return default;
        }

        public IEnumerable<T> GetLinksForSubject(string primaryUid)
        {
            if (_links.TryGetValue(primaryUid, out IDictionary<string, T> dict))
            {
                return dict.Values;
            }

            return Enumerable.Empty<T>();
        }

        public IEnumerable<T> GetLinksForObject(string secondaryUid)
        {
            foreach (var dict in _links.Values)
            {
                if (dict.TryGetValue(secondaryUid, out T data))
                {
                    yield return data;
                }
            }
        }

        public void PutLinks(IEnumerable<T> links)
        {
            foreach (var link in links)
            {
                if (link == null)
                {
                    continue;
                }
                if (!_links.TryGetValue(link.SubjectUid, out IDictionary<string, T> dict))
                {
                    dict = new Dictionary<string, T>();
                    _links.Add(link.SubjectUid, dict);
                }

                var objectId = link.ObjectUid ?? "";
                if (dict.TryGetValue(objectId, out var elem))
                {
                    if (!ReferenceEquals(elem, link))
                    {
                        dict[objectId] = link;
                    }
                }
                else
                {
                    dict.Add(objectId, link);
                }
            }
        }
    }

    /// <summary>
    /// Provides in memory implementation of IKeeperStorage interface.
    /// </summary>
    /// <seealso cref="IKeeperStorage" />
    public class InMemoryKeeperStorage : IKeeperStorage
    {
        public InMemoryKeeperStorage()
        {
            Clear();
        }

        /// <inheritdoc/>
        public string PersonalScopeUid { get; } = "PersonalScopeUid";

        /// <inheritdoc/>
        public IVaultSettings VaultSettings { get; set; }

        /// <inheritdoc/>
        public IEntityStorage<IStorageRecord> Records { get; private set; }

        /// <inheritdoc/>
        public IEntityStorage<ISharedFolder> SharedFolders { get; private set; }

        /// <inheritdoc/>
        public IEntityStorage<IEnterpriseTeam> Teams { get; private set; }

        /// <inheritdoc/>
        public IEntityStorage<INonSharedData> NonSharedData { get; private set; }

        /// <inheritdoc/>
        public ILinkStorage<IRecordMetadata> RecordKeys { get; private set; }

        /// <inheritdoc/>
        public ILinkStorage<ISharedFolderKey> SharedFolderKeys { get; private set; }

        /// <inheritdoc/>
        public ILinkStorage<ISharedFolderPermission> SharedFolderPermissions { get; private set; }

        /// <inheritdoc/>
        public IEntityStorage<IFolder> Folders { get; private set; }

        /// <inheritdoc/>
        public ILinkStorage<IFolderRecordLink> FolderRecords { get; private set; }

        /// <inheritdoc/>
        public IEntityStorage<IRecordType> RecordTypes { get; private set; }

        /// <inheritdoc/>
        public IEntityStorage<IUserEmail> UserEmails { get; private set; }


        /// <inheritdoc/>
        public void Clear()
        {
            Records = new InMemoryItemStorage<IStorageRecord>();
            SharedFolders = new InMemoryItemStorage<ISharedFolder>();
            Teams = new InMemoryItemStorage<IEnterpriseTeam>();
            NonSharedData = new InMemoryItemStorage<INonSharedData>();
            RecordKeys = new InMemoryLinkStorage<IRecordMetadata>();
            SharedFolderKeys = new InMemoryLinkStorage<ISharedFolderKey>();
            SharedFolderPermissions = new InMemoryLinkStorage<ISharedFolderPermission>();
            Folders = new InMemoryItemStorage<IFolder>();
            FolderRecords = new InMemoryLinkStorage<IFolderRecordLink>();
            RecordTypes = new InMemoryItemStorage<IRecordType>();
            UserEmails = new InMemoryItemStorage<IUserEmail>();

            VaultSettings = null;
        }
    }

    internal class UidLink : Tuple<string, string>, IUidLink
    {
        private UidLink(string subjectUid, string objectUid) : base(subjectUid, objectUid ?? "")
        {
        }

        public static IUidLink Create(string subjectUid, string objectUid)
        {
            return new UidLink(subjectUid, objectUid);
        }

        string IUidLink.SubjectUid => Item1;
        string IUidLink.ObjectUid => Item2;
    }

    internal class VaultSettings : IVaultSettings
    {
        public VaultSettings(IVaultSettings other)
        {
            Revision = other?.Revision ?? 0;
            SyncDownToken = other?.SyncDownToken ?? null;
        }
        public long Revision { get; set; }

        public string SyncDownToken { get; set; }
    }
}