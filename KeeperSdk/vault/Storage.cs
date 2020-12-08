﻿//  _  __
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
        /// No entity key. Use data key.
        /// </summary>
        NoKey = 0,
        /// <summary>
        /// Key encrypted with the user data kay.
        /// </summary>
        DataKey = 1,
        /// <summary>
        /// Key is encrypted with the user RSA key.
        /// </summary>
        PrivateKey = 2,
        /// <summary>
        /// Key is encrypted with shared folder key.
        /// </summary>
        SharedFolderKey = 3,
        /// <summary>
        /// Key is encrypted with team key.
        /// </summary>
        TeamKey = 4
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
        bool CanShare { get; set; }
        /// <summary>
        /// Can user edit record?
        /// </summary>
        bool CanEdit { get; set; }
    }

    /// <summary>
    /// Defines Password Record properties.
    /// </summary>
    public interface IPasswordRecord : IUid
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
        /// Last modification time. Unix epoch in seconds.
        /// </summary>
        long ClientModifiedTime { get; }
        /// <summary>
        /// Encrypted record data 
        /// </summary>
        string Data { get; set; }
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
        bool Shared { get; }
        /// <summary>
        /// Is user owner of the record?
        /// </summary>
        bool Owner { get; set; }
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
        /// User email or Team UID.
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
        long Revision { get; }
        /// <summary>
        /// Shared folder name. Encrypted with the shared folder key.
        /// </summary>
        string Name { get; }
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
        /// Team private key. Encrypted with the team key.
        /// </summary>
        string TeamPrivateKey { get; }
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
    public interface IPredicateStorage<T> where T : IUidLink
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
        /// <param name="objectUid">List of Object UIDs to delete.</param>
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
    }

    /// <summary>
    /// Defines properties for offline Keeper vault storage.
    /// </summary>
    public interface IKeeperStorage
    {
        /// <summary>
        /// Pseudo UID for logged in user. 
        /// </summary>
        string PersonalScopeUid { get; }

        /// <summary>
        /// Revision.
        /// </summary>
        long Revision { get; set; }

        /// <summary>
        /// Gets record entity storage.
        /// </summary>
        IEntityStorage<IPasswordRecord> Records { get; }
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
        /// <item><term>Object UID</term><description>Record UID</description></item>
        /// <item><term>Subject UID</term><description><c>PersonalScopeUid</c> or Shared Folder UID</description></item>
        /// </list>
        /// </remarks>
        IPredicateStorage<IRecordMetadata> RecordKeys { get; } // RecordUid / "" or SharedFolderUid
        /// <summary>
        /// Gets shared folder key entity link storage
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Object UID</term><description>Shared Folder UID</description></item>
        /// <item><term>Subject UID</term><description><c>PersonalScopeUid</c> or Team UID</description></item>
        /// </list>
        /// </remarks>
        IPredicateStorage<ISharedFolderKey> SharedFolderKeys { get; }
        // SharedFolderUid / "" or teamUid

        /// <summary>
        /// Gets shared folder user permission entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Object UID</term><description>Shared Folder UID</description></item>
        /// <item><term>Subject UID</term><description>User Email or Team UID</description></item>
        /// </list>
        /// </remarks>
        IPredicateStorage<ISharedFolderPermission> SharedFolderPermissions { get; } 
        // SharedFolderUid / username or teamUid

        /// <summary>
        /// Gets folder entity storage.
        /// </summary>
        IEntityStorage<IFolder> Folders { get; }
        /// <summary>
        /// Gets folder's record entity link storage.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        /// <item><term>Object UID</term><description>Folder UID</description></item>
        /// <item><term>Subject UID</term><description>Record UID</description></item>
        /// </list>
        /// </remarks>
        IPredicateStorage<IFolderRecordLink> FolderRecords { get; } // FolderUid / RecordUid

        /// <summary>
        /// Clear offline Keeper vault storage.
        /// </summary>
        void Clear();
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
                _items[entity.Uid] = entity;
            }
        }
    }

    internal class InMemorySentenceStorage<T> : IPredicateStorage<T> where T : IUidLink
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
    /// Provides in memory implementation if <see cref="IKeeperStorage" interface./>
    /// </summary>
    public class InMemoryKeeperStorage : IKeeperStorage
    {
        public InMemoryKeeperStorage()
        {
            Clear();
        }

        public string PersonalScopeUid { get; } = "PersonalScopeUid";

        public long Revision { get; set; }

        public IEntityStorage<IPasswordRecord> Records { get; private set; }
        public IEntityStorage<ISharedFolder> SharedFolders { get; private set; }
        public IEntityStorage<IEnterpriseTeam> Teams { get; private set; }
        public IEntityStorage<INonSharedData> NonSharedData { get; private set; }
        public IPredicateStorage<IRecordMetadata> RecordKeys { get; private set; }
        public IPredicateStorage<ISharedFolderKey> SharedFolderKeys { get; private set; }
        public IPredicateStorage<ISharedFolderPermission> SharedFolderPermissions { get; private set; }
        public IEntityStorage<IFolder> Folders { get; private set; }
        public IPredicateStorage<IFolderRecordLink> FolderRecords { get; private set; }

        public void Clear()
        {
            Records = new InMemoryItemStorage<IPasswordRecord>();
            SharedFolders = new InMemoryItemStorage<ISharedFolder>();
            Teams = new InMemoryItemStorage<IEnterpriseTeam>();
            NonSharedData = new InMemoryItemStorage<INonSharedData>();
            RecordKeys = new InMemorySentenceStorage<IRecordMetadata>();
            SharedFolderKeys = new InMemorySentenceStorage<ISharedFolderKey>();
            SharedFolderPermissions = new InMemorySentenceStorage<ISharedFolderPermission>();
            Folders = new InMemoryItemStorage<IFolder>();
            FolderRecords = new InMemorySentenceStorage<IFolderRecordLink>();
            Revision = 0;
        }
    }

    internal class UidLink : Tuple<string, string>, IUidLink
    {
        private UidLink(string objectUid, string subjectUid) : base(objectUid, subjectUid ?? "")
        {
        }

        public static UidLink Create(string objectUid, string subjectUid)
        {
            return new UidLink(objectUid, subjectUid);
        }

        string IUidLink.SubjectUid => Item1;
        string IUidLink.ObjectUid => Item2;
    }
}