//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Sdk
{
    public enum KeyType
    {
        NoKey = 0,
        DataKey = 1,
        PrivateKey = 2,
        SharedFolderKey = 3,
        TeamKey = 4
    }

    public interface IUidLink
    {
        string SubjectUid { get; }
        string ObjectUid { get; }
    }

    public interface IRecordMetadata : IUidLink
    {
        string RecordUid { get; }
        string SharedFolderUid { get; }
        string RecordKey { get; }
        int RecordKeyType { get; }
        bool CanShare { get; set; }
        bool CanEdit { get; set; }
    }

    public interface IPasswordRecord
    {
        string RecordUid { get; }
        long Revision { get; }
        long ClientModifiedTime { get; }
        string Data { get; set; }
        string Extra { get; }
        string Udata { get; }
        bool Shared { get; }
        bool Owner { get; set; }
    }

    public interface IKeeperUser
    {
        string Username { get; set; }
    }

    public interface ISharedFolderKey : IUidLink
    {
        string SharedFolderUid { get; }
        string TeamUid { get; }
        int KeyType { get; }
        string SharedFolderKey { get; }
    }

    public interface ISharedFolderPermission : IUidLink
    {
        string SharedFolderUid { get; }
        string UserId { get; }
        int UserType { get; }
        bool ManageRecords { get; }
        bool ManageUsers { get; }
    }

    public interface ISharedFolder
    {
        string SharedFolderUid { get; }
        long Revision { get; }
        string Name { get; }
        bool DefaultManageRecords { get; }
        bool DefaultManageUsers { get; }
        bool DefaultCanEdit { get; }
        bool DefaultCanShare { get; }
    }

    public interface IEnterpriseTeam
    {
        string TeamUid { get; }
        string Name { get; }
        string TeamKey { get; }
        int KeyType { get; }
        string TeamPrivateKey { get; }
        bool RestrictEdit { get; }
        bool RestrictShare { get; }
        bool RestrictView { get; }
    }

    public interface IFolder
    {
        string ParentUid { get; }
        string FolderUid { get; }
        string FolderType { get; }
        string FolderKey { get; }
        string SharedFolderUid { get; }
        long Revision { get; }
        string Data { get; }
    }

    public interface IFolderRecordLink : IUidLink
    {
        string FolderUid { get; }
        string RecordUid { get; }
    }

    public enum FolderUidType
    {
        KeyScope,
        Folder
    }

    public interface IEntityStorage<T>
    {
        T Get(string uid);
        void Put(string uid, T data);
        void Delete(string uid);
        IEnumerable<T> GetAll();
        void Clear();
    }

    public interface IPredicateStorage<T> where T : IUidLink
    {
        void Put(T data);
        void Delete(IUidLink link);
        IEnumerable<T> GetLinksForSubject(string subjectUid);
        IEnumerable<T> GetLinksForObject(string objectUid);
        IEnumerable<T> GetAllLinks();
        void Clear();
    }

    public interface IKeeperStorage
    {
        string PersonalScopeUid { get; }

        long Revision { get; set; }

        IEntityStorage<IPasswordRecord> Records { get; }
        IEntityStorage<ISharedFolder> SharedFolders { get; }
        IEntityStorage<IEnterpriseTeam> Teams { get; }
        IEntityStorage<IKeeperUser> Users { get; }
        IEntityStorage<string> NonSharedData { get; }

        IPredicateStorage<IRecordMetadata> RecordKeys { get; }   // RecordUid / "" or SharedFolderUid
        IPredicateStorage<ISharedFolderKey> SharedFolderKeys { get; } // SharedFolderUid / "" or teamUid
        IPredicateStorage<ISharedFolderPermission> SharedFolderPermissions { get; }  // SharedFolderUid / username or teamUid


        IEntityStorage<IFolder> Folders { get; }
        IPredicateStorage<IFolderRecordLink> FolderRecords { get; }     // FolderUid / RecordUid

        void Clear();
    }

    public class InMemoryItemStorage<T> : IEntityStorage<T>
    {
        private Dictionary<string, T> _items = new Dictionary<string, T>();

        public void Delete(string uid)
        {
            _items.Remove(uid);
        }

        public T Get(string uid)
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

        public void Put(string uid, T data)
        {
            _items[uid] = data;
        }

        public void Clear()
        {
            _items.Clear();
        }
    }

    public class IUidLinkComparer : IComparer<IUidLink>
    {
        public int Compare(IUidLink x, IUidLink y)
        {
            var res = string.Compare(x.SubjectUid, y.SubjectUid);
            if (res == 0)
            {
                res = string.Compare(x.ObjectUid ?? "", y.ObjectUid ?? "");
            }
            return res;
        }
    }
    public class InMemorySentenceStorage<T> : IPredicateStorage<T> where T : IUidLink
    {
        private readonly Dictionary<string, IDictionary<string, T>> _links = new Dictionary<string, IDictionary<string, T>>();

        public void Clear()
        {
            _links.Clear();
        }

        public void Delete(IUidLink link)
        {
            if (_links.TryGetValue(link.SubjectUid, out IDictionary<string, T> dict))
            {
                dict.Remove(link.ObjectUid ?? "");
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

        public void Put(T data)
        {
            if (!_links.TryGetValue(data.SubjectUid, out IDictionary<string, T> dict))
            {
                dict = new Dictionary<string, T>();
                _links.Add(data.SubjectUid, dict);
            }
            var objectId = data.ObjectUid ?? "";
            if (dict.TryGetValue(objectId, out T elem)) {
                if (!ReferenceEquals(elem, data)) {
                    dict[objectId] = data;
                }
            }
            else {
                dict.Add(objectId, data);
            }
        }
    }

    public class InMemoryKeeperStorage : IKeeperStorage
    {
        public string PersonalScopeUid { get; } = "PersonalScopeUid";

        public long Revision { get; set; }

        public IEntityStorage<IPasswordRecord> Records { get; } = new InMemoryItemStorage<IPasswordRecord>();
        public IEntityStorage<ISharedFolder> SharedFolders { get; } = new InMemoryItemStorage<ISharedFolder>();
        public IEntityStorage<IEnterpriseTeam> Teams { get; } = new InMemoryItemStorage<IEnterpriseTeam>();
        public IEntityStorage<IKeeperUser> Users { get; } = new InMemoryItemStorage<IKeeperUser>();
        public IEntityStorage<string> NonSharedData { get; } = new InMemoryItemStorage<string>();

        public IPredicateStorage<IRecordMetadata> RecordKeys { get; } = new InMemorySentenceStorage<IRecordMetadata>();
        public IPredicateStorage<ISharedFolderKey> SharedFolderKeys { get; } = new InMemorySentenceStorage<ISharedFolderKey>();
        public IPredicateStorage<ISharedFolderPermission> SharedFolderPermissions { get; } = new InMemorySentenceStorage<ISharedFolderPermission>();

        public IEntityStorage<IFolder> Folders { get; } = new InMemoryItemStorage<IFolder>();
        public IPredicateStorage<IFolderRecordLink> FolderRecords { get; } = new InMemorySentenceStorage<IFolderRecordLink>();

        public void Clear()
        {
            Records.Clear();
            SharedFolders.Clear();
            Teams.Clear();
            Users.Clear();
            NonSharedData.Clear();

            RecordKeys.Clear();
            SharedFolderKeys.Clear();
            SharedFolderPermissions.Clear();

            Folders.Clear();
            FolderRecords.Clear();
        }
    }

    public class UidLink : Tuple<string, string>, IUidLink
    {
        internal UidLink(string objectUid, string subjectUid) : base(objectUid, subjectUid ?? "") { }

        public static UidLink Create(string objectUid, string subjectUid)
        {
            return new UidLink(objectUid, subjectUid);
        }

        string IUidLink.SubjectUid => Item1;
        string IUidLink.ObjectUid => Item2;
    }

    public static class StorageExtensions
    {
        public static T Get<T>(this IPredicateStorage<T> table, string objectUid, string subjectUid) where T : IUidLink
        {
            return table.GetLinksForSubject(objectUid).Where(x => string.Compare(x.ObjectUid ?? "", subjectUid ?? "") == 0).FirstOrDefault();
        }

        public static void Delete<T>(this IPredicateStorage<T> table, string objectUid, string subjectUid) where T : IUidLink
        {
            table.Delete(UidLink.Create(objectUid, subjectUid));
        }

        public static void DeleteSubject<T>(this IPredicateStorage<T> table, string subjectUid) where T : IUidLink
        {
            foreach (var link in table.GetLinksForSubject(subjectUid).ToArray())
            {
                table.Delete(link);
            }
        }
        public static void DeleteObject<T>(this IPredicateStorage<T> table, string objectUid) where T : IUidLink
        {
            foreach (var link in table.GetLinksForObject(objectUid).ToArray())
            {
                table.Delete(link);
            }
        }
    }
}
