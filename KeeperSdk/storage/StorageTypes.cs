using System;
using System.Collections.Generic;

namespace KeeperSecurity.Storage
{
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
        private EqualityComparerIUidLink()
        {
        }

        public static EqualityComparerIUidLink Instance { get; } = new();

        public override bool Equals(IUidLink x, IUidLink y)
        {
            if (x != null && y != null)
            {
                return string.Equals(x.SubjectUid, y.SubjectUid) && string.Equals(x.ObjectUid, y.ObjectUid);
            }

            return x == null && y == null;
        }

        public override int GetHashCode(IUidLink obj)
        {
            return Tuple.Create(obj.SubjectUid ?? "", obj.ObjectUid ?? "").GetHashCode();
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

    /// <exclude/>
    public interface IEntityCopy<in T>
    {
        void CopyFields(T source);
    }

    /// <summary>
    /// Defines record storage methods
    /// </summary>
    /// <typeparam name="T">Type of record</typeparam>
    public interface IRecordStorage<T>
    {
        /// <summary>
        /// Loads a record
        /// </summary>
        /// <returns>Record instance</returns>
        T Load();
        /// <summary>
        /// Stores a record
        /// </summary>
        /// <param name="record">a record to store</param>
        void Store(T record);
        /// <summary>
        /// Deletes record storage
        /// </summary>
        void Delete();
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
}