using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Storage
{
    /// <exclude/>
    public sealed class InMemoryRecordStorage<T> : IRecordStorage<T> where T : class
    {
        private T _record;

        public T Load()
        {
            return _record;
        }

        public void Store(T record)
        {
            _record = record;
        }

        public void Delete()
        {
            _record = null;
        }

        public void Clear()
        {
            Delete();
        }
    }

    /// <exclude/>
    public sealed class InMemoryEntityStorage<T> : IEntityStorage<T>
        where T : IUid
    {
        private readonly Dictionary<string, T> _items = new();

        public void DeleteUids(IEnumerable<string> uids)
        {
            foreach (var uid in uids)
            {
                _items.Remove(uid);
            }
        }

        public T GetEntity(string uid)
        {
            return _items.TryGetValue(uid, out var entity) ? entity : default;
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

        public void Clear()
        {
            _items.Clear();
        }
    }

    /// <exclude/>
    public sealed class InMemoryLinkStorage<T> : ILinkStorage<T> where T : IUidLink
    {
        private readonly Dictionary<string, IDictionary<string, T>> _links = new();

        public void DeleteLinks(IEnumerable<IUidLink> links)
        {
            foreach (var link in links)
            {
                if (_links.TryGetValue(link.SubjectUid, out var dict))
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

        public T GetLink(IUidLink link)
        {
            if (!_links.TryGetValue(link.SubjectUid, out var subjects)) return default;
            return subjects.TryGetValue(link.ObjectUid, value: out var link1) ? link1 : default;
        }

        public IEnumerable<T> GetLinksForSubject(string primaryUid)
        {
            return _links.TryGetValue(primaryUid, out var dict) ? dict.Values : Enumerable.Empty<T>();
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

                if (!_links.TryGetValue(link.SubjectUid, out var dict))
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

        public void Clear()
        {
            _links.Clear();
        }
    }
}