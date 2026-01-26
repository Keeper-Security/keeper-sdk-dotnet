using System.Collections.Generic;
using System.Linq;

namespace KeeperSecurity.Storage;

/// <summary>
/// Cached wrapper for IRecordStorage - tracks single record modifications.
/// </summary>
public class SnapshotRecordStorage<T> : IRecordStorage<T>
{
    private readonly IRecordStorage<T> _source;

    public SnapshotRecordStorage(IRecordStorage<T> source)
    {
        _source = source;
    }

    private T _cachedRecord;
    private bool _isModified;
    private bool _isDeleted;

    public T Load()
    {
        if (_isDeleted)
        {
            return default;
        }

        if (_isModified)
        {
            return _cachedRecord;
        }

        return _source.Load();
    }

    public void Store(T record)
    {
        // Store in cache only
        _cachedRecord = record;
        _isModified = true;
        _isDeleted = false;
    }

    public void Delete()
    {
        _isDeleted = true;
        _isModified = false;
        _cachedRecord = default;
    }
}

/// <summary>
/// Cached wrapper for IEntityStorage - tracks individual entity modifications.
/// </summary>
public class SnapshotEntityStorage<T> : IEntityStorage<T> where T : IUid
{
    private readonly IEntityStorage<T> _source;
    private readonly Dictionary<string, T> _modified = new();
    private readonly HashSet<string> _deleted = new();

    public SnapshotEntityStorage(IEntityStorage<T> source)
    {
        _source = source;
    }

    public T GetEntity(string uid)
    {
        if (_deleted.Contains(uid))
        {
            return default;
        }

        return _modified.TryGetValue(uid, out var cached) ? cached : _source.GetEntity(uid);
    }

    public void PutEntities(IEnumerable<T> entities)
    {
        foreach (var entity in entities)
        {
            _modified[entity.Uid] = entity;
            _deleted.Remove(entity.Uid); // Un-delete if was deleted
        }
    }

    public void DeleteUids(IEnumerable<string> uids)
    {
        foreach (var uid in uids)
        {
            _deleted.Add(uid);
            _modified.Remove(uid); // Remove from modified if was there
        }
    }

    public IEnumerable<T> GetAll()
    {
        foreach (var entity in _modified.Values)
        {
            yield return entity;   
        }
        foreach (var entity in _source.GetAll())
        {
            if (_deleted.Contains(entity.Uid)) continue;
            if (_modified.ContainsKey(entity.Uid)) continue;
            
            yield return entity;
        }
    }
}

/// <summary>
/// Cached wrapper for ILinkStorage - tracks individual link modifications.
/// Uses tuple keys for type safety and cleaner code.
/// </summary>
public class SnapshotLinkStorage<T> : ILinkStorage<T> where T : IUidLink
{
    private readonly ILinkStorage<T> _source;
    private readonly Dictionary<(string SubjectUid, string ObjectUid), T> _modified = new();
    private readonly HashSet<(string SubjectUid, string ObjectUid)> _deleted = new();

    public SnapshotLinkStorage(ILinkStorage<T> source)
    {
        _source = source;
    }

    private static (string, string) GetLinkKey(IUidLink link)
    {
        return (link.SubjectUid, link.ObjectUid);
    }

    public T GetLink(IUidLink link)
    {
        var key = GetLinkKey(link);
        if (_deleted.Contains(key))
        {
            return default;
        }

        return _modified.TryGetValue(key, out var cached) ? cached : _source.GetLink(link);
    }

    public void PutLinks(IEnumerable<T> links)
    {
        foreach (var link in links)
        {
            var key = GetLinkKey(link);
            _modified[key] = link;
            _deleted.Remove(key); // Un-delete if was deleted
        }
    }

    public void DeleteLinks(IEnumerable<IUidLink> links)
    {
        foreach (var link in links)
        {
            var key = GetLinkKey(link);
            _deleted.Add(key);
            _modified.Remove(key); // Remove from modified if was there
        }
    }

    public void DeleteLinksForSubjects(IEnumerable<string> subjectUids)
    {
        // Query underlying storage to get actual links, then mark them deleted
        // This converts a bulk operation (delete all links for subject X)
        // into individual link deletions that can be tracked in _deleted set
        foreach (var subjectUid in subjectUids)
        {
            var links = _source.GetLinksForSubject(subjectUid);
            foreach (var link in links)
            {
                var key = GetLinkKey(link);
                _deleted.Add(key);
                _modified.Remove(key); // Remove from modified if present
            }
        }
    }

    public void DeleteLinksForObjects(IEnumerable<string> objectUids)
    {
        // Query underlying storage to get actual links, then mark them deleted
        // This converts a bulk operation (delete all links for object X)
        // into individual link deletions that can be tracked in _deleted set
        foreach (var objectUid in objectUids)
        {
            var links = _source.GetLinksForObject(objectUid);
            foreach (var link in links)
            {
                var key = GetLinkKey(link);
                _deleted.Add(key);
                _modified.Remove(key); // Remove from modified if present
            }
        }
    }

    public IEnumerable<T> GetLinksForSubject(string subjectUid)
    {
        foreach (var link in _modified.Values.Where(link => link.SubjectUid == subjectUid))
        {
            yield return link;
        }

        foreach (var link in _source.GetLinksForSubject(subjectUid))
        {
            var key = GetLinkKey(link);
            if (_deleted.Contains(key)) continue;
            if (_modified.ContainsKey(key)) continue;

            yield return link;
        }
    }

    public IEnumerable<T> GetLinksForObject(string objectUid)
    {
        foreach (var link in _modified.Values.Where(link => link.ObjectUid == objectUid))
        {
            yield return link;
        }

        foreach (var link in _source.GetLinksForObject(objectUid))
        {
            var key = GetLinkKey(link);
            if (_deleted.Contains(key)) continue;
            if (_modified.ContainsKey(key)) continue;

            yield return link;
        }
    }

    public IEnumerable<T> GetAllLinks()
    {
        foreach (var link in _modified.Values)
        {
            yield return link;
        }

        foreach (var link in _source.GetAllLinks())
        {
            var key = GetLinkKey(link);
            if (_deleted.Contains(key)) continue;
            if (_modified.ContainsKey(key)) continue;

            yield return link;
        }
    }
}