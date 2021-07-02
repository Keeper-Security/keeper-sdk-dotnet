using Enterprise;
using Google.Protobuf;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using KeeperEnterpriseData = Enterprise.EnterpriseData;

namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public interface IKeeperEnterpriseEntity
    {
        EnterpriseDataEntity DataEntity { get; }
        void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData);
        void Clear();
    }

    /// <exclude />
    public abstract class KeeperEnterpriseDataEntity<TK> : IKeeperEnterpriseEntity
    where TK : IMessage<TK>
    {
        private readonly MessageParser<TK> _parser;

        public EnterpriseDataEntity DataEntity { get; }

        public KeeperEnterpriseDataEntity(EnterpriseDataEntity dataEntity)
        {
            DataEntity = dataEntity;

            var keeperType = typeof(TK);
            var parser = keeperType.GetProperty("Parser", BindingFlags.Static | BindingFlags.Public);
            if (parser == null) throw new Exception($"Cannot get Parser for {keeperType.Name} Google Profobuf class");
            _parser = (MessageParser<TK>)(parser.GetMethod.Invoke(null, null));
        }

        protected TK Parse(ByteString data)
        {
            return _parser.ParseFrom(data);
        }

        protected virtual void DataStructureChanged() { }

        public abstract void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData);
        public abstract void Clear();
    }

    /// <exclude />
    public interface IGetEnterprise
    {
        Func<IEnterpriseLoader> GetEnterprise { get; set; }
    }

    /// <exclude />
    public abstract class EnterpriseSingleData<TK, TS> : KeeperEnterpriseDataEntity<TK>
        where TK : IMessage<TK>
        where TS : class
    {
        public EnterpriseSingleData(EnterpriseDataEntity dataEntity) : base(dataEntity)
        {
        }

        public TS Entity { get; protected set; }

        protected abstract TS GetSdkFromKeeper(TK keeper);

        public override void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData)
        {
            if (entityData.Delete)
            {
                Entity = null;
            }
            else
            {
                var data = entityData.Data.LastOrDefault();
                if (data != null)
                {

                    Entity = GetSdkFromKeeper(Parse(data));
                }
            }
        }
        public override void Clear()
        {
            Entity = null;
        }
    }

    /// <exclude />
    public abstract class EnterpriseDataDictionary<TD, TK, TS> : KeeperEnterpriseDataEntity<TK>
        where TK : IMessage<TK>
        where TS : class, new()
    {
        internal readonly ConcurrentDictionary<TD, TS> _entities = new ConcurrentDictionary<TD, TS>();

        public EnterpriseDataDictionary(EnterpriseDataEntity dataEntity) : base(dataEntity)
        {
        }

        protected abstract void PopulateSdkFromKeeper(TS sdk, TK keeper);
        protected abstract void SetEntityId(TS entity, TD id);

        protected abstract TD GetEntityId(TK keeperData);

        public override void Clear()
        {
            _entities.Clear();
        }

        public bool TryGetEntity(TD key, out TS entity)
        {
            return _entities.TryGetValue(key, out entity);
        }

        public IEnumerable<TS> Entities => _entities.Values;

        public int Count => _entities.Count;

        public override void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData)
        {
            foreach (var data in entityData.Data)
            {
                var keeperEntity = Parse(data);
                var id = GetEntityId(keeperEntity);
                if (entityData.Delete)
                {
                    _entities.TryRemove(id, out _);
                }
                else
                {
                    if (!_entities.TryGetValue(id, out var sdkEntity))
                    {
                        sdkEntity = new TS();
                        SetEntityId(sdkEntity, id);
                        _entities.TryAdd(id, sdkEntity);
                    }

                    PopulateSdkFromKeeper(sdkEntity, keeperEntity);
                }
            }
            DataStructureChanged();
        }
    }

    /// <exclude />
    public abstract class EnterpriseDataList<TK, TS> : KeeperEnterpriseDataEntity<TK>
    where TK : IMessage<TK>
    where TS : class, new()
    {
        internal readonly List<TS> _entities = new List<TS>();

        protected abstract bool MatchByKeeperEntity(TS sdkEntity, TK keeperEntity);
        protected abstract TS CreateFromKeeperEntity(TK keeperEntity);

        public EnterpriseDataList(EnterpriseDataEntity dataEntity) : base(dataEntity)
        {
        }

        public override void Clear()
        {
            _entities.Clear();
        }

        public override void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData)
        {
            foreach (var data in entityData.Data)
            {
                var keeperEntity = Parse(data);
                if (entityData.Delete)
                {
                    lock (_entities)
                    {
                        _entities.RemoveAll((se) => MatchByKeeperEntity(se, keeperEntity));
                    }
                }
                else
                {
                    var se = CreateFromKeeperEntity(keeperEntity);
                    lock (_entities)
                    {
                        _entities.Add(se);
                    }
                }
            }
            DataStructureChanged();
        }

        public IEnumerable<TS> Entities => _entities;
    }

    /// <exclude />
    public abstract class EnterpriseDataLink<TK, TS, TD1, TD2> : KeeperEnterpriseDataEntity<TK>
        where TK : IMessage<TK>
        where TD1 : IComparable<TD1>
        where TD2 : IComparable<TD2>
    {

        private readonly Comparer<TS> comp1;
        private readonly Comparer<TS> comp2;

        protected readonly List<TS> _links = new List<TS>();

        public EnterpriseDataLink(EnterpriseDataEntity dataEntity) : base(dataEntity)
        {
            comp1 = Comparer<TS>.Create((x, y) => {
                var x1 = GetEntity1Id(x);
                var y1 = GetEntity1Id(y);
                return x1.CompareTo(y1);
            });

            comp2 = Comparer<TS>.Create((x, y) => {
                var x2 = GetEntity2Id(x);
                var y2 = GetEntity2Id(y);
                return x2.CompareTo(y2);
            });
        }

        protected abstract TD1 GetEntity1Id(TS keeperData);
        protected abstract TD2 GetEntity2Id(TS keeperData);
        protected abstract TS CreateFromKeeperEntity(TK keeperEntity);

        public override void Clear()
        {
            _links.Clear();
        }

        public IList<TS> LinksForPrimaryKey(TD1 primaryId)
        {
            lock (_links)
            {
                return _links.Where(x => GetEntity1Id(x).CompareTo(primaryId) == 0).ToList();
            }
        }

        public IList<TS> LinksForSecondaryKey(TD2 secondaryId)
        {
            lock (_links)
            {
                return _links.Where(x => GetEntity2Id(x).CompareTo(secondaryId) == 0).ToList();
            }
        }

        public IList<TS> GetAllLinks()
        {
            lock (_links)
            {
                return _links.ToArray();
            }
        }

        public override void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData)
        {
            foreach (var data in entityData.Data)
            {
                var keeperEntity = Parse(data);
                var sdkEntity = CreateFromKeeperEntity(keeperEntity);
                if (entityData.Delete)
                {
                    lock (_links)
                    {
                        _links.RemoveAll(x => GetEntity1Id(x).CompareTo(GetEntity1Id(sdkEntity)) == 0 && GetEntity2Id(x).CompareTo(GetEntity2Id(sdkEntity)) == 0);
                    }
                }
                else
                {
                    lock (_links)
                    {
                        _links.Add(sdkEntity);
                    }
                }
            }

            DataStructureChanged();
        }
    }

}
