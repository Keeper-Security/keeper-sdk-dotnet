using Enterprise;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using KeeperEnterpriseData = Enterprise.EnterpriseData;


namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public interface IUserAliasData
    {
        IEnumerable<string> GetAliasesForUser(long userId);
    }

    /// <exclude />
    public class UserAliasData : EnterpriseDataPlugin, IUserAliasData
    {
        private readonly EnterpriseUserAliasDictionary _aliases = new EnterpriseUserAliasDictionary();

        public UserAliasData()
        {
            Entities = new[] { _aliases };
        }
        public IEnumerable<string> GetAliasesForUser(long userId)
        {
            if (_aliases.TryGetEntity(userId, out var entity))
            {
                return entity;
            }
            return Enumerable.Empty<string>();
        }

        public override IEnumerable<IKeeperEnterpriseEntity> Entities { get; }
    }

    /// <exclude />
    public class EnterpriseUserAliasDictionary : KeeperEnterpriseDataEntity<UserAlias>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        internal readonly ConcurrentDictionary<long, ISet<string>> _entities = new ConcurrentDictionary<long, ISet<string>>();

        public EnterpriseUserAliasDictionary() : base(EnterpriseDataEntity.UserAliases)
        {
        }

        public override void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData)
        {
            foreach (var data in entityData.Data)
            {
                var keeperEntity = Parse(data);
                var id = keeperEntity.EnterpriseUserId;
                if (!_entities.TryGetValue(id, out var sdkEntity))
                {
                    sdkEntity = new HashSet<string>();
                    _entities.TryAdd(id, sdkEntity);
                }

                if (entityData.Delete)
                {
                    sdkEntity.Remove(keeperEntity.Username);
                    if (sdkEntity.Count == 0)
                    {
                        _entities.TryRemove(id, out _);
                    }
                }
                else
                {
                    sdkEntity.Add(keeperEntity.Username);
                }
            }
            DataStructureChanged();
        }

        public bool TryGetEntity(long userId, out ISet<string> entity)
        {
            return _entities.TryGetValue(userId, out entity);
        }


        public override void Clear()
        {
            _entities.Clear();
        }

        public IEnumerable<long> UserIDs => _entities.Keys;

        public int Count => _entities.Count;

    }
}
