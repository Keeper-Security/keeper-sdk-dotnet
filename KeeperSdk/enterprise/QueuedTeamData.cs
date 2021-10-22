using Enterprise;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using KeeperEnterpriseData = Enterprise.EnterpriseData;

namespace KeeperSecurity.Enterprise
{
    public interface IQueuedTeamData
    {
        IEnumerable<EnterpriseQueuedTeam> QueuedTeams { get; }
        IEnumerable<long> GetQueuedUsersForTeam(string teamUid);
    }

    public class EnterpriseQueuedTeam : IParentNodeEntity, IEncryptedData
    {
        public string Uid { get; internal set; }
        public string Name { get; set; }
        public long ParentNodeId { get; internal set; }

        public string EncryptedData { get; internal set; }
    }

    public class QueuedTeamData : EnterpriseDataPlugin, IQueuedTeamData
    {
        private readonly QueuedTeamDictionary _queuedTeams;
        private readonly QueuedUserDictionary _queuedUsers;

        public QueuedTeamData() : base()
        {
            _queuedTeams = new QueuedTeamDictionary();
            _queuedUsers = new QueuedUserDictionary();

            Entities = new IKeeperEnterpriseEntity[] { _queuedTeams, _queuedUsers };
        }

        public override IEnumerable<IKeeperEnterpriseEntity> Entities { get; }

        public IEnumerable<EnterpriseQueuedTeam> QueuedTeams => _queuedTeams.Entities;
        public int QueuedTeamCount => _queuedTeams.Count;

        public IEnumerable<long> GetQueuedUsersForTeam(string teamUid)
        {
            if (_queuedUsers.TryGetMembers(teamUid, out var users))
            {
                return users;
            }
            return Enumerable.Empty<long>();
        }
    }

    public class QueuedTeamDictionary : EnterpriseDataDictionary<string, QueuedTeam, EnterpriseQueuedTeam>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        public QueuedTeamDictionary() : base(EnterpriseDataEntity.QueuedTeams)
        {
        }

        protected override string GetEntityId(QueuedTeam keeperData)
        {
            return keeperData.TeamUid.ToByteArray().Base64UrlEncode();
        }

        protected override void SetEntityId(EnterpriseQueuedTeam entity, string uid)
        {
            entity.Uid = uid;
        }

        protected override void PopulateSdkFromKeeper(EnterpriseQueuedTeam sdk, QueuedTeam keeper)
        {
            sdk.Name = keeper.Name;
            sdk.ParentNodeId = keeper.NodeId;
            sdk.EncryptedData = keeper.EncryptedData;
        }
    }

    public class QueuedUserDictionary : KeeperEnterpriseDataEntity<QueuedTeamUser>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        internal readonly ConcurrentDictionary<string, ISet<long>> _entities = new ConcurrentDictionary<string, ISet<long>>();

        public QueuedUserDictionary() : base(EnterpriseDataEntity.QueuedTeamUsers)
        {
        }

        public override void ProcessKeeperEnterpriseData(KeeperEnterpriseData entityData)
        {
            foreach (var data in entityData.Data)
            {
                var keeperEntity = Parse(data);
                var id = keeperEntity.TeamUid.ToByteArray().Base64UrlEncode();
                if (!_entities.TryGetValue(id, out var sdkEntity))
                {
                    sdkEntity = new HashSet<long>();
                    _entities.TryAdd(id, sdkEntity);
                }

                foreach (var userId in keeperEntity.Users)
                {
                    if (entityData.Delete)
                    {
                        sdkEntity.Remove(userId);
                    }
                    else
                    {
                        sdkEntity.Add(userId);
                    }
                }

                if (sdkEntity.Count == 0)
                {
                    _entities.TryRemove(id, out _);
                }
            }
            DataStructureChanged();
        }

        public bool TryGetMembers(string key, out ISet<long> entity)
        {
            return _entities.TryGetValue(key, out entity);
        }


        public override void Clear()
        {
            _entities.Clear();
        }
    }
}
