using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperEnterpriseData = Enterprise.EnterpriseData;

namespace Commander.Enterprise
{
    public class EnterpriseQueuedTeam : IParentNodeEntity
    {
        public string Uid { get; internal set; }
        public string Name { get; set; }
        public long ParentNodeId { get; internal set; }
    }

    public class EnterpriseQueuedUsers
    {
        public string TeamUid { get; internal set; }
        public ISet<long> UserIDs { get; } = new HashSet<long>();
    }

    public interface IQueuedTeamData
    {
        IEnumerable<EnterpriseQueuedTeam> QueuedTeams { get; }
        IEnumerable<long> GetQueuedUsersForTeam(string teamUid);
    }

    public interface IQueuedTeamDataManagement
    {
        Task QueueUserToTeam(long enterpriseUserId, string teamUid);
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
        public IEnumerable<long> GetQueuedUsersForTeam(string teamUid)
        {
            if (_queuedUsers.TryGetEntity(teamUid, out var users))
            {
                return users.UserIDs;
            }
            return Enumerable.Empty<long>();
        }
    }

    public class QueuedTeamDataManagement : QueuedTeamData, IQueuedTeamDataManagement
    {
        public async Task QueueUserToTeam(long enterpriseUserId, string teamUid)
        {
            var rq = new TeamQueueUserCommand
            {
                TeamUid = teamUid,
                EnterpriseUserId = enterpriseUserId
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
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
        }
    }

    public class QueuedUserDictionary : KeeperEnterpriseDataEntity<QueuedTeamUser>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        internal readonly ConcurrentDictionary<string, EnterpriseQueuedUsers> _entities = new ConcurrentDictionary<string, EnterpriseQueuedUsers>();

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
                    sdkEntity = new EnterpriseQueuedUsers
                    {
                        TeamUid = id
                    };
                    _entities.TryAdd(id, sdkEntity);
                }

                foreach (var userId in keeperEntity.Users)
                {
                    if (entityData.Delete)
                    {
                        sdkEntity.UserIDs.Remove(userId);
                    }
                    else
                    {
                        sdkEntity.UserIDs.Add(userId);
                    }
                }

                if (sdkEntity.UserIDs.Count == 0)
                {
                    _entities.TryRemove(id, out _);
                }
            }
            DataStructureChanged();
        }

        public bool TryGetEntity(string key, out EnterpriseQueuedUsers entity)
        {
            return _entities.TryGetValue(key, out entity);
        }


        public override void Clear()
        {
            _entities.Clear();
        }
    }
}
