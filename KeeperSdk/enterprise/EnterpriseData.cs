using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{

    /// <summary>
    ///     Represents decrypted basic Enterprise data structures: Nodes, Users, Teams
    /// </summary>
    public partial class EnterpriseData : EnterpriseDataPlugin, IEnterpriseData
    {
        /// <summary>
        /// Instantiates <see cref="EnterpriseData"/> instance.
        /// </summary>
        /// <param name="auth">Keeper authentication.</param>
        /// <param name="treeKey">Enterprise tree key. Optional.</param>
        public EnterpriseData()
        {
            _nodes = new NodeDictionary();
            _users = new UserDictionary();
            _teams = new TeamDictionary();
            _teamUsers = new TeamUserDataLink();
            _license = new LicenseSingleData();

            Entities = new IKeeperEnterpriseEntity[] { _nodes, _users, _teams, _teamUsers, _license };
        }

        /// <exclude/>
        [Obsolete]
        public EnterpriseData(IAuthentication Auth) : this()
        {
            new EnterpriseLoader(Auth, new[] { this });
        }

        internal readonly Dictionary<string, byte[]> UserPublicKeyCache = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

        private readonly NodeDictionary _nodes;
        private readonly UserDictionary _users;
        private readonly TeamDictionary _teams;
        private readonly TeamUserDataLink _teamUsers;
        private readonly LicenseSingleData _license;

        /// <exclude />
        public override IEnumerable<IKeeperEnterpriseEntity> Entities { get; }

        /// <summary>
        /// Gets list of all enterprise nodes 
        /// </summary>
        public IEnumerable<EnterpriseNode> Nodes => _nodes.Entities;

        /// <summary>
        /// Gets the enterprise node associated with the specified ID.
        /// </summary>
        /// <param name="nodeId">Node Enterprise ID</param>
        /// <param name="node">When this method returns <c>true</c>, contains requested enterprise node; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a node with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetNode(long nodeId, out EnterpriseNode node)
        {
            return _nodes.TryGetEntity(nodeId, out node);
        }
        /// <summary>
        /// Gets the number of all nodes in the enterprise.
        /// </summary>
        public int NodeCount => _nodes.Count;

        /// <summary>
        /// Gets the Enterprise Root Node.
        /// </summary>
        public EnterpriseNode RootNode => _nodes.RootNode;

        /// <summary>
        /// Get the list of all users in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseUser> Users => _users.Entities;
        /// <summary>
        /// Gets the enterprise user associated with the specified ID.
        /// </summary>
        /// <param name="userId">User Enterprise ID</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetUserById(long userId, out EnterpriseUser user)
        {
            return _users.TryGetEntity(userId, out user);
        }
        /// <summary>
        /// Gets the enterprise user associated with the specified email address.
        /// </summary>
        /// <param name="email">User Email Address.</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetUserByEmail(string email, out EnterpriseUser user)
        {
            return _users.TryGetUserByEmail(email, out user);
        }
        /// <summary>
        /// Gets the number of all users in the enterprise.
        /// </summary>
        public int UserCount => _users.Count;

        /// <summary>
        /// Get the list of all teams in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseTeam> Teams => _teams.Entities;
        /// <summary>
        /// Gets the enterprise team associated with the specified team UID.
        /// </summary>
        /// <param name="teamUid">Team UID</param>
        /// <param name="team">When this method returns <c>true</c>, contains requested enterprise team; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a team with specified UID; otherwise, <c>false</c></returns>
        public bool TryGetTeam(string teamUid, out EnterpriseTeam team)
        {
            return _teams.TryGetEntity(teamUid, out team);
        }
        /// <summary>
        /// Gets the number of all teams in the enterprise.
        /// </summary>
        public int TeamCount => _teams.Count;

        /// <summary>
        /// Gets a list of user IDs for specified team.
        /// </summary>
        /// <param name="teamUid">Team UID.</param>
        /// <returns>A list of user IDs</returns>
        public long[] GetUsersForTeam(string teamUid) 
        {
            return _teamUsers.LinksForPrimaryKey(teamUid).Select(x => x.EnterpriseUserId).ToArray();
        }

        /// <summary>
        /// Gets a list of team UID for the specified user.
        /// </summary>
        /// <param name="userId">Enterprise User ID.</param>
        /// <returns>A list of team UIDs.</returns>
        public string[] GetTeamsForUser(long userId)
        {
            return _teamUsers.LinksForSecondaryKey(userId).Select(x => x.TeamUid.ToByteArray().Base64UrlEncode()).ToArray();
        }

        /// <exclude/>
        public License EnterpriseLicense => _license.Entity;

        /// <exclude/>
        [Obsolete]
        public async Task PopulateEnterprise() 
        {
            await Enterprise.Load();
        }
    }

    /// <exclude/>
    public class NodeDictionary : EnterpriseDataDictionary<long, Node, EnterpriseNode>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        public EnterpriseNode RootNode { get; private set; }

        public NodeDictionary() : base(EnterpriseDataEntity.Nodes)
        {
        }

        protected override long GetEntityId(Node keeperData)
        {
            return keeperData.NodeId;
        }

        protected override void SetEntityId(EnterpriseNode entity, long id)
        {
            entity.Id = id;
        }

        public override void Clear()
        {
            base.Clear();

            RootNode = null;
        }

        protected override void PopulateSdkFromKeeper(EnterpriseNode sdk, Node keeper)
        {
            sdk.ParentNodeId = keeper.ParentId;
            sdk.RestrictVisibility = keeper.RestrictVisibility;
            var enterprise = GetEnterprise?.Invoke();
            if (enterprise != null && enterprise.TreeKey != null)
            {
                EnterpriseUtils.DecryptEncryptedData(keeper.EncryptedData, enterprise.TreeKey, sdk);
            }
        }

        protected override void DataStructureChanged()
        {
            foreach (var node in _entities.Values)
            {
                node.Subnodes.Clear();
                if (node.ParentNodeId == 0)
                {
                    RootNode = node;
                }
            }
            foreach (var node in _entities.Values)
            {
                if (_entities.TryGetValue(node.ParentNodeId, out var pNode))
                {
                    pNode.Subnodes.Add(node.Id);
                }
            }

            if (string.IsNullOrEmpty(RootNode?.DisplayName))
            {
                var enterprise = GetEnterprise?.Invoke();
                if (enterprise != null)
                {
                    RootNode.DisplayName = enterprise.EnterpriseName;
                }
            }
        }
    }

    /// <exclude />
    public class UserDictionary : EnterpriseDataDictionary<long, User, EnterpriseUser>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        private readonly ConcurrentDictionary<string, long> _userNames = new ConcurrentDictionary<string, long>(1, 100, StringComparer.InvariantCultureIgnoreCase);

        public UserDictionary() : base(EnterpriseDataEntity.Users)
        {
        }

        protected override long GetEntityId(User keeperData)
        {
            return keeperData.EnterpriseUserId;
        }

        protected override void SetEntityId(EnterpriseUser entity, long id)
        {
            entity.Id = id;
        }

        public override void Clear()
        {
            base.Clear();

            _userNames.Clear();
        }

        protected override void PopulateSdkFromKeeper(EnterpriseUser sdk, User keeper)
        {
            sdk.ParentNodeId = keeper.NodeId;
            sdk.ParentNodeId = keeper.NodeId;
            sdk.Email = keeper.Username;
            if (keeper.Status == "active")
            {
                switch (keeper.Lock)
                {
                    case 0:
                    sdk.UserStatus = UserStatus.Active;
                    break;
                    case 1:
                    sdk.UserStatus = UserStatus.Locked;
                    break;
                    case 2:
                    sdk.UserStatus = UserStatus.Disabled;
                    break;
                    default:
                    sdk.UserStatus = UserStatus.Active;
                    break;
                }

                if (keeper.AccountShareExpiration > 0)
                {
                    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    if (now > keeper.AccountShareExpiration)
                    {
                        sdk.UserStatus = UserStatus.Blocked;
                    }
                }
            }
            else
            {
                sdk.UserStatus = UserStatus.Inactive;
            }

            var enterprise = GetEnterprise?.Invoke();
            if (enterprise != null && enterprise.TreeKey != null)
            {
                EnterpriseUtils.DecryptEncryptedData(keeper.EncryptedData, enterprise.TreeKey, sdk);
            }
        }

        public bool TryGetUserByEmail(string email, out EnterpriseUser user)
        {
            user = null;
            if (_userNames.TryGetValue(email, out var id))
            {
                return _entities.TryGetValue(id, out user);
            }

            return false;
        }

        protected override void DataStructureChanged()
        {
            _userNames.Clear();
            foreach (var user in _entities.Values)
            {
                _userNames.TryAdd(user.Email, user.Id);
            }
        }
    }

    /// <exclude />
    public class TeamDictionary : EnterpriseDataDictionary<string, Team, EnterpriseTeam>, IGetEnterprise
    {
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        public TeamDictionary() : base(EnterpriseDataEntity.Teams)
        {
        }

        protected override string GetEntityId(Team keeperData)
        {
            return keeperData.TeamUid.ToByteArray().Base64UrlEncode();
        }

        protected override void SetEntityId(EnterpriseTeam entity, string uid)
        {
            entity.Uid = uid;
        }

        protected override void PopulateSdkFromKeeper(EnterpriseTeam sdk, Team keeper)
        {
            sdk.ParentNodeId = keeper.NodeId;
            sdk.RestrictEdit = keeper.RestrictEdit;
            sdk.RestrictSharing = keeper.RestrictShare;
            sdk.RestrictView = keeper.RestrictView;
            sdk.Name = keeper.Name;

            if (!string.IsNullOrEmpty(keeper.EncryptedTeamKey))
            {
                var enterprise = GetEnterprise?.Invoke();
                if (enterprise != null && enterprise.TreeKey != null)
                {
                    try
                    {
                        sdk.TeamKey = CryptoUtils.DecryptAesV2(keeper.EncryptedTeamKey.Base64UrlDecode(), enterprise.TreeKey);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }
            }
        }
    }

    /// <exclude />
    public class TeamUserDataLink : EnterpriseDataLink<TeamUser, TeamUser, string, long>
    {
        public TeamUserDataLink() : base(EnterpriseDataEntity.TeamUsers)
        {
        }

        protected override TeamUser CreateFromKeeperEntity(TeamUser keeperEntity)
        {
            return keeperEntity;
        }

        protected override string GetEntity1Id(TeamUser keeperData)
        {
            return keeperData.TeamUid.ToByteArray().Base64UrlEncode();
        }
        protected override long GetEntity2Id(TeamUser keeperData)
        {
            return keeperData.EnterpriseUserId;
        }
    }

    /// <exclude />
    public class LicenseSingleData : EnterpriseSingleData<License, License>
    {
        public LicenseSingleData() : base(EnterpriseDataEntity.Licenses) { }
        protected override License GetSdkFromKeeper(License keeper)
        {
            return keeper;
        }
    }
}
