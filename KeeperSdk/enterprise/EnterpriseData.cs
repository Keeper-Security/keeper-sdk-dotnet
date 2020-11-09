using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Represents decrypted Enterprise data structure.
    /// </summary>
    public partial class EnterpriseData: IEnterprise
    {
        /// <summary>
        /// Gets Enterprise Tree encryption key.
        /// </summary>
        public byte[] TreeKey { get; private set; }

        /// <summary>
        /// Instantiates <see cref="EnterpriseData"/> instance.
        /// </summary>
        /// <param name="auth">Keeper authentication.</param>
        public EnterpriseData(IAuthentication auth)
        {
            Auth = auth;
        }

        internal readonly Dictionary<string, byte[]> UserPublicKeyCache = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

        private readonly ConcurrentDictionary<long, EnterpriseNode> _nodes = new ConcurrentDictionary<long, EnterpriseNode>();
        private readonly ConcurrentDictionary<long, EnterpriseUser> _users = new ConcurrentDictionary<long, EnterpriseUser>();
        private readonly ConcurrentDictionary<string, EnterpriseTeam> _teams = new ConcurrentDictionary<string, EnterpriseTeam>();
        private readonly ConcurrentDictionary<string, long> _userNames = new ConcurrentDictionary<string, long>(1, 100, StringComparer.InvariantCultureIgnoreCase);
        
        /// <summary>
        /// Retrieves Enterprise data structure.
        /// </summary>
        /// <returns>Awaitable task.</returns>
        public async Task GetEnterpriseData()
        {
            var rq = new GetEnterpriseDataCommand
            {
                include = new [] {"nodes", "users", "teams", "team_users" }
            };
            var rs = await Auth.ExecuteAuthCommand<GetEnterpriseDataCommand, GetEnterpriseDataResponse>(rq);

            var encTreeKey = rs.TreeKey.Base64UrlDecode();
            switch (rs.KeyTypeId)
            {
                case 1:
                    TreeKey = CryptoUtils.DecryptAesV1(encTreeKey, Auth.AuthContext.DataKey);
                    break;
                case 2:
                    TreeKey = CryptoUtils.DecryptRsa(encTreeKey, Auth.AuthContext.PrivateKey);
                    break;
                default:
                    throw new Exception("cannot decrypt tree key");
            }

            var ids = new HashSet<long>(_nodes.Keys);
            foreach (var n in rs.Nodes)
            {
                if (_nodes.TryGetValue(n.NodeId, out var node))
                {
                    ids.Remove(n.NodeId);
                    node.Subnodes.Clear();
                }
                else
                {
                    node = new EnterpriseNode {Id = n.NodeId};
                    _nodes.TryAdd(n.NodeId, node);
                }

                EnterpriseUtils.DecryptEncryptedData(n, TreeKey, node);

                if (n.ParentId.HasValue && n.ParentId.Value > 0)
                {
                    node.ParentNodeId = n.ParentId.Value;
                }
                else
                {
                    RootNode = node;
                    RootNode.DisplayName = rs.EnterpriseName;
                    node.ParentNodeId = 0;
                }
            }
            foreach (var id in ids)
            {
                _nodes.TryRemove(id, out _);
            }

            foreach (var node in _nodes.Values)
            {
                if (node.ParentNodeId <= 0) continue;
                if (_nodes.TryGetValue(node.ParentNodeId, out var parent))
                {
                    parent.Subnodes.Add(node.Id);
                }
            }

            if (rs.Users != null)
            {
                ids.Clear();
                ids.UnionWith(_users.Keys);
                foreach (var u in rs.Users)
                {
                    if (_users.TryGetValue(u.EnterpriseUserId, out var user))
                    {
                        ids.Remove(u.EnterpriseUserId);
                        user.Teams.Clear();
                    }
                    else
                    {
                        user = new EnterpriseUser
                        {
                            Id = u.EnterpriseUserId
                        };
                        _users.TryAdd(u.EnterpriseUserId, user);
                    }

                    user.ParentNodeId = u.NodeId;
                    user.Email = u.Username;
                    EnterpriseUtils.DecryptEncryptedData(u, TreeKey, user);

                    if (u.Status == "active")
                    {
                        switch (u.Lock)
                        {
                            case 0:
                                user.UserStatus = UserStatus.Active;
                                break;
                            case 1:
                                user.UserStatus = UserStatus.Locked;
                                break;
                            case 2:
                                user.UserStatus = UserStatus.Disabled;
                                break;
                            default:
                                user.UserStatus = UserStatus.Active;
                                break;
                        }
                        if (u.AccountShareExpiration.HasValue && u.AccountShareExpiration.Value > 0)
                        {
                            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                            if (now > (long) u.AccountShareExpiration.Value)
                            {
                                user.UserStatus = UserStatus.Blocked;
                            }
                        }
                    }
                    else
                    {
                        user.UserStatus = UserStatus.Inactive;
                    }
                }

                foreach (var id in ids)
                {
                    _users.TryRemove(id, out _);
                }
                _userNames.Clear();
                foreach (var u in rs.Users)
                {
                    _userNames.TryAdd(u.Username, u.EnterpriseUserId);
                }
            }

            if (rs.Teams != null)
            {
                var uids = new HashSet<string>();
                uids.UnionWith(_teams.Keys);
                foreach (var t in rs.Teams)
                {
                    if (_teams.TryGetValue(t.TeamUid, out var team))
                    {
                        uids.Remove(t.TeamUid);
                        team.Users.Clear();
                    }
                    else
                    {
                        team = new EnterpriseTeam
                        {
                            Uid = t.TeamUid
                        };
                        _teams.TryAdd(t.TeamUid, team);
                    }

                    team.Name = t.Name;

                    team.ParentNodeId = t.NodeId;
                    team.RestrictEdit = t.RestrictEdit;
                    team.RestrictSharing = t.RestrictSharing;
                    team.RestrictView = t.RestrictView;
                    if (!string.IsNullOrEmpty(t.EncryptedTeamKey))
                    {
                        try
                        {
                            team.TeamKey = CryptoUtils.DecryptAesV2(t.EncryptedTeamKey.Base64UrlDecode(), TreeKey);
                        }
                        catch (Exception e)
                        {
                            Debug.WriteLine(e.Message);
                        }
                    }
                }

                foreach (var uid in uids)
                {
                    _teams.TryRemove(uid, out _);
                }
            }

            if (rs.TeamUsers != null)
            {
                foreach (var tu in rs.TeamUsers)
                {
                    if (_users.TryGetValue(tu.EnterpriseUserId, out var user) && _teams.TryGetValue(tu.TeamUid, out var team))
                    {
                        team.Users.Add(user.Id);
                        user.Teams.Add(team.Uid);
                    }
                }
            }
        }

        /// <summary>
        /// Gets Keeper authentication.
        /// </summary>
        public IAuthentication Auth { get; }

        /// <summary>
        /// Gets list of all enterprise nodes 
        /// </summary>
        public IEnumerable<EnterpriseNode> Nodes => _nodes.Values;

        /// <summary>
        /// Gets the enterprise node associated with the specified ID.
        /// </summary>
        /// <param name="nodeId">Node Enterprise ID</param>
        /// <param name="node">When this method returns <c>true</c>, contains requested enterprise node; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a node with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetNode(long nodeId, out EnterpriseNode node)
        {
            return _nodes.TryGetValue(nodeId, out node);
        }
        /// <summary>
        /// Gets the number of all nodes in the enterprise.
        /// </summary>
        public int NodeCount => _nodes.Count;
        /// <summary>
        /// Gets the Enterprise Root Node.
        /// </summary>
        public EnterpriseNode RootNode { get; private set; }

        /// <summary>
        /// Get the list of all users in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseUser> Users => _users.Values;
        /// <summary>
        /// Gets the enterprise user associated with the specified ID.
        /// </summary>
        /// <param name="userId">User Enterprise ID</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetUserById(long userId, out EnterpriseUser user)
        {
            return _users.TryGetValue(userId, out user);
        }
        /// <summary>
        /// Gets the enterprise user associated with the specified email address.
        /// </summary>
        /// <param name="email">User Email Address.</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetUserByEmail(string email, out EnterpriseUser user)
        {
            if (!_userNames.TryGetValue(email, out var id))
            {
                user = null;
                return false;
            }

            return _users.TryGetValue(id, out user);
        }
        /// <summary>
        /// Gets the number of all users in the enterprise.
        /// </summary>
        public int UserCount => _users.Count;

        /// <summary>
        /// Get the list of all teams in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseTeam> Teams => _teams.Values;
        /// <summary>
        /// Gets the enterprise team associated with the specified team UID.
        /// </summary>
        /// <param name="teamUid">Team UID</param>
        /// <param name="team">When this method returns <c>true</c>, contains requested enterprise team; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a team with specified UID; otherwise, <c>false</c></returns>
        public bool TryGetTeam(string teamUid, out EnterpriseTeam team)
        {
            return _teams.TryGetValue(teamUid, out team);
        }
        /// <summary>
        /// Gets the number of all teams in the enterprise.
        /// </summary>
        public int TeamCount => _teams.Count;

    }
}
