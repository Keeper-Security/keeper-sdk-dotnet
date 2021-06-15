using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Represents decrypted Enterprise data structure.
    /// </summary>
    public partial class EnterpriseData : IEnterprise
    {
        /// <summary>
        /// Gets enterprise data
        /// </summary>
        public string EnterpriseName { get; private set; }

        /// <summary>
        /// Gets Enterprise Tree encryption key.
        /// </summary>
        public byte[] TreeKey { get; private set; }


        /// <exclude/>
        public byte[] RsaPrivateKey { get; set; }

        /// <exclude/>
        public byte[] EcPrivateKey { get; set; }

        private byte[] _continuationToken;

        /// <summary>
        /// Instantiates <see cref="EnterpriseData"/> instance.
        /// </summary>
        /// <param name="auth">Keeper authentication.</param>
        /// <param name="treeKey">Enterprise tree key. Optional.</param>
        public EnterpriseData(IAuthentication auth, byte[] treeKey = null)
        {
            Auth = auth;
            TreeKey = treeKey;
            _continuationToken = new byte[0];
        }

        internal readonly Dictionary<string, byte[]> UserPublicKeyCache = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);

        internal readonly ConcurrentDictionary<long, EnterpriseNode> _nodes = new ConcurrentDictionary<long, EnterpriseNode>();
        private readonly ConcurrentDictionary<long, EnterpriseRole> _roles = new ConcurrentDictionary<long, EnterpriseRole>();
        private readonly ConcurrentDictionary<long, EnterpriseUser> _users = new ConcurrentDictionary<long, EnterpriseUser>();
        private readonly ConcurrentDictionary<string, EnterpriseTeam> _teams = new ConcurrentDictionary<string, EnterpriseTeam>();
        private readonly ConcurrentDictionary<string, long> _userNames = new ConcurrentDictionary<string, long>(1, 100, StringComparer.InvariantCultureIgnoreCase);
        private readonly List<DeviceRequestForAdminApproval> _adminApprovals = new List<DeviceRequestForAdminApproval>();
        private readonly ConcurrentDictionary<int, EnterpriseManagedCompany> _managedCompanies = new ConcurrentDictionary<int, EnterpriseManagedCompany>();

        /// <summary>
        /// Retrieves Enterprise node structure.
        /// </summary>
        /// <returns>Awaitable task.</returns>
        public async Task PopulateEnterprise()
        {
            if (TreeKey == null)
            {
                var krq = new GetEnterpriseDataKeysRequest();
                var krs = await Auth.ExecuteAuthRest<GetEnterpriseDataKeysRequest, GetEnterpriseDataKeysResponse>("enterprise/get_enterprise_data_keys", krq);
                var encTreeKey = krs.TreeKey.TreeKey_.Base64UrlDecode();
                switch (krs.TreeKey.KeyTypeId)
                {
                    case BackupKeyType.EncryptedByDataKey:
                        TreeKey = CryptoUtils.DecryptAesV1(encTreeKey, Auth.AuthContext.DataKey);
                        break;
                    case BackupKeyType.EncryptedByPublicKey:
                        if (encTreeKey.Length > 60)
                        {
                            TreeKey = CryptoUtils.DecryptRsa(encTreeKey, Auth.AuthContext.PrivateKey);
                        }
                        break;
                    default:
                        throw new Exception("cannot decrypt tree key");
                }

                if (krs.EnterpriseKeys != null)
                {
                    if (!krs.EnterpriseKeys.RsaEncryptedPrivateKey.IsEmpty)
                    {
                        RsaPrivateKey = CryptoUtils.DecryptAesV2(krs.EnterpriseKeys.RsaEncryptedPrivateKey.ToByteArray(), TreeKey);
                    }
                    if (!krs.EnterpriseKeys.EccEncryptedPrivateKey.IsEmpty)
                    {
                        EcPrivateKey = CryptoUtils.DecryptAesV2(krs.EnterpriseKeys.EccEncryptedPrivateKey.ToByteArray(), TreeKey);
                    }
                }
            }

            var nodesChanged = false;
            var usersChanged = false;

            var done = false;
            while (!done)
            {
                var rrq = new EnterpriseDataRequest
                {
                    ContinuationToken = Google.Protobuf.ByteString.CopyFrom(_continuationToken)
                };
                var rrs = await Auth.ExecuteAuthRest<EnterpriseDataRequest, EnterpriseDataResponse>("enterprise/get_enterprise_data_for_user", rrq);
                if (rrs.CacheStatus == CacheStatus.Clear)
                {
                    _nodes.Clear();
                    _roles.Clear();
                    _users.Clear();
                    _teams.Clear();
                    _userNames.Clear();
                }
                if (rrs.GeneralData != null)
                {
                }
                done = !rrs.HasMore;
                _continuationToken = rrs.ContinuationToken.ToByteArray();
                if (string.IsNullOrEmpty(EnterpriseName) && rrs.GeneralData != null)
                {
                    EnterpriseName = rrs.GeneralData.EnterpriseName;
                }

                foreach (var entityData in rrs.Data)
                {
                    switch (entityData.Entity)
                    {
                        case EnterpriseDataEntity.Nodes:
                            {
                                nodesChanged = true;
                                foreach (var data in entityData.Data)
                                {
                                    var node = Node.Parser.ParseFrom(data);
                                    if (entityData.Delete)
                                    {
                                        _nodes.TryRemove(node.NodeId, out _);
                                    }
                                    else
                                    {
                                        if (!_nodes.TryGetValue(node.NodeId, out var n))
                                        {
                                            n = new EnterpriseNode
                                            {
                                                Id = node.NodeId,
                                            };
                                            _nodes.TryAdd(node.NodeId, n);
                                        }
                                        n.ParentNodeId = node.ParentId;
                                        n.RestrictVisibility = node.RestrictVisibility;
                                        EnterpriseUtils.DecryptEncryptedData(node.EncryptedData, TreeKey, n);
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.Users:
                            {
                                usersChanged = true;
                                foreach (var data in entityData.Data)
                                {
                                    var user = User.Parser.ParseFrom(data);
                                    if (entityData.Delete)
                                    {
                                        _users.TryRemove(user.EnterpriseUserId, out _);
                                    }
                                    else
                                    {
                                        if (!_users.TryGetValue(user.EnterpriseUserId, out var u))
                                        {
                                            u = new EnterpriseUser
                                            {
                                                Id = user.EnterpriseUserId,
                                            };
                                            _users.TryAdd(u.Id, u);
                                        }

                                        u.ParentNodeId = user.NodeId;
                                        u.Email = user.Username;
                                        EnterpriseUtils.DecryptEncryptedData(user.EncryptedData, TreeKey, u);
                                        if (user.Status == "active")
                                        {
                                            switch (user.Lock)
                                            {
                                                case 0:
                                                    u.UserStatus = UserStatus.Active;
                                                    break;
                                                case 1:
                                                    u.UserStatus = UserStatus.Locked;
                                                    break;
                                                case 2:
                                                    u.UserStatus = UserStatus.Disabled;
                                                    break;
                                                default:
                                                    u.UserStatus = UserStatus.Active;
                                                    break;
                                            }

                                            if (user.AccountShareExpiration > 0)
                                            {
                                                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                                                if (now > user.AccountShareExpiration)
                                                {
                                                    u.UserStatus = UserStatus.Blocked;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            u.UserStatus = UserStatus.Inactive;
                                        }
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.Teams:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var team = Team.Parser.ParseFrom(data);
                                    var teamUid = team.TeamUid.ToByteArray().Base64UrlEncode();
                                    if (entityData.Delete)
                                    {
                                        _teams.TryRemove(teamUid, out _);
                                    }
                                    else
                                    {
                                        if (!_teams.TryGetValue(teamUid, out var t))
                                        {
                                            t = new EnterpriseTeam
                                            {
                                                Uid = teamUid,
                                            };
                                            _teams.TryAdd(t.Uid, t);
                                        }

                                        t.ParentNodeId = team.NodeId;
                                        t.RestrictEdit = team.RestrictEdit;
                                        t.RestrictSharing = team.RestrictShare;
                                        t.RestrictView = team.RestrictView;
                                        t.Name = team.Name;

                                        if (!string.IsNullOrEmpty(team.EncryptedTeamKey))
                                        {
                                            try
                                            {
                                                t.TeamKey = CryptoUtils.DecryptAesV2(team.EncryptedTeamKey.Base64UrlDecode(), TreeKey);
                                            }
                                            catch (Exception e)
                                            {
                                                Debug.WriteLine(e.Message);
                                            }
                                        }
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.TeamUsers:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var teamUser = TeamUser.Parser.ParseFrom(data);
                                    var teamUid = teamUser.TeamUid.ToByteArray().Base64UrlEncode();

                                    if (_teams.TryGetValue(teamUid, out var team))
                                    {
                                        if (entityData.Delete)
                                        {
                                            team.Users.Remove(teamUser.EnterpriseUserId);
                                            if (_users.TryGetValue(teamUser.EnterpriseUserId, out var user))
                                                user.Teams.Remove(teamUid);
                                        }
                                        else
                                        {
                                            team.Users.Add(teamUser.EnterpriseUserId);
                                            if (_users.TryGetValue(teamUser.EnterpriseUserId, out var user))
                                                user.Teams.Add(teamUid);
                                        }
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.Roles:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var role = Role.Parser.ParseFrom(data);
                                    var roleId = role.RoleId;
                                    if (entityData.Delete)
                                    {
                                        _roles.TryRemove(roleId, out _);
                                    }
                                    else
                                    {
                                        if (!_roles.TryGetValue(roleId, out var t))
                                        {
                                            t = new EnterpriseRole { Id = roleId };
                                            _roles.TryAdd(roleId, t);
                                        }

                                        t.NodeId = role.NodeId;
                                        t.KeyType = role.KeyType;
                                        t.VisibleBelow = role.VisibleBelow;
                                        t.NewUserInherit = role.NewUserInherit;
                                        t.RoleType = role.RoleType;

                                        if (!string.IsNullOrEmpty(role.EncryptedData))
                                        {
                                            try
                                            {
                                                EnterpriseUtils.DecryptEncryptedData(role.EncryptedData, TreeKey, t);
                                            }
                                            catch (Exception e)
                                            {
                                                Debug.WriteLine(e.Message);
                                            }
                                        }
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.RoleUsers:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var roleUser = RoleUser.Parser.ParseFrom(data);
                                    if (_roles.TryGetValue(roleUser.RoleId, out var role))
                                    {
                                        if (entityData.Delete)
                                            role.Users.Remove(roleUser.EnterpriseUserId);
                                        else
                                            role.Users.Add(roleUser.EnterpriseUserId);
                                    }
                                    else
                                    {
                                        Debug.WriteLine($"Skipped Enterprise User ID = {roleUser.EnterpriseUserId} for an unknown role ID: {roleUser.RoleId}");
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.RoleTeams:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var roleTeam = RoleTeam.Parser.ParseFrom(data);
                                    var teamUid = roleTeam.TeamUid.ToByteArray().Base64UrlEncode();
                                    if (_roles.TryGetValue(roleTeam.RoleId, out var role))
                                    {
                                        if (entityData.Delete)
                                        {
                                            role.Teams.Remove(teamUid);
                                        }
                                        else
                                        {
                                            role.Teams.Add(teamUid);
                                        }
                                    }
                                    else
                                    {
                                        Debug.WriteLine($"Skipped Team UID = {teamUid} for an unknown role ID: {roleTeam.RoleId}");
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.RoleEnforcements:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var roleEnforcement = RoleEnforcement.Parser.ParseFrom(data);
                                    if (_roles.TryGetValue(roleEnforcement.RoleId, out var role))
                                    {
                                        if (entityData.Delete)
                                        {
                                            role.Enforcements.Remove(roleEnforcement.EnforcementType);
                                        }
                                        else
                                        {
                                            if (role.Enforcements.ContainsKey(roleEnforcement.EnforcementType))
                                                role.Enforcements[roleEnforcement.EnforcementType] = roleEnforcement.Value;
                                            else
                                                role.Enforcements.Add(roleEnforcement.EnforcementType, roleEnforcement.Value);
                                        }
                                    }
                                    else
                                    {
                                        Debug.WriteLine($"Skipped RoleEnforcement = {roleEnforcement.EnforcementType} for an unknown role ID: {roleEnforcement.RoleId}");
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.RolePrivileges:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var rolePrivilege = RolePrivilege.Parser.ParseFrom(data);
                                    if (_roles.TryGetValue(rolePrivilege.RoleId, out var role))
                                    {
                                        if (!role.ManagedNodes.TryGetValue(rolePrivilege.ManagedNodeId, out var _))
                                            role.ManagedNodes.Add(rolePrivilege.ManagedNodeId, new HashSet<string>());
                                        if (role.ManagedNodes.TryGetValue(rolePrivilege.ManagedNodeId, out var p))
                                        {
                                            if (entityData.Delete)
                                            {
                                                p?.Remove(rolePrivilege.PrivilegeType);
                                            }
                                            else
                                            {
                                                if (p == null)
                                                    p = new HashSet<string>();
                                                p.Add(rolePrivilege.PrivilegeType);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        Debug.WriteLine($"Skipped Role Privelege = {rolePrivilege.PrivilegeType} for an unknown role ID: {rolePrivilege.RoleId}");
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.DevicesRequestForAdminApproval:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var ar = DeviceRequestForAdminApproval.Parser.ParseFrom(data);

                                    if (entityData.Delete)
                                    {
                                        _adminApprovals.RemoveAll(x => x.DeviceId == ar.DeviceId && x.EnterpriseUserId == ar.EnterpriseUserId);
                                    }
                                    else
                                    {
                                        _adminApprovals.Add(ar);
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.ManagedCompanies:
                            {
                                foreach (var data in entityData.Data)
                                {
                                    var mc = ManagedCompany.Parser.ParseFrom(data);

                                    if (entityData.Delete)
                                    {
                                        _managedCompanies.TryRemove(mc.McEnterpriseId, out _);
                                    }
                                    else
                                    {
                                        if (!_managedCompanies.TryGetValue(mc.McEnterpriseId, out var eCompany))
                                        {
                                            eCompany = new EnterpriseManagedCompany()
                                            {
                                                EnterpriseId = mc.McEnterpriseId
                                            };
                                            _managedCompanies.TryAdd(eCompany.EnterpriseId, eCompany);
                                        }
                                        eCompany.EnterpriseName = mc.McEnterpriseName;
                                        eCompany.ProductId = mc.ProductId;
                                        eCompany.NumberOfSeats = mc.NumberOfSeats;
                                        eCompany.NumberOfUsers = mc.NumberOfUsers;
                                        eCompany.ParentNodeId = mc.MspNodeId;
                                        eCompany.IsExpired = mc.IsExpired;
                                    }
                                }
                            }
                            break;

                        case EnterpriseDataEntity.Licenses:
                            {
                                if (!entityData.Delete)
                                {
                                    foreach (var data in entityData.Data)
                                    {
                                        EnterpriseLicense = License.Parser.ParseFrom(data);
                                    }
                                }
                            }
                            break;
                    }
                }
            }

            if (nodesChanged)
            {
                foreach (var node in _nodes.Values)
                {
                    node.Subnodes.Clear();
                    if (node.ParentNodeId == 0)
                    {
                        RootNode = node;
                        RootNode.DisplayName = EnterpriseName;
                    }
                }
                foreach (var node in _nodes.Values)
                {
                    if (_nodes.TryGetValue(node.ParentNodeId, out var pNode))
                    {
                        pNode.Subnodes.Add(node.Id);
                    }
                }
            }

            if (usersChanged)
            {
                _userNames.Clear();
                foreach (var user in _users.Values)
                {
                    _userNames.TryAdd(user.Email, user.Id);
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
        /// <returns><c>true</c> if the enterprise contains a node with specified ID; otherwise, <c>false</c></returns>
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
        /// <returns><c>true</c> if the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetUserById(long userId, out EnterpriseUser user)
        {
            return _users.TryGetValue(userId, out user);
        }
        /// <summary>
        /// Gets the enterprise user associated with the specified email address.
        /// </summary>
        /// <param name="email">User Email Address.</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
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
        /// <returns><c>true</c> if the enterprise contains a team with specified UID; otherwise, <c>false</c></returns>
        public bool TryGetTeam(string teamUid, out EnterpriseTeam team)
        {
            return _teams.TryGetValue(teamUid, out team);
        }
        /// <summary>
        /// Gets the number of all teams in the enterprise.
        /// </summary>
        public int TeamCount => _teams.Count;

        /// <summary>
        /// Get the list of all roles in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseRole> Roles => _roles.Values;
        /// <summary>
        /// Gets the enterprise role associated with the specified role ID.
        /// </summary>
        /// <param name="roleId">Role ID</param>
        /// <param name="role">When this method returns <c>true</c>, contains requested enterprise role; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a role with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetRole(long roleId, out EnterpriseRole role)
        {
            return _roles.TryGetValue(roleId, out role);
        }
        /// <summary>
        /// Gets the number of all roles in the enterprise.
        /// </summary>
        public int RoleCount => _roles.Count;

        /// <summary>
        /// Get the list of all managed companies in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseManagedCompany> ManagedCompanies => _managedCompanies.Values;

        /// <exclude/>
        public License EnterpriseLicense { get; internal set; }

        /// <exclude/>
        public DeviceRequestForAdminApproval[] GetDeviceApprovalRequests()
        {
            lock (_adminApprovals)
            {
                return _adminApprovals.ToArray();
            }
        }

        private readonly ConcurrentBag<long> _availableIds = new ConcurrentBag<long>();
        internal async Task<long> GetEnterpriseId()
        {
            if (_availableIds.TryTake(out var id))
            {
                return id;
            }

            var rs = await Auth.ExecuteAuthCommand<EnterpriseAllocateIdsCommand, EnterpriseAllocateIdsResponse>(new EnterpriseAllocateIdsCommand());
            if (rs.IsSuccess)
            {
                for (int i = 1; i < rs.NumberAllocated; i++)
                {
                    _availableIds.Add(rs.BaseId + i);
                }
                return rs.BaseId;
            }
            throw new Exception("Unable to allocate enterprise ID");
        }
    }
}
