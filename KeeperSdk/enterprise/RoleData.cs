using Enterprise;
using System;
using System.Collections.Generic;
using KeeperSecurity.Utils;
using System.Linq;
using System.Threading.Tasks;
using System.Diagnostics;
using KeeperSecurity.Authentication;

namespace KeeperSecurity.Enterprise
{
    public class RolePermissions
    {
        const string MANAGE_NODES = "MANAGE_NODES";
        const string MANAGE_USERS = "MANAGE_USER";
        const string MANAGE_ROLES = "MANAGE_ROLES";
        const string MANAGE_TEAMS = "MANAGE_TEAMS";
        const string MANAGE_AUDIT_REPORTS = "RUN_REPORTS";
        const string MANAGE_BRIDGE_SSO = "MANAGE_BRIDGE";
        const string APPROVE_DEVICE = "APPROVE_DEVICE";
        const string MANAGE_RECORD_TYPES = "MANAGE_RECORD_TYPES";
        const string RUN_COMPLIANCE_REPORTS = "RUN_COMPLIANCE_REPORTS";
        const string MANAGE_COMPANIES = "MANAGE_COMPANIES";
        const string TRANSFER_ACCOUNT = "TRANSFER_ACCOUNT";
        const string SHARE_ADMIN = "SHARING_ADMINISTRATOR";

        internal ISet<string> privileges = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
        public long RoleId { get; internal set; }
        public long NodeId { get; internal set; }
        public bool Cascade { get; internal set; }
        public bool ManageNodes => privileges.Contains(MANAGE_NODES);
        public bool ManageUsers => privileges.Contains(MANAGE_USERS);
        public bool ManageRoles => privileges.Contains(MANAGE_ROLES);
        public bool ManageTeams => privileges.Contains(MANAGE_TEAMS);
        public bool ManageAuditReports => privileges.Contains(MANAGE_AUDIT_REPORTS);
        public bool ManageBridgeSso => privileges.Contains(MANAGE_BRIDGE_SSO);
        public bool ApproveDevice => privileges.Contains(APPROVE_DEVICE);
        public bool ManageRecordTypes => privileges.Contains(MANAGE_RECORD_TYPES);
        public bool RunComplianceReports => privileges.Contains(RUN_COMPLIANCE_REPORTS);
        public bool ManageCompanies => privileges.Contains(MANAGE_COMPANIES);
        public bool TransferAccount => privileges.Contains(TRANSFER_ACCOUNT);
        public bool ShareAdmin => privileges.Contains(SHARE_ADMIN);
    }

    /// <summary>
    /// Defines Role enterprise data.
    /// </summary>
    public interface IRoleData 
    {
        /// <summary>
        /// Get a list of all roles in the enterprise
        /// </summary>
        IEnumerable<EnterpriseRole> Roles { get; }
        /// <summary>
        /// Gets the number of all roles in the enterprise.
        /// </summary>
        int RoleCount { get; }
        /// <summary>
        /// Gets the enterprise role assocoated with the specified ID.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID</param>
        /// <param name="role">When this method returns <c>true</c>, contains requested enterprise role; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a role with specified ID; otherwise, <c>false</c></returns>
        bool TryGetRole(long roleId, out EnterpriseRole role);
        /// <summary>
        /// Gets a list of user IDs for specified role.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>List of Enterprise User IDs.</returns>
        IEnumerable<long> GetUsersForRole(long roleId);
        /// <summary>
        /// Gets a list of role IDs for specified user.
        /// </summary>
        /// <param name="userId">Enterprise User ID.</param>
        /// <returns>List of Enterprise Role IDs</returns>
        IEnumerable<long> GetRolesForUser(long userId);
        /// <summary>
        /// Gets a list of team UIDs for specified role.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>List of Enterprise Team UIDs.</returns>
        IEnumerable<string> GetTeamsForRole(long roleId);
        /// <summary>
        /// Gets a list of role IDs for specified team.
        /// </summary>
        /// <param name="teamUid">Team UID.</param>
        /// <returns>List of Enterprise Role IDs</returns>
        IEnumerable<long> GetRolesForTeam(string teamUid);
        /// <summary>
        /// Gets a list of role enforcements for specified role.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>List of Role Enforcements</returns>
        IEnumerable<RoleEnforcement> GetEnforcementsForRole(long roleId);

        /// <summary>
        /// Gets a list of all administrative permissions
        /// </summary>
        /// <returns></returns>
        IEnumerable<RolePermissions> GetAdminPermissions();
        /// <summary>
        /// Gets a list administrative permissions for a role
        /// </summary>
        /// <param name="roleId"></param>
        /// <returns></returns>
        IEnumerable<RolePermissions> GetRolePermissions(long roleId);

        /// <summary>
        /// Gets role key.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>Role Key</returns>
        Task<byte[]> GetRoleKey(long roleId);
    }

    /// <summary>
    /// Represents Role enterprise data.
    /// </summary>
    public partial class RoleData : EnterpriseDataPlugin, IRoleData
    {
        private readonly RoleDictionary _roles = new RoleDictionary();
        private readonly RoleUserLink _roleUsers = new RoleUserLink();
        private readonly RoleTeamLink _roleTeams = new RoleTeamLink();
        private readonly RoleEnforcementLink _roleEnforcements = new RoleEnforcementLink();
        private readonly ManagedNodeLink _managedNodes = new ManagedNodeLink();
        private readonly RolePrivilegesList _rolePrivileges = new RolePrivilegesList();

        public RoleData()
        {
            Entities = new IKeeperEnterpriseEntity[] { _roles, _roleUsers, _roleTeams, _roleEnforcements, _managedNodes, _rolePrivileges };
        }

        /// <exclude/>
        public override IEnumerable<IKeeperEnterpriseEntity> Entities { get; }

        /// <inheritdoc/>
        public IEnumerable<EnterpriseRole> Roles => _roles.Entities;

        /// <inheritdoc/>
        public int RoleCount => _roles.Count;


        /// <inheritdoc/>
        public bool TryGetRole(long roleId, out EnterpriseRole role)
        {
            return _roles.TryGetEntity(roleId, out role);
        }

        /// <inheritdoc/>
        public IEnumerable<long> GetUsersForRole(long roleId)
        {
            return _roleUsers.LinksForPrimaryKey(roleId).Select(x => x.EnterpriseUserId);
        }

        /// <inheritdoc/>
        public IEnumerable<long> GetRolesForUser(long userId)
        {
            return _roleUsers.LinksForSecondaryKey(userId).Select(x => x.RoleId);
        }

        /// <inheritdoc/>
        public IEnumerable<string> GetTeamsForRole(long roleId)
        {
            return _roleTeams.LinksForPrimaryKey(roleId).Select(x => x.TeamUid.ToByteArray().Base64UrlEncode());
        }

        /// <inheritdoc/>
        public IEnumerable<long> GetRolesForTeam(string teamUid)
        {
            return _roleTeams.LinksForSecondaryKey(teamUid).Select(x => x.RoleId);
        }

        /// <inheritdoc/>
        public IEnumerable<RoleEnforcement> GetEnforcementsForRole(long roleId)
        {
            return _roleEnforcements.LinksForPrimaryKey(roleId);
        }

        internal RolePermissions GetRolePermission(ManagedNode managedNode) 
        {
            var rp = new RolePermissions
            {
                RoleId = managedNode.RoleId,
                NodeId = managedNode.ManagedNodeId,
                Cascade = managedNode.CascadeNodeManagement
            };

            foreach (var p in GetPrivilegesForRoleAndNode(rp.RoleId, rp.NodeId)) 
            {
                rp.privileges.Add(p.PrivilegeType);
            }
            return rp;
        }
        public IEnumerable<RolePermissions> GetAdminPermissions() 
        {
            foreach (var p in GetManagedNodes()) {
                yield return GetRolePermission(p);
            }
        }

        public IEnumerable<RolePermissions> GetRolePermissions(long roleId) 
        {
            foreach (var p in _managedNodes.LinksForPrimaryKey(roleId))
            {
                yield return GetRolePermission(p);
            }
        }

        /// <summary>
        /// Gets a list of privileges for specified role and node
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <param name="nodeId">Enterprise Node ID.</param>
        /// <returns>List of Role Privileges</returns>
        public IEnumerable<RolePrivilege> GetPrivilegesForRoleAndNode(long roleId, long nodeId)
        {
            return _rolePrivileges.Entities.Where(x => x.RoleId == roleId && x.ManagedNodeId == nodeId);
        }

        /// <summary>
        /// Gets a list of all managed nodes in the enterprise
        /// </summary>
        /// <returns></returns>
        public IList<ManagedNode> GetManagedNodes() {
            return _managedNodes.GetAllLinks();
        }

        private Dictionary<long, byte[]> _adminRoleKeys = new Dictionary<long, byte[]>();

        /// <inheritdoc/>
        public async Task<byte[]> GetRoleKey(long roleId)
        {
            lock (_adminRoleKeys)
            {
                if (_adminRoleKeys.TryGetValue(roleId, out var result))
                {
                    return result;
                }
            }

            var krq = new GetEnterpriseDataKeysRequest();
            krq.RoleId.Add(roleId);
            var krs = await Enterprise.Auth.ExecuteAuthRest<GetEnterpriseDataKeysRequest, GetEnterpriseDataKeysResponse>("enterprise/get_enterprise_data_keys", krq);
            foreach (var rKey in krs.ReEncryptedRoleKey)
            {
                if (rKey.RoleId == roleId)
                {
                    try
                    {
                        var roleKey = CryptoUtils.DecryptAesV2(rKey.EncryptedRoleKey.ToByteArray(), Enterprise.TreeKey);
                        lock (_adminRoleKeys)
                        {
                            if (!_adminRoleKeys.ContainsKey(roleId))
                            {
                                _adminRoleKeys.Add(roleId, roleKey);
                            }
                            return roleKey;
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }
            }

            foreach (var rKey in krs.RoleKey)
            {
                if (rKey.RoleId == roleId)
                {
                    byte[] roleKey = null;
                    try
                    {
                        switch (rKey.KeyType)
                        {
                            case EncryptedKeyType.KtEncryptedByDataKey:
                                roleKey = CryptoUtils.DecryptAesV1(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.DataKey);
                                break;
                            case EncryptedKeyType.KtEncryptedByDataKeyGcm:
                                roleKey = CryptoUtils.DecryptAesV2(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.DataKey);
                                break;
                            case EncryptedKeyType.KtEncryptedByPublicKey:
                                roleKey = CryptoUtils.DecryptRsa(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.PrivateRsaKey);
                                break;
                            case EncryptedKeyType.KtEncryptedByPublicKeyEcc:
                                if (Enterprise.Auth.AuthContext.PrivateEcKey != null)
                                {
                                    roleKey = CryptoUtils.DecryptEc(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.PrivateEcKey);
                                }
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }

                    if (roleKey != null)
                    {
                        lock (_adminRoleKeys)
                        {
                            if (!_adminRoleKeys.ContainsKey(roleId))
                            {
                                _adminRoleKeys.Add(roleId, roleKey);
                            }
                            return roleKey;
                        }
                    }
                }
            }

            return null;
        }

    }

    /// <exclude/>
    public class RoleDictionary : EnterpriseDataDictionary<long, Role, EnterpriseRole>, IGetEnterprise
    {
        public RoleDictionary() : base(EnterpriseDataEntity.Roles)
        {
        }

        public Func<IEnterpriseLoader> GetEnterprise { get; set; }

        protected override long GetEntityId(Role keeperData)
        {
            return keeperData.RoleId;
        }

        protected override void PopulateSdkFromKeeper(EnterpriseRole sdk, Role keeper)
        {
            sdk.ParentNodeId = keeper.NodeId;
            sdk.EncryptedData = keeper.EncryptedData;
            sdk.KeyType = keeper.KeyType;
            sdk.NewUserInherit = keeper.NewUserInherit;
            sdk.VisibleBelow = keeper.VisibleBelow;
            sdk.RoleType = keeper.RoleType;
            var enterprise = GetEnterprise?.Invoke();
            if (enterprise != null && enterprise.TreeKey != null)
            {
                EnterpriseUtils.DecryptEncryptedData(keeper.EncryptedData, enterprise.TreeKey, sdk);
            }
            if (string.Equals(sdk.RoleType, "pool_manager", StringComparison.InvariantCultureIgnoreCase))
            {
                sdk.DisplayName = "MSP Subscription Manager";
            }
        }
        protected override void SetEntityId(EnterpriseRole entity, long id)
        {
            entity.Id = id;
        }
    }

    /// <exclude/>
    public class RoleUserLink : EnterpriseDataLink<RoleUser, RoleUser, long, long>
    {
        public RoleUserLink() : base(EnterpriseDataEntity.RoleUsers) { }

        protected override RoleUser CreateFromKeeperEntity(RoleUser keeperEntity)
        {
            return keeperEntity;
        }

        protected override long GetEntity1Id(RoleUser keeperData)
        {
            return keeperData.RoleId;
        }

        protected override long GetEntity2Id(RoleUser keeperData)
        {
            return keeperData.EnterpriseUserId;
        }
    }

    /// <exclude/>
    public class RoleTeamLink : EnterpriseDataLink<RoleTeam, RoleTeam, long, string>
    {
        public RoleTeamLink() : base(EnterpriseDataEntity.RoleTeams) { }

        protected override RoleTeam CreateFromKeeperEntity(RoleTeam keeperEntity)
        {
            return keeperEntity;
        }

        protected override long GetEntity1Id(RoleTeam keeperData)
        {
            return keeperData.RoleId;
        }

        protected override string GetEntity2Id(RoleTeam keeperData)
        {
            return keeperData.TeamUid.ToByteArray().Base64UrlEncode();
        }
    }

    /// <exclude/>
    public class RoleEnforcementLink : EnterpriseDataLink<RoleEnforcement, RoleEnforcement, long, string>
    {
        public RoleEnforcementLink() : base(EnterpriseDataEntity.RoleEnforcements) { }

        protected override RoleEnforcement CreateFromKeeperEntity(RoleEnforcement keeperEntity)
        {
            return keeperEntity;
        }

        protected override long GetEntity1Id(RoleEnforcement keeperData)
        {
            return keeperData.RoleId;
        }

        protected override string GetEntity2Id(RoleEnforcement keeperData)
        {
            return keeperData.EnforcementType;
        }
    }

    /////////

    /// <exclude/>
    public class ManagedNodeLink : EnterpriseDataLink<ManagedNode, ManagedNode, long, long>
    {
        public ManagedNodeLink() : base(EnterpriseDataEntity.ManagedNodes) { }

        protected override ManagedNode CreateFromKeeperEntity(ManagedNode keeperEntity)
        {
            return keeperEntity;
        }

        protected override long GetEntity1Id(ManagedNode keeperData)
        {
            return keeperData.RoleId;
        }

        protected override long GetEntity2Id(ManagedNode keeperData)
        {
            return keeperData.ManagedNodeId;
        }
    }

    /// <exclude/>
    public class RolePrivilegesList : EnterpriseDataList<RolePrivilege, RolePrivilege>
    {
        public RolePrivilegesList() : base(EnterpriseDataEntity.RolePrivileges) { }

        protected override RolePrivilege CreateFromKeeperEntity(RolePrivilege keeperEntity)
        {
            return keeperEntity;
        }

        protected override bool MatchByKeeperEntity(RolePrivilege sdkEntity, RolePrivilege keeperEntity)
        {
            return 
                sdkEntity.RoleId == keeperEntity.RoleId && 
                sdkEntity.ManagedNodeId == keeperEntity.ManagedNodeId &&
                string.Equals(sdkEntity.PrivilegeType, keeperEntity.PrivilegeType);
        }
    }
}
