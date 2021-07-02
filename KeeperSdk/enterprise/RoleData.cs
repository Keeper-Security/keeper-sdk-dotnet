using Enterprise;
using System;
using System.Collections.Generic;
using KeeperSecurity.Utils;
using System.Linq;

namespace KeeperSecurity.Enterprise
{
    /// <exclude/>
    public interface IRoleData 
    { 
        IEnumerable<EnterpriseRole> Roles { get; }
        bool TryGetRole(long roleId, out EnterpriseRole role);
        IEnumerable<long> GetUsersForRole(long roleId);
        IEnumerable<long> GetRolesForUser(long userId);
        IEnumerable<string> GetTeamsForRole(long roleId);
        IEnumerable<long> GetRolesForTeam(string teamUid);
        IEnumerable<RoleEnforcement> GetEnforcementsForRole(long roleId);
    }

    /// <summary>
    /// Represents Role enterprise data.
    /// </summary>
    public class RoleData : EnterpriseDataPlugin, IRoleData
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

        /// <summary>
        /// Get a list of all roles in the enterprise
        /// </summary>
        public IEnumerable<EnterpriseRole> Roles => _roles.Entities;

        /// <summary>
        /// Gets the enterprise role assocoated with the specified ID.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID</param>
        /// <param name="role">When this method returns <c>true</c>, contains requested enterprise role; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> if the enterprise contains a role with specified ID; otherwise, <c>false</c></returns>
        public bool TryGetRole(long roleId, out EnterpriseRole role)
        {
            return _roles.TryGetEntity(roleId, out role);
        }

        /// <summary>
        /// Gets a list of user IDs for specified role.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>List of Enterprise User IDs.</returns>
        public IEnumerable<long> GetUsersForRole(long roleId)
        {
            return _roleUsers.LinksForPrimaryKey(roleId).Select(x => x.EnterpriseUserId);
        }

        /// <summary>
        /// Gets a list of role IDs for specified user.
        /// </summary>
        /// <param name="userId">Enterprise User ID.</param>
        /// <returns>List of Enterprise Role IDs</returns>
        public IEnumerable<long> GetRolesForUser(long userId)
        {
            return _roleUsers.LinksForSecondaryKey(userId).Select(x => x.RoleId);
        }

        /// <summary>
        /// Gets a list of team UIDs for specified role.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>List of Enterprise Team UIDs.</returns>
        public IEnumerable<string> GetTeamsForRole(long roleId)
        {
            return _roleTeams.LinksForPrimaryKey(roleId).Select(x => x.TeamUid.ToByteArray().Base64UrlEncode());
        }

        /// <summary>
        /// Gets a list of role IDs for specified team.
        /// </summary>
        /// <param name="teamUid">Team UID.</param>
        /// <returns>List of Enterprise Role IDs</returns>
        public IEnumerable<long> GetRolesForTeam(string teamUid)
        {
            return _roleTeams.LinksForSecondaryKey(teamUid).Select(x => x.RoleId);
        }

        /// <summary>
        /// Gets a list of role enforcements for specified role.
        /// </summary>
        /// <param name="roleId">Enterprise Role ID.</param>
        /// <returns>List of Role Enforcements</returns>
        public IEnumerable<RoleEnforcement> GetEnforcementsForRole(long roleId)
        {
            return _roleEnforcements.LinksForPrimaryKey(roleId);
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
            sdk.KeyType = keeper.KeyType;
            sdk.NewUserInherit = keeper.NewUserInherit;
            sdk.VisibleBelow = keeper.VisibleBelow;
            sdk.RoleType = keeper.RoleType;
            var enterprise = GetEnterprise?.Invoke();
            if (enterprise != null && enterprise.TreeKey != null)
            {
                EnterpriseUtils.DecryptEncryptedData(keeper.EncryptedData, enterprise.TreeKey, sdk);
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
