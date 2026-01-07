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
        const string MANAGE_LICENCES = "MANAGE_LICENCES";

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
        public bool ManageLicences => privileges.Contains(MANAGE_LICENCES);
    }

    public enum RoleManagedNodePrivilege
    {
        MANAGE_NODES = 0,
        MANAGE_USER = 1,
        MANAGE_LICENCES = 2,
        MANAGE_ROLES = 3,
        MANAGE_TEAMS = 4,
        TRANSFER_ACCOUNT = 5,
        RUN_REPORTS = 6,
        VIEW_TREE = 7,
        MANAGE_BRIDGE = 8,
        MANAGE_COMPANIES = 9,
        SHARING_ADMINISTRATOR = 10,
        APPROVE_DEVICE = 11,
        MANAGE_RECORD_TYPES = 12,
        RUN_COMPLIANCE_REPORTS = 13,
    }

    public enum RoleEnforcementPolicies
    {
        // Two-Factor Authentication Enforcements
        TWO_FACTOR_BY_IP = 1,
        REQUIRE_TWO_FACTOR = 2,
        RESTRICT_TWO_FACTOR_CHANNEL_TEXT = 3,
        RESTRICT_TWO_FACTOR_CHANNEL_GOOGLE = 4,
        RESTRICT_TWO_FACTOR_CHANNEL_DNA = 5,
        RESTRICT_TWO_FACTOR_CHANNEL_DUO = 6,
        RESTRICT_TWO_FACTOR_CHANNEL_RSA = 7,
        RESTRICT_TWO_FACTOR_CHANNEL_SECURITY_KEYS = 8,
        TWO_FACTOR_DURATION_WEB = 9,
        TWO_FACTOR_DURATION_MOBILE = 10,
        TWO_FACTOR_DURATION_DESKTOP = 11,

        // Master Password Enforcements
        MASTER_PASSWORD_MINIMUM_LENGTH = 12,
        MASTER_PASSWORD_MINIMUM_SPECIAL = 13,
        MASTER_PASSWORD_MINIMUM_UPPER = 14,
        MASTER_PASSWORD_MINIMUM_LOWER = 15,
        MASTER_PASSWORD_MINIMUM_DIGITS = 16,
        MASTER_PASSWORD_MINIMUM_LENGTH_NO_PROMPT = 17,
        MASTER_PASSWORD_MAXIMUM_DAYS_BEFORE_CHANGE = 18,
        MASTER_PASSWORD_EXPIRED_AS_OF = 19,
        MASTER_PASSWORD_RESTRICT_DAYS_BEFORE_REUSE = 20,
        MASTER_PASSWORD_REENTRY = 21,

        // Sharing Enforcements
        RESTRICT_SHARING_ALL = 22,
        RESTRICT_SHARING_ENTERPRISE = 23,
        RESTIRCT_SHARING_RECORD_AND_FOLDER = 24,
        RESTRICT_SHARING_RECORD_ATTACHMENTS = 25,
        RESTRICT_SHARING_OUTSIDE_OF_ISOLATED_NODES = 26,
        RESTRICT_SHARING_INCOMING_ALL = 27,
        RESTRICT_SHARING_INCOMING_ENTERPRISE = 28,

        // Shared Folder Enforcements
        RESTRICT_SF_FOLDER_DELETION = 29,
        RESTRICT_SF_RECORD_REMOVAL = 30,

        // Access Restriction Enforcements
        RESTRICT_WEB_VAULT_ACCESS = 31,
        RESTRICT_EXTENSIONS_ACCESS = 32,
        RESTRICT_MOBILE_ACCESS = 33,
        RESTRICT_DESKTOP_ACCESS = 34,
        RESTRICT_CHAT_DESKTOP_ACCESS = 35,
        RESTRICT_CHAT_MOBILE_ACCESS = 36,
        RESTRICT_COMMANDER_ACCESS = 37,
        RESTRICT_MOBILE_IOS_ACCESS = 38,
        RESTRICT_MOBILE_ANDROID_ACCESS = 39,
        RESTRICT_MOBILE_WINDOWS_PHONE_ACCESS = 40,
        RESTRICT_DESKTOP_WIN_ACCESS = 41,
        RESTRICT_DESKTOP_MAC_ACCESS = 42,
        RESTRICT_OFFLINE_ACCESS = 43,
        RESTRICT_PERSISTENT_LOGIN = 44,

        // IP and Domain Restrictions
        RESTRICT_IP_ADDRESSES = 45,
        RESTRICT_VAULT_IP_ADDRESSES = 46,
        RESTRICT_IP_AUTOAPPROVAL = 47,
        RESTRICT_DOMAIN_ACCESS = 48,
        RESTRICT_DOMAIN_CREATE = 49,
        TIP_ZONE_RESTRICT_ALLOWED_IP_RANGES = 50,

        // Fingerprint/Biometric Restrictions
        RESTRICT_IOS_FINGERPRINT = 51,
        RESTRICT_MAC_FINGERPRINT = 52,
        RESTRICT_ANDROID_FINGERPRINT = 53,
        RESTRICT_WINDOWS_FINGERPRINT = 54,

        // Timeout and Session Enforcements
        LOGOUT_TIMER_WEB = 55,
        LOGOUT_TIMER_MOBILE = 56,
        LOGOUT_TIMER_DESKTOP = 57,
        MAX_SESSION_LOGIN_TIME = 58,

        // Security Enforcements
        MINIMUM_PBKDF2_ITERATIONS = 59,
        REQUIRE_SELF_DESTRUCT = 60,
        REQUIRE_DEVICE_APPROVAL = 61,
        REQUIRE_ACCOUNT_SHARE = 62,
        REQUIRE_ACCOUNT_RECOVERY_APPROVAL = 63,

        // Export/Import Enforcements
        RESTRICT_EXPORT = 64,
        RESTRICT_IMPORT = 65,
        RESTRICT_IMPORT_SHARED_FOLDERS = 66,
        RESTRICT_FILE_UPLOAD = 67,

        // Browser Extension Enforcements
        RESTRICT_FORCEFIELD = 68,
        RESTRICT_SNAPSHOT_TOOL = 69,
        RESTRICT_HOVER_LOCKS = 70,
        RESTRICT_PROMPT_TO_LOGIN = 71,
        RESTRICT_PROMPT_TO_FILL = 72,
        RESTRICT_AUTO_FILL = 73,
        RESTRICT_AUTO_SUBMIT = 74,
        RESTRICT_PROMPT_TO_SAVE = 75,
        RESTRICT_PROMPT_TO_CHANGE = 76,

        // Record and Folder Enforcements
        RESTRICT_CREATE_FOLDER = 77,
        RESTRICT_CREATE_IDENTITY_PAYMENT_RECORDS = 78,
        RESTRICT_RECORD_TYPES = 79,
        DAYS_BEFORE_DELETED_RECORDS_CLEARED_PERM = 80,
        DAYS_BEFORE_DELETED_RECORDS_AUTO_CLEARED = 81,

        // Masking Enforcements
        MASK_CUSTOM_FIELDS = 82,
        MASK_NOTES = 83,
        MASK_PASSWORDS_WHILE_EDITING = 84,

        // Password Generation Enforcements
        GENERATED_PASSWORD_COMPLEXITY = 85,
        GENERATED_SECURITY_QUESTION_COMPLEXITY = 86,
        ALLOW_ALTERNATE_PASSWORDS = 87,

        // Backup and Recovery Enforcements
        AUTOMATIC_BACKUP_EVERY_X_DAYS = 88,

        // Email and Invitation Enforcements
        SEND_INVITE_AT_REGISTRATION = 89,
        RESTRICT_EMAIL_CHANGE = 90,
        RESEND_ENTERPRISE_INVITE_IN_X_DAYS = 91,

        // BreachWatch Enforcements
        SEND_BREACH_WATCH_EVENTS = 92,
        RESTRICT_BREACH_WATCH = 93,

        // Licensing Enforcements
        RESTRICT_PERSONAL_LICENSE = 94,

        // UI/UX Enforcements
        DISABLE_SETUP_TOUR = 95,
        DISABLE_ONBOARDING = 96,
        STAY_LOGGED_IN_DEFAULT = 97,

        // Client Version Enforcements
        DISALLOW_V2_CLIENTS = 98,

        // Secrets Manager and PAM Enforcements
        ALLOW_SECRETS_MANAGER = 99,
        ALLOW_PAM_ROTATION = 100,
        ALLOW_PAM_DISCOVERY = 101,
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
        private readonly RoleDictionary _roles = new();
        private readonly RoleUserLink _roleUsers = new();
        private readonly RoleTeamLink _roleTeams = new();
        private readonly RoleEnforcementLink _roleEnforcements = new();
        private readonly ManagedNodeLink _managedNodes = new();
        private readonly RolePrivilegesList _rolePrivileges = new();

        /// <summary>
        /// Gets or sets the EnterpriseData reference for user lookups.
        /// Set this when both RoleData and EnterpriseData are loaded together.
        /// </summary>
        public IEnterpriseData EnterpriseData { get; set; }

        /// <summary>
        /// Gets or sets the ManagedCompanyData reference for MSP operations.
        /// Set this when RoleData and ManagedCompanyData are loaded together.
        /// </summary>
        public IManagedCompanyData ManagedCompanyData { get; set; }

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
            foreach (var p in GetManagedNodes())
            {
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
        public IList<ManagedNode> GetManagedNodes()
        {
            return _managedNodes.GetAllLinks();
        }

        private readonly Dictionary<long, byte[]> _adminRoleKeys = new();

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
