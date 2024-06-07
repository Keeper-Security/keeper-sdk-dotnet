using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;

namespace KeeperSecurity.Enterprise
{
    /// <exclude/>
    public interface IEnterpriseLoader 
    {
        IAuthentication Auth { get; }
        string EnterpriseName { get; }
        byte[] TreeKey { get; }
        Task Load();
        Task<long> GetEnterpriseId();
    }

    /// <exclude/>
    public interface IEnterpriseData
    {
        IEnumerable<EnterpriseNode> Nodes { get; }
        int NodeCount { get; }
        EnterpriseNode RootNode { get; }
        IEnumerable<EnterpriseUser> Users { get; }
        int UserCount { get; }
        IEnumerable<EnterpriseTeam> Teams { get; }
        int TeamCount { get; }

        bool TryGetNode(long nodeId, out EnterpriseNode node);
        bool TryGetUserById(long userId, out EnterpriseUser user);
        bool TryGetUserByEmail(string email, out EnterpriseUser user);
        bool TryGetTeam(string teamUid, out EnterpriseTeam team);
    }

    /// <summary>
    /// Defines optional Invite User properties 
    /// </summary>
    public class InviteUserOptions 
    { 
        /// <summary>
        /// User Full Name
        /// </summary>
        public string FullName { get; set; }
        /// <summary>
        /// Enterprise Node ID
        /// </summary>
        public long? NodeId { get; set; }
    }

    /// <summary>
    /// Defines Transfer Account Result properties
    /// </summary>
    public class AccountTransferResult
    {
        /// <summary>
        /// Number of records
        /// </summary>
        public int RecordsTransfered { get; internal set; }
        /// <summary>
        /// Number of shared folders
        /// </summary>
        public int SharedFoldersTransfered { get; internal set; }
        /// <summary>
        /// Number of teams
        /// </summary>
        public int TeamsTransfered { get; internal set; }
        /// <summary>
        /// Number of user folders
        /// </summary>
        public int UserFoldersTransfered { get; internal set; }

        /// <summary>
        /// Number of corrupted records
        /// </summary>
        public int RecordsCorrupted { get; internal set; }
        /// <summary>
        /// Number of corrupted shared folders
        /// </summary>
        public int SharedFoldersCorrupted { get; internal set; }
        /// <summary>
        /// Number of corrupted teams
        /// </summary>
        public int TeamsCorrupted { get; internal set; }
        /// <summary>
        /// Number of corrupted user folders
        /// </summary>
        public int UserFoldersCorrupted { get; internal set; }
    };

    /// <summary>
    /// Defines methods for modifying enterprise users and teams. 
    /// </summary>
    public interface IEnterpriseDataManagement
    {
        /// <summary>
        ///     Invides User to Enterprise.
        /// </summary>
        /// <param name="email">User email</param>
        /// <param name="options">Invided user options</param>
        /// <returns>Invited User</returns>
        Task<EnterpriseUser> InviteUser(string email, InviteUserOptions options = null);
        /// <summary>
        ///     Locks or Unlocks Enterprise User.
        /// </summary>
        /// <param name="user">Enterprise User</param>
        /// <param name="locked">Lock flag</param>
        /// <returns>User</returns>
        Task<EnterpriseUser> SetUserLocked(EnterpriseUser user, bool locked);
        /// <summary>
        ///     Deletes Enterprise User.
        /// </summary>
        /// <param name="user">Enterprise User</param>
        /// <returns>Task</returns>
        Task DeleteUser(EnterpriseUser user);
        /// <summary>
        ///     Transfers Enterprise User account to another user.
        /// </summary>
        /// <param name="roleData">Enterprise Role data</param>
        /// <param name="fromUser">Enterprise User to transfer account from</param>
        /// <param name="targetUser">Target Enterprise User</param>
        /// <returns>Task</returns>
        Task<AccountTransferResult> TransferUserAccount(IRoleData roleData, EnterpriseUser fromUser, EnterpriseUser targetUser);

        /// <summary>
        ///     Creates Enterprise Team.
        /// </summary>
        /// <param name="team">Enterprise Team</param>
        /// <returns>Created Team</returns>
        Task<EnterpriseTeam> CreateTeam(EnterpriseTeam team);
        /// <summary>
        ///     Modifies Enterprise Team.
        /// </summary>
        /// <param name="team">Enterprise Team</param>
        /// <returns>Updated Team</returns>
        Task<EnterpriseTeam> UpdateTeam(EnterpriseTeam team);
        /// <summary>
        ///     Deletes Enterprise Team.
        /// </summary>
        /// <param name="teamUid">Team UID</param>
        /// <returns>Task</returns>
        Task DeleteTeam(string teamUid);
        /// <summary>
        ///     Adds Users to Team.
        /// </summary>
        /// <param name="emails">Emails</param>
        /// <param name="teamUids">Array of team Uids</param>
        /// <param name="warnings">(Optional)</param>
        /// <returns>Task</returns>
        Task AddUsersToTeams(string[] emails, string[] teamUids, Action<string> warnings = null);
        /// <summary>
        ///     Removes Users(s) from Team(s)
        /// </summary>
        /// <param name="emails">A list of user emails</param>
        /// <param name="teamUids">A list of team UIDs</param>
        /// <param name="warnings">A callback that receives warnings</param>
        /// <returns>Awaitable task.</returns>
        Task RemoveUsersFromTeams(string[] emails, string[] teamUids, Action<string> warnings = null);
    }

    /// <exclude />
    public interface IEnterpriseEntity
    {
        long Id { get; }
    }

    /// <exclude />
    public interface IParentNodeEntity
    {
        long ParentNodeId { get; }
    }

    /// <summary>
    ///     Represents Enterprise Node.
    /// </summary>
    public class EnterpriseNode : IEnterpriseEntity, IParentNodeEntity, IEncryptedData, IDisplayName
    {
        /// <summary>
        ///     A list of child node IDs
        /// </summary>
        public ISet<long> Subnodes { get; } = new HashSet<long>();

        /// <summary>
        ///     Node Name.
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        ///     Node ID.
        /// </summary>
        public long Id { get; internal set; }

        /// <summary>
        ///     Parent Node ID.
        /// </summary>
        public long ParentNodeId { get; internal set; }

        /// <summary>
        ///     Node Isolation flag.
        /// </summary>
        public bool RestrictVisibility { get; internal set; }

        /// <exclude/>
        public string EncryptedData { get; internal set; }

        /// <exclude/>
        public long BridgeId { get; internal set; }

        /// <exclude/>
        public long ScimId { get; internal set; }

        /// <exclude/>
        public long[] SsoServiceProviderIds { get; internal set; }
    }

    /// <summary>
    ///     Specifies Enterprise User statuses.
    /// </summary>
    public enum UserStatus
    {
        /// <summary>
        ///     Active user.
        /// </summary>
        Active,

        /// <summary>
        ///     Invited User.
        /// </summary>
        Inactive,

        /// <summary>
        ///     Locked User.
        /// </summary>
        Locked,

        /// <summary>
        ///     Blocked User.
        /// </summary>
        /// <remarks>User that did not accept Account Transfer Consent.</remarks>
        Blocked,

        /// <summary>
        ///     Disable User.
        /// </summary>
        /// <remarks>
        ///     Enterprise Bridge disables users that are not active in Active Directory.
        /// </remarks>
        Disabled
    }

    /// <summary>
    ///     Represents Enterprise User
    /// </summary>
    public class EnterpriseUser : IEnterpriseEntity, IParentNodeEntity, IEncryptedData, IDisplayName
    {
        /// <summary>
        ///     User email address.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        ///     User Status.
        /// </summary>
        public UserStatus UserStatus { get; internal set; }

        /// <summary>
        ///     User Name.
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        ///     User ID.
        /// </summary>
        public long Id { get; internal set; }

        /// <summary>
        ///     Node that owns the user.
        /// </summary>
        public long ParentNodeId { get; internal set; }

        /// <exclude />
        public int UserId { get; internal set; }

        /// <exclude />
        public string KeyType { get; internal set; }

        /// <exclude />
        public string EncryptedData { get; internal set; }

        /// <summary>
        /// Account Share Expiration. Unix epoch time in milliseconds.
        /// </summary>
        public long AccountShareExpiration { get; internal set; }
    }

    /// <summary>
    ///     Represents Enterprise Role
    /// </summary>
    public class EnterpriseRole : IEnterpriseEntity, IParentNodeEntity, IEncryptedData, IDisplayName
    {
        /// <summary>
        ///     Role ID.
        /// </summary>
        public long Id { get; internal set; }

        /// <summary>
        ///     User Name.
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// Role is visible to the subnodes.
        /// </summary>
        public bool VisibleBelow { get; set; }

        /// <summary>
        /// New users automaticall added to this role
        /// </summary>
        public bool NewUserInherit { get; set; }

        /// <exclude/>
        public string RoleType { get; set; }
        internal string KeyType { get; set; }
        /// <summary>
        ///     Node that owns the role.
        /// </summary>
        public long ParentNodeId { get; set; }
        public string EncryptedData { get; set; }
    }


    /// <summary>
    ///     Represents Enterprise Team.
    /// </summary>
    public class EnterpriseTeam : IParentNodeEntity
    {
        /// <summary>
        ///     Team UID.
        /// </summary>
        public string Uid { get; internal set; }

        /// <summary>
        ///     Team Name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     Restricts Record Sharing?
        /// </summary>
        public bool RestrictSharing { get; set; }

        /// <summary>
        ///     Restricts Record Edit?
        /// </summary>
        public bool RestrictEdit { get; set; }

        /// <summary>
        ///     Restricts Record View?
        /// </summary>
        public bool RestrictView { get; set; }

        /// <summary>
        ///     Team Encryption Key.
        /// </summary>
        public byte[] TeamKey { get; internal set; }

        /// <summary>
        ///     Node that owns the team.
        /// </summary>
        public long ParentNodeId { get; set; }
    }

    /// <summary>
    ///     Represends Managed Company Add-On
    /// </summary>
    public class ManagedCompanyLicenseAddOn
    {
        /// <summary>
        ///     Add-On name
        /// </summary>
        public string Name { get; internal set; }

        /// <summary>
        ///     Is Add-On enabled
        /// </summary>
        public bool IsEnabled { get; internal set; }

        /// <summary>
        ///     Is Add-On trial
        /// </summary>
        public bool IsTrial { get; internal set; }

        /// <summary>
        /// Number of Seats
        /// </summary>
        public int Seats { get; internal set; }

        /// <summary>
        /// Add-On expiration time. UNIX epoch
        /// </summary>
        public long Expiration { get; internal set; }

        /// <summary>
        /// Add-On creation time. UNIX epoch
        /// </summary>
        public long Creation { get; internal set; }

        /// <summary>
        /// Add-On activation time. UNIX epoch
        /// </summary>
        public long Activation { get; internal set; }
    }

    /// <summary>
    ///     Represents Enterprise Managed Company.
    /// </summary>
    public class EnterpriseManagedCompany : IParentNodeEntity
    {
        /// <summary>
        ///     Managed Company Enterprise ID
        /// </summary>
        public int EnterpriseId { get; internal set; }

        /// <summary>
        ///     Managed Company Enterprise Name
        /// </summary>
        public string EnterpriseName { get; internal set; }

        /// <summary>
        ///     Managed Company Product ID
        /// </summary>
        public string ProductId { get; internal set; }

        /// <summary>
        ///     Number of Seats
        /// </summary>
        public int NumberOfSeats { get; internal set; }

        /// <summary>
        ///     Number of Users
        /// </summary>
        public int NumberOfUsers { get; internal set; }

        /// <summary>
        ///     File / Storage Plan Type
        /// </summary>
        public string FilePlanType { get; internal set; }

        /// <summary>
        ///     Is Managed Company Expired
        /// </summary>
        public bool IsExpired { get; internal set; }

        /// <summary>
        ///     Node that owns the managed company.
        /// </summary>
        public long ParentNodeId { get; internal set; }

        public ManagedCompanyLicenseAddOn[] AddOns { get; internal set; }

        /// <exclude />
        public long TreeKeyRole { get; internal set; }

        /// <exclude />
        public byte[] TreeKey { get; internal set; }
    }

    /// <summary>
    ///     Cannot proceed with enterprise operation.
    /// </summary>
    public class EnterpriseException : Exception
    {
        public EnterpriseException(string message) : base(message)
        {
        }
    }
}
