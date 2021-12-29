﻿using System;
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
        /// <summary>
        /// Callback method that receives enterprise invitation code.
        /// When provided the enterprise invitation email will not be sent.
        /// </summary>
        public Action<string> SuppressEmail { get; set; }
    }
    /// <exclude/>
    public interface IEnterpriseDataManagement
    {
        Task<EnterpriseUser> InviteUser(string email, InviteUserOptions options = null);
        Task<EnterpriseUser> SetUserLocked(EnterpriseUser user, bool locked);

        Task<EnterpriseTeam> CreateTeam(EnterpriseTeam team);
        Task<EnterpriseTeam> UpdateTeam(EnterpriseTeam team);
        Task DeleteTeam(string teamUid);
        Task AddUsersToTeams(string[] emails, string[] teamUids, Action<string> warnings = null);
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

        /// <excluded />
        public int UserId { get; internal set; }

        /// <excluded />
        public string KeyType { get; internal set; }

        /// <excluded />
        public string EncryptedData { get; internal set; }

        /// <excluded />
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
        ///     Is Managed Company Expired
        /// </summary>
        public bool IsExpired { get; internal set; }

        /// <summary>
        ///     Node that owns the managed company.
        /// </summary>
        public long ParentNodeId { get; set; }
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
