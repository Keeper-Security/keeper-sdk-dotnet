using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    ///     Defines properties and methods of Enterprise data structure.
    /// </summary>
    public interface IEnterprise
    {
        /// <summary>
        ///     Gets Keeper authentication.
        /// </summary>
        IAuthentication Auth { get; }

        /// <summary>
        ///     Gets Enterprise Tree encryption key.
        /// </summary>
        byte[] TreeKey { get; }

        /// <summary>
        ///     Get the list of all nodes in the enterprise.
        /// </summary>
        IEnumerable<EnterpriseNode> Nodes { get; }

        /// <summary>
        ///     Gets the number of all nodes in the enterprise.
        /// </summary>
        int NodeCount { get; }

        /// <summary>
        ///     Gets the Enterprise Root Node.
        /// </summary>
        EnterpriseNode RootNode { get; }

        /// <summary>
        ///     Get the list of all users in the enterprise.
        /// </summary>
        IEnumerable<EnterpriseUser> Users { get; }

        /// <summary>
        ///     Gets the number of all users in the enterprise.
        /// </summary>
        int UserCount { get; }

        /// <summary>
        ///     Get the list of all teams in the enterprise.
        /// </summary>
        IEnumerable<EnterpriseTeam> Teams { get; }

        /// <summary>
        ///     Gets the number of all teams in the enterprise.
        /// </summary>
        int TeamCount { get; }

        /// <summary>
        ///     Retrieves from Keeper and decrypts Enterprise Data structure.
        /// </summary>
        /// <returns></returns>
        Task GetEnterpriseData();

        /// <summary>
        ///     Gets the enterprise node associated with the specified ID.
        /// </summary>
        /// <param name="nodeId">Node Enterprise ID</param>
        /// <param name="node">When this method returns <c>true</c>, contains requested enterprise node; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a node with specified ID; otherwise, <c>false</c></returns>
        bool TryGetNode(long nodeId, out EnterpriseNode node);

        /// <summary>
        ///     Gets the enterprise user associated with the specified ID.
        /// </summary>
        /// <param name="userId">User Enterprise ID</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        bool TryGetUserById(long userId, out EnterpriseUser user);

        /// <summary>
        ///     Gets the enterprise user associated with the specified email address.
        /// </summary>
        /// <param name="email">User Email Address.</param>
        /// <param name="user">When this method returns <c>true</c>, contains requested enterprise user; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a user with specified ID; otherwise, <c>false</c></returns>
        bool TryGetUserByEmail(string email, out EnterpriseUser user);

        /// <summary>
        ///     Gets the enterprise team associated with the specified team UID.
        /// </summary>
        /// <param name="teamUid">Team UID</param>
        /// <param name="team">When this method returns <c>true</c>, contains requested enterprise team; otherwise <c>null</c>.</param>
        /// <returns><c>true</c> in the enterprise contains a team with specified UID; otherwise, <c>false</c></returns>
        bool TryGetTeam(string teamUid, out EnterpriseTeam team);
    }

    /// <summary>
    /// Defines method for enterprise management.
    /// </summary>
    public interface IEnterpriseManagement
    {
        /// <summary>
        ///     Creates Enterprise Team.
        /// </summary>
        /// <param name="team">Enterprise Team</param>
        /// <returns>Created Team</returns>
        Task<EnterpriseTeam> CreateTeam(EnterpriseTeam team);

        /// <summary>
        ///     Updates Enterprise Team
        /// </summary>
        /// <param name="team">Enterprise Team</param>
        /// <returns>Updated Team</returns>
        Task<EnterpriseTeam> UpdateTeam(EnterpriseTeam team);

        /// <summary>
        ///     Deletes Enterprise Team.
        /// </summary>
        /// <param name="teamUid">Enterprise Team UID.</param>
        /// <returns>Awaitable task.</returns>
        Task DeleteTeam(string teamUid);

        /// <summary>
        ///     Add Enterprise User(s) to Team(s).
        /// </summary>
        /// <param name="emails">A list of user emails</param>
        /// <param name="teamUids">A list of team UIDs</param>
        /// <param name="warnings">A callback that receives warnings</param>
        /// <returns>Awaitable task.</returns>
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
    public class EnterpriseNode : IEnterpriseEntity, IParentNodeEntity, IDisplayName
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
    public class EnterpriseUser : IEnterpriseEntity, IParentNodeEntity, IDisplayName
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
        ///     A list of team UID that user is member of.
        /// </summary>
        public ISet<string> Teams { get; } = new HashSet<string>();

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
        ///     A list of team users.
        /// </summary>
        public ISet<long> Users { get; } = new HashSet<long>();

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
    ///     Cannot proceed with enterprise operation.
    /// </summary>
    public class EnterpriseException : Exception
    {
        public EnterpriseException(string message) : base(message)
        {
        }
    }
}
