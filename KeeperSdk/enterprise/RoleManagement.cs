using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Linq;
using System.Threading.Tasks;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Defines methods for managing enerprise roles
    /// </summary>
    public interface IRoleDataManagement
    {
        /// <summary>
        /// Creates Enterprise Role
        /// </summary>
        /// <param name="roleName">Role name</param>
        /// <param name="nodeId">Role's node ID</param>
        /// <param name="newUserInherit">Set role as default for new users</param>
        /// <returns>Created role</returns>
        Task<EnterpriseRole> CreateRole(string roleName, long nodeId, bool newUserInherit);
        /// <summary>
        /// Deletes Enterprise Role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <returns>Task</returns>
        Task DeleteRole(EnterpriseRole role);
        /// <summary>
        /// Add a user to a role
        /// </summary>
        /// <param name="role">Enterprise role</param>r
        /// <param name="user">Enterprise user</param>
        /// <returns>Task</returns>
        Task AddUserToRole(EnterpriseRole role, EnterpriseUser user);
        /// <summary>
        /// Adds a user to Admin role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="user">Enterprise user</param>
        /// <returns>Task</returns>
        Task AddUserToAdminRole(EnterpriseRole role, EnterpriseUser user);
        /// <summary>
        /// Removes a user from a role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="user">Enterprise user</param>
        /// <returns>Task</returns>
        Task RemoveUserFromRole(EnterpriseRole role, EnterpriseUser user);
        /// <summary>
        /// Adds a team to a role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="team">Enterprise team</param>
        /// <returns>Task</returns>
        Task AddTeamToRole(EnterpriseRole role, EnterpriseTeam team);
        /// <summary>
        /// Removes a team from a role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="team">Enterprise team</param>
        /// <returns>Task</returns>
        Task RemoveTeamFromRole(EnterpriseRole role, EnterpriseTeam team);
    }

    public partial class RoleData : IRoleDataManagement
    {
        /// <inheritdoc />
        public async Task<EnterpriseRole> CreateRole(string roleName, long nodeId, bool newUserInherit)
        {
            var encryptedData = new EncryptedData
            {
                DisplayName = roleName
            };

            var roleId = await Enterprise.GetEnterpriseId();
            var rq = new RoleAddCommand
            {
                RoleId = roleId,
                NodeId = nodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, Enterprise.TreeKey),
                NewUserInherit = newUserInherit
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            return TryGetRole(roleId, out var role) ? role : null;
        }

        /// <inheritdoc />
        public async Task DeleteRole(EnterpriseRole role)
        {
            await Enterprise.Auth.ExecuteAuthCommand(new RoleDeleteCommand { RoleId = role.Id }); ;
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task AddUserToRole(EnterpriseRole role, EnterpriseUser user)
        {
            var rq = new RoleUserAddCommand
            {
                RoleId = role.Id,
                EnterpriseUserId = user.Id,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task AddUserToAdminRole(EnterpriseRole role, EnterpriseUser user)
        {

            await Enterprise.Auth.LoadUsersKeys(Enumerable.Repeat(user.Email, 1));
            if (!Enterprise.Auth.TryGetUserKeys(user.Email, out var keys))
            {
                throw new System.Exception($"User ${user.Email}: public key is not available");
            }
            var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
            var rq = new RoleUserAddCommand
            {
                RoleId = role.Id,
                EnterpriseUserId = user.UserId,
                TreeKey = CryptoUtils.EncryptRsa(Enterprise.TreeKey, publicKey).Base64UrlEncode(),
            };
            var roleKey = await GetRoleKey(role.Id);
            if (roleKey != null)
            {
                rq.RoleAdminKey = CryptoUtils.EncryptRsa(roleKey, publicKey).Base64UrlEncode();
            }
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task RemoveUserFromRole(EnterpriseRole role, EnterpriseUser user)
        {
            var rq = new RoleUserRemoveCommand
            {
                RoleId = role.Id,
                EnterpriseUserId = user.Id,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task AddTeamToRole(EnterpriseRole role, EnterpriseTeam team)
        {
            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam
            {
                RoleId = role.Id,
                TeamUid = ByteString.CopyFrom(team.Uid.Base64UrlDecode()),
            });

            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_add", rq);
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task RemoveTeamFromRole(EnterpriseRole role, EnterpriseTeam team)
        {
            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam
            {
                RoleId = role.Id,
                TeamUid = ByteString.CopyFrom(team.Uid.Base64UrlDecode()),
            });

            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_remove", rq);
            await Enterprise.Load();
        }
    }
}
