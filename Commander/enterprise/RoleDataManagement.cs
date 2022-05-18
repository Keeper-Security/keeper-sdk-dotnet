using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using System.Collections.Generic;
using Enterprise;
using System;
using System.Diagnostics;
using Google.Protobuf;
using KeeperSecurity.Enterprise;

namespace Commander.Enterprise
{
    public interface IRoleDataManagement : IRoleData
    {
        Task<EnterpriseRole> CreateRole(string roleName, long nodeId, bool visibleBelow, bool newUserInherit);
        Task DeleteRole(long roleId);

        Task AddUserToRole(long roleId, long userId);
        Task AddUserToAdminRole(long roleId, long userId, byte[] userRsaPublicKey);
        Task RemoveUserFromRole(long roleId, long userId);
        Task AddTeamToRole(long roleId, string teamUid);
        Task RemoveTeamFromRole(long roleId, string teamUid);
    }

    public class RoleDataManagement : RoleData, IRoleDataManagement
    {
        public async Task<EnterpriseRole> CreateRole(string roleName, long nodeId, bool visibleBelow, bool newUserInherit)
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
                VisibleBelow = visibleBelow,
                NewUserInherit = newUserInherit
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            return TryGetRole(roleId, out var role) ? role : null;
        }

        public async Task DeleteRole(long roleId) 
        {
            await Enterprise.Auth.ExecuteAuthCommand(new RoleDeleteCommand { RoleId = roleId }); ;
            await Enterprise.Load();
        }

        public async Task AddUserToRole(long roleId, long userId)
        {
            var rq = new RoleUserAddCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task AddUserToAdminRole(long roleId, long userId, byte[] userRsaPublicKey)
        {
            var publicKey = CryptoUtils.LoadPublicKey(userRsaPublicKey);
            var rq = new RoleUserAddCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
                TreeKey = CryptoUtils.EncryptRsa(Enterprise.TreeKey, publicKey).Base64UrlEncode(),
            };
            var roleKey = await GetRoleKey(roleId);
            if (roleKey != null)
            {
                rq.RoleAdminKey = CryptoUtils.EncryptRsa(roleKey, publicKey).Base64UrlEncode();
            }
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task RemoveUserFromRole(long roleId, long userId)
        {
            var rq = new RoleUserRemoveCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task AddTeamToRole(long roleId, string teamUid) {
            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam 
            { 
                RoleId = roleId,
                TeamUid = ByteString.CopyFrom(teamUid.Base64UrlDecode()),
            });

            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_add", rq);
            await Enterprise.Load();
        }

        public async Task RemoveTeamFromRole(long roleId, string teamUid) 
        {
            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam
            {
                RoleId = roleId,
                TeamUid = ByteString.CopyFrom(teamUid.Base64UrlDecode()),
            });

            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_remove", rq);
            await Enterprise.Load();
        }
    }
}
