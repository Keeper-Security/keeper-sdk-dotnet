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
        private Dictionary<long, byte[]> _adminRoleKeys = new Dictionary<long, byte[]>();

        private async Task<byte[]> GetRoleKey(long roleId)
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
                            case EncryptedKeyType.KtEncryptedByPublicKey:
                                roleKey = CryptoUtils.DecryptRsa(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.PrivateKey);
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
