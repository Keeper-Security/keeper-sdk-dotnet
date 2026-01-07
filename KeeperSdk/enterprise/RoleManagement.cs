using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Defines methods for managing enterprise roles
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
        /// Updates Enterprise Role properties
        /// </summary>
        /// <param name="role">Enterprise role to update</param>
        /// <param name="newUserInherit">Optional: Set role as default for new users. If null, property is not changed.</param>
        /// <param name="visibleBelow">Optional: Set role visibility to subnodes. If null, property is not changed.</param>
        /// <param name="displayName">Optional: New role display name. If null, property is not changed.</param>
        /// <returns>Updated role</returns>
        Task<EnterpriseRole> UpdateRole(EnterpriseRole role, bool? newUserInherit = null, bool? visibleBelow = null, string displayName = null);
        /// <summary>
        /// Deletes Enterprise Role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <returns>Task</returns>
        Task DeleteRole(EnterpriseRole role);
        /// <summary>
        /// Add a user to a role
        /// </summary>
        /// <param name="role">Enterprise role</param>
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
        /// <summary>
        /// Adds a managed node to a role.
        /// Set RoleData.EnterpriseData property before calling to enable user key lookups.
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="node">Enterprise node to be managed</param>
        /// <param name="cascadeNodeManagement">Whether privileges for this managed node apply to children nodes</param>
        /// <returns>Task</returns>
        Task RoleManagedNodeAdd(EnterpriseRole role, EnterpriseNode node, bool cascadeNodeManagement);
        /// <summary>
        /// Removes a managed node from a role
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="node">Enterprise node</param>
        /// <returns>Task</returns>
        Task RoleManagedNodeRemove(EnterpriseRole role, EnterpriseNode node);
        /// <summary>
        /// Adds multiple privileges to a role's managed node in a batch.
        /// For TRANSFER_ACCOUNT privilege, role keys will be generated and encrypted.
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="node">Managed node</param>
        /// <param name="privileges">List of privileges to add</param>
        /// <returns>List of responses from the batch execution</returns>
        Task<IList<KeeperApiResponse>> RoleManagedNodePrivilegeAddBatch(EnterpriseRole role, EnterpriseNode node, List<RoleManagedNodePrivilege> privileges);
        /// <summary>
        /// Removes a privilege from a role's managed node
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="node">Managed node</param>
        /// <param name="privilege">Privilege</param>
        /// <returns>Task</returns>
        Task<IList<KeeperApiResponse>> RoleManagedNodePrivilegeRemoveBatch(EnterpriseRole role, EnterpriseNode node, List<RoleManagedNodePrivilege> privileges);
        /// <summary>
        /// Adds multiple enforcements to a role's managed node in a batch
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="enforcements">Dictionary of enforcement policies with their string values (auto-converted to appropriate type)</param>
        /// <returns>List of responses from the batch execution</returns>
        Task<IList<KeeperApiResponse>> RoleEnforcementAddBatch(EnterpriseRole role, IDictionary<RoleEnforcementPolicies, string> enforcements);
        /// <summary>
        /// Removes a enforcement from a role's managed node
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="enforcement">Enforcement: MASTER_PASSWORD_MINIMUM_LENGTH, TWO_FACTOR_BY_IP, TWO_FACTOR_BY_DEVICE, TWO_FACTOR_BY_LOCATION, TWO_FACTOR_BY_TIME, TWO_FACTOR_BY_USER_AGENT, TWO_FACTOR_BY_APP, TWO_FACTOR_BY_EMAIL, TWO_FACTOR_BY_SMS, TWO_FACTOR_BY_PHONE, TWO_FACTOR_BY_OTP, TWO_FACTOR_BY_YUBIKEY, TWO_FACTOR_BY_FIDO2, TWO_FACTOR_BY_FIDO3, TWO_FACTOR_BY_FIDO4, TWO_FACTOR_BY_FIDO5, TWO_FACTOR_BY_FIDO6, TWO_FACTOR_BY_FIDO7, TWO_FACTOR_BY_FIDO8, TWO_FACTOR_BY_FIDO9, TWO_FACTOR_BY_FIDO10</param>
        /// <returns>Task</returns>
        Task<IList<KeeperApiResponse>> RoleEnforcementRemoveBatch(EnterpriseRole role, List<RoleEnforcementPolicies> enforcement);
        /// <summary>
        /// Updates a enforcement from a role's managed node
        /// </summary>
        /// <param name="role">Enterprise role</param>
        /// <param name="enforcement">Enforcement: MASTER_PASSWORD_MINIMUM_LENGTH, TWO_FACTOR_BY_IP, TWO_FACTOR_BY_DEVICE, TWO_FACTOR_BY_LOCATION, TWO_FACTOR_BY_TIME, TWO_FACTOR_BY_USER_AGENT, TWO_FACTOR_BY_APP, TWO_FACTOR_BY_EMAIL, TWO_FACTOR_BY_SMS, TWO_FACTOR_BY_PHONE, TWO_FACTOR_BY_OTP, TWO_FACTOR_BY_YUBIKEY, TWO_FACTOR_BY_FIDO2, TWO_FACTOR_BY_FIDO3, TWO_FACTOR_BY_FIDO4, TWO_FACTOR_BY_FIDO5, TWO_FACTOR_BY_FIDO6, TWO_FACTOR_BY_FIDO7, TWO_FACTOR_BY_FIDO8, TWO_FACTOR_BY_FIDO9, TWO_FACTOR_BY_FIDO10</param>
        /// <param name="value">Value: Value for the enforcement</param>
        /// <returns>Task</returns>
        Task<IList<KeeperApiResponse>> RoleEnforcementUpdateBatch(EnterpriseRole role, IDictionary<RoleEnforcementPolicies, string> enforcements);
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
        public async Task<EnterpriseRole> UpdateRole(EnterpriseRole role, bool? newUserInherit = null, bool? visibleBelow = null, string displayName = null)
        {
            var encryptedData = new EncryptedData();
            if (!string.IsNullOrEmpty(displayName))
            {
                encryptedData.DisplayName = displayName;
            }
            else
            {
                encryptedData.DisplayName = role.DisplayName;
            }

            var rq = new RoleUpdateCommand
            {
                RoleId = role.Id,
                NodeId = role.ParentNodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, Enterprise.TreeKey),
                NewUserInherit = newUserInherit ?? role.NewUserInherit,
                VisibleBelow = visibleBelow ?? role.VisibleBelow
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            return TryGetRole(role.Id, out var updatedRole) ? updatedRole : null;
        }

        /// <inheritdoc />
        public async Task DeleteRole(EnterpriseRole role)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            
            await Enterprise.Auth.ExecuteAuthCommand(new RoleDeleteCommand { RoleId = role.Id }); ;
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task AddUserToRole(EnterpriseRole role, EnterpriseUser user)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (user == null) throw new ArgumentNullException(nameof(user));

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
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (user == null) throw new ArgumentNullException(nameof(user));

            await Enterprise.Auth.LoadUsersKeys(Enumerable.Repeat(user.Email, 1));
            if (!Enterprise.Auth.TryGetUserKeys(user.Email, out var keys))
            {
                throw new System.Exception($"User ${user.Email}: public key is not available");
            }
            var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
            var rq = new RoleUserAddCommand
            {
                RoleId = role.Id,
                EnterpriseUserId = user.Id,
                TreeKey = CryptoUtils.EncryptRsa(Enterprise.TreeKey, publicKey).Base64UrlEncode(),
                TreeKeyType = "encrypted_by_public_key",
            };
            var roleKey = await GetRoleKey(role.Id);
            if (roleKey != null)
            {
                rq.RoleAdminKey = CryptoUtils.EncryptRsa(roleKey, publicKey).Base64UrlEncode();
                rq.RoleAdminKeyType = "encrypted_by_public_key";
            }
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        /// <inheritdoc />
        public async Task RemoveUserFromRole(EnterpriseRole role, EnterpriseUser user)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (user == null) throw new ArgumentNullException(nameof(user));

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
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (team == null) throw new ArgumentNullException(nameof(team));

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
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (team == null) throw new ArgumentNullException(nameof(team));

            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam
            {
                RoleId = role.Id,
                TeamUid = ByteString.CopyFrom(team.Uid.Base64UrlDecode()),
            });
            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_remove", rq);
            await Enterprise.Load();
        }

        public async Task RoleManagedNodeAdd(EnterpriseRole role, EnterpriseNode node, bool cascadeNodeManagement)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (node == null) throw new ArgumentNullException(nameof(node));

            RoleManagedNodeTreeKey[] treeKeys = null;

            if (EnterpriseData != null)
            {
                var users = GetUsersForRole(role.Id)
                    .Select(id => EnterpriseData.TryGetUserById(id, out var u) ? u : null)
                    .Where(u => u != null && !string.IsNullOrEmpty(u.Email))
                    .ToList();

                if (users.Count > 0)
                {
                    await Enterprise.Auth.LoadUsersKeys(users.Select(u => u.Email));
                    treeKeys = users
                        .Where(u => Enterprise.Auth.TryGetUserKeys(u.Email, out _))
                        .Select(u =>
                        {
                            Enterprise.Auth.TryGetUserKeys(u.Email, out var keys);
                            var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                            return new RoleManagedNodeTreeKey
                            {
                                EnterpriseUserId = u.Id,
                                TreeKey = CryptoUtils.EncryptRsa(Enterprise.TreeKey, publicKey).Base64UrlEncode(),
                                TreeKeyType = "encrypted_by_public_key",
                            };
                        }).ToArray();
                }
            }

            var rq = new RoleManagedNodeAddCommand
            {
                RoleId = role.Id,
                ManagedNodeId = node.Id,
                CascadeNodeManagement = cascadeNodeManagement,
                TreeKeys = treeKeys?.Length > 0 ? treeKeys : null
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task RoleManagedNodeUpdate(EnterpriseRole role, EnterpriseNode node, bool cascadeNodeManagement)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (node == null) throw new ArgumentNullException(nameof(node));

            var rq = new RoleManagedNodeUpdateCommand
            {
                RoleId = role.Id,
                ManagedNodeId = node.Id,
                CascadeNodeManagement = cascadeNodeManagement
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }


        public async Task RoleManagedNodeRemove(EnterpriseRole role, EnterpriseNode node)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (node == null) throw new ArgumentNullException(nameof(node));

            var rq = new RoleManagedNodeRemoveCommand
            {
                RoleId = role.Id,
                ManagedNodeId = node.Id,
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task<IList<KeeperApiResponse>> RoleManagedNodePrivilegeAddBatch(EnterpriseRole role, EnterpriseNode node, List<RoleManagedNodePrivilege> privileges)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (node == null) throw new ArgumentNullException(nameof(node));
            if (privileges == null) throw new ArgumentNullException(nameof(privileges));

            var commands = new List<KeeperApiCommand>();

            byte[] roleKey = null;
            byte[] encryptedPrivateKey = null;
            byte[] roleKeyEncWithTreeKey = null;
            string rolePublicKeyBase64 = null;
            ManagedNodeRoleKey[] roleKeys = null;

            if (privileges.Contains(RoleManagedNodePrivilege.TRANSFER_ACCOUNT))
            {
                roleKey = await GetRoleKey(role.Id);
                if (roleKey == null)
                {
                    roleKey = CryptoUtils.GenerateEncryptionKey();
                }

                CryptoUtils.GenerateRsaKey(out var rsaPrivateKey, out var rsaPublicKey);

                encryptedPrivateKey = CryptoUtils.EncryptAesV2(CryptoUtils.UnloadRsaPrivateKey(rsaPrivateKey), roleKey);
                roleKeyEncWithTreeKey = CryptoUtils.EncryptAesV2(roleKey, Enterprise.TreeKey);
                rolePublicKeyBase64 = CryptoUtils.UnloadRsaPublicKey(rsaPublicKey).Base64UrlEncode();

                if (EnterpriseData != null)
                {
                    var adminUsers = GetUsersForRole(role.Id)
                        .Select(id => EnterpriseData.TryGetUserById(id, out var u) ? u : null)
                        .Where(u => u != null && !string.IsNullOrEmpty(u.Email))
                        .ToList();

                    if (adminUsers.Count > 0)
                    {
                        await Enterprise.Auth.LoadUsersKeys(adminUsers.Select(u => u.Email));
                        roleKeys = adminUsers
                            .Where(u => Enterprise.Auth.TryGetUserKeys(u.Email, out _))
                            .Select(u =>
                            {
                                Enterprise.Auth.TryGetUserKeys(u.Email, out var keys);
                                var publicKey = CryptoUtils.LoadRsaPublicKey(keys.RsaPublicKey);
                                return new ManagedNodeRoleKey
                                {
                                    EnterpriseUserId = u.Id,
                                    RoleKey = CryptoUtils.EncryptRsa(roleKey, publicKey).Base64UrlEncode(),
                                    TreeKeyType = "encrypted_by_public_key",
                                };
                            }).ToArray();
                    }
                }
            }

            foreach (var privilege in privileges)
            {
                var rq = new RoleManagedNodePrivilegeAddCommand
                {
                    RoleId = role.Id,
                    ManagedNodeId = node.Id,
                    Privilege = privilege.ToString().ToLowerInvariant(),
                };

                if (privilege == RoleManagedNodePrivilege.TRANSFER_ACCOUNT)
                {
                    rq.RolePublicKey = rolePublicKeyBase64;
                    rq.RolePrivateKey = encryptedPrivateKey.Base64UrlEncode();
                    rq.RoleKeyEncryptedWithTreeKey = roleKeyEncWithTreeKey.Base64UrlEncode();
                    rq.RoleKeys = roleKeys;
                }

                commands.Add(rq);
            }

            var responses = await Enterprise.Auth.ExecuteBatch(commands);
            await Enterprise.Load();
            return responses;
        }

        public async Task<IList<KeeperApiResponse>> RoleManagedNodePrivilegeRemoveBatch(EnterpriseRole role, EnterpriseNode node, List<RoleManagedNodePrivilege> privileges)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (node == null) throw new ArgumentNullException(nameof(node));
            if (privileges == null) throw new ArgumentNullException(nameof(privileges));

            var commands = new List<KeeperApiCommand>();
            foreach (var privilege in privileges)
            {
                var rq = new RoleManagedNodePrivilegeRemoveCommand
                {
                    RoleId = role.Id,
                    ManagedNodeId = node.Id,
                    Privilege = privilege.ToString().ToLowerInvariant()
                };
                commands.Add(rq);
            }
            var responses = await Enterprise.Auth.ExecuteBatch(commands);
            await Enterprise.Load();
            return responses;
        }

        public async Task<IList<KeeperApiResponse>> RoleEnforcementAddBatch(EnterpriseRole role, IDictionary<RoleEnforcementPolicies, string> enforcements)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (enforcements == null) throw new ArgumentNullException(nameof(enforcements));

            var commands = new List<KeeperApiCommand>();

            foreach (var kvp in enforcements)
            {
                var enforcement = kvp.Key;
                var value = kvp.Value;

                var rq = new RoleEnforcementAddCommand
                {
                    RoleId = role.Id,
                    Enforcement = enforcement.ToString().ToLowerInvariant(),
                };

                if (!string.IsNullOrEmpty(value))
                {
                    if (bool.TryParse(value, out var boolValue))
                    {
                        commands.Add(rq);
                        continue;
                    }
                    else if (int.TryParse(value, out var intValue))
                    {
                        rq.Value = Convert.ToInt64(intValue);
                    }
                    else if (long.TryParse(value, out var longValue))
                    {
                        rq.Value = longValue;
                    }
                    else
                    {
                        rq.Value = value;
                    }
                }
                commands.Add(rq);
            }
            var responses = await Enterprise.Auth.ExecuteBatch(commands);
            await Enterprise.Load();
            return responses;
        }

        public async Task<IList<KeeperApiResponse>> RoleEnforcementRemoveBatch(EnterpriseRole role, List<RoleEnforcementPolicies> enforcements)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (enforcements == null) throw new ArgumentNullException(nameof(enforcements));

            var commands = new List<KeeperApiCommand>();
            foreach (var enforcement in enforcements)
            {
                var rq = new RoleEnforcementRemoveCommand
                {
                    RoleId = role.Id,
                    Enforcement = enforcement.ToString().ToLowerInvariant(),
                };
                commands.Add(rq);
            }
            var responses = await Enterprise.Auth.ExecuteBatch(commands);
            await Enterprise.Load();
            return responses;
        }

        public async Task<IList<KeeperApiResponse>> RoleEnforcementUpdateBatch(EnterpriseRole role, IDictionary<RoleEnforcementPolicies, string> enforcements)
        {
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (enforcements == null) throw new ArgumentNullException(nameof(enforcements));

            var commands = new List<KeeperApiCommand>();

            foreach (var kvp in enforcements)
            {
                var enforcement = kvp.Key;
                var value = kvp.Value;
                var enforcementName = enforcement.ToString().ToLowerInvariant();

                if (!string.IsNullOrEmpty(value) && bool.TryParse(value, out var boolValue))
                {
                    commands.Add(boolValue
                        ? new RoleEnforcementAddCommand { RoleId = role.Id, Enforcement = enforcementName, }
                        : new RoleEnforcementRemoveCommand { RoleId = role.Id, Enforcement = enforcementName,});
                }
                else
                {
                    var rq = new RoleEnforcementUpdateCommand
                    {
                        RoleId = role.Id,
                        Enforcement = enforcementName,
                    };

                    if (!string.IsNullOrEmpty(value))
                    {
                        rq.Value = long.TryParse(value, out var longValue) ? longValue : value;
                    }

                    commands.Add(rq);
                }
            }

            var responses = await Enterprise.Auth.ExecuteBatch(commands);
            await Enterprise.Load();
            return responses;
        }
    }
}