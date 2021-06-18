using KeeperSecurity.Commands;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using Enterprise;
using System.Collections.Generic;
using System.Linq;
using KeeperSecurity.Authentication.Async;
using System;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Miscellaneous Enterprise Methods
    /// </summary>
    public static class EnterpriseExtensions
    {
        /// <summary>
        /// Toggles "Node Isolation" flag for enterprise node.
        /// </summary>
        /// <param name="enterprise">Enterprise Data.</param>
        /// <param name="nodeId">Node ID</param>
        /// <returns>Awaitable Task</returns>
        public static async Task SetRestrictVisibility(this EnterpriseData enterprise, long nodeId)
        {
            var rq = new SetRestrictVisibilityRequest
            {
                NodeId = nodeId
            };
            await enterprise.Auth.ExecuteAuthRest("enterprise/set_restrict_visibility", rq);
        }

        /// <summary>
        /// Creates Enterprise Node
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="nodeName">Node Name</param>
        /// <param name="parentNode">Parent Node</param>
        /// <returns>Awaitable task returning created node</returns>
        public static async Task<EnterpriseNode> CreateNode(this EnterpriseData enterprise, string nodeName, EnterpriseNode parentNode = null)
        {
            parentNode = parentNode ?? enterprise.RootNode;
            var encryptedData = new EncryptedData
            {
                DisplayName = nodeName
            };

            var nodeId = await enterprise.GetEnterpriseId();
            var rq = new NodeAddCommand
            {
                NodeId = nodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, enterprise.TreeKey)
            };
            if (parentNode.Id > 0)
            {
                rq.ParentId = parentNode.Id;
            }
            await enterprise.Auth.ExecuteAuthCommand(rq);
            var node = new EnterpriseNode
            {
                Id = nodeId,
                DisplayName = nodeName,
                ParentNodeId = parentNode?.Id ?? 0,
            };
            enterprise._nodes.TryAdd(nodeId, node);
            parentNode.Subnodes.Add(nodeId);

            return node;
        }

        /// <summary>
        /// Updates existing node
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="node">Enterprise node</param>
        /// <param name="newParentNode">New Parent Node</param>
        /// <returns>Awaitable task</returns>
        public static async Task UpdateNode(this EnterpriseData enterprise, EnterpriseNode node, EnterpriseNode newParentNode = null)
        {
            var encryptedData = new EncryptedData
            {
                DisplayName = node.DisplayName
            };

            var rq = new NodeUpdateCommand
            {
                NodeId = node.Id,
                ParentId = newParentNode != null ? newParentNode.Id : node.ParentNodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, enterprise.TreeKey)
            };
            await enterprise.Auth.ExecuteAuthCommand(rq);
            if (newParentNode != null)
            {
                if (enterprise._nodes.TryGetValue(node.Id, out var pNode))
                {
                    pNode.Subnodes.Remove(node.Id);
                }
                newParentNode.Subnodes.Add(node.Id);
                node.ParentNodeId = newParentNode.Id;
            }
        }

        /// <summary>
        /// Deletes existing node
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="nodeId">Node ID to be deleted</param>
        /// <returns>Awaitable task</returns>
        public static async Task DeleteNode(this EnterpriseData enterprise, long nodeId)
        {
            if (nodeId != enterprise.RootNode.Id)
            {
                var rq = new NodeDeleteCommand
                {
                    NodeId = nodeId
                };
                await enterprise.Auth.ExecuteAuthCommand(rq);
                if (enterprise._nodes.TryGetValue(nodeId, out var node))
                {
                    if (enterprise._nodes.TryGetValue(node.ParentNodeId, out node))
                    {
                        node.Subnodes.Remove(nodeId);
                    }
                }
            }
        }

        /// <summary>
        /// Creates Enterprise Role
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="roleName">Role Name</param>
        /// <param name="nodeId">Node ID</param>
        /// <param name="visibleBelow">Specifies if admins below can see this role to add a user to</param>
        /// <param name="newUserInherit">Specifies if new users in this node, or sub nodes are automatically added to this role.</param>
        /// <returns>Awaitable task returning created role</returns>
        public static async Task<EnterpriseRole> CreateRole(this EnterpriseData enterprise, string roleName, long nodeId, bool visibleBelow, bool newUserInherit)
        {
            var encryptedData = new EncryptedData
            {
                DisplayName = roleName
            };

            var roleId = await enterprise.GetEnterpriseId();
            var rq = new RoleAddCommand
            {
                RoleId = roleId,
                NodeId = nodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, enterprise.TreeKey),
                VisibleBelow = visibleBelow,
                NewUserInherit = newUserInherit
            };

            await enterprise.Auth.ExecuteAuthCommand(rq);
            var role = new EnterpriseRole
            {
                Id = rq.RoleId,
                NodeId = rq.NodeId,
                VisibleBelow = rq.VisibleBelow,
                NewUserInherit = rq.NewUserInherit,
                DisplayName = roleName
            };
            enterprise._roles.TryAdd(roleId, role);

            return role;
        }

        /// <summary>
        /// Copy Enterprise Role with its enforcements
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="srcRole">Enterprise Role</param>
        /// <param name="nodeId">Node ID</param>
        /// <param name="newRoleName">New Role Name</param>
        /// <returns>Awaitable task returning newly created role</returns>
        public static async Task<EnterpriseRole> CopyRole(this EnterpriseData enterprise, EnterpriseRole srcRole, long nodeId, string newRoleName)
        {
            var newRole = await CreateRole(enterprise, newRoleName, nodeId, srcRole.VisibleBelow, srcRole.NewUserInherit);

            var commands = new List<KeeperApiCommand>();
            foreach (var enforcement in srcRole.Enforcements)
            {
                commands.Add(new RoleEnforcementAddCommand
                {
                    RoleId = newRole.Id,
                    Enforcement = enforcement.Key,
                    Value = enforcement.Value
                });
            }

            var cmds = commands.AsEnumerable();
            while (cmds.Any())
            {
                var batch = cmds.Take(99).ToList();
                cmds = cmds.Skip(99);
                var execRq = new ExecuteCommand
                {
                    Requests = batch
                };
                var execRs = await enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
                if (execRs.Results?.Count > 0)
                {
                    var last = execRs.Results.Last();
                    var success = execRs.Results.Count + (last.IsSuccess ? 0 : -1);
                    Console.WriteLine($"Successfully added {success} role enforcement(s)");
                    if (!last.IsSuccess) Console.WriteLine(last.message);
                }
            }

            return newRole;
        }
        /// <summary>
        /// Adds Enterprise User to Enterprise Role
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="roleId">Role ID</param>
        /// <param name="nodeId">Node ID</param>
        /// <param name="treeKey">Specifies if admins below can see this role to add a user to</param>
        /// <param name="roleAdminKey">Specifies if new users in this node, or sub nodes are automatically added to this role.</param>
        /// <returns>Awaitable task returning created role</returns>
        public static async Task AddUserToRole(this EnterpriseData enterprise, long roleId, long userId, string treeKey=null, string roleAdminKey=null)
        {
            var rq = new RoleUserAddCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
                TreeKey = treeKey,
                RoleAdminKey = roleAdminKey
            };

            await enterprise.Auth.ExecuteAuthCommand(rq);
        }
    }
}
