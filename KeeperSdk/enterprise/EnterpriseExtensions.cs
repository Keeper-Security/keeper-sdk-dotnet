using KeeperSecurity.Commands;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using Enterprise;

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
        /// <returns>Awaitable task returning crerated node</returns>
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
    }
}