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
        public static async Task SetRestrictVisibility(this EnterpriseData enterpriseData, long nodeId)
        {
            var rq = new SetRestrictVisibilityRequest
            {
                NodeId = nodeId
            };
            await enterpriseData.Enterprise.Auth.ExecuteAuthRest("enterprise/set_restrict_visibility", rq);
        }

        /// <summary>
        /// Creates Enterprise Node
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="nodeName">Node Name</param>
        /// <param name="parentNode">Parent Node</param>
        /// <returns>Awaitable task returning created node</returns>
        public static async Task<EnterpriseNode> CreateNode(this EnterpriseData enterpriseData, string nodeName, EnterpriseNode parentNode = null)
        {
            parentNode = parentNode ?? enterpriseData.RootNode;
            var encryptedData = new EncryptedData
            {
                DisplayName = nodeName
            };

            var nodeId = await enterpriseData.Enterprise.GetEnterpriseId();
            var rq = new NodeAddCommand
            {
                NodeId = nodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, enterpriseData.Enterprise.TreeKey)
            };
            if (parentNode.Id > 0)
            {
                rq.ParentId = parentNode.Id;
            }
            await enterpriseData.Enterprise.Auth.ExecuteAuthCommand(rq);
            var node = new EnterpriseNode
            {
                Id = nodeId,
                DisplayName = nodeName,
                ParentNodeId = parentNode?.Id ?? 0,
            };

            await enterpriseData.Enterprise.Load();

            return node;
        }

        /// <summary>
        /// Updates existing node
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="node">Enterprise node</param>
        /// <param name="newParentNode">New Parent Node</param>
        /// <returns>Awaitable task</returns>
        public static async Task UpdateNode(this EnterpriseData enterpriseData, EnterpriseNode node, EnterpriseNode newParentNode = null)
        {
            var encryptedData = new EncryptedData
            {
                DisplayName = node.DisplayName
            };

            var rq = new NodeUpdateCommand
            {
                NodeId = node.Id,
                ParentId = newParentNode != null ? newParentNode.Id : node.ParentNodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, enterpriseData.Enterprise.TreeKey)
            };
            await enterpriseData.Enterprise.Auth.ExecuteAuthCommand(rq);
            await enterpriseData.Enterprise.Load();
        }

        /// <summary>
        /// Deletes existing node
        /// </summary>
        /// <param name="enterprise">Enterprise Data</param>
        /// <param name="nodeId">Node ID to be deleted</param>
        /// <returns>Awaitable task</returns>
        public static async Task DeleteNode(this EnterpriseData enterpriseData, long nodeId)
        {
            if (nodeId != enterpriseData.RootNode.Id)
            {
                var rq = new NodeDeleteCommand
                {
                    NodeId = nodeId
                };
                await enterpriseData.Enterprise.Auth.ExecuteAuthCommand(rq);
                await enterpriseData.Enterprise.Load();
            }
        }
    }
}