using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using Enterprise;
using System;
using System.IO;
using System.Net.Http;
using System.Runtime.Serialization;

namespace KeeperSecurity.Enterprise
{
    /// <summary>
    /// Miscellaneous Enterprise Methods
    /// </summary>
    public static class EnterpriseExtensions
    {
        private const string MIME_TYPE_JPEG = "image/jpeg";
        private const string MIME_TYPE_PNG = "image/png";
        private const string MIME_TYPE_GIF = "image/gif";
        private const string CHECK_STATUS_PENDING = "pending";
        private const string CHECK_STATUS_ACTIVE = "active";
        private const string CHECK_STATUS_INVALID_DIMENSIONS = "invalid_dimensions";
        private const string CONTENT_TYPE_HEADER = "Content-Type";
        private const long MAX_FILE_SIZE_BYTES = 500000;
        /// <summary>
        /// Toggles "Node Isolation" flag for enterprise node.
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data.</param>
        /// <param name="nodeId">Node ID</param>
        /// <returns>Awaitable Task</returns>
        public static async Task SetRestrictVisibility(this EnterpriseData enterpriseData, long nodeId)
        {
            var rq = new SetRestrictVisibilityRequest
            {
                NodeId = nodeId
            };
            enterpriseData.TryGetNode(nodeId, out var node);
            await enterpriseData.Enterprise.Auth.ExecuteAuthRest("enterprise/set_restrict_visibility", rq);
            if (node != null)
            {
                node.RestrictVisibility = !node.RestrictVisibility;
            }
        }

        /// <summary>
        /// Creates Enterprise Node
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data</param>
        /// <param name="nodeName">Node Name</param>
        /// <param name="parentNode">Parent Node</param>
        /// <returns>Awaitable task returning created node</returns>
        public static async Task<EnterpriseNode> CreateNode(this EnterpriseData enterpriseData, string nodeName, EnterpriseNode parentNode = null)
        {
            parentNode ??= enterpriseData.RootNode;
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
                ParentNodeId = parentNode.Id,
            };

            await enterpriseData.Enterprise.Load();

            return node;
        }

        /// <summary>
        /// Updates existing node
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data</param>
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
                ParentId = newParentNode?.Id ?? node.ParentNodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, enterpriseData.Enterprise.TreeKey)
            };
            await enterpriseData.Enterprise.Auth.ExecuteAuthCommand(rq);
            await enterpriseData.Enterprise.Load();
        }

        /// <summary>
        /// Deletes existing node
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data</param>
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

        /// <summary>
        /// Set custom invitation template to a node from a JSON file
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data</param>
        /// <param name="nodeId">Node ID</param>
        /// <param name="jsonFilePath">Path to JSON file containing invitation template (subject, header, body, buttonLabel)</param>
        /// <returns>Awaitable task</returns>
        public static async Task SetEnterpriseCustomInvitation(this EnterpriseData enterpriseData, long nodeId, string jsonFilePath)
        {
            if (string.IsNullOrEmpty(jsonFilePath)) throw new ArgumentNullException(nameof(jsonFilePath));
            
            var fullPath = Path.GetFullPath(jsonFilePath.Trim().Trim('"'));
            if (!File.Exists(fullPath)) throw new FileNotFoundException($"Invitation template file not found: {fullPath}", fullPath);

            var jsonBytes = File.ReadAllBytes(fullPath);
            var template = JsonUtils.ParseJson<CustomInvitationTemplate>(jsonBytes);

            var rq = new SetEnterpriseCustomInvitationCommand 
            {
                NodeId = nodeId,
                Subject = template.Subject,
                Header = template.Header,
                Body = template.Body,
                ButtonLabel = template.ButtonLabel
            };
            await enterpriseData.Enterprise.Auth.ExecuteAuthCommand(rq);
            await enterpriseData.Enterprise.Load();
        }

        /// <summary>
        /// Get custom invitation template of a node
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data</param>
        /// <param name="nodeId">Node ID</param>
        /// <returns>Awaitable task returning invitation template of a node</returns>
        public static async Task<GetEnterpriseCustomInvitationResponse> GetEnterpriseCustomInvitation(this EnterpriseData enterpriseData, long nodeId)
        {
            var rq = new GetEnterpriseCustomInvitationCommand
            {
                NodeId = nodeId
            };

            var response = await enterpriseData.Enterprise.Auth.ExecuteAuthCommand<GetEnterpriseCustomInvitationCommand, GetEnterpriseCustomInvitationResponse>(rq);
            return response;
        }

        /// <summary>
        /// Upload custom logo for a node. Handles the complete flow:
        /// 1. Validates file type (JPEG, PNG, GIF) and size (max 500KB)
        /// 2. Requests upload parameters from server
        /// 3. Uploads file to cloud storage
        /// 4. Verifies the upload
        /// </summary>
        /// <param name="enterpriseData">Enterprise Data</param>
        /// <param name="nodeId">Node ID</param>
        /// <param name="logoType">Logo Type (e.g., "enterprise", "email")</param>
        /// <param name="filePath">Path to the logo image file</param>
        /// <returns>Awaitable task returning the upload response with logo path and status</returns>
        public static async Task<CheckEnterpriseCustomLogoUploadResponse> UploadEnterpriseCustomLogo(this EnterpriseData enterpriseData, long nodeId, string logoType, string filePath)
        {
            if (string.IsNullOrEmpty(logoType)) throw new ArgumentNullException(nameof(logoType));
            if (string.IsNullOrEmpty(filePath)) throw new ArgumentNullException(nameof(filePath));

            var fullPath = Path.GetFullPath(filePath.Trim().Trim('"'));
            if (!File.Exists(fullPath)) throw new FileNotFoundException($"Logo file not found: {fullPath}", fullPath);

            var fileData = File.ReadAllBytes(fullPath);
            var mimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(fullPath));
            
            if (mimeType != MIME_TYPE_JPEG && mimeType != MIME_TYPE_PNG && mimeType != MIME_TYPE_GIF)
            {
                throw new ArgumentException("File must be a JPEG, PNG, or GIF image", nameof(filePath));
            }
            
            if (fileData.Length > MAX_FILE_SIZE_BYTES)
            {
                throw new ArgumentException($"File size must be less than 500 KB. Current size: {fileData.Length} bytes", nameof(filePath));
            }

            var rq = new SetEnterpriseCustomLogoCommand(logoType) { NodeId = nodeId };
            var uploadParams = await enterpriseData.Enterprise.Auth.ExecuteAuthCommand<SetEnterpriseCustomLogoCommand, SetEnterpriseCustomLogoResponse>(rq);

            var content = new MultipartFormDataContent();
       
            foreach (var pair in uploadParams.Parameters)
            {
                if (!pair.Key.Equals(CONTENT_TYPE_HEADER, StringComparison.OrdinalIgnoreCase))
                {
                    content.Add(new StringContent(pair.Value), pair.Key);
                }
            }

            content.Add(new StringContent(mimeType), CONTENT_TYPE_HEADER);
            
            var fileContent = new ByteArrayContent(fileData);
            fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mimeType);
            content.Add(fileContent, uploadParams.FileParameter);

            var handler = new HttpClientHandler();
            if (enterpriseData.Enterprise.Auth.Endpoint.WebProxy != null)
            {
                handler.Proxy = enterpriseData.Enterprise.Auth.Endpoint.WebProxy;
            }
            using var httpClient = new HttpClient(handler, true);
            var uploadResponse = await httpClient.PostAsync(uploadParams.Url, content);
            
            if ((int)uploadResponse.StatusCode != uploadParams.SuccessStatusCode)
            {
                var errorBody = await uploadResponse.Content.ReadAsStringAsync();
                throw new Exception($"Logo upload failed: HTTP {uploadResponse.StatusCode}. Response: {errorBody}");
            }

            var checkRq = new CheckEnterpriseCustomLogoUploadCommand(logoType)
            {
                NodeId = nodeId,
                UploadId = uploadParams.UploadId
            };

            while (true)
            {
                var checkResponse = await enterpriseData.Enterprise.Auth.ExecuteAuthCommand<CheckEnterpriseCustomLogoUploadCommand, CheckEnterpriseCustomLogoUploadResponse>(checkRq);
                var checkStatus = checkResponse.Status?.ToLowerInvariant();

                if (checkStatus == CHECK_STATUS_PENDING)
                {
                    await Task.Delay(2000);
                }
                else
                {
                    if (checkStatus != CHECK_STATUS_ACTIVE)
                    {
                        if (checkStatus == CHECK_STATUS_INVALID_DIMENSIONS)
                        {
                            throw new Exception("Image dimensions must be between 10x10 and 320x320");
                        }
                        else
                        {
                            throw new Exception($"Upload status = {checkStatus}");
                        }
                    }
                    else
                    {
                        await enterpriseData.Enterprise.Load();
                        return checkResponse;
                    }
                }
            }
        }
    }
}