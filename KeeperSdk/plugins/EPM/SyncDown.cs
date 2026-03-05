using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using PEDMProto = PEDM;

namespace KeeperSecurity.Plugins.EPM
{
    /// <exclude/>
    public static class EpmSyncExtensions
    {
        /// <summary>
        /// Syncs EPM data from the server.
        /// </summary>
        /// <param name="auth">Authentication context with session token.</param>
        /// <param name="storage">EPM storage to store synced data.</param>
        /// <param name="treeKey">Enterprise tree key for decrypting deployment keys. If null, keys will be stored encrypted.</param>
        /// <param name="fullSync">Force full sync by clearing continuation token.</param>
        /// <returns>Task that completes when sync is done.</returns>
        public static async Task SyncEpmData(this IAuthentication auth, IEpmStorage storage, byte[] treeKey = null, bool fullSync = false)
        {
            byte[] continuationToken = null;
            var tokenSetting = storage.Settings.GetEntity("PEDM_SYNC_TOKEN");
            if (!fullSync && tokenSetting != null && !string.IsNullOrEmpty(tokenSetting.Value))
            {
                try
                {
                    continuationToken = tokenSetting.Value.Base64UrlDecode();
                }
                catch
                {
                    continuationToken = null;
                }
            }

            var done = false;

            while (!done)
            {
                var request = new PEDMProto.GetPedmDataRequest();
                if (continuationToken != null && continuationToken.Length > 0)
                {
                    request.ContinuationToken = ByteString.CopyFrom(continuationToken);
                }

                var response = await auth.ExecuteRouter<PEDMProto.GetPedmDataRequest, PEDMProto.GetPedmDataResponse>(
                    "pedm/sync_pedm_data", 
                    request, 
                    typeof(PEDMProto.GetPedmDataResponse));
                
                if (response == null)
                {
                    throw new Exception("Empty response from EPM sync");
                }
                if (response.ResetCache)
                {
                    storage.Reset();
                }

                continuationToken = response.ContinuationToken?.ToByteArray();

                ProcessRemovedItems(storage, response);
                await ProcessAddedItems(storage, response, treeKey);
                ProcessApprovalTimeouts(storage);

                done = !response.HasMore;
            }

            if (tokenSetting == null)
            {
                tokenSetting = new EpmAdminSettingsData
                {
                    Key = "PEDM_SYNC_TOKEN",
                    Value = ""
                };
            }

            if (continuationToken != null && continuationToken.Length > 0)
            {
                tokenSetting.Value = continuationToken.Base64UrlEncode();
            }
            else
            {
                tokenSetting.Value = "";
            }

            storage.Settings.PutEntities(new[] { tokenSetting });
        }

        private static void ProcessRemovedItems(IEpmStorage storage, PEDMProto.GetPedmDataResponse response)
        {
            if (response.RemovedDeployments.Count > 0)
            {
                var removedUids = response.RemovedDeployments
                    .Select(x => x.ToByteArray().Base64UrlEncode())
                    .ToArray();
                storage.Deployments.DeleteUids(removedUids);

                var allAgents = storage.Agents.GetAll().ToList();
                var agentsToRemove = allAgents
                    .Where(a => removedUids.Contains(a.DeploymentUid))
                    .Select(a => a.AgentUid)
                    .ToArray();
                if (agentsToRemove.Length > 0)
                {
                    storage.Agents.DeleteUids(agentsToRemove);
                    CleanupCollectionLinksForAgents(storage, agentsToRemove);
                }
            }

            if (response.RemovedAgents.Count > 0)
            {
                var removedUids = response.RemovedAgents
                    .Select(x => x.ToByteArray().Base64UrlEncode())
                    .ToArray();
                storage.Agents.DeleteUids(removedUids);
                CleanupCollectionLinksForAgents(storage, removedUids);
            }

            if (response.RemovedPolicies.Count > 0)
            {
                var removedUids = response.RemovedPolicies
                    .Select(x => x.ToByteArray().Base64UrlEncode())
                    .ToArray();
                storage.Policies.DeleteUids(removedUids);
            }

            if (response.RemovedCollection.Count > 0)
            {
                var removedUids = response.RemovedCollection
                    .Select(x => x.ToByteArray().Base64UrlEncode())
                    .ToArray();
                storage.Collections.DeleteUids(removedUids);
                storage.CollectionLinks.DeleteLinksForSubjects(removedUids);
            }

            if (response.RemovedCollectionLink.Count > 0)
            {
                var removedLinks = response.RemovedCollectionLink
                    .Select(x => new EpmStorageCollectionLinkData
                    {
                        CollectionUid = x.CollectionUid.ToByteArray().Base64UrlEncode(),
                        LinkUid = x.LinkUid.ToByteArray().Base64UrlEncode(),
                        LinkType = (int)x.LinkType
                    })
                    .ToArray();
                storage.CollectionLinks.DeleteLinks(removedLinks);
            }

            if (response.RemovedApprovals.Count > 0)
            {
                var removedUids = response.RemovedApprovals
                    .Select(x => x.ToByteArray().Base64UrlEncode())
                    .ToArray();
                storage.Approvals.DeleteUids(removedUids);
                storage.ApprovalStatus.DeleteUids(removedUids);
            }
        }

        private static void CleanupCollectionLinksForAgents(IEpmStorage storage, string[] agentUids)
        {
            var allLinks = storage.CollectionLinks.GetAllLinks().ToList();
            var linksToRemove = allLinks
                .Where(link => link.LinkType == (int)PEDMProto.CollectionLinkType.CltAgent && agentUids.Contains(link.LinkUid))
                .ToArray();
            if (linksToRemove.Length > 0)
            {
                storage.CollectionLinks.DeleteLinks(linksToRemove);
            }
        }

        private static Task ProcessAddedItems(IEpmStorage storage, PEDMProto.GetPedmDataResponse response, byte[] treeKey)
        {
            if (response.Deployments.Count > 0)
            {
                var deployments = response.Deployments.Select(ToStorageDeployment).Where(x => x != null).ToArray();
                if (deployments.Length > 0)
                {
                    storage.Deployments.PutEntities(deployments);
                }
            }

            if (response.Agents.Count > 0)
            {
                var agents = response.Agents.Select(ToStorageAgent).ToArray();
                storage.Agents.PutEntities(agents);
            }

            if (response.Policies.Count > 0)
            {
                var policies = response.Policies.Select(ToStoragePolicy).ToArray();
                storage.Policies.PutEntities(policies);
            }

            if (response.Collections.Count > 0)
            {
                var collections = response.Collections.Select(ToStorageCollection).ToArray();
                storage.Collections.PutEntities(collections);
            }

            if (response.CollectionLink.Count > 0)
            {
                var links = response.CollectionLink.Select((PEDMProto.CollectionLink x) => ToStorageCollectionLink(x)).ToArray();
                storage.CollectionLinks.PutLinks(links);
            }

            if (response.Approvals.Count > 0)
            {
                var approvals = response.Approvals.Select(ToStorageApproval).ToArray();
                storage.Approvals.PutEntities(approvals);
            }

            if (response.ApprovalStatus.Count > 0)
            {
                var approvalStatuses = response.ApprovalStatus.Select(ToStorageApprovalStatus).ToArray();
                storage.ApprovalStatus.PutEntities(approvalStatuses);
            }

            return Task.CompletedTask;
        }

        private static IEpmStorageDeployment ToStorageDeployment(PEDMProto.DeploymentNode node)
        {
            byte[] encryptedKey = node.AesKey?.ToByteArray() ?? Array.Empty<byte>();

            return new EpmStorageDeploymentData
            {
                DeploymentUid = node.DeploymentUid.ToByteArray().Base64UrlEncode(),
                EncryptedKey = encryptedKey,
                Disabled = node.Disabled,
                Data = node.EncryptedData?.ToByteArray() ?? Array.Empty<byte>(),
                PublicKey = node.EcPublicKey?.ToByteArray() ?? Array.Empty<byte>(),
                Created = node.Created,
                LastUpdated = node.Modified
            };
        }

        private static IEpmStorageAgent ToStorageAgent(PEDMProto.AgentNode node)
        {
            return new EpmStorageAgentData
            {
                AgentUid = node.AgentUid.ToByteArray().Base64UrlEncode(),
                MachineId = node.MachineId,
                DeploymentUid = node.DeploymentUid.ToByteArray().Base64UrlEncode(),
                PublicKey = node.EcPublicKey?.ToByteArray() ?? Array.Empty<byte>(),
                Data = node.EncryptedData?.ToByteArray() ?? Array.Empty<byte>(),
                Disabled = node.Disabled,
                Created = node.Created,
                Modified = node.Modified
            };
        }

        private static bool ExtractDisabledRecursively(object obj)
        {
            if (obj == null)
                return false;

            if (obj is Dictionary<string, object> dict)
            {
                if (dict.TryGetValue("disabled", out var disabledValue))
                {
                    if (disabledValue is bool boolValue)
                        return boolValue;
                    if (bool.TryParse(disabledValue?.ToString(), out var parsed))
                        return parsed;
                }

                foreach (var value in dict.Values)
                {
                    var result = ExtractDisabledRecursively(value);
                    if (result)
                        return true;
                }
            }
            else if (obj is System.Collections.IList list)
            {
                foreach (var item in list)
                {
                    var result = ExtractDisabledRecursively(item);
                    if (result)
                        return true;
                }
            }

            return false;
        }

        private static IEpmStoragePolicy ToStoragePolicy(PEDMProto.PolicyNode node)
        {
            bool disabled = false;
            byte[] adminDataBytes = node.PlainData?.ToByteArray() ?? Array.Empty<byte>();
            
            if (adminDataBytes.Length > 0)
            {
                try
                {
                    var adminData = JsonUtils.ParseJson<Dictionary<string, object>>(adminDataBytes);
                    disabled = ExtractDisabledRecursively(adminData);
                }
                catch
                {
                }
            }

            var policy = new EpmStoragePolicyData
            {
                PolicyUid = node.PolicyUid.ToByteArray().Base64UrlEncode(),
                AdminData = adminDataBytes,
                Data = node.EncryptedData?.ToByteArray() ?? Array.Empty<byte>(),
                Key = node.EncryptedKey?.ToByteArray() ?? Array.Empty<byte>(),
                Disabled = disabled,
                Created = node.Created,
                Updated = node.Modified
            };
            return policy;
        }

        private static IEpmStorageCollection ToStorageCollection(PEDMProto.CollectionNode node)
        {
            return new EpmStorageCollectionData
            {
                CollectionUid = node.CollectionUid.ToByteArray().Base64UrlEncode(),
                CollectionType = node.CollectionType,
                Data = node.EncryptedData?.ToByteArray() ?? Array.Empty<byte>(),
                Created = node.Created
            };
        }

        private static IEpmStorageCollectionLink ToStorageCollectionLink(PEDMProto.CollectionLink node)
        {
            return new EpmStorageCollectionLinkData
            {
                CollectionUid = node.CollectionUid.ToByteArray().Base64UrlEncode(),
                LinkUid = node.LinkUid.ToByteArray().Base64UrlEncode(),
                LinkType = (int)node.LinkType
            };
        }

        private static IEpmStorageApproval ToStorageApproval(PEDMProto.ApprovalNode node)
        {
            return new EpmStorageApprovalData
            {
                ApprovalUid = node.ApprovalUid.ToByteArray().Base64UrlEncode(),
                ApprovalType = node.ApprovalType,
                AgentUid = node.AgentUid.ToByteArray().Base64UrlEncode(),
                AccountInfo = node.AccountInfo?.ToByteArray() ?? Array.Empty<byte>(),
                ApplicationInfo = node.ApplicationInfo?.ToByteArray() ?? Array.Empty<byte>(),
                Justification = node.Justification?.ToByteArray() ?? Array.Empty<byte>(),
                ExpireIn = node.ExpireIn,
                Created = node.Created
            };
        }

        private static IEpmStorageApprovalStatus ToStorageApprovalStatus(PEDMProto.ApprovalStatusNode node)
        {
            return new EpmStorageApprovalStatusData
            {
                ApprovalUid = node.ApprovalUid.ToByteArray().Base64UrlEncode(),
                ApprovalStatus = (int)node.ApprovalStatus,
                EnterpriseUserId = (int)node.EnterpriseUserId,
                Modified = node.Modified
            };
        }

        private static void ProcessApprovalTimeouts(IEpmStorage storage)
        {
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var allApprovals = storage.Approvals.GetAll().ToList();
            var approvalsToDeny = new List<string>();

            foreach (var approval in allApprovals)
            {
                if (approval.ExpireIn <= 0) continue;

                var created = approval.Created;
                var expireTime = created + approval.ExpireIn;

                if (currentTime > expireTime)
                {
                    var approvalStatus = storage.ApprovalStatus.GetEntity(approval.ApprovalUid);
                    var isEscalated = approvalStatus != null && approvalStatus.EnterpriseUserId > 0;

                    if (isEscalated)
                    {
                        var escalatedExpireTime = created + (2 * approval.ExpireIn);
                        if (currentTime > escalatedExpireTime)
                        {
                            approvalsToDeny.Add(approval.ApprovalUid);
                        }
                    }
                    else
                    {
                        approvalsToDeny.Add(approval.ApprovalUid);
                    }
                }
            }

            if (approvalsToDeny.Count > 0)
            {
                storage.Approvals.DeleteUids(approvalsToDeny);
                storage.ApprovalStatus.DeleteUids(approvalsToDeny);
            }
        }
    }
}

