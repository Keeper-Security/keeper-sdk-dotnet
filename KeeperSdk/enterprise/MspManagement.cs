using Enterprise;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using System.Linq;
using System;
using System.Collections.Generic;
using Authentication;
using Google.Protobuf;

namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public class ManagedCompanyAddonOptions 
    {
        public string Addon { get; set; }
        public int? NumberOfSeats { get; set; }
    }

    /// <summary>
    /// Represends Managed Companies create/update options
    /// </summary>
    public class ManagedCompanyOptions
    {
        /// <summary>
        ///     Managed Company Name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     Enterprise Node ID
        /// </summary>
        public long? NodeId { get; set; }

        /// <summary>
        ///     Managed Company Product ID
        /// </summary>
        public string ProductId { get; set; }

        /// <summary>
        ///     Maximum Number of Seats. -1 unlimited
        /// </summary>
        public int? NumberOfSeats { get; set; }

        /// <summary>
        ///     File/Storage Plan
        /// </summary>
        public string FilePlanType { get; set; }

        /// <summary>
        ///     Addons
        /// </summary>
        public ManagedCompanyAddonOptions[] Addons { get; set; }
    }

    /// <summary>
    /// Defines Managed Company actions
    /// </summary>
    public interface IMspManagement
    {
        /// <summary>
        /// Creates Managed Company
        /// </summary>
        /// <param name="options">Company options</param>
        /// <returns>Created managed company</returns>
        Task<EnterpriseManagedCompany> CreateManagedCompany(ManagedCompanyOptions options);
        /// <summary>
        /// Updates Managed Company
        /// </summary>
        /// <param name="companyId">Managed Company ID</param>
        /// <param name="options">Company options</param>
        /// <returns>Updated managed company</returns>
        Task<EnterpriseManagedCompany> UpdateManagedCompany(int companyId, ManagedCompanyOptions options);
        /// <summary>
        /// Removes Managed Company
        /// </summary>
        /// <param name="companyId">Managed Company ID</param>
        /// <returns></returns>
        Task RemoveManagedCompany(int companyId);
    }

    public partial class ManagedCompanyData : IMspManagement
    {
        private const int EnterpriseUserDataKeyTypeEcc = 4;
        /// <summary>
        /// Retrieves MSP legacy license adjustment entries for the supplied Unix-millisecond interval.
        /// </summary>
        public async Task<IList<LicenseAdjustmentLogEntry>> GetMspLegacyReport(long from, long to)
        {
            if (from > to) throw new EnterpriseException("The report start date must not be after the end date.");
            var response = await Enterprise.Auth.ExecuteAuthCommand<GetMcLicenseAdjustmentLogCommand, GetMcLicenseAdjustmentLogResponse>(
                new GetMcLicenseAdjustmentLogCommand { From = from, To = to });
            return response.Log ?? new List<LicenseAdjustmentLogEntry>();
        }

        /// <summary>
        /// Converts a validated enterprise subtree into a newly created managed company.
        /// </summary>
        public async Task<EnterpriseManagedCompany> ConvertNodeToManagedCompany(EnterpriseData enterpriseData,
            IRoleData roleData, IQueuedTeamData queuedTeamData, long nodeId, int? seats = null, string productId = "business")
        {
            if (!enterpriseData.TryGetNode(nodeId, out var root) || nodeId == enterpriseData.RootNode.Id)
                throw new EnterpriseException("The node must exist and must not be the enterprise root node.");
            if (seats.HasValue && seats.Value < 0) throw new EnterpriseException("Seat count cannot be negative.");
            if (string.IsNullOrWhiteSpace(productId)) throw new EnterpriseException("Product plan is required.");
            var product = ManagedCompanyConstants.MspProducts.FirstOrDefault(x =>
                string.Equals(x.ProductCode, productId, StringComparison.OrdinalIgnoreCase));
            if (product == null)
                throw new EnterpriseException($"Invalid license plan: {productId}. Supported plans are {string.Join(", ", ManagedCompanyConstants.MspProducts.Select(x => x.ProductCode))}");

            var nodeIds = new HashSet<long> { nodeId };
            var pending = new Queue<long>(); pending.Enqueue(nodeId);
            while (pending.Count > 0)
            {
                var id = pending.Dequeue();
                if (!enterpriseData.TryGetNode(id, out var node)) continue;
                foreach (var child in node.Subnodes) if (nodeIds.Add(child)) pending.Enqueue(child);
            }
            var roleIds = new HashSet<long>(roleData.Roles.Where(x => nodeIds.Contains(x.ParentNodeId)).Select(x => x.Id));
            var teamUids = new HashSet<string>(enterpriseData.Teams.Where(x => nodeIds.Contains(x.ParentNodeId)).Select(x => x.Uid));
            var userIds = new HashSet<long>(enterpriseData.Users.Where(x => nodeIds.Contains(x.ParentNodeId)).Select(x => x.Id));
            if (seats.HasValue && seats.Value < userIds.Count)
                throw new EnterpriseException($"Seat count ({seats.Value}) cannot be lower than the subtree user count ({userIds.Count}).");
            if (ManagedCompanies.Any(x => string.Equals(x.EnterpriseName, root.DisplayName, StringComparison.Ordinal)))
                throw new EnterpriseException($"A managed company named '{root.DisplayName}' already exists. Conversion requires a newly created managed company.");
            if (!(Enterprise is EnterpriseLoader sourceEnterprise) || sourceEnterprise.EcPrivateKey is not { Length: > 0 })
                throw new EnterpriseException("The MSP enterprise ECC private key is required to preserve user recoverable data keys.");
            if (enterpriseData.Nodes.Where(x => nodeIds.Contains(x.Id)).Any(x => string.IsNullOrWhiteSpace(x.EncryptedData)) ||
                roleData.Roles.Where(x => roleIds.Contains(x.Id)).Any(x => string.IsNullOrWhiteSpace(x.EncryptedData)) ||
                enterpriseData.Users.Where(x => userIds.Contains(x.Id) && x.KeyType != "no_key").Any(x => string.IsNullOrWhiteSpace(x.EncryptedData)))
                throw new EnterpriseException("The subtree contains an entity with missing encrypted data and cannot be converted safely.");
            if (enterpriseData.TryGetUserByEmail(Enterprise.Auth.Username, out var currentUser) && userIds.Contains(currentUser.Id))
                throw new EnterpriseException("The subtree contains the signed-in MSP administrator and cannot be converted.");
            var errors = new List<string>();
            foreach (var node in enterpriseData.Nodes.Where(x => nodeIds.Contains(x.Id)))
            {
                if (node.BridgeId != 0 || node.ScimId != 0 || node.SsoServiceProviderIds?.Length > 0)
                    errors.Add($"Remove provisioning from node '{node.DisplayName}' before conversion.");
            }
            if (ManagedCompanies.Any(x => nodeIds.Contains(x.ParentNodeId)))
                errors.Add("Move managed companies out of the subtree before conversion.");
            if (queuedTeamData != null && queuedTeamData.QueuedTeams.Any(x => nodeIds.Contains(x.ParentNodeId))) errors.Add("Remove queued teams from the subtree before conversion.");
            if (enterpriseData.Users.Any(x => userIds.Contains(x.Id) && x.UserStatus == UserStatus.Inactive)) errors.Add("Remove pending users from the subtree before conversion.");
            foreach (var role in roleData.Roles)
            {
                var moveRole = roleIds.Contains(role.Id);
                if (roleData.GetUsersForRole(role.Id).Any(id => moveRole != userIds.Contains(id)) || roleData.GetTeamsForRole(role.Id).Any(id => moveRole != teamUids.Contains(id)))
                    errors.Add($"Role '{role.DisplayName}' has memberships outside the subtree.");
            }
            foreach (var team in enterpriseData.Teams)
            {
                var moveTeam = teamUids.Contains(team.Uid);
                if (enterpriseData.GetUsersForTeam(team.Uid).Any(id => moveTeam != userIds.Contains(id))) errors.Add($"Team '{team.Name}' has memberships outside the subtree.");
            }
            foreach (var permission in roleData.GetAdminPermissions()) if (roleIds.Contains(permission.RoleId) != nodeIds.Contains(permission.NodeId)) errors.Add("An admin role manages a node outside the subtree.");
            if (errors.Count > 0) throw new EnterpriseException(string.Join(" ", errors.Distinct()));

            EnterpriseManagedCompany company = null;
            ManagedCompanyAuth mcAuth = null;
            var createdCompany = false;
            try
            {
            company = await CreateManagedCompany(new ManagedCompanyOptions { Name = root.DisplayName, NodeId = enterpriseData.RootNode.Id, ProductId = product.ProductCode, NumberOfSeats = Math.Max(seats ?? 0, Math.Max(userIds.Count, 1)) });
            createdCompany = true;
            mcAuth = new ManagedCompanyAuth(); await mcAuth.LoginToManagedCompany(Enterprise, company.EnterpriseId);
            var mcEnterprise = new EnterpriseLoader(mcAuth, Array.Empty<EnterpriseDataPlugin>()); await mcEnterprise.Load();
            string ReEncrypt(string data) => CryptoUtils.EncryptAesV1(CryptoUtils.DecryptAesV1(data.Base64UrlDecode(), Enterprise.TreeKey), mcEnterprise.TreeKey).Base64UrlEncode();
            var request = new NodeToManagedCompanyRequest { CompanyId = company.EnterpriseId };
            foreach (var node in enterpriseData.Nodes.Where(x => nodeIds.Contains(x.Id))) request.Nodes.Add(new ReEncryptedData { Id = node.Id, Data = ReEncrypt(node.EncryptedData) });
            foreach (var role in roleData.Roles.Where(x => roleIds.Contains(x.Id)))
            {
                var key = await roleData.GetRoleKey(role.Id);
                if (key == null || key.Length == 0)
                    throw new EnterpriseException($"Role key for '{role.DisplayName}' is unavailable; conversion cannot continue safely.");
                request.Roles.Add(new ReEncryptedData { Id = role.Id, Data = ReEncrypt(role.EncryptedData) });
                request.RoleKeys.Add(new ReEncryptedRoleKey { RoleId = role.Id, EncryptedRoleKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(key, mcEnterprise.TreeKey)) });
            }
            foreach (var user in enterpriseData.Users.Where(x => userIds.Contains(x.Id))) request.Users.Add(new ReEncryptedData { Id = user.Id, Data = user.KeyType == "no_key" ? user.DisplayName : ReEncrypt(user.EncryptedData) });
            foreach (var team in enterpriseData.Teams.Where(x => teamUids.Contains(x.Uid)))
            {
                var teamKey = new EncryptedTeamKeyRequest { TeamUid = ByteString.CopyFrom(team.Uid.Base64UrlDecode()) };
                if (team.TeamKey?.Length > 0)
                    teamKey.EncryptedTeamKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(team.TeamKey, mcEnterprise.TreeKey));
                else
                    teamKey.Force = true;
                request.TeamKeys.Add(teamKey);
            }
            if (mcEnterprise.EcPrivateKey is not { Length: > 0 })
                throw new EnterpriseException("The managed company ECC private key is required to preserve user recoverable data keys.");
            var dataKeyRequest = new UserDataKeyByNodeRequest();
            dataKeyRequest.NodeIds.Add(nodeIds);
            var dataKeys = await Enterprise.Auth.ExecuteAuthRest<UserDataKeyByNodeRequest, EnterpriseUserDataKeysByNodeResponse>(
                "enterprise/get_enterprise_user_data_key_by_node", dataKeyRequest);
            var sourcePrivateKey = CryptoUtils.LoadEcPrivateKey(sourceEnterprise.EcPrivateKey);
            var targetPublicKey = CryptoUtils.GetEcPublicKey(CryptoUtils.LoadEcPrivateKey(mcEnterprise.EcPrivateKey));
            foreach (var key in dataKeys.Keys.SelectMany(x => x.Keys).Where(x => x.KeyTypeId == EnterpriseUserDataKeyTypeEcc && userIds.Contains(x.EnterpriseUserId)))
            {
                var plainKey = CryptoUtils.DecryptEc(key.UserEncryptedDataKey.ToByteArray(), sourcePrivateKey);
                request.UsersDataKeys.Add(new ReEncryptedUserDataKey
                {
                    EnterpriseUserId = key.EnterpriseUserId,
                    UserEncryptedDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(plainKey, targetPublicKey))
                });
            }
            createdCompany = false;
            await Enterprise.Auth.ExecuteAuthRest("enterprise/node_to_managed_company", request);
            await Enterprise.Load();
            return ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == company.EnterpriseId) ?? company;
            }
            catch (Exception e)
            {
                if (createdCompany && company != null)
                {
                    try
                    {
                        await RemoveManagedCompany(company.EnterpriseId);
                    }
                    catch (Exception cleanupException)
                    {
                        throw new EnterpriseException($"Conversion failed and managed company {company.EnterpriseId} could not be removed: {cleanupException.Message}. Original error: {e.Message}");
                    }
                    throw new EnterpriseException($"Conversion failed; managed company {company.EnterpriseId} was removed. Original error: {e.Message}");
                }
                else if (company != null)
                    throw new EnterpriseException($"Conversion outcome is unknown for managed company {company.EnterpriseId}. It was not removed. Original error: {e.Message}");
                throw;
            }
            finally
            {
                if (mcAuth != null)
                {
                    try
                    {
                        await mcAuth.Logout();
                    }
                    catch (Exception logoutException)
                    {
                        System.Diagnostics.Debug.WriteLine($"Managed company logout failed: {logoutException.Message}");
                    }
                }
            }
        }

        /// <inheritdoc/>
        public async Task<EnterpriseManagedCompany> CreateManagedCompany(ManagedCompanyOptions options)
        {
            if (string.IsNullOrEmpty(options.Name))
            {
                options.Name = CryptoUtils.GenerateUid();
            }

            if (ManagedCompanies.Any(x => string.Equals(x.EnterpriseName, options.Name, System.StringComparison.OrdinalIgnoreCase)))
            {
                throw new EnterpriseException($"Managed Company '{options.Name}' already exists");
            }

            var treeKey = CryptoUtils.GenerateEncryptionKey();
            var encryptedTreeKey = CryptoUtils.EncryptAesV2(treeKey, Enterprise.TreeKey);

            var encData = new EncryptedData
            {
                DisplayName = "Keeper Administrator"
            };
            var encryptedRoleData = CryptoUtils.EncryptAesV1(JsonUtils.DumpJson(encData), treeKey);

            encData.DisplayName = "root";
            var encryptedNodeData = CryptoUtils.EncryptAesV1(JsonUtils.DumpJson(encData), treeKey);

            var rq = new EnterpriseRegistrationByMspCommand
            {
                NodeId = options.NodeId,
                Seats = options.NumberOfSeats ?? 0,
                ProductId = options.ProductId,
                FilePlanType = options.FilePlanType,
                EnterpriseName = options.Name,
                EncryptedTreeKey = encryptedTreeKey.Base64UrlEncode(),
                RoleData = encryptedRoleData.Base64UrlEncode(),
                RootNode = encryptedNodeData.Base64UrlEncode(),
            };
            if (options.Addons != null)
            {
                rq.AddOns = options.Addons.Select(x => new Commands.MspAddon
                {
                    AddOn = x.Addon,
                    Seats = x.NumberOfSeats
                }).ToArray();
            }

            var rs = await Enterprise.Auth.ExecuteAuthCommand<EnterpriseRegistrationByMspCommand, EnterpriseManagedCompanyByMspResponse>(rq);
            await Enterprise.Load();

            return ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == rs.EnterpriseId);
        }

        /// <inheritdoc/>
        public async Task<EnterpriseManagedCompany> UpdateManagedCompany(int companyId, ManagedCompanyOptions options)
        {
            if (!_managedCompanies.TryGetEntity(companyId, out var mc))
            {
                throw new EnterpriseException($"Managed Company #{companyId} does not exist");
            }

            var rq = new EnterpriseUpdateByMspCommand
            {
                EnterpriseId = companyId,
                NodeId = options.NodeId,
                FilePlanType = options.FilePlanType,
                EnterpriseName = options.Name ?? mc.EnterpriseName,
                Seats = options.NumberOfSeats ?? mc.NumberOfSeats,
                ProductId = options.ProductId ?? mc.ProductId,
            };
            if (options.Addons != null)
            {
                rq.AddOns = options.Addons.Select(x => new Commands.MspAddon
                {
                    AddOn = x.Addon,
                    Seats = x.NumberOfSeats
                }).ToArray();
            }

            await Enterprise.Auth.ExecuteAuthCommand<EnterpriseUpdateByMspCommand, EnterpriseManagedCompanyByMspResponse>(rq);
            await Enterprise.Load();

            return ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == companyId);
        }


        /// <inheritdoc/>
        public async Task RemoveManagedCompany(int companyId)
        {
            var rq = new EnterpriseRemoveByMspCommand
            {
                EnterpriseId = companyId,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }
    }
}
    
