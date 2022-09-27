using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using System.Linq;

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
        /// <inheritdoc/>
        public async Task<EnterpriseManagedCompany> CreateManagedCompany(ManagedCompanyOptions options)
        {
            if (string.IsNullOrEmpty(options.Name))
            {
                options.Name = CryptoUtils.GenerateUid();
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

            var rs = await Enterprise.Auth.ExecuteAuthCommand<EnterpriseUpdateByMspCommand, EnterpriseManagedCompanyByMspResponse>(rq);
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
    
