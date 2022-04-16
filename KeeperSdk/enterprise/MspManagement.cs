using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using System.Linq;

namespace KeeperSecurity.Enterprise
{
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
        ///     Number of Seats
        /// </summary>
        public int? NumberOfSeats { get; set; }

        /// <summary>
        ///     File/Storage Plan
        /// </summary>
        public string FilePlanType { get; set; }
    }

    public interface IMspManagement
    {
        Task<EnterpriseManagedCompany> CreateManagedCompany(ManagedCompanyOptions options);
        Task<EnterpriseManagedCompany> UpdateManagedCompany(int companyId, ManagedCompanyOptions options);
        Task RemoveManagedCompany(int enterpriseId);
    }


    public partial class ManagedCompanyData : IMspManagement
    {
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
                EnterpriseName = options.Name,
                EncryptedTreeKey = encryptedTreeKey.Base64UrlEncode(),
                RoleData = encryptedRoleData.Base64UrlEncode(),
                RootNode = encryptedNodeData.Base64UrlEncode(),
            };

            var rs = await Enterprise.Auth.ExecuteAuthCommand<EnterpriseRegistrationByMspCommand, EnterpriseManagedCompanyByMspResponse>(rq);
            await Enterprise.Load();

            return ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == rs.EnterpriseId);
        }

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
                EnterpriseName = options.Name ?? mc.EnterpriseName,
                Seats = options.NumberOfSeats ?? mc.NumberOfSeats,
                ProductId = options.ProductId ?? mc.ProductId,
            };

            var rs = await Enterprise.Auth.ExecuteAuthCommand<EnterpriseUpdateByMspCommand, EnterpriseManagedCompanyByMspResponse>(rq);
            await Enterprise.Load();

            return ManagedCompanies.FirstOrDefault(x => x.EnterpriseId == companyId);
        }


        public async Task RemoveManagedCompany(int enterpriseId)
        {
            var rq = new EnterpriseRemoveByMspCommand
            {
                EnterpriseId = enterpriseId,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }
    }
}
    
