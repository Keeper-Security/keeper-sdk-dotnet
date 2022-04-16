using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public interface IManagedCompanyData 
    {
        IEnumerable<EnterpriseManagedCompany> ManagedCompanies { get; }
    }



    /// <summary>
    /// Represends Managed Companies enterprise data.
    /// </summary>
    public partial class ManagedCompanyData : EnterpriseDataPlugin, IManagedCompanyData
    {
        private readonly ManagedCompanyDictionary _managedCompanies;
        public ManagedCompanyData()
        {
            _managedCompanies = new ManagedCompanyDictionary();

            Entities = new IKeeperEnterpriseEntity[] { _managedCompanies };
        }

        /// <exclude />
        public override IEnumerable<IKeeperEnterpriseEntity> Entities { get; }

        /// <summary>
        /// Get a list of all managed companies in the enterprise.
        /// </summary>
        public IEnumerable<EnterpriseManagedCompany> ManagedCompanies => _managedCompanies.Entities;

        /// <exclude />
        public const string BusinessLicense = "business";
        /// <exclude />
        public const string BusinessPlusLicense = "businessPlus";
        /// <exclude />
        public const string EnterpriseLicense = "enterprise";
        /// <exclude />
        public const string EnterprisePlusLicense = "enterprisePlus";


    }

    /// <exclude />
    public class ManagedCompanyDictionary : EnterpriseDataDictionary<int, ManagedCompany, EnterpriseManagedCompany>, IGetEnterprise
    {
        public ManagedCompanyDictionary() : base(EnterpriseDataEntity.ManagedCompanies)
        {
        }

        protected override int GetEntityId(ManagedCompany keeperData)
        {
            return keeperData.McEnterpriseId;
        }

        protected override void SetEntityId(EnterpriseManagedCompany entity, int id)
        {
            entity.EnterpriseId = id;
        }

        protected override void PopulateSdkFromKeeper(EnterpriseManagedCompany sdk, ManagedCompany keeper)
        {
            sdk.EnterpriseName = keeper.McEnterpriseName;
            sdk.ProductId = keeper.ProductId;
            sdk.NumberOfSeats = keeper.NumberOfSeats;
            sdk.NumberOfUsers = keeper.NumberOfUsers;
            sdk.ParentNodeId = keeper.MspNodeId;
            sdk.IsExpired = keeper.IsExpired;
            sdk.FilePlanType = keeper.FilePlanType;
            sdk.TreeKeyRole = keeper.TreeKeyRole;
            var treeKeyEncoded = keeper.TreeKey;
            if (!string.IsNullOrEmpty(treeKeyEncoded))
            {
                try
                {
                    var enterprise = GetEnterprise?.Invoke();
                    if (enterprise?.TreeKey != null)
                    {
                        sdk.TreeKey = CryptoUtils.DecryptAesV2(treeKeyEncoded.Base64UrlDecode(), enterprise.TreeKey);
                    }
                }
                catch { }
            }
            sdk.AddOns = keeper.AddOns.Select(x => new ManagedCompanyLicenseAddOn
            {
                Name = x.Name,
                Seats = x.Seats,
                IsEnabled = x.Enabled,
                IsTrial = x.IsTrial,
                Expiration = x.Expiration,
                Creation = x.Created,
                Activation = x.ActivationTime,
            }).ToArray();
        }
        public Func<IEnterpriseLoader> GetEnterprise { get; set; }
    }

    /// <exclude />
    public class ManagedCompanyAuth: AuthCommon
    {
        public byte[] TreeKey { get; private set; }

        public async Task LoginToManagedCompany(IEnterpriseLoader enterprise, int mcEnterpriseId)
        {
            Endpoint = enterprise.Auth.Endpoint;
            DeviceToken = enterprise.Auth.DeviceToken;
            Username = enterprise.Auth.Username;
            var mcRq = new LoginToMcRequest
            {
                McEnterpriseId = mcEnterpriseId,
                
            };
            var mcRs = await enterprise.Auth.ExecuteAuthRest<LoginToMcRequest, LoginToMcResponse>(
                "authentication/login_to_mc", mcRq);

            authContext = new AuthContext
            {
                DataKey = enterprise.Auth.AuthContext.DataKey,
                SessionToken = mcRs.EncryptedSessionToken.ToByteArray(),
                AccountAuthType = AccountAuthType.ManagedCompany,
            };

            TreeKey = CryptoUtils.DecryptAesV2(mcRs.EncryptedTreeKey.Base64UrlDecode(), enterprise.TreeKey);
            await PostLogin();
        }

        public override IAuthCallback AuthCallback => null;
    }
}
