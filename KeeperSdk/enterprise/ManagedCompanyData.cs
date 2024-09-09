using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using BI;
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

    /// <exclude />
    public class MspAddon
    {
        public string AddonCode { get; internal set; }
        public string AddonName { get; internal set; }
        public bool SeatsRequired { get; internal set; }
    }

    /// <exclude />
    public class MspFilePlan
    {
        public string FilePlanCode { get; internal set; }
        public string FilePlanName { get; internal set; }
    }

    /// <exclude />
    public class MspProduct
    {
        public string ProductCode { get; internal set; }
        public string ProductName { get; internal set; }
        public string FilePlanCode { get; internal set; }
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

    }

    /// <exclude />
    public static class ManagedCompanyConstants
    {
        public static readonly MspProduct[] MspProducts = new[]
        {
            new MspProduct
            {
                ProductCode = BusinessLicense,
                ProductName = "Business",
                FilePlanCode = StoragePlan100GB,
            },
            new MspProduct
            {
                ProductCode = BusinessPlusLicense,
                ProductName = "Business Plus",
                FilePlanCode = StoragePlan1TB,
            },
            new MspProduct
            {
                ProductCode = EnterpriseLicense,
                ProductName = "Enterprise",
                FilePlanCode = StoragePlan100GB,
            },
            new MspProduct
            {
                ProductCode = EnterprisePlusLicense,
                ProductName = "Enterprise Plus",
                FilePlanCode = StoragePlan1TB,
            },
        };
        public static readonly MspFilePlan[] MspFilePlans = new[]
        {
            new MspFilePlan
            {
                FilePlanCode = StoragePlan100GB,
                FilePlanName = "100GB",
            },
            new MspFilePlan
            {
                FilePlanCode = StoragePlan1TB,
                FilePlanName = "1TB",
            },
            new MspFilePlan
            {
                FilePlanCode = StoragePlan10TB,
                FilePlanName = "10TB",
            },
        };

        public static readonly MspAddon[] MspAddons = new[]
        {
            new MspAddon
            {
                AddonCode = AddonBreachWatch,
                AddonName = "BreachWatch",
                SeatsRequired = false,
            },
            new MspAddon
            {
                AddonCode = AddonComplianceReport,
                AddonName = "Compliance Reporting",
                SeatsRequired = false,
            },
            new MspAddon
            {
                AddonCode = AddonAuditReport,
                AddonName = "Advanced Reporting & Alerts Module",
                SeatsRequired = false,
            },
            new MspAddon
            {
                AddonCode = AddonServiceAndSupport,
                AddonName = "MSP Dedicated Service & Support",
                SeatsRequired = false,
            },
            new MspAddon
            {
                AddonCode = AddonSecretsManager,
                AddonName = "Keeper Secrets Manager (KSM)",
                SeatsRequired = false,
            },
            new MspAddon
            {
                AddonCode = AddonConnectionManager,
                AddonName = "Keeper Connection Manager (KCM)",
                SeatsRequired = true,
            },
            new MspAddon
            {
                AddonCode = AddonChat,
                AddonName = "KeeperChat",
                SeatsRequired = false,
            },
        };

        public const string BusinessLicense = "business";
        public const string BusinessPlusLicense = "businessPlus";
        public const string EnterpriseLicense = "enterprise";
        public const string EnterprisePlusLicense = "enterprisePlus";

        public const string StoragePlan100GB = "STORAGE_100GB";
        public const string StoragePlan1TB = "STORAGE_1000GB";
        public const string StoragePlan10TB = "STORAGE_10000GB";

        public const string AddonBreachWatch = "enterprise_breach_watch";
        public const string AddonComplianceReport = "compliance_report";
        public const string AddonAuditReport = "enterprise_audit_and_reporting";
        public const string AddonServiceAndSupport = "msp_service_and_support";
        public const string AddonSecretsManager = "secrets_manager";
        public const string AddonConnectionManager = "connection_manager";
        public const string AddonChat = "chat";
    }

    /// <exclude />
    public class MspPrice
    {
        public float Amount { get; internal set; }
        public Cost.Types.AmountPer Rate { get; internal set; }
        public long AmountConsumed { get; internal set; }
        public Currency Currency { get; internal set; }
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

        private readonly Dictionary<string, MspPrice> _prices = new();

        protected override void DataStructureChanged()
        {
            lock (this)
            {
                if (_prices.Count > 0)
                {
                    return;
                }
                var enterprise = GetEnterprise?.Invoke();
                if (enterprise == null)
                {
                    return;
                }

                var names = new Dictionary<int, string>
                {
                    [1] = ManagedCompanyConstants.BusinessLicense,
                    [2] = ManagedCompanyConstants.BusinessPlusLicense,
                    [10] = ManagedCompanyConstants.EnterpriseLicense,
                    [11] = ManagedCompanyConstants.EnterprisePlusLicense,
                    [400] = ManagedCompanyConstants.StoragePlan100GB,
                    [700] = ManagedCompanyConstants.StoragePlan1TB,
                    [800] = ManagedCompanyConstants.StoragePlan10TB,
                };

                Task.Run(async () =>
                {
                    try
                    {
                        var endpoint = enterprise.Auth.GetBiUrl("mapping/addons");
                        var rq = new MappingAddonsRequest();
                        var rs = await enterprise.Auth.ExecuteAuthRest<MappingAddonsRequest, MappingAddonsResponse>(endpoint, rq);
                        foreach (var fp in rs.FilePlans)
                        {
                            names[fp.Id * 100] = fp.Name;
                        }
                        foreach (var ap in rs.Addons)
                        {
                            names[ap.Id * 10000] = ap.Name;
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }

                    try
                    {
                        var endpoint = enterprise.Auth.GetBiUrl("subscription/mc_pricing");
                        var rq = new SubscriptionMcPricingRequest();
                        var rs = await enterprise.Auth.ExecuteAuthRest<SubscriptionMcPricingRequest, SubscriptionMcPricingResponse>(endpoint, rq);
                        foreach (var bp in rs.BasePlans)
                        {
                            if (names.TryGetValue(bp.Id, out var name))
                            {
                                _prices[name] = new MspPrice
                                {
                                    Amount = (float) bp.Cost.Amount,
                                    Currency = bp.Cost.Currency,
                                    Rate = bp.Cost.AmountPer,
                                };
                            }
                        }
                        foreach (var fp in rs.FilePlans)
                        {
                            if (names.TryGetValue(fp.Id * 100, out var name))
                            {
                                _prices[name] = new MspPrice
                                {
                                    Amount = (float) fp.Cost.Amount,
                                    Currency = fp.Cost.Currency,
                                    Rate = fp.Cost.AmountPer,
                                };
                            }
                        }
                        foreach (var ap in rs.Addons)
                        {
                            if (names.TryGetValue(ap.Id * 10000, out var name))
                            {
                                _prices[name] = new MspPrice
                                {
                                    Amount = (float) ap.Cost.Amount,
                                    Currency = ap.Cost.Currency,
                                    Rate = ap.Cost.AmountPer,
                                    AmountConsumed = ap.AmountConsumed,
                                };
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                });
            }
        }

        public Func<IEnterpriseLoader> GetEnterprise { get; set; }
    }

    /// <exclude />
    public class ManagedCompanyAuth : AuthCommon
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

        public override object AuthCallback => null;
    }
}
