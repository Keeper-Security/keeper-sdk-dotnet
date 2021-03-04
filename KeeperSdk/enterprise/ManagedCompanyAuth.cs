using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace KeeperSecurity.Enterprise
{
    /// <exclude />
    public class ManagedCompanyAuth: AuthCommon
    {
        public byte[] TreeKey { get; private set; }

        public async Task LoginToManagedCompany(EnterpriseData enterprise, int mcEnterpriseId)
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
