using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class SetEnterpriseCustomInvitationExample
    {
        public static async Task SetEnterpriseCustomInvitationExample(long nodeId, string jsonFilePath)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                await enterpriseData.SetEnterpriseCustomInvitation(nodeId, jsonFilePath);
                Console.WriteLine($"Enterprise custom invitation set successfully with nodeId: {nodeId}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}