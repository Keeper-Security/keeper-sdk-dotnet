using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class GetEnterpriseCustomInvitationExample
    {
        public static async Task GetEnterpriseCustomInvitation(long nodeId)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                var invitation = await enterpriseData.GetEnterpriseCustomInvitation(nodeId);
                Console.WriteLine($"Subject: {invitation.Subject}");
                Console.WriteLine($"Header: {invitation.Header}");
                Console.WriteLine($"Body: {invitation.Body}");
                Console.WriteLine($"ButtonLabel: {invitation.ButtonLabel}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}