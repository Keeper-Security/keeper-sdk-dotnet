using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseNodeExamples
{
    public static class SetEnterpriseCustomLogoExample
    {
        public static async Task SetEnterpriseCustomLogoExample(long nodeId, string logoType, string filePath)
        {
            try
            {   
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                var response = await enterpriseData.UploadEnterpriseCustomLogo(nodeId, logoType, filePath);
                Console.WriteLine($"Logo Path: {response.LogoPath}");
                Console.WriteLine($"Status: {response.Status}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}