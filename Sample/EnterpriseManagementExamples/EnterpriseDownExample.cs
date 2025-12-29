using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples
{
    public static class EnterpriseDownExample
    {
        public static async Task EnterpriseGetData()
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth, 
                    new EnterpriseDataPlugin[] { enterpriseData });
                
                await enterpriseLoader.Load();
                
                Console.WriteLine("Enterprise data loaded successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}