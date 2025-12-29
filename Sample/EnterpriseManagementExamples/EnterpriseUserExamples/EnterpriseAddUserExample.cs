using System;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using Cli;

namespace Sample.EnterpriseManagementExamples.EnterpriseUserExamples
{
    public static class EnterpriseAddUserExample
    {

        public static async Task InviteUser(string email, InviteUserOptions options = null)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                // Load enterprise data
                var enterpriseData = new EnterpriseData();
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData });
                await enterpriseLoader.Load();

                if (options != null && (!string.IsNullOrEmpty(options.FullName) || options.NodeId.HasValue))
                    options = new InviteUserOptions { FullName = options.FullName, NodeId = options.NodeId };

                var newUser = await enterpriseData.InviteUser(email, options);

                Console.WriteLine("======== User Invited Successfully ========");
                Console.WriteLine($"User ID:      {newUser.Id}");
                Console.WriteLine($"Email:        {newUser.Email}");
                Console.WriteLine($"Display Name: {newUser.DisplayName ?? "N/A"}");
                Console.WriteLine($"Status:       {newUser.UserStatus}");
                Console.WriteLine($"Node ID:      {newUser.ParentNodeId}");
                Console.WriteLine("============================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}