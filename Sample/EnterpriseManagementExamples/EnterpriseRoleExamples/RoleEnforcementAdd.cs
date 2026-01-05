using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Enterprise;
using System.Collections.Generic;

namespace Sample.EnterpriseManagementExamples.EnterpriseRoleExamples
{
    public static class RoleEnforcementAdd
    {
        public static async Task RoleEnforcementAdd(string roleName, IDictionary<RoleEnforcementPolicies, string> enforcements)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                var enterpriseData = new EnterpriseData();
                var roleData = new RoleData { EnterpriseData = enterpriseData };
                var enterpriseLoader = new EnterpriseLoader(
                    vault.Auth,
                    new EnterpriseDataPlugin[] { enterpriseData, roleData });
                await enterpriseLoader.Load();

                // Get the role by name
                var role = roleData.Roles.FirstOrDefault(r => r.DisplayName == roleName);
                if (role == null)
                {
                    Console.WriteLine("Role not found");
                    return;
                }

                var responses = await roleData.RoleEnforcementAddBatch(role, enforcements);
                Console.WriteLine($"Batch enforcement results for role: {role.Id}");
                var enforcementKeys = enforcements.Keys.ToList();
                for (int i = 0; i < responses.Count; i++)
                {
                    var response = responses[i];
                    var enforcementPolicy = enforcementKeys[i];
                    if (response.IsSuccess)
                    {
                        Console.WriteLine($"Command: {response.command}, Enforcement: {enforcementPolicy}, Result: {response.result}");
                    }
                    else
                    {
                        Console.WriteLine($"Command: {response.command}, Enforcement: {enforcementPolicy}, Result: {response.result}, Code: {response.resultCode}, Message: {response.message}");
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}